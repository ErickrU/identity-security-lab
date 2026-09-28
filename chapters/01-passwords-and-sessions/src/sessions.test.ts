import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ABSOLUTE_TIMEOUT_MS,
  DEFAULT_IDLE_TIMEOUT_MS,
  SessionStore,
  newOpaqueId,
} from './sessions';

const MINUTE = 60 * 1000;
const HOUR = 60 * MINUTE;

/** A store with a clock we control. Nothing here sleeps. */
function storeWithClock() {
  let t = Date.UTC(2030, 0, 1, 9, 0, 0);
  const clock = {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
  };
  return { store: new SessionStore({ now: clock.now }), clock };
}

describe('opaque ids', () => {
  it('are 32 random bytes as base64url (43 chars, URL and cookie safe)', () => {
    const id = newOpaqueId();
    expect(id).toHaveLength(43);
    expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(id, 'base64url')).toHaveLength(32);
  });

  it('never repeat', () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newOpaqueId()));
    expect(ids.size).toBe(1000);
  });
});

describe('SessionStore', () => {
  it('creates a session and finds it again by id', () => {
    const { store } = storeWithClock();
    const session = store.createSession('alice');
    expect(session.userId).toBe('alice');
    expect(store.getSession(session.id)?.userId).toBe('alice');
    expect(store.size).toBe(1);
  });

  it('gives each session its own CSRF token, distinct from the id', () => {
    const { store } = storeWithClock();
    const a = store.createSession('alice');
    const b = store.createSession('alice');
    expect(a.csrfToken).toHaveLength(43);
    expect(a.csrfToken).not.toBe(a.id);
    expect(a.csrfToken).not.toBe(b.csrfToken);
  });

  it('reports why a lookup failed', () => {
    const { store } = storeWithClock();
    expect(store.lookup(undefined)).toEqual({ ok: false, reason: 'no-id' });
    expect(store.lookup('never-issued')).toEqual({ ok: false, reason: 'unknown' });
    expect(store.getSession('never-issued')).toBeUndefined();
  });

  it('expires after 30 minutes idle, and activity slides the window', () => {
    const { store, clock } = storeWithClock();
    const { id } = store.createSession('alice');

    clock.advance(DEFAULT_IDLE_TIMEOUT_MS - 1);
    expect(store.getSession(id)).toBeDefined(); // just under, and this touch resets the timer

    clock.advance(DEFAULT_IDLE_TIMEOUT_MS - 1);
    expect(store.getSession(id)).toBeDefined(); // 59 min after login, still fine because it was used

    clock.advance(DEFAULT_IDLE_TIMEOUT_MS);
    expect(store.lookup(id)).toEqual({ ok: false, reason: 'idle-timeout' });
    expect(store.size).toBe(0); // deleted, not just hidden
  });

  it('expires 8 hours after login even when constantly active', () => {
    const { store, clock } = storeWithClock();
    const { id } = store.createSession('alice');

    const step = 10 * MINUTE;
    for (let elapsed = step; elapsed < DEFAULT_ABSOLUTE_TIMEOUT_MS; elapsed += step) {
      clock.advance(step);
      expect(store.getSession(id), `at ${elapsed / HOUR} h`).toBeDefined();
    }
    clock.advance(step); // crosses 8 h
    expect(store.lookup(id)).toEqual({ ok: false, reason: 'absolute-timeout' });
  });

  it('destroySession makes the id useless immediately', () => {
    const { store } = storeWithClock();
    const { id } = store.createSession('alice');
    expect(store.destroySession(id)).toBe(true);
    expect(store.getSession(id)).toBeUndefined();
    expect(store.destroySession(id)).toBe(false); // idempotent
  });

  it('rotateSession issues a new id at login and kills the presented one (fixation)', () => {
    const { store } = storeWithClock();
    const planted = store.createSession('anonymous'); // what an attacker might have set in the victim's browser
    const fresh = store.rotateSession(planted.id, 'alice');
    expect(fresh.id).not.toBe(planted.id);
    expect(fresh.csrfToken).not.toBe(planted.csrfToken);
    expect(store.getSession(planted.id)).toBeUndefined();
    expect(store.getSession(fresh.id)?.userId).toBe('alice');
  });

  it('rotateSession works when the browser presented nothing', () => {
    const { store } = storeWithClock();
    const fresh = store.rotateSession(undefined, 'alice');
    expect(store.getSession(fresh.id)?.userId).toBe('alice');
  });

  it('destroyAllForUser logs a user out everywhere and leaves others alone', () => {
    const { store } = storeWithClock();
    const a1 = store.createSession('alice');
    const a2 = store.createSession('alice');
    const b = store.createSession('bob');
    expect(store.destroyAllForUser('alice')).toBe(2);
    expect(store.getSession(a1.id)).toBeUndefined();
    expect(store.getSession(a2.id)).toBeUndefined();
    expect(store.getSession(b.id)?.userId).toBe('bob');
  });

  it('sweep removes expired sessions nobody came back for', () => {
    const { store, clock } = storeWithClock();
    store.createSession('alice');
    store.createSession('bob');
    const active = store.createSession('carol');
    clock.advance(20 * MINUTE);
    store.getSession(active.id); // carol keeps using the app
    clock.advance(20 * MINUTE); // alice and bob are now 40 min idle, carol 20
    expect(store.sweep()).toBe(2);
    expect(store.size).toBe(1);
  });

  it('honours custom timeouts', () => {
    let t = 0;
    const store = new SessionStore({ now: () => t, idleTimeoutMs: 1000, absoluteTimeoutMs: 5000 });
    const { id } = store.createSession('alice');
    t = 999;
    expect(store.getSession(id)).toBeDefined();
    t = 1998;
    expect(store.getSession(id)).toBeDefined();
    t = 3000;
    expect(store.lookup(id)).toEqual({ ok: false, reason: 'idle-timeout' });
    const second = store.createSession('bob'); // created at t = 3000
    for (t = 3900; t < 8000; t += 900) expect(store.getSession(second.id)).toBeDefined(); // kept alive every 0.9 s
    t = 8000;
    expect(store.lookup(second.id)).toEqual({ ok: false, reason: 'absolute-timeout' });
  });
});
