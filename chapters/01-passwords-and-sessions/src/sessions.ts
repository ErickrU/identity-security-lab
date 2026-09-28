/**
 * 01 · Server-side sessions.
 *
 * After a successful login the server needs a way to recognise the same
 * browser on the next request without asking for the password again. The
 * classic answer: the server creates a record ("alice, logged in at 10:02"),
 * gives the browser an OPAQUE handle to it, and the browser sends that
 * handle back in a cookie.
 *
 * Opaque means the id carries no information. It is 32 random bytes (256
 * bits), so it cannot be guessed, forged or decoded. Everything about the
 * session lives on the server, which is exactly what makes it revocable in
 * an instant: delete the record and the cookie is worthless. Compare with a
 * JWT (chapter 03), which carries its own claims and cannot be un-issued.
 *
 * Two timeouts, both enforced here and not in the cookie, because the client
 * controls its own clock and its own cookie jar:
 *   idle      30 min without a request → gone. Limits what a forgotten open
 *             laptop or a stolen cookie is worth.
 *   absolute  8 h after login → gone, however active. Caps the lifetime of a
 *             cookie that was stolen and kept warm by the thief.
 *
 * The store is an in-memory Map: fine for one process, useless for two. The
 * README covers what changes when you scale (Redis/ElastiCache, DynamoDB
 * with TTL, sticky sessions).
 */
import { randomBytes } from 'node:crypto';

export interface Session {
  /** Opaque handle the browser holds. 32 random bytes, base64url (43 chars). */
  id: string;
  userId: string;
  /** Per-session secret the client must echo in a header on state-changing requests. */
  csrfToken: string;
  /** ms since epoch, per the injected clock. */
  createdAt: number;
  lastSeenAt: number;
}

export type SessionLookup =
  | { ok: true; session: Session }
  | { ok: false; reason: 'no-id' | 'unknown' | 'idle-timeout' | 'absolute-timeout' };

export interface SessionStoreOptions {
  /** Clock in ms. Injected so tests can fast-forward instead of sleeping. */
  now?: () => number;
  idleTimeoutMs?: number;
  absoluteTimeoutMs?: number;
}

export const DEFAULT_IDLE_TIMEOUT_MS = 30 * 60 * 1000;
export const DEFAULT_ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
export const SESSION_ID_BYTES = 32;

/**
 * A random, unguessable identifier. 32 bytes = 256 bits: even at a billion
 * guesses per second an attacker would not stumble on a valid id before the
 * sun burns out. OWASP's floor is 64 bits; there is no reason to be near it.
 */
export function newOpaqueId(bytes: number = SESSION_ID_BYTES): string {
  return randomBytes(bytes).toString('base64url');
}

export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly now: () => number;
  readonly idleTimeoutMs: number;
  readonly absoluteTimeoutMs: number;

  constructor(options: SessionStoreOptions = {}) {
    this.now = options.now ?? Date.now;
    this.idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.absoluteTimeoutMs = options.absoluteTimeoutMs ?? DEFAULT_ABSOLUTE_TIMEOUT_MS;
  }

  /** Start a session for a user who has just proven who they are. */
  createSession(userId: string): Session {
    const now = this.now();
    const session: Session = {
      id: newOpaqueId(),
      userId,
      csrfToken: newOpaqueId(),
      createdAt: now,
      lastSeenAt: now,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Find a session and enforce both timeouts. A valid lookup also refreshes
   * `lastSeenAt` (the idle window slides). Expired sessions are deleted on
   * the spot so a later request cannot revive them. Returns the reason on
   * failure so the server can explain its decision in the log.
   */
  lookup(id: string | undefined): SessionLookup {
    if (!id) return { ok: false, reason: 'no-id' };
    const session = this.sessions.get(id);
    if (!session) return { ok: false, reason: 'unknown' };

    const now = this.now();
    if (now - session.createdAt >= this.absoluteTimeoutMs) {
      this.sessions.delete(id);
      return { ok: false, reason: 'absolute-timeout' };
    }
    if (now - session.lastSeenAt >= this.idleTimeoutMs) {
      this.sessions.delete(id);
      return { ok: false, reason: 'idle-timeout' };
    }
    session.lastSeenAt = now;
    return { ok: true, session };
  }

  /** `lookup` without the reason. */
  getSession(id: string | undefined): Session | undefined {
    const result = this.lookup(id);
    return result.ok ? result.session : undefined;
  }

  /** Logout. Once this returns, the id is dead everywhere, whatever cookies still exist. */
  destroySession(id: string): boolean {
    return this.sessions.delete(id);
  }

  /**
   * Session fixation defence. Called at login with whatever id the browser
   * presented (maybe none, maybe one an attacker planted). We never upgrade
   * an existing id to "logged in"; we delete it and issue a fresh one. So an
   * attacker who managed to set a known id in the victim's browser gains
   * nothing: after the victim logs in, the attacker's id points nowhere.
   */
  rotateSession(presentedId: string | undefined, userId: string): Session {
    if (presentedId) this.sessions.delete(presentedId);
    return this.createSession(userId);
  }

  /**
   * "Log me out everywhere". Run this on password change, on a reported
   * stolen laptop, on account compromise. Only possible because sessions are
   * server-side; with stateless tokens you would need a denylist.
   */
  destroyAllForUser(userId: string): number {
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (session.userId === userId) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Garbage collection. Abandoned sessions are only deleted when someone
   * presents them, so a long-running server would leak memory without this.
   * Real stores get it for free: Redis EXPIRE, DynamoDB TTL.
   */
  sweep(): number {
    const now = this.now();
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (now - session.createdAt >= this.absoluteTimeoutMs || now - session.lastSeenAt >= this.idleTimeoutMs) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  get size(): number {
    return this.sessions.size;
  }
}
