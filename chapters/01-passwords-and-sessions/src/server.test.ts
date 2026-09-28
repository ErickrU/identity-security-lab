import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LOGIN_RATE_LIMIT, LoginRateLimiter, startServer, type RunningServer } from './server';
import { DEFAULT_ABSOLUTE_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS } from './sessions';

const MINUTE = 60_000;
const GOOD = 'correct horse battery staple';

interface Reply {
  status: number;
  json: any;
  setCookie: string[];
  headers: Headers;
}

/** Just enough of a browser: remembers the `sid` cookie and the CSRF token. */
class Client {
  sid: string | undefined;
  csrfToken: string | undefined;

  constructor(private readonly base: string) {}

  async call(
    method: string,
    path: string,
    opts: { body?: unknown; rawBody?: string; headers?: Record<string, string>; sendCookie?: boolean } = {},
  ): Promise<Reply> {
    const headers: Record<string, string> = { ...opts.headers };
    let body: string | undefined = opts.rawBody;
    if (opts.body !== undefined) body = JSON.stringify(opts.body);
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (this.sid && opts.sendCookie !== false) headers.cookie = `sid=${this.sid}`;

    const res = await fetch(this.base + path, { method, headers, body });
    const setCookie = res.headers.getSetCookie();
    for (const cookie of setCookie) {
      const match = /^sid=([^;]*)/.exec(cookie);
      if (match) this.sid = match[1] || undefined; // `sid=; Max-Age=0` clears it
    }
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : undefined, setCookie, headers: res.headers };
  }

  register(username: string, password: string) {
    return this.call('POST', '/register', { body: { username, password } });
  }

  async login(username: string, password: string) {
    const reply = await this.call('POST', '/login', { body: { username, password } });
    if (reply.status === 200) this.csrfToken = reply.json.csrfToken;
    return reply;
  }

  me() {
    return this.call('GET', '/me');
  }

  /** Pass `null` to send no token at all. */
  transfer(to: string, amount: number, token: string | null = this.csrfToken ?? null) {
    return this.call('POST', '/transfer', { body: { to, amount }, headers: token ? { 'x-csrf-token': token } : {} });
  }

  logout() {
    return this.call('POST', '/logout');
  }
}

describe('bounded login-rate-limit state', () => {
  it('sweeps expired unique usernames instead of retaining them forever', () => {
    let now = 0;
    const limiter = new LoginRateLimiter(5, 1_000, () => now, 3);
    expect(limiter.hit('a').allowed).toBe(true);
    expect(limiter.hit('b').allowed).toBe(true);
    expect(limiter.hit('c').allowed).toBe(true);
    expect(limiter.size).toBe(3);
    now = 1_001;
    expect(limiter.hit('d').allowed).toBe(true); // hit triggers the scheduled global sweep
    expect(limiter.size).toBe(1);
  });

  it('fails closed at the hard key cap instead of growing memory or evicting another account limit', () => {
    const limiter = new LoginRateLimiter(5, 60_000, () => 0, 2);
    expect(limiter.hit('a').allowed).toBe(true);
    expect(limiter.hit('b').allowed).toBe(true);
    expect(limiter.hit('sprayed-third-name')).toEqual({ allowed: false, retryAfterMs: 60_000 });
    expect(limiter.size).toBe(2);
  });
});

describe('01 · passwords and sessions server', () => {
  let t = Date.UTC(2030, 0, 1, 9, 0, 0);
  const advance = (ms: number) => {
    t += ms;
  };
  let running: RunningServer;
  let url: string;

  beforeAll(async () => {
    running = await startServer(0, { now: () => t, log: () => {} });
    url = running.url;
    const setup = new Client(url);
    for (const user of ['alice', 'bob', 'ratelimited', 'sleepy', 'workaholic', 'quitter']) {
      expect((await setup.register(user, GOOD)).status).toBe(201);
    }
  });

  afterAll(() => running.stop());

  describe('POST /register', () => {
    it('creates a user and stores a scrypt hash, never the password', async () => {
      const reply = await new Client(url).register('Carol', GOOD);
      expect(reply.status).toBe(201);
      expect(reply.json).toEqual({ username: 'carol' }); // normalised to lower case
      const stored = running.app.users.get('carol')!.passwordHash;
      expect(stored.startsWith('scrypt$32768$8$1$')).toBe(true);
      expect(stored).not.toContain(GOOD);
    });

    it('refuses a duplicate username with 409', async () => {
      const reply = await new Client(url).register('alice', 'another fine passphrase');
      expect(reply.status).toBe(409);
    });

    it('atomically reserves a username while the slow hash is running', async () => {
      const first = new Client(url).register('simultaneous', 'first correct horse battery staple');
      const second = new Client(url).register('simultaneous', 'second correct horse battery staple');
      const replies = await Promise.all([first, second]);
      expect(replies.map((reply) => reply.status).sort()).toEqual([201, 409]);
      expect(running.app.users.has('simultaneous')).toBe(true);
    });

    it('enforces the password policy: length, not character classes', async () => {
      const client = new Client(url);
      expect((await client.register('dave', 'short')).status).toBe(400);
      expect((await client.register('dave', 'Password1!')).status).toBe(400);
      expect((await client.register('dave', 'alllowercasebutlong')).status).toBe(201);
    });

    it('rejects malformed input with 400', async () => {
      const client = new Client(url);
      expect((await client.call('POST', '/register', { rawBody: '{not json' })).status).toBe(400);
      expect((await client.call('POST', '/register', { body: { username: 'erin' } })).status).toBe(400);
      expect((await client.call('POST', '/register', { body: { username: 'no spaces', password: GOOD } })).status).toBe(400);
      expect((await client.call('POST', '/register', { body: ['alice', GOOD] })).status).toBe(400);
    });
  });

  describe('POST /login', () => {
    it('answers an unknown user and a wrong password with the exact same error', async () => {
      const client = new Client(url);
      const unknown = await client.login('nobody', GOOD);
      const wrong = await client.login('alice', 'not the password');
      expect(unknown.status).toBe(401);
      expect(wrong.status).toBe(401);
      expect(JSON.stringify(unknown.json)).toBe(JSON.stringify(wrong.json));
      expect(unknown.json).toEqual({ error: 'invalid credentials' });
      expect(unknown.setCookie).toEqual([]);
      expect(wrong.setCookie).toEqual([]);
    });

    it('sets a cookie with HttpOnly, SameSite=Lax and Path=/ on success', async () => {
      const client = new Client(url);
      const reply = await client.login('alice', GOOD);
      expect(reply.status).toBe(200);
      expect(reply.json.username).toBe('alice');
      expect(reply.json.csrfToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

      expect(reply.setCookie).toHaveLength(1);
      const cookie = reply.setCookie[0];
      expect(cookie).toMatch(/^sid=[A-Za-z0-9_-]{43}; /);
      expect(cookie).toContain('HttpOnly');
      expect(cookie).toContain('SameSite=Lax');
      expect(cookie).toContain('Path=/');
      expect(cookie).not.toContain('Secure'); // plain http in this test
      expect(cookie).not.toMatch(/Max-Age|Expires/); // a session cookie; the server owns the lifetime
    });

    it('adds the Secure attribute when TLS is on', async () => {
      const tls = await startServer(0, { secureCookies: true, log: () => {} });
      try {
        const client = new Client(tls.url);
        await client.register('alice', GOOD);
        const reply = await client.login('alice', GOOD);
        expect(reply.setCookie[0]).toContain('Secure');
        const out = await client.logout();
        expect(out.setCookie[0]).toContain('Secure');
      } finally {
        await tls.stop();
      }
    });

    it('issues a new session id on every login and kills the presented one (fixation)', async () => {
      const client = new Client(url);
      await client.login('alice', GOOD);
      const first = client.sid!;
      await client.login('alice', GOOD); // browser still carries `first`
      const second = client.sid!;
      expect(second).not.toBe(first);
      expect(running.app.sessions.getSession(first)).toBeUndefined();
      expect(running.app.sessions.getSession(second)?.userId).toBe('alice');
    });

    it('rate-limits to 5 attempts a minute per username, then recovers', async () => {
      const client = new Client(url);
      for (let i = 0; i < LOGIN_RATE_LIMIT.max; i++) {
        expect((await client.login('ratelimited', 'wrong')).status).toBe(401);
      }
      const blocked = await client.login('ratelimited', GOOD); // even the right password
      expect(blocked.status).toBe(429);
      expect(blocked.headers.get('retry-after')).toBe('60');
      expect(blocked.setCookie).toEqual([]);

      advance(LOGIN_RATE_LIMIT.windowMs + 1);
      expect((await client.login('ratelimited', GOOD)).status).toBe(200);
    });

    it('counts attempts per username, so one account under attack does not block another', async () => {
      const client = new Client(url);
      for (let i = 0; i < LOGIN_RATE_LIMIT.max; i++) await client.login('bob', 'wrong');
      expect((await client.login('bob', GOOD)).status).toBe(429);
      expect((await new Client(url).login('alice', GOOD)).status).toBe(200);
    });
  });

  describe('GET /me', () => {
    it('is 401 without a cookie and 401 with an id we never issued', async () => {
      const client = new Client(url);
      expect((await client.me()).status).toBe(401);
      client.sid = 'A'.repeat(43);
      const forged = await client.me();
      expect(forged.status).toBe(401);
      expect(forged.setCookie[0]).toMatch(/^sid=; .*Max-Age=0/); // and the dead cookie is cleared
    });

    it('is 200 with a live session cookie', async () => {
      const client = new Client(url);
      await client.login('alice', GOOD);
      const reply = await client.me();
      expect(reply.status).toBe(200);
      expect(reply.json.username).toBe('alice');
      expect(reply.json.csrfToken).toBe(client.csrfToken);
    });
  });

  describe('session lifetime (injected clock, no sleeping)', () => {
    it('expires after 30 minutes without a request; activity slides the window', async () => {
      const client = new Client(url);
      await client.login('sleepy', GOOD);
      advance(DEFAULT_IDLE_TIMEOUT_MS - MINUTE);
      expect((await client.me()).status).toBe(200);
      advance(DEFAULT_IDLE_TIMEOUT_MS - MINUTE);
      expect((await client.me()).status).toBe(200); // 58 min after login, still alive because it was used
      advance(DEFAULT_IDLE_TIMEOUT_MS);
      const expired = await client.me();
      expect(expired.status).toBe(401);
      expect(expired.setCookie[0]).toMatch(/Max-Age=0/);
    });

    it('expires 8 hours after login even when used every 10 minutes', async () => {
      const client = new Client(url);
      await client.login('workaholic', GOOD);
      const step = 10 * MINUTE;
      for (let elapsed = step; elapsed < DEFAULT_ABSOLUTE_TIMEOUT_MS; elapsed += step) {
        advance(step);
        expect((await client.me()).status, `${elapsed / MINUTE} min after login`).toBe(200);
      }
      advance(step);
      expect((await client.me()).status).toBe(401);
    });
  });

  describe('POST /transfer (cookie + CSRF token)', () => {
    it('is 401 without a session', async () => {
      const reply = await new Client(url).transfer('bob', 10, 'whatever');
      expect(reply.status).toBe(401);
    });

    it('is 403 with the cookie but no token, and with a wrong token', async () => {
      const client = new Client(url);
      await client.login('alice', GOOD);
      expect((await client.transfer('bob', 10, null)).status).toBe(403);
      expect((await client.transfer('bob', 10, 'B'.repeat(43))).status).toBe(403);
      expect((await client.transfer('bob', 10, client.csrfToken!.slice(0, -1))).status).toBe(403);
    });

    it('is 200 with cookie and matching token; the sender comes from the session, not the body', async () => {
      const client = new Client(url);
      await client.login('alice', GOOD);
      const reply = await client.call('POST', '/transfer', {
        body: { from: 'bob', to: 'bob', amount: 10 }, // "from" is ignored on purpose
        headers: { 'x-csrf-token': client.csrfToken! },
      });
      expect(reply.status).toBe(200);
      expect(reply.json).toEqual({ ok: true, from: 'alice', to: 'bob', amount: 10 });
    });

    it('validates the payload', async () => {
      const client = new Client(url);
      await client.login('alice', GOOD);
      expect((await client.transfer('bob', -5)).status).toBe(400);
    });
  });

  describe('POST /logout', () => {
    it('destroys the session on the server and clears the cookie', async () => {
      const client = new Client(url);
      await client.login('quitter', GOOD);
      const stolenCopy = client.sid!;

      const reply = await client.logout();
      expect(reply.status).toBe(200);
      expect(reply.setCookie[0]).toMatch(/^sid=; .*Max-Age=0/);
      expect(client.sid).toBeUndefined();

      // A copy of the cookie kept elsewhere is just as dead.
      client.sid = stolenCopy;
      expect((await client.me()).status).toBe(401);
      expect(running.app.sessions.getSession(stolenCopy)).toBeUndefined();
    });

    it('is harmless without a session', async () => {
      expect((await new Client(url).logout()).status).toBe(200);
    });
  });

  describe('routing', () => {
    it('is 404 for unknown paths and 405 for wrong methods', async () => {
      const client = new Client(url);
      expect((await client.call('GET', '/nope')).status).toBe(404);
      const wrongMethod = await client.call('GET', '/login');
      expect(wrongMethod.status).toBe(405);
      expect(wrongMethod.headers.get('allow')).toBe('POST');
    });
  });
});
