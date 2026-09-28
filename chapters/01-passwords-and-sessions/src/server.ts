/**
 * 01 · A small JSON API with password login and cookie sessions.
 *
 * Plain node:http on purpose: every header and every decision is in this
 * file, nothing is hidden in a framework.
 *
 *   POST /register  {username, password}                → 201 | 400 | 409
 *   POST /login     {username, password}                → 200 + Set-Cookie sid | 401 | 429
 *   GET  /me        Cookie: sid                         → 200 {username} | 401
 *   POST /transfer  Cookie: sid + x-csrf-token header   → 200 | 401 | 403
 *   POST /logout    Cookie: sid                         → 200, session destroyed, cookie cleared
 *
 * `createApp()` builds the handler with an injectable clock so tests can
 * fast-forward time; `startServer(0)` binds a random port for tests and the
 * demo; `npm run 01` runs it on 4010.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { performance } from 'node:perf_hooks';
import { checkPasswordPolicy, hashPassword, verifyPassword } from './passwords';
import { SessionStore, type Session, type SessionLookup } from './sessions';

export const COOKIE_NAME = 'sid';
export const CSRF_HEADER = 'x-csrf-token';
export const DEFAULT_PORT = 4010;
export const LOGIN_RATE_LIMIT = { max: 5, windowMs: 60_000, maxKeys: 10_000 };
const MAX_BODY_BYTES = 16 * 1024;

export interface UserRecord {
  username: string;
  /** `scrypt$N$r$p$salt$hash`. Never the password. */
  passwordHash: string;
  createdAt: number;
}

export interface AppOptions {
  /** Clock in ms since epoch. Tests inject one; default Date.now. */
  now?: () => number;
  /** Add the `Secure` cookie attribute. Default: env TLS=1. */
  secureCookies?: boolean;
  /** Teaching output. Default console.log; tests pass () => {}. */
  log?: (line: string) => void;
  loginRateLimit?: { max: number; windowMs: number; maxKeys?: number };
}

export interface App {
  handler: (req: IncomingMessage, res: ServerResponse) => void;
  /** Exposed so the demo can print a stored hash and tests can inspect state. */
  users: Map<string, UserRecord>;
  sessions: SessionStore;
}

/** Thrown by route handlers; the dispatcher turns it into a JSON error response. */
class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

interface Reply {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

type Route = (req: IncomingMessage) => Promise<Reply>;

/**
 * Login attempts per username in a sliding window. The point is to make
 * online guessing slow: at 5 tries a minute a dictionary of a million words
 * takes 139 days per account, instead of a few seconds.
 *
 * Per-username alone has a downside: an attacker can lock a victim out by
 * spamming wrong passwords. Real systems combine per-username with per-IP
 * limits, device signals and step-up challenges (CAPTCHA, MFA) rather than
 * a hard lock, and they never reveal the counter to the client. This in-memory
 * teaching limiter also sweeps expired names and caps key cardinality; production
 * uses a bounded shared store with per-account and per-source controls.
 */
export class LoginRateLimiter {
  private readonly attempts = new Map<string, number[]>();
  private nextSweepAt = 0;

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
    private readonly now: () => number,
    private readonly maxKeys = 10_000,
  ) {
    if (max <= 0 || windowMs <= 0 || maxKeys <= 0) throw new Error('rate-limit values must be positive');
  }

  /** Record an attempt, or refuse it and say how long to wait. Memory is globally bounded. */
  hit(key: string): { allowed: true } | { allowed: false; retryAfterMs: number } {
    const now = this.now();
    if (now >= this.nextSweepAt || this.attempts.size >= this.maxKeys) this.sweep(now);
    const prior = this.attempts.get(key);
    const recent = (prior ?? []).filter((t) => now - t < this.windowMs);
    if (!prior && this.attempts.size >= this.maxKeys) {
      // Do not trade an unbounded-memory attack for silent eviction/bypass of another account's limit.
      return { allowed: false, retryAfterMs: this.windowMs };
    }
    if (recent.length >= this.max) {
      this.attempts.set(key, recent);
      return { allowed: false, retryAfterMs: recent[0] + this.windowMs - now };
    }
    recent.push(now);
    this.attempts.set(key, recent);
    return { allowed: true };
  }

  /** Remove every key with no attempt in the active window. Shared production limiters use TTLs. */
  sweep(at = this.now()): number {
    let removed = 0;
    for (const [key, times] of this.attempts) {
      const recent = times.filter((t) => at - t < this.windowMs);
      if (recent.length === 0) { this.attempts.delete(key); removed++; }
      else this.attempts.set(key, recent);
    }
    this.nextSweepAt = at + this.windowMs;
    return removed;
  }

  get size(): number { return this.attempts.size; }

  /** A successful login clears the slate for that account. */
  reset(key: string): void {
    this.attempts.delete(key);
  }
}

export function createApp(options: AppOptions = {}): App {
  const now = options.now ?? Date.now;
  const log = options.log ?? ((line: string) => console.log(line));
  const secureCookies = options.secureCookies ?? process.env.TLS === '1';
  const users = new Map<string, UserRecord>();
  const sessions = new SessionStore({ now });
  const limit = options.loginRateLimit ?? LOGIN_RATE_LIMIT;
  const limiter = new LoginRateLimiter(limit.max, limit.windowMs, now, limit.maxKeys ?? LOGIN_RATE_LIMIT.maxKeys);
  // Reserve names before the asynchronous password KDF. Without this, two simultaneous
  // registrations can both see "available" and whichever hash finishes last owns the account.
  // A real database enforces the same invariant with a unique constraint/conditional insert.
  const registrationsInFlight = new Set<string>();

  // A hash of a random password nobody knows. When a login names a user that
  // does not exist we verify against THIS instead of skipping the work, so
  // "unknown user" and "wrong password" take the same time. Without it an
  // attacker could enumerate accounts with a stopwatch: a fast 401 would mean
  // "no such user", a slow one "user exists, wrong password".
  const decoyHash = hashPassword(randomBytes(16).toString('hex'));

  // ---- cookies --------------------------------------------------------------

  /**
   * The session cookie. Each attribute closes one hole.
   *
   *   HttpOnly      page JavaScript cannot read it (document.cookie), so an
   *                 XSS bug cannot exfiltrate it. XSS can still act through
   *                 the browser while the page is open, which is why the
   *                 CSRF token below is kept in JS memory and not in a cookie.
   *   SameSite=Lax  the browser omits the cookie on cross-site POSTs, fetches,
   *                 iframes and images. It is only sent on same-site requests
   *                 and on top-level GET navigations. This alone kills the
   *                 classic CSRF form on evil.example.
   *   Path=/        valid for the whole app. Path is scoping, not security:
   *                 any page on the origin can reach any path.
   *   Secure        only with TLS=1: never sent over plain http://, so a
   *                 hostile network cannot read it. Always on in production;
   *                 off here only so the demo works on http://127.0.0.1.
   *
   * No Max-Age or Expires: browsers treat that as a "session cookie" and drop
   * it when they close. The lifetime you can trust is the server-side one
   * (idle 30 min, absolute 8 h), because the client controls its cookie jar.
   * A `__Host-` prefix would additionally force Secure + Path=/ + no Domain;
   * we skip it only because the prefix requires https.
   */
  const cookieAttributes = ['HttpOnly', 'SameSite=Lax', 'Path=/', ...(secureCookies ? ['Secure'] : [])].join('; ');
  const sessionCookie = (id: string) => `${COOKIE_NAME}=${id}; ${cookieAttributes}`;
  // Max-Age=0 tells the browser to delete the cookie right away.
  const clearedCookie = () => `${COOKIE_NAME}=; ${cookieAttributes}; Max-Age=0`;

  function presentedSessionId(req: IncomingMessage): string | undefined {
    return parseCookies(req.headers.cookie).get(COOKIE_NAME);
  }

  function requireSession(req: IncomingMessage, route: string): Session {
    const sid = presentedSessionId(req);
    const result = sessions.lookup(sid);
    if (!result.ok) {
      log(`→ rejecting ${route}: ${describeLookupFailure(result)}`);
      // If a cookie was sent and it is dead, tell the browser to drop it.
      throw new HttpError(401, 'not authenticated', sid ? { 'Set-Cookie': clearedCookie() } : {});
    }
    return result.session;
  }

  // ---- routes ---------------------------------------------------------------

  const register: Route = async (req) => {
    const body = await readJson(req);
    const username = normalizeUsername(field(body, 'username', 64));
    const password = field(body, 'password', 1024);

    const policyProblem = checkPasswordPolicy(password);
    if (policyProblem) {
      log(`→ rejecting registration for "${username}": ${policyProblem}`);
      throw new HttpError(400, policyProblem);
    }
    // Registration cannot hide whether a name is taken; a 409 is an accepted
    // enumeration channel. Mitigate with rate limits or an email-first flow
    // ("we sent you a link" whether or not the address is known).
    if (users.has(username) || registrationsInFlight.has(username)) {
      log(`→ rejecting registration: "${username}" already exists or is being created`);
      throw new HttpError(409, 'username already taken');
    }

    registrationsInFlight.add(username);
    const started = performance.now();
    try {
      const passwordHash = await hashPassword(password);
      users.set(username, { username, passwordHash, createdAt: now() });
      log(`→ registered "${username}": scrypt hash computed in ${(performance.now() - started).toFixed(0)} ms, password discarded`);
      return { status: 201, body: { username } };
    } finally {
      registrationsInFlight.delete(username);
    }
  };

  const login: Route = async (req) => {
    const body = await readJson(req);
    const username = normalizeUsername(field(body, 'username', 64));
    const password = field(body, 'password', 1024);

    // Rate limit BEFORE the expensive hash, or the limiter itself becomes a
    // way to burn our CPU.
    const gate = limiter.hit(username);
    if (!gate.allowed) {
      const seconds = Math.ceil(gate.retryAfterMs / 1000);
      log(`→ rejecting login for "${username}": ${limit.max} attempts in ${limit.windowMs / 1000}s, retry in ${seconds}s`);
      throw new HttpError(429, 'too many attempts, try again later', { 'Retry-After': String(seconds) });
    }

    const user = users.get(username);
    const passwordMatches = await verifyPassword(password, user?.passwordHash ?? (await decoyHash));
    if (!user || !passwordMatches) {
      // Same status, same body, same timing for both failures. The server log
      // may know which one it was; the client must not.
      log(
        user
          ? `→ rejecting login for "${username}": wrong password (client gets the generic error)`
          : `→ rejecting login for "${username}": no such user (client gets the SAME generic error)`,
      );
      throw new HttpError(401, 'invalid credentials');
    }

    limiter.reset(username);
    // Never keep the id the browser arrived with (session fixation): destroy
    // it and issue a brand new one.
    const presented = presentedSessionId(req);
    const session = sessions.rotateSession(presented, user.username);
    log(
      `→ login ok for "${username}": new session ${short(session.id)}` +
        (presented ? ` (presented id ${short(presented)} destroyed, never upgraded)` : ''),
    );
    // The CSRF token goes in the JSON body, not in a cookie: the page keeps it
    // in memory and sends it back in a header. Only same-origin code that
    // could read this response can know it.
    return {
      status: 200,
      body: { username: user.username, csrfToken: session.csrfToken },
      headers: { 'Set-Cookie': sessionCookie(session.id) },
    };
  };

  const me: Route = async (req) => {
    const session = requireSession(req, 'GET /me');
    log(`→ GET /me: session ${short(session.id)} is "${session.userId}", idle timer reset`);
    return { status: 200, body: { username: session.userId, csrfToken: session.csrfToken } };
  };

  /**
   * A state-changing route. It needs the cookie (who) AND the CSRF token (did
   * this request really come from our page?).
   *
   * SameSite=Lax already stops the browser from attaching the cookie to a
   * cross-site POST, so why the token? Defence in depth:
   *   - a sibling subdomain (blog.example.com, taken over) is same-SITE, so
   *     SameSite does not apply, but it cannot read our token;
   *   - older browsers or a mis-set SameSite=None fall back to the token;
   *   - the custom header also makes the request "non-simple" for CORS, so a
   *     cross-origin page cannot send it without a preflight we never allow.
   * The token is a synchronizer token: a secret tied to the session, handed
   * to the page at login, echoed in a header. A forged request from another
   * origin has the cookie (maybe) but never the token.
   */
  const transfer: Route = async (req) => {
    const session = requireSession(req, 'POST /transfer');
    const header = req.headers[CSRF_HEADER];
    const token = Array.isArray(header) ? header[0] : header;
    if (!token || !constantTimeEqual(token, session.csrfToken)) {
      log(`→ rejecting POST /transfer for "${session.userId}": ${token ? 'CSRF token does not match' : 'no CSRF token'} (cookie alone is not enough)`);
      throw new HttpError(403, 'missing or invalid CSRF token');
    }
    const body = await readJson(req);
    const to = normalizeUsername(field(body, 'to', 64));
    const amount = (body as Record<string, unknown>).amount;
    if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
      throw new HttpError(400, 'amount must be a positive number');
    }
    // Note what we did NOT do: read the sender from the body. The identity
    // comes from the session, never from anything the client typed.
    log(`→ POST /transfer: ${session.userId} → ${to}, ${amount} (cookie and CSRF token both valid)`);
    return { status: 200, body: { ok: true, from: session.userId, to, amount } };
  };

  const logout: Route = async (req) => {
    const sid = presentedSessionId(req);
    const destroyed = sid ? sessions.destroySession(sid) : false;
    log(
      destroyed
        ? `→ logout: session ${short(sid!)} deleted server-side; the cookie value is now meaningless`
        : '→ logout: no live session to delete, clearing the cookie anyway',
    );
    // Clearing the cookie is a courtesy to the browser. Deleting the record
    // is the security control: a copy of the cookie kept elsewhere is dead too.
    return { status: 200, body: { ok: true }, headers: { 'Set-Cookie': clearedCookie() } };
  };

  const routes: Record<string, Record<string, Route>> = {
    '/register': { POST: register },
    '/login': { POST: login },
    '/me': { GET: me },
    '/transfer': { POST: transfer },
    '/logout': { POST: logout },
  };

  // ---- dispatch -------------------------------------------------------------

  async function dispatch(req: IncomingMessage): Promise<Reply> {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const byMethod = routes[url.pathname];
    if (!byMethod) throw new HttpError(404, 'not found');
    const route = byMethod[req.method ?? ''];
    if (!route) throw new HttpError(405, 'method not allowed', { Allow: Object.keys(byMethod).join(', ') });
    return route(req);
  }

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    const started = performance.now();
    dispatch(req)
      .catch((err: unknown): Reply => {
        if (err instanceof HttpError) return { status: err.status, body: { error: err.message }, headers: err.headers };
        log(`→ unexpected error: ${err instanceof Error ? err.message : String(err)}`);
        return { status: 500, body: { error: 'internal error' } };
      })
      .then((reply) => {
        send(res, reply);
        log(`${req.method} ${req.url} → ${reply.status} (${(performance.now() - started).toFixed(0)} ms)`);
      });
  };

  return { handler, users, sessions };
}

// ---- helpers ------------------------------------------------------------------

/** `Cookie: a=1; sid=abc` → Map { a → 1, sid → abc }. */
export function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!header) return cookies;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name) cookies.set(name, value);
  }
  return cookies;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'body too large');
    chunks.push(buf);
  }
  if (size === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'body must be valid JSON');
  }
}

/** A required, non-empty string field of a JSON object body. */
function field(body: unknown, name: string, maxLength: number): string {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'body must be a JSON object');
  }
  const value = (body as Record<string, unknown>)[name];
  if (typeof value !== 'string' || value.length === 0) throw new HttpError(400, `${name} is required`);
  if (value.length > maxLength) throw new HttpError(400, `${name} is too long`);
  return value;
}

/** Lower-case, 3-32 chars of [a-z0-9._-]. Case-folding avoids "Alice" and "alice" being two accounts. */
function normalizeUsername(raw: string): string {
  const username = raw.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) {
    throw new HttpError(400, 'username must be 3-32 characters: letters, digits, . _ -');
  }
  return username;
}

function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  // Lengths are public (tokens have a fixed size), so an early return here leaks nothing.
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

function describeLookupFailure(result: Extract<SessionLookup, { ok: false }>): string {
  switch (result.reason) {
    case 'no-id':
      return 'no session cookie';
    case 'unknown':
      return 'session id not found (logged out, rotated, or never issued by us)';
    case 'idle-timeout':
      return 'session expired (idle timeout)';
    case 'absolute-timeout':
      return 'session expired (absolute timeout, even though it was active)';
  }
}

/** Never log a full session id: it is a bearer secret. */
function short(id: string): string {
  return `${id.slice(0, 8)}…`;
}

function send(res: ServerResponse, reply: Reply): void {
  const payload = JSON.stringify(reply.body);
  res.writeHead(reply.status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    // Responses that depend on who you are must never be cached.
    'Cache-Control': 'no-store',
    ...reply.headers,
  });
  res.end(payload);
}

// ---- server -------------------------------------------------------------------

export interface RunningServer {
  app: App;
  server: Server;
  port: number;
  url: string;
  stop: () => Promise<void>;
}

/** Bind on 127.0.0.1. Port 0 asks the OS for a free one (tests, demo). */
export async function startServer(port: number, options: AppOptions = {}): Promise<RunningServer> {
  const app = createApp(options);
  const server = createServer(app.handler);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  const { port: boundPort } = server.address() as AddressInfo;
  return {
    app,
    server,
    port: boundPort,
    url: `http://127.0.0.1:${boundPort}`,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

// `npm run 01` (tsx, CommonJS): start the server. Under vitest the file is
// loaded as a module and this block must not run, hence the typeof guards.
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  startServer(port)
    .then(({ url }) => {
      console.log(`01 · passwords and sessions · listening on ${url}${process.env.TLS === '1' ? ' (Secure cookies on)' : ''}`);
      console.log(`try: curl -i -X POST ${url}/register -H 'content-type: application/json' -d '{"username":"alice","password":"correct horse battery staple"}'`);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
