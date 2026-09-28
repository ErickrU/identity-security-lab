/**
 * 01 · Demo. Starts the server in-process on a random port and walks through
 * the whole story with fetch, printing every request, every response and
 * every server decision. Run with:
 *
 *   npx tsx chapters/01-passwords-and-sessions/src/demo.ts
 */
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { hashPassword, parseStoredHash, scryptMemoryBytes, verifyPassword } from './passwords';
import { startServer } from './server';

const GOOD = 'correct horse battery staple';

function heading(title: string): void {
  console.log(`\n${'═'.repeat(78)}\n  ${title}\n${'═'.repeat(78)}`);
}

function note(text: string): void {
  for (const line of text.split('\n')) console.log(`  ${line}`);
}

/** Enough of a browser: keeps the `sid` cookie and remembers the CSRF token. */
class Browser {
  sid: string | undefined;
  csrfToken: string | undefined;

  constructor(private readonly base: string) {}

  async call(
    method: string,
    path: string,
    opts: { body?: unknown; headers?: Record<string, string>; quiet?: boolean } = {},
  ) {
    const headers: Record<string, string> = { ...opts.headers };
    const body = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    if (body) headers['content-type'] = 'application/json';
    if (this.sid) headers.cookie = `sid=${this.sid}`;

    if (opts.quiet) {
      console.log(`\n  ▶ ${method} ${path} ${body ? redact(body) : ''}`);
    } else {
      console.log(`\n  ▶ ${method} ${path}`);
      for (const [name, value] of Object.entries(headers)) {
        console.log(`      ${name}: ${name === 'cookie' || name === 'x-csrf-token' ? prefix(value) : value}`);
      }
      if (body) console.log(`      ${redact(body)}`);
    }

    const res = await fetch(this.base + path, { method, headers, body });
    const setCookie = res.headers.getSetCookie();
    const text = await res.text();
    const json = text ? JSON.parse(text) : undefined;

    console.log(`  ◀ ${res.status} ${res.statusText}${opts.quiet && json ? ` ${JSON.stringify(json)}` : ''}`);
    for (const cookie of setCookie) {
      if (!opts.quiet) console.log(`      Set-Cookie: ${cookie.replace(/^sid=([^;]{8})[^;]*/, 'sid=$1…')}`);
      const match = /^sid=([^;]*)/.exec(cookie);
      if (match) this.sid = match[1] || undefined;
    }
    const retryAfter = res.headers.get('retry-after');
    if (retryAfter) console.log(`      Retry-After: ${retryAfter}`);
    if (json !== undefined && !opts.quiet) console.log(`      ${redact(JSON.stringify(json))}`);
    if (json?.csrfToken) this.csrfToken = json.csrfToken;
    return { status: res.status, json, setCookie };
  }
}

/** Secrets get a prefix, like in a real log. */
function prefix(value: string): string {
  return value.replace(/([=]?)([A-Za-z0-9_-]{8})[A-Za-z0-9_-]{9,}/, '$1$2…');
}

/** Passwords and tokens are secrets; the demo shows a prefix, like a real log should. */
function redact(json: string): string {
  return json
    .replace(/("password":")([^"]*)"/g, (_, key, value: string) => `${key}${value.slice(0, 3)}…" (redacted)`)
    .replace(/("csrfToken":")([^"]{8})[^"]*"/g, '$1$2…"');
}

async function main(): Promise<void> {
  heading('1. Hashing a password: slow on purpose');

  const started = performance.now();
  const stored = await hashPassword(GOOD);
  const scryptMs = performance.now() - started;

  const rounds = 10_000;
  const sha = performance.now();
  for (let i = 0; i < rounds; i++) createHash('sha256').update(GOOD).digest();
  const sha256Ms = (performance.now() - sha) / rounds;

  const parsed = parseStoredHash(stored);
  note(`password : "${GOOD.slice(0, 3)}…" (never stored, never logged)`);
  note(`stored   : ${stored}`);
  note('');
  note('Read it left to right:');
  note(`  scrypt                 the algorithm, so we can migrate later`);
  note(`  ${parsed.params.N}                  N, the CPU/memory cost = 2^15 → ${scryptMemoryBytes(parsed.params) / 1024 / 1024} MiB of RAM per hash`);
  note(`  ${parsed.params.r}                      r, block size`);
  note(`  ${parsed.params.p}                      p, parallelism`);
  note(`  ${parsed.salt.toString('base64')}   salt, ${parsed.salt.length} random bytes, public, unique per user`);
  note(`  ${parsed.hash.toString('base64').slice(0, 24)}…  the derived key, ${parsed.hash.length} bytes`);
  note('');
  note(`one scrypt hash  : ${scryptMs.toFixed(1)} ms`);
  note(`one sha256 hash  : ${sha256Ms.toFixed(4)} ms`);
  note(`ratio            : ~${Math.round(scryptMs / sha256Ms).toLocaleString()}× slower, by design.`);
  note('Your user pays this once per login. An attacker with a copy of the database');
  note('pays it once per GUESS, and needs 32 MiB of RAM per guess in flight, which is');
  note('why GPUs (fast, little memory per core) are poor at it. Raise N when hardware');
  note('gets faster; the parameters travel with the hash, so old hashes still verify.');
  note('');
  note(`verify right password → ${await verifyPassword(GOOD, stored)}`);
  note(`verify wrong password → ${await verifyPassword('correct horse battery stable', stored)}`);
  note(`same password hashed again → ${(await hashPassword(GOOD)) === stored ? 'same' : 'different'} string (fresh salt)`);

  heading('2. The server story');
  const running = await startServer(0, { log: (line) => console.log(`      server: ${line}`) });
  note(`server listening on ${running.url} (in-process, random port)`);
  const browser = new Browser(running.url);

  try {
    heading('2a. Register alice');
    await browser.call('POST', '/register', { body: { username: 'alice', password: GOOD } });
    note(`\nstored on the server: ${running.app.users.get('alice')!.passwordHash}`);

    heading('2b. Log in with the wrong password, then as a user that does not exist');
    note('Same status, same body. The client cannot tell which half was wrong, so it');
    note('cannot build a list of valid usernames. The server log knows; the client does not.');
    const wrongStart = performance.now();
    await browser.call('POST', '/login', { body: { username: 'alice', password: 'wrong horse' } });
    const wrongMs = performance.now() - wrongStart;
    const unknownStart = performance.now();
    await browser.call('POST', '/login', { body: { username: 'mallory', password: 'wrong horse' } });
    const unknownMs = performance.now() - unknownStart;
    note(`\nwrong password took ${wrongMs.toFixed(0)} ms, unknown user took ${unknownMs.toFixed(0)} ms:`);
    note('both ran scrypt (the unknown user against a decoy hash), so timing leaks nothing either.');

    heading('2c. Log in correctly');
    await browser.call('POST', '/login', { body: { username: 'alice', password: GOOD } });
    note('\nLook at Set-Cookie:');
    note('  HttpOnly       page JavaScript cannot read it → XSS cannot steal it');
    note('  SameSite=Lax   not sent on cross-site POST/fetch/iframe → classic CSRF fails');
    note('  Path=/         valid for the whole app');
    note('  (Secure)       missing because this is http://127.0.0.1; run with TLS=1 to see it. Always on in prod.');
    note('  no Max-Age     a browser "session cookie"; the server enforces 30 min idle / 8 h absolute');
    note('The csrfToken in the body is NOT a cookie: the page keeps it in memory and sends it as a header.');

    heading('2d. GET /me with the cookie');
    await browser.call('GET', '/me');
    note('\nThe cookie is an opaque id. The server looked it up, checked both timeouts,');
    note('reset the idle timer and answered from its own record. Nothing came from the client.');

    heading('2e. POST /transfer without the CSRF token → 403');
    await browser.call('POST', '/transfer', { body: { to: 'bob', amount: 25 } });
    note('\nThis is what a forged request looks like: the cookie may ride along, the token cannot.');

    heading('2f. POST /transfer with the CSRF token → 200');
    await browser.call('POST', '/transfer', {
      body: { from: 'bob', to: 'bob', amount: 25 },
      headers: { 'x-csrf-token': browser.csrfToken! },
    });
    note('\nNote "from": "alice" in the response even though the body said "bob".');
    note('The sender is whoever owns the session. Never trust the client for identity.');

    heading('2g. Logout, then GET /me with the old cookie');
    const oldCookie = browser.sid!;
    await browser.call('POST', '/logout');
    note('\nThe browser dropped the cookie (Max-Age=0). Now pretend a thief kept a copy:');
    browser.sid = oldCookie;
    await browser.call('GET', '/me');
    note('\nDead, because logout deleted the record on the server. Clearing the cookie');
    note('alone would only have logged out this browser; deleting the session logs out every copy.');

    heading('2h. Bonus: the login rate limit');
    browser.sid = undefined;
    note('Five wrong guesses at alice, as an attacker would:');
    for (let i = 1; i <= 5; i++) {
      await browser.call('POST', '/login', { body: { username: 'alice', password: `guess-${i}` }, quiet: true });
    }
    note('\nSixth attempt inside the same minute, even with the RIGHT password:');
    await browser.call('POST', '/login', { body: { username: 'alice', password: GOOD } });
    note('\n5 guesses a minute turns a million-word dictionary into a 139-day job per account.');
    note('The limiter runs before scrypt (0 ms above), so it cannot be used to burn our CPU.');
  } finally {
    await running.stop();
  }

  heading('Done');
  note('Next: chapter 02 puts TLS under all of this, chapter 03 replaces the opaque id with a signed token.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
