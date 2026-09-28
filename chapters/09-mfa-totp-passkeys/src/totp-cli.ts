/**
 * Chapter 09 CLI: TOTP end to end, against your real authenticator app.
 *
 *   npm run 09                         usage + a narrated demo (fixed secret, fake clock)
 *   npm run 09 -- enroll [account]     new secret, otpauth URL, QR code, live codes for 60 s
 *   npm run 09 -- verify <secret> <code>
 *   npm run 09 -- vectors              RFC 6238 Appendix B and RFC 4226 Appendix D
 */
import qrcode from 'qrcode-terminal';
import { base32Decode } from './base32';
import { hotpSteps, type HmacAlgorithm } from './hotp';
import { HOTP_SECRET, HOTP_VECTORS, TOTP_SECRETS, TOTP_VECTORS } from './rfc-vectors';
import { generateSecret, otpauthUrl, totp, totpCounter, verifyTotp, type VerifyResult } from './totp';

const ISSUER = 'Identity Lab';
const STEP = 30;

// ---------------------------------------------------------------- helpers

/** "GEZDGNBV..." -> "GEZD GNBV ..." the way apps show a secret for manual entry. */
function groups(secret: string): string {
  return secret.replace(/(.{4})/g, '$1 ').trim();
}

function utc(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function secondsLeft(ms: number): number {
  return STEP - (Math.floor(ms / 1000) % STEP);
}

function explain(result: VerifyResult, current: number): string {
  if (result.ok) {
    const delta = result.counter - current;
    const which = delta === 0 ? 'the current step' : delta < 0 ? `current ${delta}, the previous step` : `current +${delta}, the next step`;
    return `→ accepted: matched counter ${result.counter} (${which})`;
  }
  switch (result.reason) {
    case 'malformed':
      return '→ rejected: not a 6-digit code';
    case 'replay':
      return '→ rejected: this code (or a newer one) was already used, replay';
    case 'no-match':
      return `→ rejected: no counter in [${current - 1}, ${current + 1}] produces this code`;
  }
}

function usage(): void {
  console.log(`TOTP from the RFC (chapter 09). Commands:

  npm run 09 -- enroll [account]        new secret + otpauth URL + QR code to scan with your
                                        authenticator app, then the expected code for 60 s
  npm run 09 -- verify <secret> <code>  stateless math/interoperability check, window ±1
                                        (no replay persistence or rate limiter; not a login endpoint)
  npm run 09 -- vectors                 RFC 6238 Appendix B and RFC 4226 Appendix D test vectors
  npm run 09                            this text and a narrated demo with a fake clock

  Add --big to enroll if the small QR code does not scan.
`);
}

// ---------------------------------------------------------------- enroll

async function enroll(account: string, big: boolean): Promise<void> {
  const secret = generateSecret(); // 20 random bytes, base32, no padding
  const key = base32Decode(secret);
  const url = otpauthUrl({ issuer: ISSUER, account, secret });

  console.log(`\nEnrolling ${account} with ${ISSUER}\n`);
  console.log(`  secret (base32)  ${groups(secret)}   (${key.length} bytes, type it if the QR fails)`);
  console.log(`  otpauth URL      ${url}\n`);
  console.log('  Scan with Google Authenticator, Authy, 1Password, Microsoft Authenticator, ...\n');
  qrcode.generate(url, { small: !big });
  console.log(`
  The phone now holds the same secret as this process. Nothing else is ever exchanged:
  both sides compute HMAC(secret, floor(unixTime / 30)) and show the last 6 digits.
  If the codes differ, the phone's clock is off (enable automatic time).

  Expected code for the next 60 s (compare with the phone):
`);

  const live = Boolean(process.stdout.isTTY);
  await new Promise<void>((resolve) => {
    let shown = -1;
    const tick = (): void => {
      const now = Date.now();
      const counter = totpCounter({ time: now });
      const line = `  ${utc(now)}   counter ${counter}   code ${totp(key, { time: now })}   valid for ${String(secondsLeft(now)).padStart(2)} s`;
      if (live) {
        if (shown !== -1 && counter !== shown) process.stdout.write('\n'); // keep the old code on screen
        process.stdout.write(`\r${line}`);
      } else if (counter !== shown) {
        console.log(line);
      }
      shown = counter;
    };
    tick();
    const timer = setInterval(tick, 1000);
    setTimeout(() => {
      clearInterval(timer);
      process.stdout.write('\n');
      resolve();
    }, 60_000);
  });

  console.log(`\n  Done. Try:  npm run 09 -- verify ${secret} <code from the phone>\n`);
}

// ---------------------------------------------------------------- verify

function verify(secretArg: string, codeArg: string): void {
  const key = base32Decode(secretArg);
  const now = Date.now();
  const current = totpCounter({ time: now });

  console.log(`\n  secret    ${groups(secretArg.toUpperCase().replace(/[\s-]/g, ''))}   (${key.length} bytes)`);
  console.log(`  now       ${utc(now)}   counter ${current}   (${secondsLeft(now)} s left in this step)`);
  console.log(`  window    ±1 → the server computes three codes and accepts any of them:`);
  for (const c of [current - 1, current, current + 1]) {
    console.log(`              counter ${c}  →  ${totp(key, { time: c * STEP * 1000 })}`);
  }
  const result = verifyTotp(key, codeArg, { time: now, window: 1 });
  console.log(`  typed     ${codeArg}`);
  console.log(`  ${explain(result, current)}\n`);
  process.exitCode = result.ok ? 0 : 1;
}

// ---------------------------------------------------------------- vectors

function vectors(): void {
  let failures = 0;
  const mark = (ok: boolean): string => {
    if (!ok) failures++;
    return ok ? 'ok' : 'MISMATCH';
  };

  console.log('\nRFC 6238 Appendix B (8 digits, step 30 s, T0 = 0)\n');
  console.log('  time (s)      UTC                  T (hex)           mode    expected   computed');
  for (const v of TOTP_VECTORS) {
    for (const algorithm of Object.keys(v.expected) as HmacAlgorithm[]) {
      const computed = totp(TOTP_SECRETS[algorithm], { time: v.time * 1000, digits: 8, algorithm });
      console.log(
        `  ${String(v.time).padEnd(13)} ${v.utc}  ${v.counterHex}  ${algorithm.toUpperCase().padEnd(7)} ${v.expected[algorithm]}   ${computed}   ${mark(computed === v.expected[algorithm])}`,
      );
    }
  }

  console.log('\nRFC 4226 Appendix D (secret "12345678901234567890", 6 digits)\n');
  console.log('  count  HMAC-SHA-1(secret, count)                 offset  truncated  expected  computed');
  for (const v of HOTP_VECTORS) {
    const s = hotpSteps(HOTP_SECRET, v.counter);
    const ok = s.code === v.code && s.hmacHex === v.hmacHex && s.truncatedHex === v.truncatedHex;
    console.log(
      `  ${String(v.counter).padEnd(6)} ${s.hmacHex}  ${String(s.offset).padEnd(7)} ${s.truncatedHex}   ${v.code}    ${s.code}   ${mark(ok)}`,
    );
  }

  console.log(failures === 0 ? '\nAll vectors match.\n' : `\n${failures} vector(s) do not match.\n`);
  process.exitCode = failures === 0 ? 0 : 1;
}

// ---------------------------------------------------------------- demo (fake clock)

function demo(): void {
  // The RFC 4226 test key, so you can check every number against the RFC.
  const secretB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const key = base32Decode(secretB32);
  const T = Date.UTC(2024, 0, 1, 0, 0, 0); // the fake clock starts here
  const at = (seconds: number): number => T + seconds * 1000;
  const code = (seconds: number): string => totp(key, { time: at(seconds) });
  const counter = (seconds: number): number => totpCounter({ time: at(seconds) });

  console.log('--- Demo: TOTP with a fixed secret and a fake clock -------------------------\n');
  console.log(`  secret (base32)  ${groups(secretB32)}   = ASCII "12345678901234567890"`);
  console.log(`  otpauth URL      ${otpauthUrl({ issuer: ISSUER, account: 'demo@example.com', secret: secretB32 })}`);

  console.log('\n1) The code changes every 30 s: counter = floor(unixTime / 30), code = HOTP(secret, counter)\n');
  let previous = '';
  for (const s of [0, 10, 29, 30, 60]) {
    const c = code(s);
    const note = c === previous ? '   (same step, same code)' : '';
    console.log(`  ${utc(at(s))}   counter ${counter(s)}   code ${c}${note}`);
    previous = c;
  }

  console.log('\n   How the first one was computed (RFC 4226 section 5.3 and 5.4):\n');
  const steps = hotpSteps(key, counter(0));
  console.log(`     counter as 8 bytes   ${steps.counterHex}`);
  console.log(`     HMAC-SHA-1           ${steps.hmacHex}`);
  console.log(`     offset               last nibble = ${steps.offset} → bytes ${steps.offset}..${steps.offset + 3}`);
  console.log(`     31-bit integer       0x${steps.truncatedHex} = ${steps.truncated}`);
  console.log(`     mod 10^6             ${steps.code}`);

  console.log('\n2) A previous code is accepted once (window ±1 absorbs clock drift and slow typing)\n');
  const k = counter(0);
  const codeK = code(0);
  let lastUsed: number | null = null; // what the server stores next to the secret
  let r = verifyTotp(key, codeK, { time: at(33), window: 1, lastUsedCounter: lastUsed });
  console.log(`  ${utc(at(33))}   user types ${codeK}, generated in step ${k} (the previous step)`);
  console.log(`  ${explain(r, counter(33))}`);
  if (r.ok) lastUsed = r.counter;
  console.log(`  server stores lastUsedCounter = ${lastUsed}`);

  console.log('\n3) The same code again is a replay, even though the window still covers it\n');
  r = verifyTotp(key, codeK, { time: at(40), window: 1, lastUsedCounter: lastUsed });
  console.log(`  ${utc(at(40))}   someone who saw the code types ${codeK} again`);
  console.log(`  ${explain(r, counter(40))}`);
  console.log(`  (counter ${k} ≤ lastUsedCounter ${lastUsed}; without that check the code stays valid for up to 90 s)`);

  console.log('\n   The current code still works, and moves lastUsedCounter forward:\n');
  r = verifyTotp(key, code(40), { time: at(40), window: 1, lastUsedCounter: lastUsed });
  console.log(`  ${utc(at(40))}   user types ${code(40)}`);
  console.log(`  ${explain(r, counter(40))}`);
  if (r.ok) lastUsed = r.counter;
  console.log(`  server stores lastUsedCounter = ${lastUsed}`);

  console.log('\n4) A code from two steps ago is outside the window\n');
  r = verifyTotp(key, codeK, { time: at(65), window: 1, lastUsedCounter: null });
  console.log(`  ${utc(at(65))}   counter ${counter(65)}; someone types ${codeK} from step ${k}`);
  console.log(`  ${explain(r, counter(65))}`);
  console.log('  (checked with no replay state at all: the window alone refuses it)');

  console.log('\n5) Wrong or malformed codes\n');
  const wrong = String((Number(code(65)) + 1) % 1_000_000).padStart(6, '0');
  console.log(`  ${utc(at(65))}   types ${wrong}      ${explain(verifyTotp(key, wrong, { time: at(65) }), counter(65))}`);
  console.log(`  ${utc(at(65))}   types 12345       ${explain(verifyTotp(key, '12345', { time: at(65) }), counter(65))}`);

  console.log(`
6) Guessing

   6 digits → 1,000,000 possible codes, 3 of them valid right now (window ±1).
   One guess succeeds with probability 3 / 1,000,000 = 0.0003 %. That is only safe if
   guesses are scarce: allow about 5 attempts per user per step, then lock and alert.
   A server without a rate limit lets a bot walk in after ~333,000 tries: minutes.
`);
}

// ---------------------------------------------------------------- main

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const big = args.includes('--big');
  const [command, ...rest] = args.filter((a) => a !== '--big');

  switch (command) {
    case 'enroll':
      await enroll(rest[0] ?? 'alice@example.com', big);
      return;
    case 'verify':
      if (rest.length < 2) {
        usage();
        process.exitCode = 2;
        return;
      }
      verify(rest[0], rest[1]);
      return;
    case 'vectors':
      vectors();
      return;
    case undefined:
      usage();
      demo();
      return;
    default:
      console.log(`unknown command "${command}"\n`);
      usage();
      process.exitCode = 2;
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
