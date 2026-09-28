/**
 * TOTP, RFC 6238 (May 2011): "TOTP: Time-Based One-Time Password Algorithm".
 *
 *   TOTP = HOTP(K, T)   with   T = floor((Current Unix time - T0) / X)      (section 4.2)
 *
 * X is the time step (30 s in practice), T0 the start of counting (0 = the Unix epoch).
 * Nothing else is new: the clock replaces the counter, so both sides agree on C
 * without ever talking to each other.
 *
 * Time unit convention in this file: `time` is in MILLISECONDS (what Date.now() gives),
 * `step` and `t0` are in SECONDS (what the RFC uses).
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { base32Decode, base32Encode } from './base32';
import { hotp, type HmacAlgorithm, type HotpOptions } from './hotp';

export interface TotpOptions extends HotpOptions {
  /** Current time, milliseconds since the Unix epoch. Default `Date.now()`. */
  time?: number;
  /** Time step X in seconds (RFC 6238 section 4.1). Default 30. */
  step?: number;
  /** T0 in seconds: the Unix time to start counting steps from (section 4.1). Default 0. */
  t0?: number;
}

/** RFC 6238 section 4.2: T = floor((Current Unix time - T0) / X). */
export function totpCounter({ time = Date.now(), step = 30, t0 = 0 }: TotpOptions = {}): number {
  if (!Number.isInteger(step) || step <= 0) {
    throw new RangeError('totp: step must be a positive number of seconds');
  }
  return Math.floor((time / 1000 - t0) / step);
}

/** The current TOTP code for `secret`. */
export function totp(secret: Uint8Array, options: TotpOptions = {}): string {
  const { digits, algorithm } = options;
  return hotp(secret, totpCounter(options), { digits, algorithm });
}

export interface VerifyTotpOptions extends TotpOptions {
  /**
   * How many steps on each side of the current one are accepted. Default 1: the
   * previous, current and next codes are valid, so a phone whose clock is up to
   * 30 s off, or a user who was slow to type, still gets in. RFC 6238 section 5.2
   * recommends "at most one time step" of tolerance. Bigger windows multiply the
   * number of codes a guesser can hit and the time a stolen code stays useful.
   */
  window?: number;
  /**
   * The highest counter this user has already logged in with (store it next to the
   * secret). Codes for that step or an older one are refused. Why: a code is valid
   * for the whole window, up to 90 s with window = 1. Anyone who saw it (over the
   * shoulder, through a phishing proxy, in a log) can use it again in that time
   * unless the server remembers it was spent. Pass `null` for "never logged in".
   */
  lastUsedCounter?: number | null;
}

export type VerifyFailure = 'malformed' | 'no-match' | 'replay';

export type VerifyResult =
  /** `counter` is the step that produced the code: persist it as the new lastUsedCounter. */
  | { ok: true; counter: number }
  /** `reason` is for your logs. Tell the user only "invalid code"; the detail helps an attacker. */
  | { ok: false; counter: null; reason: VerifyFailure };

/**
 * Verify a code the user typed.
 *
 * Checks every counter in [T - window, T + window], refuses anything at or below
 * `lastUsedCounter`, and compares in constant time.
 */
export function verifyTotp(secret: Uint8Array, code: string, options: VerifyTotpOptions = {}): VerifyResult {
  const { window = 1, lastUsedCounter = null, digits = 6, algorithm = 'sha1' } = options;
  if (!Number.isInteger(window) || window < 0) {
    throw new RangeError('totp: window must be a non-negative integer');
  }

  // Normalise what people type ("123 456") and refuse anything that is not exactly
  // `digits` digits. This also guarantees equal lengths for timingSafeEqual below.
  const typed = code.replace(/\s+/g, '');
  if (!new RegExp(`^[0-9]{${digits}}$`).test(typed)) {
    return { ok: false, counter: null, reason: 'malformed' };
  }

  const current = totpCounter(options);

  // Compute every candidate and compare each one; no early exit, so the time taken
  // does not depend on which (if any) counter matched.
  let matched: number | null = null;
  for (let c = current - window; c <= current + window; c++) {
    if (c < 0) continue; // before T0: no code can exist for it
    const expected = hotp(secret, c, { digits, algorithm });
    if (constantTimeEqual(expected, typed)) matched = c;
  }

  if (matched === null) {
    return { ok: false, counter: null, reason: 'no-match' };
  }
  if (lastUsedCounter !== null && matched <= lastUsedCounter) {
    // Right code, wrong moment: it (or a newer one) has already been used.
    return { ok: false, counter: null, reason: 'replay' };
  }
  return { ok: true, counter: matched };
}

/**
 * Compare two codes without leaking where they differ. `===` stops at the first
 * different character, which in theory lets an attacker learn the code one digit at
 * a time from response times. Six digits make that hard to exploit over a network,
 * but the constant-time version costs nothing.
 */
function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

/**
 * A new shared secret, base32 without padding, ready for an otpauth URL.
 *
 * RFC 4226 section 4 (R6): the secret MUST be at least 128 bits and SHOULD be 160 bits,
 * the output size of SHA-1. 20 bytes = 160 bits = exactly 32 base32 characters.
 */
export function generateSecret(bytes = 20): string {
  if (!Number.isInteger(bytes) || bytes < 16) {
    throw new RangeError('generateSecret: use at least 16 bytes (128 bits), RFC 4226 section 4');
  }
  return base32Encode(randomBytes(bytes), { padding: false });
}

export interface OtpauthParams {
  /** Who the account is with, shown in the app ("Identity Lab"). Must not contain ":". */
  issuer: string;
  /** Which account, shown in the app ("alice@example.com"). */
  account: string;
  /** The shared secret in base32. Padding, spaces and case are normalised away. */
  secret: string;
  digits?: number;
  /** Time step in seconds. Default 30. */
  period?: number;
  algorithm?: HmacAlgorithm;
}

/**
 * Build the URL that authenticator apps read from a QR code (the "Key Uri Format",
 * a de facto standard from Google Authenticator, not an RFC):
 *
 *   otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
 *
 * The issuer appears twice on purpose: in the label (older apps only read the label)
 * and as a parameter (the documented place). Label and issuer are URL-encoded.
 *
 * This URL IS the secret. Never log it, never put it in analytics or a GET parameter.
 */
export function otpauthUrl({
  issuer,
  account,
  secret,
  digits = 6,
  period = 30,
  algorithm = 'sha1',
}: OtpauthParams): string {
  if (!issuer || issuer.includes(':')) {
    throw new Error('otpauth: issuer is required and must not contain ":"');
  }
  if (!account) {
    throw new Error('otpauth: account is required');
  }
  const cleanSecret = secret.toUpperCase().replace(/[\s=-]/g, '');
  base32Decode(cleanSecret); // throws if it is not base32

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const query = [
    `secret=${cleanSecret}`,
    `issuer=${encodeURIComponent(issuer)}`,
    `algorithm=${algorithm.toUpperCase()}`,
    `digits=${digits}`,
    `period=${period}`,
  ].join('&');
  return `otpauth://totp/${label}?${query}`;
}
