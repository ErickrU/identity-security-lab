/**
 * 01 · Password storage.
 *
 * Goal: a stolen copy of the user table must not turn into a stolen set of
 * accounts. We never store the password. We store the output of a slow,
 * salted, memory-hard function of it, and we re-run that function at login.
 *
 * Why NOT sha256 / md5 / sha1?
 *   They are general-purpose hashes, built to be FAST. One consumer GPU
 *   computes on the order of 10^10 to 10^11 MD5s per second. Fast is exactly
 *   what an attacker holding your database wants: cracking is a guessing
 *   game (hash a candidate, compare, next), and most human passwords fall to
 *   a few billion guesses. On top of that a bare hash is unsalted: the same
 *   password always gives the same digest, so one precomputed table (a
 *   "rainbow table") cracks every user of every site that used it.
 *
 * What the work factor buys
 *   scrypt's N is the CPU/memory cost. With N = 2^15 and r = 8 one hash needs
 *   128 * N * r = 32 MiB of RAM and tens of milliseconds of CPU. Your user
 *   pays that once per login and never notices. The attacker pays it per
 *   GUESS, billions of times, and the memory requirement stops them from
 *   running thousands of guesses in parallel on a GPU. Doubling N doubles the
 *   attacker's bill. That is the whole idea: make each guess expensive.
 *
 * Salt vs pepper
 *   Salt   16 random bytes, stored next to the hash, not secret. It makes
 *          every hash unique: no shared precomputed tables, two users with
 *          the same password get different hashes, and each account must be
 *          attacked separately.
 *   Pepper a secret key that is NOT in the database (AWS Secrets Manager, an
 *          HSM, an environment the database server never sees). It is mixed
 *          in before or after the slow hash. A database dump alone is then
 *          useless; the attacker also needs the pepper. This file implements
 *          salt. The README says where a pepper would go and what it costs.
 *
 * Storage format (self-describing, one string per user):
 *   scrypt$N$r$p$<salt base64>$<hash base64>
 *   Because the parameters travel with the hash, you can raise N next year
 *   and re-hash each user transparently at their next successful login.
 */
import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto';

export interface ScryptParams {
  /** CPU/memory cost. Must be a power of two. Memory used is 128 * N * r bytes. */
  N: number;
  /** Block size. 8 is the standard choice. */
  r: number;
  /** Parallelisation. 1 unless you have spare cores you want the attacker to also need. */
  p: number;
  /** Length of the derived key in bytes. */
  keylen: number;
}

/** 32 MiB of memory, tens of milliseconds. See README "How to pick a work factor". */
export const DEFAULT_SCRYPT_PARAMS: ScryptParams = { N: 2 ** 15, r: 8, p: 1, keylen: 64 };

/** 128 bits of salt. NIST asks for at least 32; 128 makes collisions a non-topic. */
export const SALT_BYTES = 16;

export const PASSWORD_MIN_LENGTH = 15;
export const PASSWORD_MAX_LENGTH = 128;

/**
 * Bytes of RAM one scrypt call needs for these parameters. Node refuses to run
 * when this is above `maxmem` (default 32 MiB), which is a safety net against
 * a typo like N = 2^25 taking the whole server down.
 */
export function scryptMemoryBytes(params: ScryptParams): number {
  return 128 * params.N * params.r;
}

function runScrypt(password: string, salt: Buffer, params: ScryptParams): Promise<Buffer> {
  const options: ScryptOptions = {
    N: params.N,
    r: params.r,
    p: params.p,
    // OpenSSL counts a little more than 128 * N * r, so give it headroom.
    maxmem: scryptMemoryBytes(params) * 2,
  };
  return new Promise((resolve, reject) => {
    scrypt(password, salt, params.keylen, options, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Hash a password for storage. Every call draws a fresh random salt, so the
 * same password hashed twice gives two different strings. That is a feature.
 */
export async function hashPassword(
  password: string,
  params: ScryptParams = DEFAULT_SCRYPT_PARAMS,
): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await runScrypt(password, salt, params);
  return ['scrypt', params.N, params.r, params.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

export interface ParsedHash {
  params: ScryptParams;
  salt: Buffer;
  hash: Buffer;
}

/** Split `scrypt$N$r$p$salt$hash` back into its parts. Throws on anything else. */
export function parseStoredHash(stored: string): ParsedHash {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    throw new Error('unsupported password hash format (expected scrypt$N$r$p$salt$hash)');
  }
  const [, n, r, p, saltB64, hashB64] = parts;
  const N = Number(n);
  const R = Number(r);
  const P = Number(p);
  const salt = Buffer.from(saltB64, 'base64');
  const hash = Buffer.from(hashB64, 'base64');
  const positiveInt = (v: number) => Number.isSafeInteger(v) && v > 0;
  if (!positiveInt(N) || !positiveInt(R) || !positiveInt(P) || salt.length === 0 || hash.length === 0) {
    throw new Error('corrupt password hash: bad parameters');
  }
  return { params: { N, r: R, p: P, keylen: hash.length }, salt, hash };
}

/**
 * Check a password against a stored hash.
 *
 * The comparison uses timingSafeEqual. A plain `===` on Buffers or strings
 * returns as soon as one byte differs, so the time it takes leaks how many
 * leading bytes were right. With a 64-byte derived key that leak is not very
 * practical to exploit, but constant-time comparison costs nothing, so it is
 * simply the habit to have whenever you compare secrets.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const { params, salt, hash } = parseStoredHash(stored);
  const candidate = await runScrypt(password, salt, params);
  return candidate.length === hash.length && timingSafeEqual(candidate, hash);
}

/**
 * True when a stored hash was made with weaker parameters than we use today.
 * Call it after a SUCCESSFUL login (that is the only moment you have the
 * plaintext) and re-hash. This is how you raise the work factor over the
 * years without asking anyone to reset their password.
 */
export function needsRehash(stored: string, params: ScryptParams = DEFAULT_SCRYPT_PARAMS): boolean {
  const current = parseStoredHash(stored).params;
  return (
    current.N < params.N ||
    current.r < params.r ||
    current.p < params.p ||
    current.keylen < params.keylen
  );
}

/**
 * The very short version of NIST SP 800-63B's password rules: length is what
 * matters, plus a denylist of passwords everybody uses. No "one uppercase,
 * one digit, one symbol" rules: they push people to `Password1!`, which is in
 * every cracking dictionary. In production the denylist is the Have I Been
 * Pwned "Pwned Passwords" corpus (k-anonymity API) or Cognito's compromised
 * credentials detection, not a hard-coded set.
 */
const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password1!',
  '12345678',
  '123456789',
  'qwerty123',
  'iloveyou',
  'letmein1',
  'welcome1',
  'admin123',
]);

/** Returns null when the password is acceptable, otherwise a reason to show the user. */
export function checkPasswordPolicy(password: string): string | null {
  const length = [...password].length; // count code points, not UTF-16 units
  if (COMMON_PASSWORDS.has(password.toLowerCase())) return 'password is on the list of commonly used passwords';
  if (length < PASSWORD_MIN_LENGTH) return `password must be at least ${PASSWORD_MIN_LENGTH} characters`;
  if (length > PASSWORD_MAX_LENGTH) return `password must be at most ${PASSWORD_MAX_LENGTH} characters`;
  return null;
}
