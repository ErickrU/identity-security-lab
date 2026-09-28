/**
 * HOTP, RFC 4226 (December 2005): "An HMAC-Based One-Time Password Algorithm".
 *
 *   HOTP(K, C) = Truncate(HMAC-SHA-1(K, C))          (section 5.2)
 *
 * K is the shared secret, C an 8-byte counter ("the moving factor") that both sides
 * increment. TOTP (RFC 6238) is HOTP where C is derived from the clock.
 *
 * Every step below is annotated with the section of the RFC it implements, so you
 * can read the two side by side.
 */
import { createHmac } from 'node:crypto';

/** RFC 4226 is SHA-1 only. RFC 6238 section 1.2 allows HMAC-SHA-256 and HMAC-SHA-512 too. */
export type HmacAlgorithm = 'sha1' | 'sha256' | 'sha512';

export interface HotpOptions {
  /**
   * Digits in the code. RFC 4226 section 5.3 defines 10^Digit for Digit = 6, 7, 8.
   * Six is what every authenticator app supports; Google Authenticator ignores
   * anything else. Default 6.
   */
  digits?: number;
  /** Hash for the HMAC. Default 'sha1' (the only value most apps support). */
  algorithm?: HmacAlgorithm;
}

/** Intermediate values of one HOTP computation, for teaching and for the RFC test vectors. */
export interface HotpSteps {
  /** C as the 8-byte big-endian string the HMAC is computed over (section 5.1). */
  counterHex: string;
  /** HS = HMAC(K, C), 20 bytes for SHA-1 (step 1, section 5.3). */
  hmacHex: string;
  /** Low-order 4 bits of the last byte of HS, 0..15 (section 5.4). */
  offset: number;
  /** The 4 bytes HS[offset..offset+3] with the top bit cleared: a 31-bit integer (section 5.4). */
  truncatedHex: string;
  truncated: number;
  /** truncated mod 10^digits, left-padded with zeros (step 3, section 5.3). */
  code: string;
}

/** The 8-byte big-endian counter of RFC 4226 section 5.1 (see also the reference code in Appendix C). */
export function counterToBuffer(counter: number | bigint): Buffer {
  if (typeof counter === 'number' && !Number.isSafeInteger(counter)) {
    throw new RangeError(`hotp: counter must be an integer, got ${counter}`);
  }
  const value = BigInt(counter);
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError('hotp: counter must fit in 8 unsigned bytes');
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(value);
  return buf;
}

/** Compute an HOTP code and return every intermediate value. */
export function hotpSteps(secret: Uint8Array, counter: number | bigint, options: HotpOptions = {}): HotpSteps {
  const { digits = 6, algorithm = 'sha1' } = options;

  if (!Number.isInteger(digits) || digits < 6 || digits > 8) {
    throw new RangeError('hotp: digits must be 6, 7 or 8 (RFC 4226 section 5.3)');
  }
  if (secret.length === 0) {
    // Section 4, R6: the secret MUST be at least 128 bits. We only refuse the absurd
    // case here; generateSecret() in totp.ts produces the recommended 160 bits.
    throw new RangeError('hotp: secret must not be empty');
  }

  // Section 5.1: C is an 8-byte counter, sent to the HMAC as a big-endian byte string.
  const movingFactor = counterToBuffer(counter);

  // Step 1 (section 5.3): HS = HMAC-SHA-1(K, C). 20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512.
  const hs = createHmac(algorithm, secret).update(movingFactor).digest();

  // Step 2 (section 5.3) = Dynamic Truncation, DT (section 5.4):
  //   OffsetBits = the low-order 4 bits of the LAST byte of HS  -> Offset in 0..15
  //   P          = HS[Offset] .. HS[Offset + 3]                  (4 bytes)
  //   Sbits      = the last 31 bits of P
  // The top bit is masked off "to avoid confusion about signed vs. unsigned modulo
  // computations" (section 5.4): 31 bits always fit in a positive signed 32-bit int.
  // Offset + 3 <= 18 < 20, so the 4 bytes are always inside the digest, for any hash.
  const offset = hs[hs.length - 1] & 0x0f;
  const truncated =
    ((hs[offset] & 0x7f) << 24) | (hs[offset + 1] << 16) | (hs[offset + 2] << 8) | hs[offset + 3];

  // Step 3 (section 5.3): D = Snum mod 10^Digit. Keep leading zeros: "007081" is a valid code
  // and must be shown with all its digits (the reference code in Appendix C pads too).
  const code = (truncated % 10 ** digits).toString().padStart(digits, '0');

  return {
    counterHex: movingFactor.toString('hex'),
    hmacHex: hs.toString('hex'),
    offset,
    truncatedHex: truncated.toString(16).padStart(8, '0'),
    truncated,
    code,
  };
}

/**
 * HOTP(K, C) as a zero-padded string of `digits` digits.
 *
 * @param secret  K, the shared secret bytes (decode the base32 first).
 * @param counter C, the moving factor. number or bigint, 0 .. 2^64-1.
 */
export function hotp(secret: Uint8Array, counter: number | bigint, options: HotpOptions = {}): string {
  return hotpSteps(secret, counter, options).code;
}
