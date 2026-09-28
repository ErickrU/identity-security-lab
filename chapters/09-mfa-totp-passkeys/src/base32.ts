/**
 * Base32, RFC 4648 section 6.
 *
 * Why base32 for TOTP secrets and not hex or base64?
 * - The alphabet (A-Z, 2-7) has no 0/O or 1/I/l look-alikes and is case-insensitive,
 *   so a person can read a secret off a screen and type it into a phone.
 * - 5 bits per character: a 20-byte (160-bit) secret is exactly 32 characters, no padding.
 * Every authenticator app expects the `secret=` parameter of an otpauth:// URL in base32.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const VALUE_OF = new Map<string, number>();
for (let i = 0; i < ALPHABET.length; i++) VALUE_OF.set(ALPHABET[i], i);

export interface Base32EncodeOptions {
  /**
   * Append "=" until the length is a multiple of 8 (RFC 4648 section 6 default).
   * Authenticator apps want the secret WITHOUT padding (Key Uri Format), so
   * `generateSecret()` passes `padding: false`.
   */
  padding?: boolean;
}

/** Encode bytes as base32. Output is upper-case. */
export function base32Encode(data: Uint8Array, { padding = true }: Base32EncodeOptions = {}): string {
  let out = '';
  let buffer = 0; // bits not yet emitted, right-aligned
  let bits = 0; // how many of them

  for (const byte of data) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    // Emit one character per 5 bits, most significant bits first.
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
    buffer &= (1 << bits) - 1; // keep only the pending bits
  }

  if (bits > 0) {
    // Last group is short: RFC 4648 section 6 pads it on the right with zero bits.
    out += ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }

  if (padding) {
    while (out.length % 8 !== 0) out += '=';
  }
  return out;
}

/**
 * Decode base32 as people and apps actually write it. Decode rules:
 * - case-insensitive (everything is upper-cased first);
 * - whitespace and dashes are ignored, so "jbsw y3dp-ee" works (secrets are
 *   often shown in groups of four);
 * - trailing "=" padding is optional: RFC 4648 output has it, otpauth secrets do not;
 * - any other character, "=" in the middle, or a length that no byte sequence can
 *   produce (1, 3 or 6 characters mod 8) is an error, because silently decoding a
 *   mistyped secret would enrol a key the phone does not have.
 */
export function base32Decode(text: string): Buffer {
  const cleaned = text.toUpperCase().replace(/[\s-]/g, '');
  const body = cleaned.replace(/=+$/, '');
  if (body.includes('=')) {
    throw new Error('base32: "=" padding is only allowed at the end');
  }
  if ([1, 3, 6].includes(body.length % 8)) {
    throw new Error(`base32: invalid length ${body.length}`);
  }

  const out: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const ch of body) {
    const value = VALUE_OF.get(ch);
    if (value === undefined) {
      throw new Error(`base32: invalid character "${ch}"`);
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      out.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
      buffer &= (1 << bits) - 1;
    }
  }
  // Fewer than 8 leftover bits are the encoder's zero padding bits: drop them.
  return Buffer.from(out);
}
