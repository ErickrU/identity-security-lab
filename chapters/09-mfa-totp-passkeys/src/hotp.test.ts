import { describe, expect, it } from 'vitest';
import { counterToBuffer, hotp, hotpSteps } from './hotp';
import { HOTP_SECRET, HOTP_VECTORS } from './rfc-vectors';

describe('HOTP (RFC 4226)', () => {
  it('reproduces the Appendix D codes for counters 0..9', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    for (let counter = 0; counter < 10; counter++) {
      expect(hotp(HOTP_SECRET, counter)).toBe(expected[counter]);
    }
  });

  it('reproduces the Appendix D intermediate values (HMAC, offset, truncated integer)', () => {
    for (const v of HOTP_VECTORS) {
      const s = hotpSteps(HOTP_SECRET, v.counter);
      expect(s.hmacHex).toBe(v.hmacHex);
      expect(s.truncatedHex).toBe(v.truncatedHex);
      expect(s.code).toBe(v.code);
      // Section 5.4: the offset is the low nibble of the last byte of the HMAC.
      expect(s.offset).toBe(parseInt(v.hmacHex.slice(-1), 16));
      // The 31-bit integer never has the sign bit set.
      expect(s.truncated).toBeGreaterThanOrEqual(0);
      expect(s.truncated).toBeLessThan(2 ** 31);
    }
    // Spelled out for counter 0: HMAC cc93cf18... offset 0, 0x4c93cf18 = 1284755224, mod 10^6 = 755224.
    const first = hotpSteps(HOTP_SECRET, 0);
    expect(first.counterHex).toBe('0000000000000000');
    expect(first.truncated).toBe(1284755224);
  });

  it('encodes the counter as 8 big-endian bytes (section 5.1)', () => {
    expect(counterToBuffer(0).toString('hex')).toBe('0000000000000000');
    expect(counterToBuffer(1).toString('hex')).toBe('0000000000000001');
    expect(counterToBuffer(0x23523ec).toString('hex')).toBe('00000000023523ec');
    expect(counterToBuffer(2n ** 64n - 1n).toString('hex')).toBe('ffffffffffffffff');
  });

  it('accepts number and bigint counters interchangeably', () => {
    for (let counter = 0; counter < 10; counter++) {
      expect(hotp(HOTP_SECRET, BigInt(counter))).toBe(hotp(HOTP_SECRET, counter));
    }
  });

  it('keeps leading zeros and pads to the requested number of digits', () => {
    // 8-digit code: the same 31-bit integer mod 10^8, so it ends with the 6-digit code.
    for (const v of HOTP_VECTORS) {
      const eight = hotp(HOTP_SECRET, v.counter, { digits: 8 });
      expect(eight).toHaveLength(8);
      expect(eight.endsWith(v.code)).toBe(true);
    }
    // 1284755224 mod 10^7 = 4755224, 1284755224 mod 10^8 = 84755224
    expect(hotp(HOTP_SECRET, 0, { digits: 7 })).toBe('4755224');
    expect(hotp(HOTP_SECRET, 0, { digits: 8 })).toBe('84755224');
    // Every code is exactly `digits` long even when the number is small.
    for (let counter = 0; counter < 200; counter++) {
      expect(hotp(HOTP_SECRET, counter)).toMatch(/^[0-9]{6}$/);
    }
  });

  it('supports SHA-256 and SHA-512 HMACs (RFC 6238 section 1.2) with longer digests', () => {
    expect(hotpSteps(HOTP_SECRET, 0, { algorithm: 'sha256' }).hmacHex).toHaveLength(64);
    expect(hotpSteps(HOTP_SECRET, 0, { algorithm: 'sha512' }).hmacHex).toHaveLength(128);
    expect(hotp(HOTP_SECRET, 0, { algorithm: 'sha256' })).toMatch(/^[0-9]{6}$/);
    expect(hotp(HOTP_SECRET, 0, { algorithm: 'sha256' })).not.toBe(hotp(HOTP_SECRET, 0));
  });

  it('refuses bad parameters', () => {
    expect(() => hotp(HOTP_SECRET, -1)).toThrow(RangeError);
    expect(() => hotp(HOTP_SECRET, 1.5)).toThrow(RangeError);
    expect(() => hotp(HOTP_SECRET, 2n ** 64n)).toThrow(RangeError);
    expect(() => hotp(HOTP_SECRET, 0, { digits: 5 })).toThrow(/digits/);
    expect(() => hotp(HOTP_SECRET, 0, { digits: 9 })).toThrow(/digits/);
    expect(() => hotp(Buffer.alloc(0), 0)).toThrow(/secret/);
  });
});
