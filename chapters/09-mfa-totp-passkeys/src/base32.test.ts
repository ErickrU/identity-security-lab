import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode } from './base32';

describe('base32 (RFC 4648 section 6)', () => {
  it('encodes the RFC 4648 section 10 test vectors', () => {
    const vectors: Array<[string, string]> = [
      ['', ''],
      ['f', 'MY======'],
      ['fo', 'MZXQ===='],
      ['foo', 'MZXW6==='],
      ['foob', 'MZXW6YQ='],
      ['fooba', 'MZXW6YTB'],
      ['foobar', 'MZXW6YTBOI======'],
    ];
    for (const [input, expected] of vectors) {
      expect(base32Encode(Buffer.from(input, 'ascii'))).toBe(expected);
      expect(base32Decode(expected).toString('ascii')).toBe(input);
    }
  });

  it('encodes "Hello!" as JBSWY3DPEE====== and decodes it with or without padding', () => {
    expect(base32Encode(Buffer.from('Hello!', 'ascii'))).toBe('JBSWY3DPEE======');
    expect(base32Encode(Buffer.from('Hello!', 'ascii'), { padding: false })).toBe('JBSWY3DPEE');
    expect(base32Decode('JBSWY3DPEE======').toString('ascii')).toBe('Hello!');
    expect(base32Decode('JBSWY3DPEE').toString('ascii')).toBe('Hello!');
  });

  it('decodes lower case and ignores spaces and dashes (how secrets are shown to people)', () => {
    expect(base32Decode('jbsw y3dp-ee').toString('ascii')).toBe('Hello!');
    expect(base32Decode(' JBSW\tY3DP\nEE ').toString('ascii')).toBe('Hello!');
  });

  it('encodes the RFC 4226 test secret without padding: 20 bytes are exactly 32 characters', () => {
    const encoded = base32Encode(Buffer.from('12345678901234567890', 'ascii'), { padding: false });
    expect(encoded).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    expect(encoded).toHaveLength(32);
  });

  it('round-trips every length from 0 to 40 bytes', () => {
    for (let length = 0; length <= 40; length++) {
      const bytes = Buffer.from(Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff));
      const padded = base32Encode(bytes);
      const bare = base32Encode(bytes, { padding: false });
      expect(padded.length % 8).toBe(0);
      expect(padded.replace(/=+$/, '')).toBe(bare);
      expect(base32Decode(padded).equals(bytes)).toBe(true);
      expect(base32Decode(bare).equals(bytes)).toBe(true);
    }
  });

  it('rejects characters outside A-Z 2-7', () => {
    expect(() => base32Decode('GEZDGNB0')).toThrow(/invalid character "0"/);
    expect(() => base32Decode('GEZDGNB1')).toThrow(/invalid character "1"/);
    expect(() => base32Decode('GEZDGNB8')).toThrow(/invalid character "8"/);
    expect(() => base32Decode('GEZD*NBV')).toThrow(/invalid character/);
  });

  it('rejects padding in the middle and lengths no byte string can produce', () => {
    expect(() => base32Decode('JBSW=Y3DPEE')).toThrow(/only allowed at the end/);
    expect(() => base32Decode('A')).toThrow(/invalid length/);
    expect(() => base32Decode('JBS')).toThrow(/invalid length/);
    expect(() => base32Decode('JBSWY3')).toThrow(/invalid length/);
  });
});
