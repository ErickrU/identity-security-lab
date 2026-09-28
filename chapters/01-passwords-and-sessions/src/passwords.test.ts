import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SCRYPT_PARAMS,
  PASSWORD_MIN_LENGTH,
  SALT_BYTES,
  checkPasswordPolicy,
  hashPassword,
  needsRehash,
  parseStoredHash,
  scryptMemoryBytes,
  verifyPassword,
} from './passwords';

const PASSWORD = 'correct horse battery staple';

describe('hashPassword / verifyPassword', () => {
  it('round-trips: the right password verifies', async () => {
    const stored = await hashPassword(PASSWORD);
    expect(await verifyPassword(PASSWORD, stored)).toBe(true);
  });

  it('rejects a wrong password, including near misses', async () => {
    const stored = await hashPassword(PASSWORD);
    expect(await verifyPassword('correct horse battery stapl', stored)).toBe(false);
    expect(await verifyPassword('Correct horse battery staple', stored)).toBe(false);
    expect(await verifyPassword('', stored)).toBe(false);
  });

  it('hashes the same password to two different strings (random salt), both valid', async () => {
    const a = await hashPassword(PASSWORD);
    const b = await hashPassword(PASSWORD);
    expect(a).not.toBe(b);
    expect(parseStoredHash(a).salt.equals(parseStoredHash(b).salt)).toBe(false);
    expect(await verifyPassword(PASSWORD, a)).toBe(true);
    expect(await verifyPassword(PASSWORD, b)).toBe(true);
  });

  it('stores a self-describing string: scrypt$N$r$p$salt$hash', async () => {
    const stored = await hashPassword(PASSWORD);
    expect(stored.startsWith('scrypt$32768$8$1$')).toBe(true);
    const parsed = parseStoredHash(stored);
    expect(parsed.params).toEqual(DEFAULT_SCRYPT_PARAMS);
    expect(parsed.salt.length).toBe(SALT_BYTES);
    expect(parsed.hash.length).toBe(DEFAULT_SCRYPT_PARAMS.keylen);
    expect(scryptMemoryBytes(parsed.params)).toBe(32 * 1024 * 1024);
  });

  it('handles unicode and long passwords without truncation', async () => {
    const long = 'pässwörd-🔑-'.repeat(12); // > 72 bytes, where bcrypt would silently cut
    const stored = await hashPassword(long);
    expect(await verifyPassword(long, stored)).toBe(true);
    expect(await verifyPassword(long + 'x', stored)).toBe(false);
  });

  it('refuses to verify against a malformed stored hash instead of guessing', async () => {
    await expect(verifyPassword(PASSWORD, 'sha256$abc')).rejects.toThrow(/unsupported/);
    await expect(verifyPassword(PASSWORD, 'scrypt$0$8$1$c2FsdA==$aGFzaA==')).rejects.toThrow(/corrupt/);
    expect(() => parseStoredHash('')).toThrow();
  });
});

describe('needsRehash', () => {
  it('is false for a fresh hash and true for one made with weaker parameters', async () => {
    const fresh = await hashPassword(PASSWORD);
    expect(needsRehash(fresh)).toBe(false);
    const weak = await hashPassword(PASSWORD, { ...DEFAULT_SCRYPT_PARAMS, N: 2 ** 14 });
    expect(needsRehash(weak)).toBe(true);
    expect(await verifyPassword(PASSWORD, weak)).toBe(true); // still verifiable while you migrate
  });
});

describe('checkPasswordPolicy (NIST SP 800-63B, short version)', () => {
  it('accepts long passwords and passphrases regardless of character classes', () => {
    expect(checkPasswordPolicy(PASSWORD)).toBeNull();
    expect(checkPasswordPolicy('alllowercaseletters')).toBeNull();
    expect(checkPasswordPolicy('123456789012345')).toBeNull();
  });

  it('rejects passwords that are too short', () => {
    expect(checkPasswordPolicy('a'.repeat(PASSWORD_MIN_LENGTH - 1))).toMatch(/at least/);
    expect(checkPasswordPolicy('a'.repeat(PASSWORD_MIN_LENGTH))).toBeNull();
  });

  it('rejects passwords on the common-password denylist, whatever the case', () => {
    expect(checkPasswordPolicy('Password1!')).toMatch(/commonly used/);
    expect(checkPasswordPolicy('12345678')).toMatch(/commonly used/);
  });

  it('rejects absurdly long passwords (bounded hashing cost)', () => {
    expect(checkPasswordPolicy('a'.repeat(129))).toMatch(/at most/);
  });
});
