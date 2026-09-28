import { describe, expect, it } from 'vitest';
import { DecryptError, decrypt, encrypt, randomKey, stringToKey } from './crypto';

describe('toy Kerberos crypto', () => {
  it('derives the same key from the same password+salt and different keys from different salts', () => {
    const a = stringToKey('password', 'LAB.EXAMPLEalice');
    expect(a).toEqual(stringToKey('password', 'LAB.EXAMPLEalice'));
    expect(a).not.toEqual(stringToKey('password', 'OTHER.EXAMPLEalice'));
    expect(a).not.toEqual(stringToKey('password', 'LAB.EXAMPLEbob'));
    expect(a).toHaveLength(32);
  });

  it('encrypts and decrypts an object with AES-256-GCM', () => {
    const key = randomKey();
    const blob = encrypt(key, { cname: 'alice', count: 7 });
    expect(decrypt(key, blob)).toEqual({ cname: 'alice', count: 7 });
    expect(blob).toMatchObject({ iv: expect.any(String), ct: expect.any(String), tag: expect.any(String) });
  });

  it('uses a fresh IV so equal plaintexts do not produce equal ciphertexts', () => {
    const key = randomKey();
    expect(encrypt(key, { x: 1 }).ct).not.toBe(encrypt(key, { x: 1 }).ct);
  });

  it('rejects the wrong key and modified ciphertext', () => {
    const key = randomKey();
    const blob = encrypt(key, { x: 1 });
    expect(() => decrypt(randomKey(), blob)).toThrow(DecryptError);
    const changed = { ...blob, ct: Buffer.from('changed').toString('base64') };
    expect(() => decrypt(key, changed)).toThrow(/wrong key or modified/);
  });
});
