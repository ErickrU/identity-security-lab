import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decodeBase64url, decodeJson, encodeBase64url, encodeJson } from './base64url';
import { decodeJwt, jwkFromPublicKey, signJwt, verifySignature } from './jws';

describe('base64url', () => {
  it('uses URL-safe characters and no padding', () => {
    const encoded = encodeBase64url(Buffer.from([251, 255, 239]));
    expect(encoded).toBe('-__v');
    expect(encoded).not.toMatch(/[+/=]/);
    expect(decodeBase64url(encoded)).toEqual(Buffer.from([251, 255, 239]));
  });

  it('round-trips JSON with Unicode', () => {
    const value = { subject: 'alice', city: 'México', ok: true };
    expect(decodeJson(encodeJson(value))).toEqual(value);
  });

  it('rejects non-base64url characters', () => {
    expect(() => decodeBase64url('abc+123')).toThrow(/invalid base64url/);
  });
});

describe('compact JWS primitives', () => {
  const payload = { sub: 'alice', iat: 1_700_000_000 };

  it('signs and verifies RS256', () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const token = signJwt({ alg: 'RS256', kid: 'rsa-1', typ: 'JWT' }, payload, pair.privateKey);
    const decoded = decodeJwt(token);
    expect(decoded.payload).toEqual(payload);
    expect(decoded.header).toMatchObject({ alg: 'RS256', kid: 'rsa-1' });
    expect(verifySignature(decoded, 'RS256', pair.publicKey)).toBe(true);
  });

  it('signs ES256 in the 64-byte JWS/P1363 representation', () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const token = signJwt({ alg: 'ES256', kid: 'ec-1' }, payload, pair.privateKey);
    const decoded = decodeJwt(token);
    expect(decoded.signature).toHaveLength(64);
    expect(verifySignature(decoded, 'ES256', pair.publicKey)).toBe(true);
  });

  it('signs and verifies HS256 with a shared secret', () => {
    const token = signJwt({ alg: 'HS256', kid: 'hmac-1' }, payload, 'correct horse battery staple');
    expect(verifySignature(decodeJwt(token), 'HS256', 'correct horse battery staple')).toBe(true);
    expect(verifySignature(decodeJwt(token), 'HS256', 'wrong secret')).toBe(false);
  });

  it('detects a payload edit', () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const token = signJwt({ alg: 'RS256', kid: 'rsa-1' }, payload, pair.privateKey);
    const [header, , signature] = token.split('.');
    const edited = `${header}.${encodeJson({ ...payload, role: 'admin' })}.${signature}`;
    expect(verifySignature(decodeJwt(edited), 'RS256', pair.publicKey)).toBe(false);
  });

  it('exports RSA and EC public JWK fields with kid/alg/use', () => {
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(jwkFromPublicKey(rsa.publicKey, 'r1', 'RS256')).toMatchObject({
      kty: 'RSA', kid: 'r1', alg: 'RS256', use: 'sig', e: 'AQAB',
    });
    expect(jwkFromPublicKey(rsa.publicKey, 'r1', 'RS256').n).toBeTypeOf('string');
    expect(jwkFromPublicKey(ec.publicKey, 'e1', 'ES256')).toMatchObject({
      kty: 'EC', kid: 'e1', alg: 'ES256', use: 'sig', crv: 'P-256',
    });
    expect(jwkFromPublicKey(ec.publicKey, 'e1', 'ES256').x).toBeTypeOf('string');
    expect(jwkFromPublicKey(ec.publicKey, 'e1', 'ES256').y).toBeTypeOf('string');
  });

  it('rejects malformed compact tokens', () => {
    expect(() => decodeJwt('only.two')).toThrow(/exactly three/);
    expect(() => decodeJwt('not-json.payload.signature')).toThrow(/JSON/);
  });
});
