import { describe, expect, it } from 'vitest';
import { decodeJwt, generateSigningKey, jwksFor, JwtError, signJwt, verifyJwt } from './keys';

const NOW = 1_700_000_000_000;

describe('small IdP signing keys', () => {
  it('publishes only the RSA public key in JWKS and verifies its token', () => {
    const key = generateSigningKey('key-1');
    const jwks = jwksFor([key]);
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', kid: 'key-1', alg: 'RS256', use: 'sig', e: 'AQAB' });
    expect(jwks.keys[0].n).toBeTypeOf('string');
    expect(jwks.keys[0]).not.toHaveProperty('d');
    const token = signJwt({ iss: 'issuer', sub: 'alice', aud: 'api', exp: NOW / 1000 + 60 }, key, 'at+jwt');
    expect(verifyJwt(token, jwks, { issuer: 'issuer', audience: 'api', now: () => NOW }).sub).toBe('alice');
    expect(decodeJwt(token).header).toMatchObject({ alg: 'RS256', typ: 'at+jwt', kid: 'key-1' });
  });

  it('rejects altered, expired, wrong issuer/audience, and unknown kid tokens', () => {
    const key = generateSigningKey('key-1');
    const base = { iss: 'issuer', sub: 'alice', aud: 'api', exp: NOW / 1000 + 60 };
    const valid = signJwt(base, key);
    const [header, , signature] = valid.split('.');
    const altered = `${header}.${Buffer.from(JSON.stringify({ ...base, sub: 'mallory' })).toString('base64url')}.${signature}`;
    expectCode(() => verifyJwt(altered, jwksFor([key]), { issuer: 'issuer', audience: 'api', now: () => NOW }), 'bad_signature');
    expectCode(() => verifyJwt(signJwt({ ...base, exp: NOW / 1000 - 31 }, key), jwksFor([key]), { issuer: 'issuer', audience: 'api', now: () => NOW }), 'expired');
    expectCode(() => verifyJwt(signJwt({ ...base, iss: 'other' }, key), jwksFor([key]), { issuer: 'issuer', audience: 'api', now: () => NOW }), 'bad_issuer');
    expectCode(() => verifyJwt(signJwt({ ...base, aud: 'other' }, key), jwksFor([key]), { issuer: 'issuer', audience: 'api', now: () => NOW }), 'bad_audience');
    expectCode(() => verifyJwt(valid, { keys: [] }, { issuer: 'issuer', audience: 'api', now: () => NOW }), 'unknown_kid');
  });
});

function expectCode(fn: () => unknown, code: JwtError['code']): void {
  try { fn(); throw new Error('expected failure'); }
  catch (error) { expect(error).toBeInstanceOf(JwtError); expect((error as JwtError).code).toBe(code); }
}
