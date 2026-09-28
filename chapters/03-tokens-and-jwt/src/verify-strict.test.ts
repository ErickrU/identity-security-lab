import { generateKeyPairSync } from 'node:crypto';
import { beforeAll, describe, expect, it } from 'vitest';
import { encodeJson } from './base64url';
import { jwkFromPublicKey, signJwt, type Jwks, type JwtHeader, type JwtPayload } from './jws';
import { verifyEmbeddedJwkNaive, verifyNaive } from './verify-naive';
import { JwtVerificationError, verifyStrict, type StrictFailureCode, type StrictVerifyOptions } from './verify-strict';

const NOW_MS = 1_700_000_000_000;
const NOW = NOW_MS / 1000;
const ISSUER = 'https://idp.example';
const AUDIENCE = 'https://api.example';

let privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'];
let publicKey: ReturnType<typeof generateKeyPairSync>['publicKey'];
let publicPem: string;
let jwks: Jwks;
let base: JwtPayload;
let options: StrictVerifyOptions;

beforeAll(() => {
  ({ privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 }));
  publicPem = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  jwks = { keys: [jwkFromPublicKey(publicKey, 'trusted-rsa', 'RS256')] };
  base = {
    iss: ISSUER, sub: 'alice', aud: AUDIENCE, iat: NOW, nbf: NOW - 10, exp: NOW + 300, role: 'user',
  };
  options = {
    algorithms: ['RS256'], jwks, issuer: ISSUER, audience: AUDIENCE,
    expectedType: 'at+jwt', clockToleranceSec: 30, now: () => NOW_MS,
  };
});

function token(payload: JwtPayload = base, header: JwtHeader = { alg: 'RS256', kid: 'trusted-rsa', typ: 'at+jwt' }): string {
  return signJwt(header, payload, privateKey);
}

function expectCode(fn: () => unknown, code: StrictFailureCode): void {
  try {
    fn();
    throw new Error(`expected ${code}`);
  } catch (error) {
    expect(error).toBeInstanceOf(JwtVerificationError);
    expect((error as JwtVerificationError).code).toBe(code);
  }
}

describe('strict verifier happy paths', () => {
  it('accepts a genuine RS256 token and returns claims', () => {
    expect(verifyStrict(token(), options)).toMatchObject({ sub: 'alice', aud: AUDIENCE });
  });

  it('accepts an audience array containing this API', () => {
    expect(verifyStrict(token({ ...base, aud: ['another-api', AUDIENCE] }), options).sub).toBe('alice');
  });

  it('supports deliberately configured ES256 and HS256 too', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const ecJwks: Jwks = { keys: [jwkFromPublicKey(ec.publicKey, 'ec1', 'ES256')] };
    const ecToken = signJwt({ alg: 'ES256', kid: 'ec1', typ: 'at+jwt' }, base, ec.privateKey);
    expect(verifyStrict(ecToken, { ...options, algorithms: ['ES256'], jwks: ecJwks }).sub).toBe('alice');

    const hsToken = signJwt({ alg: 'HS256', kid: 'hs1', typ: 'at+jwt' }, base, 'long-random-shared-secret');
    expect(verifyStrict(hsToken, {
      ...options, algorithms: ['HS256'], jwks: { keys: [] }, hmacSecrets: { hs1: 'long-random-shared-secret' },
    }).sub).toBe('alice');
  });
});

describe('classic attacks: naive accepts, strict rejects', () => {
  it('alg=none', () => {
    const forged = signJwt({ alg: 'none', kid: 'trusted-rsa', typ: 'at+jwt' }, { ...base, role: 'admin' });
    expect(verifyNaive(forged, publicPem).role).toBe('admin');
    expectCode(() => verifyStrict(forged, options), 'algorithm_not_allowed');
  });

  it('RS256→HS256 key confusion with the public PEM as HMAC secret', () => {
    const forged = signJwt({ alg: 'HS256', kid: 'trusted-rsa', typ: 'at+jwt' }, { ...base, role: 'admin' }, publicPem);
    expect(verifyNaive(forged, publicPem).role).toBe('admin');
    expectCode(() => verifyStrict(forged, options), 'algorithm_not_allowed');
  });

  it('expired token', () => {
    const old = token({ ...base, exp: NOW - 31 });
    expect(verifyNaive(old, publicPem).sub).toBe('alice');
    expectCode(() => verifyStrict(old, options), 'expired');
  });

  it('token substitution from a different audience', () => {
    const substituted = token({ ...base, aud: 'https://other-api.example' });
    expect(verifyNaive(substituted, publicPem).sub).toBe('alice');
    expectCode(() => verifyStrict(substituted, options), 'wrong_audience');
  });

  it('unknown kid is ignored by naive but enforced by strict', () => {
    const unknown = token(base, { alg: 'RS256', kid: 'attacker-key', typ: 'at+jwt' });
    expect(verifyNaive(unknown, publicPem).sub).toBe('alice');
    expectCode(() => verifyStrict(unknown, options), 'unknown_kid');
  });

  it('rejects an attacker-signed token that supplies its own embedded JWK', () => {
    const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const attackerJwk = jwkFromPublicKey(attacker.publicKey, 'attacker-key', 'RS256');
    const injected = signJwt(
      { alg: 'RS256', kid: 'attacker-key', typ: 'at+jwt', jwk: attackerJwk },
      { ...base, role: 'admin' },
      attacker.privateKey,
    );
    expect(verifyEmbeddedJwkNaive(injected).role).toBe('admin');
    expectCode(() => verifyStrict(injected, options), 'untrusted_key_header');
  });

  it('refuses remote jku/x5u key-selection headers even on an otherwise valid token', () => {
    for (const extra of [{ jku: 'https://attacker.example/jwks' }, { x5u: 'http://169.254.169.254/latest/meta-data' }]) {
      const withHeader = token(base, { alg: 'RS256', kid: 'trusted-rsa', typ: 'at+jwt', ...extra });
      expect(verifyNaive(withHeader, publicPem).sub).toBe('alice');
      expectCode(() => verifyStrict(withHeader, options), 'untrusted_key_header');
    }
  });
});

describe('signature and claim validation', () => {
  it('rejects a payload edit while retaining the original signature', () => {
    const genuine = token();
    const [header, , signature] = genuine.split('.');
    const edited = `${header}.${encodeJson({ ...base, role: 'admin' })}.${signature}`;
    expect(() => verifyNaive(edited, publicPem)).toThrow(/bad signature/);
    expectCode(() => verifyStrict(edited, options), 'bad_signature');
  });

  it('uses exactly the configured clock tolerance for exp, nbf and iat', () => {
    expect(() => verifyStrict(token({ ...base, exp: NOW - 29 }), options)).not.toThrow();
    expectCode(() => verifyStrict(token({ ...base, exp: NOW - 30 }), options), 'expired');
    expect(() => verifyStrict(token({ ...base, nbf: NOW + 30 }), options)).not.toThrow();
    expectCode(() => verifyStrict(token({ ...base, nbf: NOW + 31 }), options), 'not_yet_valid');
    expect(() => verifyStrict(token({ ...base, iat: NOW + 30 }), options)).not.toThrow();
    expectCode(() => verifyStrict(token({ ...base, iat: NOW + 31 }), options), 'issued_in_future');
  });

  it('rejects the wrong issuer', () => {
    expectCode(() => verifyStrict(token({ ...base, iss: 'https://evil.example' }), options), 'wrong_issuer');
  });

  it('rejects a non-string/non-array audience', () => {
    expectCode(() => verifyStrict(token({ ...base, aud: 42 }), options), 'bad_claim_type');
  });

  it('rejects a non-numeric exp', () => {
    expectCode(() => verifyStrict(token({ ...base, exp: 'tomorrow' }), options), 'bad_claim_type');
  });

  it('rejects a missing required subject', () => {
    const payload = { ...base };
    delete payload.sub;
    expectCode(() => verifyStrict(token(payload), options), 'missing_claim');
  });

  it('enforces expected typ to avoid confusing token kinds', () => {
    expectCode(() => verifyStrict(token(base, { alg: 'RS256', kid: 'trusted-rsa', typ: 'JWT' }), options), 'wrong_type');
    expectCode(() => verifyStrict(token(base, { alg: 'RS256', kid: 'trusted-rsa' }), options), 'wrong_type');
  });

  it('requires kid and checks that key metadata matches the algorithm', () => {
    expectCode(() => verifyStrict(token(base, { alg: 'RS256', typ: 'at+jwt' }), options), 'missing_kid');
    const badMetadata: Jwks = { keys: [{ ...jwks.keys[0], alg: 'ES256' }] };
    expectCode(() => verifyStrict(token(), { ...options, jwks: badMetadata }), 'key_algorithm_mismatch');
  });

  it('rejects malformed tokens', () => {
    expectCode(() => verifyStrict('not.a.jwt', options), 'malformed');
  });
});
