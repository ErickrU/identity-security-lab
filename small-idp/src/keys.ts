/**
 * Signing keys and a minimal RS256 JWT implementation for the small IdP.
 *
 * Only what OAuth 2.0 / OIDC need here: sign a JSON payload with an RSA key,
 * publish the public half as a JWKS, verify a token against that JWKS.
 * Chapter 03 dissects this format and its failure modes in detail; this file
 * is the "known good" subset.
 */
import { createPublicKey, createSign, createVerify, generateKeyPairSync, type KeyObject, randomUUID } from 'node:crypto';

export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface Jwk {
  kty: string;
  kid: string;
  alg: string;
  use: string;
  n?: string;
  e?: string;
}

export interface Jwks {
  keys: Jwk[];
}

export type Claims = Record<string, unknown>;

export const b64url = {
  encode: (data: Buffer | string): string => Buffer.from(data).toString('base64url'),
  decode: (text: string): Buffer => Buffer.from(text, 'base64url'),
};

/** A fresh RSA-2048 key pair. Real IdPs keep the private key in an HSM or KMS and rotate it. */
export function generateSigningKey(kid = `lab-${randomUUID().slice(0, 8)}`): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, privateKey, publicKey };
}

/** The JSON Web Key Set: public keys only, one entry per kid. This is what {issuer}/jwks.json serves. */
export function jwksFor(keys: SigningKey[]): Jwks {
  return {
    keys: keys.map((k) => {
      const jwk = k.publicKey.export({ format: 'jwk' }) as { kty: string; n: string; e: string };
      return { kty: jwk.kty, n: jwk.n, e: jwk.e, kid: k.kid, alg: 'RS256', use: 'sig' };
    }),
  };
}

/** header.payload.signature, RS256. `typ` is optional in JOSE/OIDC; this provider uses "at+jwt" for access tokens and "JWT" for ID tokens. */
export function signJwt(payload: Claims, key: SigningKey, typ?: 'JWT' | 'at+jwt'): string {
  const protectedHeader = { alg: 'RS256', kid: key.kid, ...(typ ? { typ } : {}) };
  const header = b64url.encode(JSON.stringify(protectedHeader));
  const body = b64url.encode(JSON.stringify(payload));
  const signature = createSign('RSA-SHA256').update(`${header}.${body}`).sign(key.privateKey);
  return `${header}.${body}.${b64url.encode(signature)}`;
}

/** Decoding is not verifying. Anyone can do this to any token. */
export function decodeJwt(token: string): { header: Record<string, unknown>; payload: Claims } {
  const parts = token.split('.');
  if (parts.length !== 3) throw new JwtError('malformed', 'a JWT has exactly three dot-separated parts');
  try {
    return {
      header: JSON.parse(b64url.decode(parts[0]).toString('utf8')),
      payload: JSON.parse(b64url.decode(parts[1]).toString('utf8')),
    };
  } catch {
    throw new JwtError('malformed', 'header or payload is not base64url(JSON)');
  }
}

export class JwtError extends Error {
  constructor(
    readonly code: 'malformed' | 'bad_alg' | 'unknown_kid' | 'bad_signature' | 'expired' | 'not_yet_valid' | 'bad_issuer' | 'bad_audience' | 'missing_claim',
    message: string,
  ) {
    super(message);
  }
}

export interface VerifyOptions {
  issuer: string;
  /** The identifier the verifier expects to find in `aud` (string or array claim). */
  audience: string;
  now?: () => number;
  clockToleranceSec?: number;
}

/**
 * The checks every RS256 verifier must do, in this order:
 * pin the algorithm, find the key by kid, check the signature, then exp/nbf/iss/aud.
 * Returns the payload only when all of them pass.
 */
export function verifyJwt(token: string, jwks: Jwks, opts: VerifyOptions): Claims {
  const { header, payload } = decodeJwt(token);
  if (header.alg !== 'RS256') throw new JwtError('bad_alg', `alg ${String(header.alg)} is not allowed; only RS256 is`);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new JwtError('unknown_kid', `no key with kid ${String(header.kid)} in the JWKS`);

  const [h, b, s] = token.split('.');
  const publicKey = createPublicKey({ key: jwk as unknown as import('node:crypto').JsonWebKey, format: 'jwk' });
  const ok = createVerify('RSA-SHA256').update(`${h}.${b}`).verify(publicKey, b64url.decode(s));
  if (!ok) throw new JwtError('bad_signature', 'signature does not match header.payload; the token was altered or signed by another key');

  const nowSec = Math.floor((opts.now?.() ?? Date.now()) / 1000);
  const tolerance = opts.clockToleranceSec ?? 30;
  if (typeof payload.exp !== 'number') throw new JwtError('missing_claim', 'exp is required');
  if (payload.exp + tolerance <= nowSec) throw new JwtError('expired', `expired at ${new Date(payload.exp * 1000).toISOString()}`);
  if (typeof payload.nbf === 'number' && payload.nbf - tolerance > nowSec) throw new JwtError('not_yet_valid', 'nbf is in the future');
  if (payload.iss !== opts.issuer) throw new JwtError('bad_issuer', `iss ${String(payload.iss)} is not the trusted issuer ${opts.issuer}`);
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(opts.audience)) throw new JwtError('bad_audience', `aud ${JSON.stringify(payload.aud)} does not include ${opts.audience}`);
  return payload;
}
