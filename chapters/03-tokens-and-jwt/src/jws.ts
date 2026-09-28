import {
  createHmac,
  createSign,
  createVerify,
  timingSafeEqual,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';
import { decodeBase64url, decodeJson, encodeBase64url, encodeJson } from './base64url';

export type JwtAlgorithm = 'RS256' | 'ES256' | 'HS256' | 'none';
export type JwtPayload = Record<string, unknown>;

export interface JwtHeader {
  alg: JwtAlgorithm | string;
  typ?: string;
  kid?: string;
  [name: string]: unknown;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signingInput: string;
  signature: Buffer;
}

export type SigningKey = KeyObject | string | Buffer;

/** Node's HMAC API accepts bytes or a secret KeyObject; normalise PEM/text to bytes. */
function asHmacKey(key: SigningKey): KeyObject | Buffer {
  return typeof key === 'string' ? Buffer.from(key, 'utf8') : key;
}

/**
 * Compact JWS (RFC 7515): base64url(header) + '.' + base64url(payload), then sign those exact bytes.
 * ES256 uses the fixed 64-byte IEEE-P1363 r||s form JWS requires, not ASN.1 DER.
 */
export function signJwt(header: JwtHeader, payload: JwtPayload, key?: SigningKey): string {
  const encodedHeader = encodeJson(header);
  const encodedPayload = encodeJson(payload);
  const input = `${encodedHeader}.${encodedPayload}`;

  let signature: Buffer;
  switch (header.alg) {
    case 'RS256':
      if (!key) throw new Error('RS256 needs a private key');
      signature = createSign('RSA-SHA256').update(input).sign(key);
      break;
    case 'ES256':
      if (!key) throw new Error('ES256 needs a private key');
      signature = createSign('SHA256').update(input).sign({ key: key as KeyObject, dsaEncoding: 'ieee-p1363' });
      break;
    case 'HS256':
      if (!key) throw new Error('HS256 needs a shared secret');
      signature = createHmac('sha256', asHmacKey(key)).update(input).digest();
      break;
    case 'none':
      signature = Buffer.alloc(0);
      break;
    default:
      throw new Error(`unsupported signing algorithm ${header.alg}`);
  }
  return `${input}.${encodeBase64url(signature)}`;
}

/** Decode only. This proves nothing: an attacker can encode JSON too. */
export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part, index) => index < 2 && part.length === 0)) {
    throw new Error('a compact JWT must have exactly three parts');
  }
  return {
    header: decodeJson<JwtHeader>(parts[0]),
    payload: decodeJson<JwtPayload>(parts[1]),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: decodeBase64url(parts[2]),
  };
}

/** Cryptographic signature check only. Claim checks belong to verify-strict.ts. */
export function verifySignature(decoded: DecodedJwt, algorithm: Exclude<JwtAlgorithm, 'none'>, key: SigningKey): boolean {
  switch (algorithm) {
    case 'RS256':
      return createVerify('RSA-SHA256').update(decoded.signingInput).verify(key, decoded.signature);
    case 'ES256':
      return createVerify('SHA256')
        .update(decoded.signingInput)
        .verify({ key: key as KeyObject, dsaEncoding: 'ieee-p1363' }, decoded.signature);
    case 'HS256': {
      const expected = createHmac('sha256', asHmacKey(key)).update(decoded.signingInput).digest();
      return expected.length === decoded.signature.length && timingSafeEqual(expected, decoded.signature);
    }
  }
}

export interface PublicJwk extends JsonWebKey {
  kid: string;
  alg: Exclude<JwtAlgorithm, 'none'>;
  use: 'sig';
  kty: string;
}

export interface Jwks {
  keys: PublicJwk[];
}

/** Export only the public half. For HMAC, the "public" JWKS model does not apply. */
export function jwkFromPublicKey(key: KeyObject, kid: string, alg: 'RS256' | 'ES256'): PublicJwk {
  const jwk = key.export({ format: 'jwk' });
  return { ...jwk, kty: jwk.kty!, kid, alg, use: 'sig' };
}

export function tokenWithPayload(token: string, payload: JwtPayload): string {
  const [header, , signature] = token.split('.');
  return `${header}.${encodeJson(payload)}.${signature}`;
}
