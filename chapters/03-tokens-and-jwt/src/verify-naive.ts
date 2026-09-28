/**
 * DELIBERATELY VULNERABLE. This models mistakes found in real JWT libraries circa 2015.
 * Never use it outside this chapter.
 */
import { createPublicKey, type JsonWebKey } from 'node:crypto';
import { decodeJwt, verifySignature, type JwtPayload, type SigningKey } from './jws';

/**
 * The central bug: the attacker-controlled `alg` header chooses how the verifier
 * interprets `key`. There are no claim checks either.
 */
export function verifyNaive(token: string, key: SigningKey): JwtPayload {
  const decoded = decodeJwt(token);

  switch (decoded.header.alg) {
    case 'none':
      // Bug 1: "none" is treated as a valid algorithm, even though this endpoint expects signed tokens.
      return decoded.payload;
    case 'HS256':
      // Bug 2: if `key` is the public RSA PEM, it becomes an HMAC secret. Public information can now forge tokens.
      if (!verifySignature(decoded, 'HS256', key)) throw new Error('bad signature');
      return decoded.payload;
    case 'RS256':
      if (!verifySignature(decoded, 'RS256', key)) throw new Error('bad signature');
      return decoded.payload;
    case 'ES256':
      if (!verifySignature(decoded, 'ES256', key)) throw new Error('bad signature');
      return decoded.payload;
    default:
      throw new Error(`unsupported alg ${String(decoded.header.alg)}`);
  }
  // Deliberately absent: exp, nbf, iat, iss, aud, typ and required-claim checks.
}

/**
 * ALSO DELIBERATELY VULNERABLE: treats header.jwk as the trust anchor.
 * This exists only to reproduce key-injection bugs. A message cannot prove itself
 * by supplying the public key used to sign it; trusted keys come from local issuer
 * configuration/JWKS discovery.
 */
export function verifyEmbeddedJwkNaive(token: string): JwtPayload {
  const decoded = decodeJwt(token);
  if (decoded.header.alg !== 'RS256' && decoded.header.alg !== 'ES256') {
    throw new Error('this broken demo accepts only embedded asymmetric keys');
  }
  if (!decoded.header.jwk || typeof decoded.header.jwk !== 'object') {
    throw new Error('no embedded jwk');
  }
  const key = createPublicKey({ key: decoded.header.jwk as JsonWebKey, format: 'jwk' });
  if (!verifySignature(decoded, decoded.header.alg, key)) throw new Error('bad signature');
  return decoded.payload;
}
