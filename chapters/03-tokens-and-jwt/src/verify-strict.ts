import { createPublicKey } from 'node:crypto';
import { decodeJwt, verifySignature, type Jwks, type JwtAlgorithm, type JwtPayload, type SigningKey } from './jws';

export type StrictFailureCode =
  | 'malformed'
  | 'algorithm_not_allowed'
  | 'untrusted_key_header'
  | 'missing_kid'
  | 'unknown_kid'
  | 'key_algorithm_mismatch'
  | 'bad_signature'
  | 'missing_claim'
  | 'bad_claim_type'
  | 'expired'
  | 'not_yet_valid'
  | 'issued_in_future'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'wrong_type';

export class JwtVerificationError extends Error {
  constructor(readonly code: StrictFailureCode, message: string) {
    super(message);
    this.name = 'JwtVerificationError';
  }
}

export interface StrictVerifyOptions {
  /** Configuration chooses algorithms. The token never gets that power. */
  algorithms: Array<'RS256' | 'ES256' | 'HS256'>;
  /** Public verification keys indexed by `kid`. Never fetch a URL from a token header. */
  jwks: Jwks;
  /** HMAC is symmetric and therefore is not published in JWKS. Map kid → secret when HS256 is intentionally allowed. */
  hmacSecrets?: Record<string, string | Buffer>;
  issuer: string;
  audience: string;
  expectedType?: string;
  requiredClaims?: string[];
  clockToleranceSec?: number;
  now?: () => number;
}

/**
 * RFC 8725-style verification: fixed algorithm policy, trusted keys, signature,
 * then semantic claim validation. Signature-only verification is not enough.
 */
export function verifyStrict(token: string, options: StrictVerifyOptions): JwtPayload {
  let decoded;
  try {
    decoded = decodeJwt(token);
  } catch (error) {
    throw new JwtVerificationError('malformed', error instanceof Error ? error.message : String(error));
  }

  const alg = decoded.header.alg as JwtAlgorithm;
  if (!options.algorithms.includes(alg as 'RS256' | 'ES256' | 'HS256')) {
    throw new JwtVerificationError('algorithm_not_allowed', `alg ${String(alg)} is not in the verifier allowlist`);
  }

  // jku/x5u ask a verifier to fetch a URL; jwk embeds an attacker-selected key.
  // Those headers can be safe only under a separately configured trust policy. This lab fails closed.
  for (const name of ['jwk', 'jku', 'x5u'] as const) {
    if (name in decoded.header) {
      throw new JwtVerificationError('untrusted_key_header', `header ${name} is not accepted; keys come only from configured storage`);
    }
  }

  const kid = decoded.header.kid;
  if (typeof kid !== 'string' || !kid) throw new JwtVerificationError('missing_kid', 'kid is required');

  let key: SigningKey;
  if (alg === 'HS256') {
    const secret = options.hmacSecrets?.[kid];
    if (!secret) throw new JwtVerificationError('unknown_kid', `no configured HMAC secret for kid ${kid}`);
    key = secret;
  } else {
    const jwk = options.jwks.keys.find((candidate) => candidate.kid === kid);
    if (!jwk) throw new JwtVerificationError('unknown_kid', `kid ${kid} is not in the trusted JWKS`);
    if (jwk.alg !== alg || jwk.use !== 'sig') {
      throw new JwtVerificationError('key_algorithm_mismatch', `key ${kid} is ${jwk.alg}/${jwk.use}, not ${alg}/sig`);
    }
    key = createPublicKey({ key: jwk, format: 'jwk' });
  }

  if (!verifySignature(decoded, alg as 'RS256' | 'ES256' | 'HS256', key)) {
    throw new JwtVerificationError('bad_signature', 'signature does not match header.payload');
  }

  const payload = decoded.payload;
  for (const claim of options.requiredClaims ?? ['sub', 'exp', 'iat']) {
    if (!(claim in payload)) throw new JwtVerificationError('missing_claim', `required claim ${claim} is missing`);
  }

  const now = Math.floor((options.now?.() ?? Date.now()) / 1000);
  const skew = options.clockToleranceSec ?? 30;
  const numeric = (name: 'exp' | 'nbf' | 'iat'): number | undefined => {
    const value = payload[name];
    if (value === undefined) return undefined;
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw new JwtVerificationError('bad_claim_type', `${name} must be a NumericDate (seconds since Unix epoch)`);
    }
    return value;
  };

  const exp = numeric('exp');
  const nbf = numeric('nbf');
  const iat = numeric('iat');
  if (exp !== undefined && now >= exp + skew) throw new JwtVerificationError('expired', `token expired at ${exp}`);
  if (nbf !== undefined && now + skew < nbf) throw new JwtVerificationError('not_yet_valid', `token is not valid before ${nbf}`);
  if (iat !== undefined && now + skew < iat) throw new JwtVerificationError('issued_in_future', `token claims it was issued at ${iat}`);

  if (payload.iss !== options.issuer) {
    throw new JwtVerificationError('wrong_issuer', `iss ${String(payload.iss)} does not equal ${options.issuer}`);
  }
  const audiences = typeof payload.aud === 'string'
    ? [payload.aud]
    : Array.isArray(payload.aud) && payload.aud.every((x) => typeof x === 'string')
      ? payload.aud
      : undefined;
  if (!audiences) throw new JwtVerificationError('bad_claim_type', 'aud must be a string or an array of strings');
  if (!audiences.includes(options.audience)) {
    throw new JwtVerificationError('wrong_audience', `aud ${JSON.stringify(payload.aud)} does not include ${options.audience}`);
  }

  if (decoded.header.typ !== undefined && typeof decoded.header.typ !== 'string') {
    throw new JwtVerificationError('wrong_type', 'typ must be a string when present');
  }
  if (options.expectedType && decoded.header.typ !== options.expectedType) {
    throw new JwtVerificationError('wrong_type', `typ ${String(decoded.header.typ)} does not equal ${options.expectedType}`);
  }

  return payload;
}
