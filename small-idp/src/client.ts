import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { decodeJwt, verifyJwt, type Claims, type Jwks } from './keys';
import { createPkcePair, OAuthError, type TokenResponse } from './protocol';

export interface Discovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint: string;
  end_session_endpoint: string;
}

export interface OidcClientConfig {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scope: string;
}

export interface LoginTransaction {
  state: string;
  nonce: string;
  codeVerifier: string;
  authorizationUrl: string;
  createdAt: number;
  /** Mutated on the first callback attempt. Production stores/takes this atomically by transaction ID. */
  consumed?: boolean;
}

export interface VerifiedLogin {
  claims: Claims;
  tokens: TokenResponse;
}

export async function discover(issuer: string): Promise<Discovery> {
  const response = await fetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!response.ok) throw new Error(`discovery failed: HTTP ${response.status}`);
  const document = await response.json() as Discovery;
  if (document.issuer !== issuer.replace(/\/$/, '')) throw new Error('discovery issuer mismatch');
  return document;
}

/** Client-side preparation: secrets state/nonce/verifier stay in a server-side transaction store. */
export async function beginLogin(config: OidcClientConfig, now = Date.now()): Promise<LoginTransaction> {
  const discovery = await discover(config.issuer);
  const state = randomBytes(24).toString('base64url');
  const nonce = randomBytes(24).toString('base64url');
  const pkce = createPkcePair();
  const url = new URL(discovery.authorization_endpoint);
  url.search = new URLSearchParams({
    response_type: 'code', client_id: config.clientId, redirect_uri: config.redirectUri,
    scope: config.scope, state, nonce, code_challenge: pkce.challenge, code_challenge_method: 'S256',
  }).toString();
  return { state, nonce, codeVerifier: pkce.verifier, authorizationUrl: url.toString(), createdAt: now, consumed: false };
}

export async function finishLogin(
  config: OidcClientConfig,
  transaction: LoginTransaction,
  callbackUrl: string,
  now = Date.now(),
): Promise<VerifiedLogin> {
  if (transaction.consumed) throw new Error('login transaction already consumed');
  transaction.consumed = true; // consume before detailed checks: one callback attempt, success or failure
  if (transaction.createdAt + 5 * 60 * 1000 <= now) throw new Error('login transaction expired');
  const callback = new URL(callbackUrl);
  const state = callback.searchParams.get('state');
  if (!state || !safeEqual(state, transaction.state)) throw new Error('state mismatch: possible login CSRF or callback mix-up');
  if (callback.searchParams.has('error')) throw new OAuthError(callback.searchParams.get('error')!, callback.searchParams.get('error_description') ?? 'authorization failed');
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('callback has no authorization code');

  const discovery = await discover(config.issuer);
  const body = new URLSearchParams({
    grant_type: 'authorization_code', code, redirect_uri: config.redirectUri,
    code_verifier: transaction.codeVerifier,
  });
  let authorization: string | undefined;
  if (config.clientSecret) {
    authorization = `Basic ${Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString('base64')}`;
  } else {
    body.set('client_id', config.clientId);
  }
  const response = await fetch(discovery.token_endpoint, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(authorization ? { authorization } : {}) }, body,
  });
  const tokens = await response.json() as TokenResponse & { error?: string; error_description?: string };
  if (!response.ok) throw new OAuthError(tokens.error ?? 'token_error', tokens.error_description ?? `HTTP ${response.status}`);
  if (!tokens.id_token) throw new Error('OIDC response did not contain id_token');

  const jwks = await fetch(discovery.jwks_uri).then((r) => r.json()) as Jwks;
  const claims = verifyJwt(tokens.id_token, jwks, { issuer: discovery.issuer, audience: config.clientId, now: () => now });
  const decoded = decodeJwt(tokens.id_token);
  // OIDC Core does not require JOSE `typ` or a `token_use` claim. If this provider profile sends
  // either, constrain it; absence remains interoperable with conforming providers.
  if (decoded.header.typ !== undefined && decoded.header.typ !== 'JWT') throw new Error('wrong token type in OIDC response');
  if (claims.token_use !== undefined && claims.token_use !== 'id') throw new Error('wrong token_use in OIDC response');
  if (typeof claims.sub !== 'string' || claims.sub.length === 0) throw new Error('ID token requires a non-empty string sub');
  if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) throw new Error('ID token requires numeric iat');
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.azp !== undefined && claims.azp !== config.clientId) throw new Error('azp does not name this OIDC client');
  if (audiences.length > 1 && claims.azp !== config.clientId) throw new Error('multi-audience ID token requires matching azp');
  if (claims.nonce !== transaction.nonce) throw new Error('nonce mismatch: ID token belongs to another authorization request');
  // OIDC Code Flow allows at_hash to be absent. When present, it must bind the access token.
  if (claims.at_hash !== undefined && claims.at_hash !== oidcHashHalf(tokens.access_token)) {
    throw new Error('at_hash mismatch: access and ID tokens were mixed');
  }
  return { claims, tokens };
}

function oidcHashHalf(value: string): string {
  const hash = createHash('sha256').update(value).digest();
  return hash.subarray(0, hash.length / 2).toString('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
