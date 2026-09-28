import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { hashPassword, verifyPassword } from '../../chapters/01-passwords-and-sessions/src/passwords';
import {
  decodeJwt,
  generateSigningKey,
  jwksFor,
  signJwt,
  verifyJwt,
  type Claims,
  type Jwks,
  type SigningKey,
} from './keys';

export type Clock = () => number;
export const ACCESS_TOKEN_LIFETIME_SEC = 5 * 60;
export const AUTHORIZATION_CODE_LIFETIME_MS = 60 * 1000;
export const PENDING_REQUEST_LIFETIME_MS = 5 * 60 * 1000;
export const SESSION_LIFETIME_MS = 8 * 60 * 60 * 1000;
export const REFRESH_TOKEN_LIFETIME_MS = 60 * 60 * 1000;

export interface LabUser {
  sub: string;
  username: string;
  passwordHash: string;
  name: string;
  email: string;
  groups: string[];
}

export type ClientType = 'public' | 'confidential';
export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials';

export interface ClientRegistration {
  clientId: string;
  clientType: ClientType;
  /** Plaintext only at registration/call site. The provider stores `secretHash`. */
  clientSecret?: string;
  redirectUris: string[];
  allowedScopes: string[];
  allowedGrants: GrantType[];
  name: string;
}

interface StoredClient extends Omit<ClientRegistration, 'clientSecret'> {
  secretHash?: Buffer;
}

export interface AuthorizationParameters {
  response_type?: string;
  client_id?: string;
  redirect_uri?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  prompt?: string;
}

export interface PendingAuthorization {
  requestId: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  nonce?: string;
  codeChallenge?: string;
  createdAt: number;
}

interface AuthorizationCode {
  clientId: string;
  redirectUri: string;
  sub: string;
  scopes: string[];
  nonce?: string;
  codeChallenge?: string;
  authTime: number;
  expiresAt: number;
}

interface BrowserSession { sub: string; authTime: number; expiresAt: number }
interface RefreshRecord {
  familyId: string;
  clientId: string;
  sub: string;
  scopes: string[];
  authTime: number;
  expiresAt: number;
}
interface SpentRefreshRecord { familyId: string; clientId: string; expiresAt: number }

export interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export type TokenRequest =
  | { grant_type: 'authorization_code'; code: string; redirect_uri: string; code_verifier?: string; client_id?: string }
  | { grant_type: 'refresh_token'; refresh_token: string; scope?: string; client_id?: string }
  | { grant_type: 'client_credentials'; scope?: string; client_id?: string };

export interface TokenResponse {
  token_type: 'Bearer';
  access_token: string;
  expires_in: number;
  scope: string;
  id_token?: string;
  refresh_token?: string;
}

export class OAuthError extends Error {
  constructor(
    readonly error: string,
    readonly error_description: string,
    readonly status = 400,
  ) {
    super(`${error}: ${error_description}`);
    this.name = 'OAuthError';
  }

  toJSON(): { error: string; error_description: string } {
    return { error: this.error, error_description: this.error_description };
  }
}

export interface ProviderOptions {
  issuer: string;
  resourceAudience?: string;
  now?: Clock;
  signingKey?: SigningKey;
}

/**
 * Protocol core for the local authorization server/OpenID Provider.
 *
 * It deliberately has no HTTP concerns. That makes the important rules—exact redirect URI,
 * state/nonce, PKCE, one-use codes, client authentication, refresh rotation, JWT claims—small
 * and unit-testable. `idp.ts` is only the HTTP adapter around this class.
 */
export class LabIdentityProvider {
  readonly issuer: string;
  readonly resourceAudience: string;
  readonly signingKey: SigningKey;
  private readonly now: Clock;
  private readonly usersByName = new Map<string, LabUser>();
  private readonly usersBySub = new Map<string, LabUser>();
  private readonly clients = new Map<string, StoredClient>();
  private readonly pending = new Map<string, PendingAuthorization>();
  private readonly codes = new Map<string, AuthorizationCode>();
  private readonly sessions = new Map<string, BrowserSession>();
  private readonly refreshTokens = new Map<string, RefreshRecord>();
  /** Spent-token tombstones let reuse revoke the still-active descendants of that family. */
  private readonly spentRefreshTokens = new Map<string, SpentRefreshRecord>();
  private readonly revokedRefreshFamilies = new Map<string, number>();
  private readonly revokedAccessJtis = new Set<string>();

  constructor(options: ProviderOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    this.resourceAudience = options.resourceAudience ?? 'http://127.0.0.1:4100';
    this.now = options.now ?? Date.now;
    this.signingKey = options.signingKey ?? generateSigningKey('small-idp-2026');
  }

  static async withDefaults(options: ProviderOptions): Promise<LabIdentityProvider> {
    const provider = new LabIdentityProvider(options);
    await provider.registerUser({
      sub: 'user-alice-0001', username: 'alice', password: 'correct horse battery staple',
      name: 'Alice Example', email: 'alice@lab.example', groups: ['staff', 'admins'],
    });
    await provider.registerUser({
      sub: 'user-bob-0002', username: 'bob', password: 'correct horse battery staple',
      name: 'Bob Example', email: 'bob@lab.example', groups: ['staff'],
    });
    provider.registerClient({
      clientId: 'orders-web', clientType: 'confidential', clientSecret: 'orders-web-secret-for-local-lab',
      name: 'Orders web app', redirectUris: ['http://127.0.0.1:4001/callback'],
      allowedScopes: ['openid', 'profile', 'email', 'groups', 'orders:read', 'orders:write'],
      allowedGrants: ['authorization_code', 'refresh_token'],
    });
    provider.registerClient({
      clientId: 'reports-web', clientType: 'confidential', clientSecret: 'reports-web-secret-for-local-lab',
      name: 'Reports web app', redirectUris: ['http://127.0.0.1:4002/callback'],
      allowedScopes: ['openid', 'profile', 'email', 'groups', 'orders:read'],
      allowedGrants: ['authorization_code', 'refresh_token'],
    });
    provider.registerClient({
      clientId: 'demo-spa', clientType: 'public', name: 'Public SPA/CLI',
      redirectUris: ['http://127.0.0.1:4003/callback'],
      allowedScopes: ['openid', 'profile', 'email', 'orders:read'],
      allowedGrants: ['authorization_code', 'refresh_token'],
    });
    provider.registerClient({
      clientId: 'inventory-job', clientType: 'confidential', clientSecret: 'inventory-machine-secret-for-local-lab',
      name: 'Inventory background job', redirectUris: [],
      allowedScopes: ['inventory:read', 'orders:read'],
      allowedGrants: ['client_credentials'],
    });
    return provider;
  }

  async registerUser(input: Omit<LabUser, 'passwordHash'> & { password: string }): Promise<void> {
    const user: LabUser = { ...input, passwordHash: await hashPassword(input.password) };
    this.usersByName.set(user.username, user);
    this.usersBySub.set(user.sub, user);
  }

  registerClient(input: ClientRegistration): void {
    if (input.clientType === 'confidential' && !input.clientSecret) {
      throw new Error(`confidential client ${input.clientId} requires a secret`);
    }
    if (input.clientType === 'public' && input.clientSecret) {
      throw new Error(`public client ${input.clientId} must not have a secret it cannot keep`);
    }
    this.clients.set(input.clientId, {
      clientId: input.clientId,
      clientType: input.clientType,
      secretHash: input.clientSecret ? digest(input.clientSecret) : undefined,
      redirectUris: [...input.redirectUris],
      allowedScopes: [...input.allowedScopes],
      allowedGrants: [...input.allowedGrants],
      name: input.name,
    });
  }

  get jwks(): Jwks { return jwksFor([this.signingKey]); }

  getClient(clientId: string): Omit<StoredClient, 'secretHash'> | undefined {
    const client = this.clients.get(clientId);
    if (!client) return undefined;
    const { secretHash: _secretHash, ...publicClient } = client;
    return publicClient;
  }

  getUser(sub: string): Omit<LabUser, 'passwordHash'> | undefined {
    const user = this.usersBySub.get(sub);
    if (!user) return undefined;
    const { passwordHash: _passwordHash, ...profile } = user;
    return profile;
  }

  /** Validate first, before login. Otherwise an attacker's redirect can receive credentials/codes. */
  beginAuthorization(params: AuthorizationParameters): PendingAuthorization {
    if (params.response_type !== 'code') throw new OAuthError('unsupported_response_type', 'only response_type=code is supported');
    const client = params.client_id ? this.clients.get(params.client_id) : undefined;
    if (!client) throw new OAuthError('invalid_request', 'unknown or missing client_id');
    if (!client.allowedGrants.includes('authorization_code')) throw new OAuthError('unauthorized_client', 'client may not use authorization_code');
    if (!params.redirect_uri || !client.redirectUris.includes(params.redirect_uri)) {
      // Never redirect this error: the supplied URI is not trusted yet.
      throw new OAuthError('invalid_request', 'redirect_uri must exactly match a registered URI');
    }
    if (!params.state || params.state.length < 16) {
      throw new OAuthError('invalid_request', 'this lab requires an unpredictable state value (at least 16 characters)');
    }
    const scopes = parseScopes(params.scope);
    if (scopes.length === 0) throw new OAuthError('invalid_scope', 'at least one scope is required');
    requireScopeSubset(scopes, client.allowedScopes);

    if (scopes.includes('openid') && (!params.nonce || params.nonce.length < 16)) {
      throw new OAuthError('invalid_request', 'OIDC requests require an unpredictable nonce (at least 16 characters)');
    }
    // This security-focused profile requires PKCE for every code client, including confidential
    // backends. Client authentication and PKCE defend different boundaries.
    if (!params.code_challenge) {
      throw new OAuthError('invalid_request', 'authorization-code clients must use PKCE');
    }
    if (params.code_challenge || params.code_challenge_method) {
      if (params.code_challenge_method !== 'S256') throw new OAuthError('invalid_request', 'only PKCE S256 is supported');
      if (!params.code_challenge || !/^[A-Za-z0-9_-]{43,128}$/.test(params.code_challenge)) {
        throw new OAuthError('invalid_request', 'code_challenge must be 43–128 base64url characters');
      }
    }

    const request: PendingAuthorization = {
      requestId: randomToken(), clientId: client.clientId, clientName: client.name,
      redirectUri: params.redirect_uri, scopes, state: params.state, nonce: params.nonce,
      codeChallenge: params.code_challenge, createdAt: this.now(),
    };
    this.pending.set(request.requestId, request);
    return { ...request, scopes: [...request.scopes] };
  }

  getPending(requestId: string): PendingAuthorization {
    const request = this.pending.get(requestId);
    if (!request || request.createdAt + PENDING_REQUEST_LIFETIME_MS <= this.now()) {
      this.pending.delete(requestId);
      throw new OAuthError('invalid_request', 'authorization request is unknown or expired');
    }
    return { ...request, scopes: [...request.scopes] };
  }

  async login(requestId: string, username: string, password: string): Promise<string> {
    this.getPending(requestId); // prove the login belongs to a validated authorization request
    const user = this.usersByName.get(username);
    // Use an existing real hash as a decoy to keep unknown-user timing close to wrong-password timing.
    const decoy = this.usersByName.values().next().value as LabUser | undefined;
    const valid = await verifyPassword(password, user?.passwordHash ?? decoy?.passwordHash ?? await hashPassword('decoy-only'));
    if (!user || !valid) throw new OAuthError('access_denied', 'invalid username or password', 401);
    return this.createSession(user.sub);
  }

  createSession(sub: string): string {
    if (!this.usersBySub.has(sub)) throw new Error(`unknown sub ${sub}`);
    const id = randomToken();
    this.sessions.set(digestText(id), { sub, authTime: Math.floor(this.now() / 1000), expiresAt: this.now() + SESSION_LIFETIME_MS });
    return id;
  }

  sessionUser(sessionId: string | undefined): Omit<LabUser, 'passwordHash'> | undefined {
    if (!sessionId) return undefined;
    const session = this.sessions.get(digestText(sessionId));
    if (!session || session.expiresAt <= this.now()) {
      if (session) this.sessions.delete(digestText(sessionId));
      return undefined;
    }
    return this.getUser(session.sub);
  }

  destroySession(sessionId: string | undefined): void {
    if (sessionId) this.sessions.delete(digestText(sessionId));
  }

  /** User consent turns a validated pending request into a one-minute, single-use code. */
  consent(requestId: string, sessionId: string | undefined, approved: boolean): string {
    const request = this.getPending(requestId);
    const session = sessionId ? this.sessions.get(digestText(sessionId)) : undefined;
    if (!session || session.expiresAt <= this.now()) throw new OAuthError('login_required', 'no valid IdP session', 401);
    this.pending.delete(requestId);

    const redirect = new URL(request.redirectUri);
    if (!approved) {
      redirect.searchParams.set('error', 'access_denied');
      redirect.searchParams.set('error_description', 'the resource owner denied consent');
      redirect.searchParams.set('state', request.state);
      return redirect.toString();
    }

    const code = randomToken();
    this.codes.set(digestText(code), {
      clientId: request.clientId, redirectUri: request.redirectUri, sub: session.sub,
      scopes: request.scopes, nonce: request.nonce, codeChallenge: request.codeChallenge,
      authTime: session.authTime, expiresAt: this.now() + AUTHORIZATION_CODE_LIFETIME_MS,
    });
    redirect.searchParams.set('code', code);
    redirect.searchParams.set('state', request.state);
    return redirect.toString();
  }

  token(request: TokenRequest, credentials: ClientCredentials): TokenResponse {
    const client = this.authenticateClient(credentials, request.client_id);
    if (!client.allowedGrants.includes(request.grant_type)) {
      throw new OAuthError('unauthorized_client', `client may not use ${request.grant_type}`, 401);
    }

    switch (request.grant_type) {
      case 'authorization_code':
        return this.exchangeAuthorizationCode(client, request);
      case 'refresh_token':
        return this.exchangeRefreshToken(client, request);
      case 'client_credentials':
        return this.exchangeClientCredentials(client, request);
    }
  }

  private exchangeAuthorizationCode(
    client: StoredClient,
    request: Extract<TokenRequest, { grant_type: 'authorization_code' }>,
  ): TokenResponse {
    const key = digestText(request.code);
    const code = this.codes.get(key);
    // Consume before detailed checks: a stolen/guessed code gets one attempt, including a bad verifier attempt.
    this.codes.delete(key);
    if (!code || code.expiresAt <= this.now()) throw new OAuthError('invalid_grant', 'authorization code is unknown, expired, or already used');
    if (code.clientId !== client.clientId || code.redirectUri !== request.redirect_uri) {
      throw new OAuthError('invalid_grant', 'code was not issued to this client and exact redirect_uri');
    }
    if (code.codeChallenge) {
      if (!request.code_verifier || !/^[A-Za-z0-9._~-]{43,128}$/.test(request.code_verifier)) {
        throw new OAuthError('invalid_grant', 'a valid PKCE code_verifier is required');
      }
      if (!safeEqual(pkceChallenge(request.code_verifier), code.codeChallenge)) {
        throw new OAuthError('invalid_grant', 'PKCE code_verifier does not match the authorization request');
      }
    }
    return this.issueUserTokens(code.sub, client, code.scopes, code.authTime, code.nonce, true);
  }

  private exchangeRefreshToken(
    client: StoredClient,
    request: Extract<TokenRequest, { grant_type: 'refresh_token' }>,
  ): TokenResponse {
    const now = this.now();
    for (const [tokenHash, item] of this.spentRefreshTokens) if (item.expiresAt <= now) this.spentRefreshTokens.delete(tokenHash);
    for (const [familyId, expiresAt] of this.revokedRefreshFamilies) if (expiresAt <= now) this.revokedRefreshFamilies.delete(familyId);
    const key = digestText(request.refresh_token);
    const spent = this.spentRefreshTokens.get(key);
    if (spent && spent.expiresAt > this.now() && spent.clientId === client.clientId) {
      this.revokeRefreshFamily(spent.familyId);
      throw new OAuthError('invalid_grant', 'refresh-token reuse detected; the token family was revoked');
    }

    const record = this.refreshTokens.get(key);
    if (!record || record.expiresAt <= this.now() || record.clientId !== client.clientId || this.revokedRefreshFamilies.has(record.familyId)) {
      if (record?.expiresAt && record.expiresAt <= this.now()) this.refreshTokens.delete(key);
      throw new OAuthError('invalid_grant', 'refresh token is unknown, expired, reused, or belongs to another client');
    }
    // Validate before consuming: a typo or attempted scope expansion must not destroy a good token.
    const requested = request.scope === undefined ? record.scopes : parseScopes(request.scope);
    requireScopeSubset(requested, record.scopes); // refresh may narrow, never expand

    this.refreshTokens.delete(key);
    this.spentRefreshTokens.set(key, {
      familyId: record.familyId, clientId: record.clientId, expiresAt: record.expiresAt,
    });
    return this.issueUserTokens(
      record.sub, client, requested, record.authTime, undefined, true, record.familyId, record.expiresAt,
    );
  }

  private exchangeClientCredentials(
    client: StoredClient,
    request: Extract<TokenRequest, { grant_type: 'client_credentials' }>,
  ): TokenResponse {
    if (client.clientType !== 'confidential') throw new OAuthError('unauthorized_client', 'public clients cannot authenticate for client_credentials');
    const scopes = parseScopes(request.scope);
    requireScopeSubset(scopes, client.allowedScopes);
    if (scopes.includes('openid')) throw new OAuthError('invalid_scope', 'client_credentials has no human, so it cannot request openid');
    return this.issueAccessToken(`client:${client.clientId}`, client, scopes);
  }

  private issueUserTokens(
    sub: string,
    client: StoredClient,
    scopes: string[],
    authTime: number,
    nonce: string | undefined,
    includeRefresh: boolean,
    refreshFamilyId: string = randomUUID(),
    refreshFamilyExpiresAt = this.now() + REFRESH_TOKEN_LIFETIME_MS,
  ): TokenResponse {
    const user = this.usersBySub.get(sub);
    if (!user) throw new OAuthError('invalid_grant', 'user no longer exists');
    const response = this.issueAccessToken(sub, client, scopes, { groups: user.groups });
    if (scopes.includes('openid')) {
      const now = Math.floor(this.now() / 1000);
      const claims: Claims = {
        iss: this.issuer, sub, aud: client.clientId, iat: now, exp: now + ACCESS_TOKEN_LIFETIME_SEC,
        auth_time: authTime, nonce, token_use: 'id', at_hash: oidcHashHalf(response.access_token),
      };
      if (scopes.includes('profile')) claims.name = user.name;
      if (scopes.includes('email')) { claims.email = user.email; claims.email_verified = true; }
      if (scopes.includes('groups')) claims.groups = user.groups;
      response.id_token = signJwt(claims, this.signingKey, 'JWT');
    }
    if (includeRefresh) {
      const refresh = randomToken();
      this.refreshTokens.set(digestText(refresh), {
        familyId: refreshFamilyId, clientId: client.clientId, sub, scopes: [...scopes], authTime,
        expiresAt: refreshFamilyExpiresAt,
      });
      response.refresh_token = refresh;
    }
    return response;
  }

  private issueAccessToken(sub: string, client: StoredClient, scopes: string[], extra: Claims = {}): TokenResponse {
    const now = Math.floor(this.now() / 1000);
    const claims: Claims = {
      iss: this.issuer, sub, aud: this.resourceAudience, client_id: client.clientId,
      iat: now, nbf: now, exp: now + ACCESS_TOKEN_LIFETIME_SEC, jti: randomUUID(),
      scope: scopes.join(' '), token_use: 'access', ...extra,
    };
    return {
      token_type: 'Bearer', access_token: signJwt(claims, this.signingKey, 'at+jwt'),
      expires_in: ACCESS_TOKEN_LIFETIME_SEC, scope: scopes.join(' '),
    };
  }

  verifyAccessToken(token: string, requiredScopes: string[] = []): Claims {
    let payload: Claims;
    try {
      payload = verifyJwt(token, this.jwks, { issuer: this.issuer, audience: this.resourceAudience, now: this.now });
    } catch (error) {
      throw new OAuthError('invalid_token', error instanceof Error ? error.message : String(error), 401);
    }
    const decoded = decodeJwt(token);
    if (decoded.header.typ !== 'at+jwt' || payload.token_use !== 'access') {
      throw new OAuthError('invalid_token', 'resource servers accept access tokens, not ID tokens', 401);
    }
    if (typeof payload.jti !== 'string' || this.revokedAccessJtis.has(payload.jti)) {
      throw new OAuthError('invalid_token', 'access token was revoked', 401);
    }
    const scopes = parseScopes(typeof payload.scope === 'string' ? payload.scope : '');
    const missing = requiredScopes.filter((scope) => !scopes.includes(scope));
    if (missing.length) throw new OAuthError('insufficient_scope', `missing required scope: ${missing.join(' ')}`, 403);
    return payload;
  }

  userInfo(accessToken: string): Claims {
    const payload = this.verifyAccessToken(accessToken, ['openid']);
    const user = this.usersBySub.get(String(payload.sub));
    if (!user) throw new OAuthError('invalid_token', 'subject no longer exists', 401);
    const scopes = parseScopes(String(payload.scope));
    const result: Claims = { sub: user.sub };
    if (scopes.includes('profile')) result.name = user.name;
    if (scopes.includes('email')) { result.email = user.email; result.email_verified = true; }
    if (scopes.includes('groups')) result.groups = user.groups;
    return result;
  }

  /** RFC 7009-style: deliberately returns no indication whether the token existed. */
  revoke(token: string, credentials: ClientCredentials): void {
    const client = this.authenticateClient(credentials);
    const key = digestText(token);
    const refresh = this.refreshTokens.get(key);
    const spent = this.spentRefreshTokens.get(key);
    if (refresh?.clientId === client.clientId) this.revokeRefreshFamily(refresh.familyId);
    if (spent?.clientId === client.clientId) this.revokeRefreshFamily(spent.familyId);
    try {
      const claims = verifyJwt(token, this.jwks, { issuer: this.issuer, audience: this.resourceAudience, now: this.now });
      if (claims.client_id === client.clientId && typeof claims.jti === 'string') this.revokedAccessJtis.add(claims.jti);
    } catch {
      // RFC 7009 returns 200 for invalid/unknown tokens to avoid a token-existence oracle.
    }
  }

  introspect(token: string, credentials: ClientCredentials): Claims & { active: boolean } {
    this.authenticateClient(credentials);
    const refresh = this.refreshTokens.get(digestText(token));
    if (refresh && refresh.expiresAt > this.now() && !this.revokedRefreshFamilies.has(refresh.familyId)) {
      return { active: true, token_type: 'refresh_token', client_id: refresh.clientId, sub: refresh.sub, scope: refresh.scopes.join(' ') };
    }
    try {
      return { active: true, ...this.verifyAccessToken(token) };
    } catch {
      return { active: false };
    }
  }

  private revokeRefreshFamily(familyId: string): void {
    let expiresAt = this.now();
    for (const [tokenHash, record] of this.refreshTokens) {
      if (record.familyId === familyId) {
        expiresAt = Math.max(expiresAt, record.expiresAt);
        this.refreshTokens.delete(tokenHash);
      }
    }
    for (const record of this.spentRefreshTokens.values()) {
      if (record.familyId === familyId) expiresAt = Math.max(expiresAt, record.expiresAt);
    }
    this.revokedRefreshFamilies.set(familyId, expiresAt);
  }

  private authenticateClient(credentials: ClientCredentials, bodyClientId?: string): StoredClient {
    if (bodyClientId && bodyClientId !== credentials.clientId) {
      throw new OAuthError('invalid_client', 'body client_id and authenticated client disagree', 401);
    }
    const client = this.clients.get(credentials.clientId);
    if (!client) throw new OAuthError('invalid_client', 'client authentication failed', 401);
    if (client.clientType === 'confidential') {
      if (!credentials.clientSecret || !client.secretHash || !safeBufferEqual(digest(credentials.clientSecret), client.secretHash)) {
        throw new OAuthError('invalid_client', 'client authentication failed', 401);
      }
    }
    return client;
  }
}

export function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(48).toString('base64url');
  return { verifier, challenge: pkceChallenge(verifier) };
}

export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export function parseBasicClientAuthorization(header: string | undefined): ClientCredentials | undefined {
  if (!header?.startsWith('Basic ')) return undefined;
  try {
    const value = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const separator = value.indexOf(':');
    if (separator < 0) return undefined;
    return { clientId: decodeURIComponent(value.slice(0, separator)), clientSecret: decodeURIComponent(value.slice(separator + 1)) };
  } catch {
    return undefined;
  }
}

export function bearerToken(header: string | undefined): string | undefined {
  return header?.match(/^Bearer\s+(\S+)$/i)?.[1];
}

function parseScopes(scope: string | undefined): string[] {
  return [...new Set((scope ?? '').trim().split(/\s+/).filter(Boolean))];
}

function requireScopeSubset(requested: string[], allowed: string[]): void {
  const invalid = requested.filter((scope) => !allowed.includes(scope));
  if (invalid.length) throw new OAuthError('invalid_scope', `not allowed: ${invalid.join(' ')}`);
}

function randomToken(): string { return randomBytes(32).toString('base64url'); }
function digest(value: string): Buffer { return createHash('sha256').update(value).digest(); }
function digestText(value: string): string { return digest(value).toString('base64url'); }
function safeBufferEqual(a: Buffer, b: Buffer): boolean { return a.length === b.length && timingSafeEqual(a, b); }
function safeEqual(a: string, b: string): boolean { return safeBufferEqual(Buffer.from(a), Buffer.from(b)); }
function oidcHashHalf(value: string): string {
  const hash = createHash('sha256').update(value).digest();
  return hash.subarray(0, hash.length / 2).toString('base64url');
}
