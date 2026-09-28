import { beforeEach, describe, expect, it } from 'vitest';
import { decodeJwt, verifyJwt } from './keys';
import {
  createPkcePair,
  pkceChallenge,
  LabIdentityProvider,
  OAuthError,
  type AuthorizationParameters,
  type ClientCredentials,
  type TokenResponse,
} from './protocol';

const NOW_MS = 1_700_000_000_000;
const REDIRECT = 'http://client.example/callback';
const WEB_VERIFIER = 'v'.repeat(64);
let now: number;
let idp: LabIdentityProvider;

beforeEach(async () => {
  now = NOW_MS;
  idp = new LabIdentityProvider({ issuer: 'https://idp.example', resourceAudience: 'https://api.example', now: () => now });
  await idp.registerUser({
    sub: 'alice-sub', username: 'alice', password: 'correct horse battery staple',
    name: 'Alice', email: 'alice@example.com', groups: ['staff', 'admins'],
  });
  idp.registerClient({
    clientId: 'web', clientType: 'confidential', clientSecret: 'web-secret-long-random', name: 'Web',
    redirectUris: [REDIRECT], allowedScopes: ['openid', 'profile', 'email', 'groups', 'orders:read', 'orders:write'],
    allowedGrants: ['authorization_code', 'refresh_token'],
  });
  idp.registerClient({
    clientId: 'spa', clientType: 'public', name: 'SPA', redirectUris: [REDIRECT],
    allowedScopes: ['openid', 'profile', 'orders:read'], allowedGrants: ['authorization_code', 'refresh_token'],
  });
  idp.registerClient({
    clientId: 'machine', clientType: 'confidential', clientSecret: 'machine-secret-long-random', name: 'Machine',
    redirectUris: [], allowedScopes: ['orders:read'], allowedGrants: ['client_credentials'],
  });
});

const creds: ClientCredentials = { clientId: 'web', clientSecret: 'web-secret-long-random' };

function authParams(overrides: Partial<AuthorizationParameters> = {}): AuthorizationParameters {
  return {
    response_type: 'code', client_id: 'web', redirect_uri: REDIRECT,
    scope: 'openid profile email groups orders:read', state: 'state-value-at-least-16',
    nonce: 'nonce-value-at-least-16', code_challenge: pkceChallenge(WEB_VERIFIER),
    code_challenge_method: 'S256', ...overrides,
  };
}

async function codeFor(params = authParams(), sessionSub = 'alice-sub'): Promise<{ code: string; verifier: string }> {
  const pending = idp.beginAuthorization(params);
  const session = idp.createSession(sessionSub);
  const callback = new URL(idp.consent(pending.requestId, session, true));
  return { code: callback.searchParams.get('code')!, verifier: WEB_VERIFIER };
}

async function loginAndExchange(): Promise<TokenResponse> {
  const { code, verifier } = await codeFor();
  return idp.token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }, creds);
}

function expectOAuth(fn: () => unknown, code: string): void {
  try { fn(); throw new Error('expected OAuthError'); }
  catch (error) { expect(error).toBeInstanceOf(OAuthError); expect((error as OAuthError).error).toBe(code); }
}

describe('authorization request validation', () => {
  it('accepts code flow and records state, nonce and exact redirect URI', () => {
    expect(idp.beginAuthorization(authParams())).toMatchObject({
      clientId: 'web', redirectUri: REDIRECT, state: 'state-value-at-least-16', nonce: 'nonce-value-at-least-16',
      scopes: ['openid', 'profile', 'email', 'groups', 'orders:read'],
    });
  });

  it('rejects wrong response type, client, redirect, scope, weak state and missing OIDC nonce', () => {
    expectOAuth(() => idp.beginAuthorization(authParams({ response_type: 'token' })), 'unsupported_response_type');
    expectOAuth(() => idp.beginAuthorization(authParams({ client_id: 'unknown' })), 'invalid_request');
    expectOAuth(() => idp.beginAuthorization(authParams({ redirect_uri: 'http://evil.example/callback' })), 'invalid_request');
    expectOAuth(() => idp.beginAuthorization(authParams({ scope: 'openid root:everything' })), 'invalid_scope');
    expectOAuth(() => idp.beginAuthorization(authParams({ state: 'short' })), 'invalid_request');
    expectOAuth(() => idp.beginAuthorization(authParams({ nonce: undefined })), 'invalid_request');
  });

  it('requires PKCE S256 for public and confidential code clients and validates challenge shape', () => {
    expectOAuth(() => idp.beginAuthorization(authParams({ code_challenge: undefined, code_challenge_method: undefined })), 'invalid_request');
    const publicParams = authParams({
      client_id: 'spa', scope: 'openid profile orders:read',
      code_challenge: undefined, code_challenge_method: undefined,
    });
    expectOAuth(() => idp.beginAuthorization(publicParams), 'invalid_request');
    expectOAuth(() => idp.beginAuthorization({ ...publicParams, code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' }), 'invalid_request');
    const pkce = createPkcePair();
    expect(() => idp.beginAuthorization({ ...publicParams, code_challenge: pkce.challenge, code_challenge_method: 'S256' })).not.toThrow();
  });

  it('expires pending requests', () => {
    const pending = idp.beginAuthorization(authParams());
    now += 5 * 60 * 1000;
    expectOAuth(() => idp.getPending(pending.requestId), 'invalid_request');
  });
});

describe('IdP login, consent and sessions', () => {
  it('returns the same generic error for unknown user and wrong password', async () => {
    const a = idp.beginAuthorization(authParams());
    const b = idp.beginAuthorization(authParams());
    const wrong = await idp.login(a.requestId, 'alice', 'wrong').catch((e) => e as OAuthError) as OAuthError;
    const unknown = await idp.login(b.requestId, 'unknown', 'wrong').catch((e) => e as OAuthError) as OAuthError;
    expect(wrong.toJSON()).toEqual(unknown.toJSON());
    expect(wrong.status).toBe(401);
  });

  it('creates/destroys the IdP session independently of client sessions', async () => {
    const pending = idp.beginAuthorization(authParams());
    const session = await idp.login(pending.requestId, 'alice', 'correct horse battery staple');
    expect(idp.sessionUser(session)?.username).toBe('alice');
    idp.destroySession(session);
    expect(idp.sessionUser(session)).toBeUndefined();
  });

  it('returns state on consent allow and deny, and never emits a code on deny', () => {
    const allowed = idp.beginAuthorization(authParams());
    const session = idp.createSession('alice-sub');
    const ok = new URL(idp.consent(allowed.requestId, session, true));
    expect(ok.searchParams.get('state')).toBe(allowed.state);
    expect(ok.searchParams.get('code')).toHaveLength(43);

    const denied = idp.beginAuthorization(authParams());
    const no = new URL(idp.consent(denied.requestId, session, false));
    expect(no.searchParams.get('state')).toBe(denied.state);
    expect(no.searchParams.get('error')).toBe('access_denied');
    expect(no.searchParams.has('code')).toBe(false);
  });
});

describe('authorization code and OIDC tokens', () => {
  it('exchanges once and emits correctly targeted access, ID and rotating refresh tokens', async () => {
    const response = await loginAndExchange();
    expect(response).toMatchObject({ token_type: 'Bearer', expires_in: 300, scope: 'openid profile email groups orders:read' });
    expect(response.id_token).toBeTypeOf('string');
    expect(response.refresh_token).toHaveLength(43);

    const access = verifyJwt(response.access_token, idp.jwks, { issuer: idp.issuer, audience: idp.resourceAudience, now: () => now });
    expect(access).toMatchObject({ sub: 'alice-sub', client_id: 'web', token_use: 'access', groups: ['staff', 'admins'] });
    expect(decodeJwt(response.access_token).header.typ).toBe('at+jwt');

    const identity = verifyJwt(response.id_token!, idp.jwks, { issuer: idp.issuer, audience: 'web', now: () => now });
    expect(identity).toMatchObject({ sub: 'alice-sub', token_use: 'id', nonce: 'nonce-value-at-least-16', name: 'Alice', email: 'alice@example.com' });
    expect(identity.at_hash).toBeTypeOf('string');
    expect(decodeJwt(response.id_token!).header.typ).toBe('JWT');
  });

  it('makes authorization codes single-use', async () => {
    const { code, verifier } = await codeFor();
    const request = { grant_type: 'authorization_code' as const, code, redirect_uri: REDIRECT, code_verifier: verifier };
    expect(() => idp.token(request, creds)).not.toThrow();
    expectOAuth(() => idp.token(request, creds), 'invalid_grant');
  });

  it('binds a code to exact client and redirect URI', async () => {
    const { code, verifier } = await codeFor();
    expectOAuth(() => idp.token({ grant_type: 'authorization_code', code, redirect_uri: `${REDIRECT}/extra`, code_verifier: verifier }, creds), 'invalid_grant');
    // It was consumed even by the bad attempt.
    expectOAuth(() => idp.token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }, creds), 'invalid_grant');
  });

  it('enforces PKCE for the public client and consumes code after a bad verifier', () => {
    const pkce = createPkcePair();
    const pending = idp.beginAuthorization(authParams({
      client_id: 'spa', scope: 'openid profile orders:read', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    }));
    const callback = new URL(idp.consent(pending.requestId, idp.createSession('alice-sub'), true));
    const code = callback.searchParams.get('code')!;
    const request = { grant_type: 'authorization_code' as const, code, redirect_uri: REDIRECT, code_verifier: 'z'.repeat(43), client_id: 'spa' };
    expectOAuth(() => idp.token(request, { clientId: 'spa' }), 'invalid_grant');
    expectOAuth(() => idp.token({ ...request, code_verifier: pkce.verifier }, { clientId: 'spa' }), 'invalid_grant');
  });

  it('accepts the correct PKCE verifier for a public client with no secret', () => {
    const pkce = createPkcePair();
    const pending = idp.beginAuthorization(authParams({
      client_id: 'spa', scope: 'openid profile orders:read', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    }));
    const code = new URL(idp.consent(pending.requestId, idp.createSession('alice-sub'), true)).searchParams.get('code')!;
    const response = idp.token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: pkce.verifier, client_id: 'spa' }, { clientId: 'spa' });
    expect(response.id_token).toBeTypeOf('string');
  });

  it('rejects wrong confidential-client authentication', async () => {
    const { code, verifier } = await codeFor();
    expectOAuth(() => idp.token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier }, { clientId: 'web', clientSecret: 'wrong' }), 'invalid_client');
  });
});

describe('refresh, machine flow, userinfo and revocation', () => {
  it('rotates refresh tokens, rejects reuse, and revokes the active family descendant', async () => {
    const original = await loginAndExchange();
    const rotated = idp.token({ grant_type: 'refresh_token', refresh_token: original.refresh_token! }, creds);
    expect(rotated.refresh_token).not.toBe(original.refresh_token);
    expectOAuth(() => idp.token({ grant_type: 'refresh_token', refresh_token: original.refresh_token! }, creds), 'invalid_grant');
    expectOAuth(() => idp.token({ grant_type: 'refresh_token', refresh_token: rotated.refresh_token! }, creds), 'invalid_grant');
  });

  it('permits scope narrowing, refuses expansion without burning the current refresh token', async () => {
    const original = await loginAndExchange();
    expectOAuth(() => idp.token({ grant_type: 'refresh_token', refresh_token: original.refresh_token!, scope: 'openid orders:read root' }, creds), 'invalid_scope');
    const narrowed = idp.token({ grant_type: 'refresh_token', refresh_token: original.refresh_token!, scope: 'openid orders:read' }, creds);
    expect(narrowed.scope).toBe('openid orders:read');
  });

  it('client_credentials represents the machine, returns no ID or refresh token', () => {
    const response = idp.token({ grant_type: 'client_credentials', scope: 'orders:read' }, { clientId: 'machine', clientSecret: 'machine-secret-long-random' });
    expect(response.id_token).toBeUndefined();
    expect(response.refresh_token).toBeUndefined();
    expect(idp.verifyAccessToken(response.access_token)).toMatchObject({ sub: 'client:machine', client_id: 'machine' });
  });

  it('returns userinfo according to granted OIDC scopes and rejects a token without openid', async () => {
    const response = await loginAndExchange();
    expect(idp.userInfo(response.access_token)).toEqual({
      sub: 'alice-sub', name: 'Alice', email: 'alice@example.com', email_verified: true, groups: ['staff', 'admins'],
    });
    const machine = idp.token({ grant_type: 'client_credentials', scope: 'orders:read' }, { clientId: 'machine', clientSecret: 'machine-secret-long-random' });
    expectOAuth(() => idp.userInfo(machine.access_token), 'insufficient_scope');
  });

  it('enforces scopes and distinguishes invalid token 401 from insufficient scope 403', async () => {
    const response = await loginAndExchange();
    expect(idp.verifyAccessToken(response.access_token, ['orders:read']).sub).toBe('alice-sub');
    try { idp.verifyAccessToken(response.access_token, ['inventory:write']); throw new Error('expected'); }
    catch (error) { expect((error as OAuthError).status).toBe(403); }
    expectOAuth(() => idp.verifyAccessToken(response.id_token!), 'invalid_token');
  });

  it('introspects and revokes access/refresh tokens without revealing unknown-token existence', async () => {
    const response = await loginAndExchange();
    expect(idp.introspect(response.access_token, creds).active).toBe(true);
    expect(idp.introspect(response.refresh_token!, creds)).toMatchObject({ active: true, token_type: 'refresh_token', sub: 'alice-sub' });
    idp.revoke(response.access_token, creds);
    expect(idp.introspect(response.access_token, creds)).toEqual({ active: false });
    idp.revoke(response.refresh_token!, creds);
    expectOAuth(() => idp.token({ grant_type: 'refresh_token', refresh_token: response.refresh_token! }, creds), 'invalid_grant');
    expect(() => idp.revoke('unknown-random-token', creds)).not.toThrow();
  });
});
