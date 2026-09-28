import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  beginLogin,
  discover,
  finishLogin,
  type LoginTransaction,
  type OidcClientConfig,
  type VerifiedLogin,
} from '../../../small-idp/src/client';
import { decodeJwt, signJwt, verifyJwt, type Claims } from '../../../small-idp/src/keys';
import { startIdp, type RunningIdp } from '../../../small-idp/src/idp';
import {
  OAuthError,
  type AuthorizationParameters,
  type TokenResponse,
} from '../../../small-idp/src/protocol';

const CLIENT_ID = 'chapter-06-test-rp';
const CLIENT_SECRET = 'chapter-06-test-confidential-secret';
const REDIRECT_URI = 'http://chapter-06-test-rp.example.invalid/callback';
const FULL_SCOPE = 'openid profile email groups orders:read';

interface AuthorizationFlow {
  config: OidcClientConfig;
  transaction: LoginTransaction;
  callbackUrl: string;
}

let idp: RunningIdp;

function configFor(scope = FULL_SCOPE): OidcClientConfig {
  return {
    issuer: idp.url,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    scope,
  };
}

function authorizationParameters(url: URL): AuthorizationParameters {
  const value = (name: string): string | undefined => url.searchParams.get(name) ?? undefined;
  return {
    response_type: value('response_type'),
    client_id: value('client_id'),
    redirect_uri: value('redirect_uri'),
    scope: value('scope'),
    state: value('state'),
    nonce: value('nonce'),
    code_challenge: value('code_challenge'),
    code_challenge_method: value('code_challenge_method'),
    prompt: value('prompt'),
  };
}

async function authorize(scope = FULL_SCOPE): Promise<AuthorizationFlow> {
  const config = configFor(scope);
  const transaction = await beginLogin(config);
  const pending = idp.provider.beginAuthorization(
    authorizationParameters(new URL(transaction.authorizationUrl)),
  );
  const session = await idp.provider.login(
    pending.requestId,
    'alice',
    'correct horse battery staple',
  );
  try {
    return {
      config,
      transaction,
      callbackUrl: idp.provider.consent(pending.requestId, session, true),
    };
  } finally {
    idp.provider.destroySession(session);
  }
}

async function login(scope = FULL_SCOPE): Promise<VerifiedLogin> {
  const flow = await authorize(scope);
  return finishLogin(flow.config, flow.transaction, flow.callbackUrl);
}

function hashHalf(value: string): string {
  const digest = createHash('sha256').update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}

function rewriteIdToken(
  tokens: TokenResponse,
  overrides: Claims,
  typ: 'JWT' | 'at+jwt' | null = 'JWT',
): TokenResponse {
  if (!tokens.id_token) throw new Error('test expected an ID token');
  return {
    ...tokens,
    id_token: signJwt(
      { ...decodeJwt(tokens.id_token).payload, ...overrides },
      idp.provider.signingKey,
      typ === null ? undefined : typ,
    ),
  };
}

async function withTokenTransform<T>(
  transform: (tokens: TokenResponse) => TokenResponse,
  action: () => Promise<T>,
): Promise<T> {
  const originalToken = idp.provider.token.bind(idp.provider);
  idp.provider.token = (request, credentials) => transform(originalToken(request, credentials));
  try {
    return await action();
  } finally {
    idp.provider.token = originalToken;
  }
}

async function userInfo(accessToken: string): Promise<Claims> {
  const metadata = await discover(idp.url);
  const response = await fetch(metadata.userinfo_endpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) throw new Error(`userinfo HTTP ${response.status}: ${await response.text()}`);
  return response.json() as Promise<Claims>;
}

beforeAll(async () => {
  idp = await startIdp(0);
  idp.provider.registerClient({
    clientId: CLIENT_ID,
    clientType: 'confidential',
    clientSecret: CLIENT_SECRET,
    name: 'Chapter 06 test RP',
    redirectUris: [REDIRECT_URI],
    allowedScopes: FULL_SCOPE.split(' '),
    allowedGrants: ['authorization_code', 'refresh_token'],
  });
});

afterAll(async () => {
  await idp?.stop();
});

describe('06 · OpenID Connect', () => {
  it('discovers an exact issuer and the authorization, token, UserInfo, and JWKS endpoints', async () => {
    const metadata = await discover(idp.url);
    expect(metadata).toMatchObject({
      issuer: idp.url,
      authorization_endpoint: `${idp.url}/authorize`,
      token_endpoint: `${idp.url}/token`,
      userinfo_endpoint: `${idp.url}/userinfo`,
      jwks_uri: `${idp.url}/jwks.json`,
    });
  });

  it('publishes a public RS256 JWKS without private key material', async () => {
    const metadata = await discover(idp.url);
    const response = await fetch(metadata.jwks_uri);
    expect(response.status).toBe(200);
    const jwks = await response.json() as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(jwks.keys[0]).not.toHaveProperty('d');
    expect(jwks.keys[0]).not.toHaveProperty('p');
    expect(jwks.keys[0]).not.toHaveProperty('q');
  });

  it('beginLogin builds an openid authorization request with state, nonce, and S256 PKCE', async () => {
    const transaction = await beginLogin(configFor());
    const url = new URL(transaction.authorizationUrl);
    expect(`${url.origin}${url.pathname}`).toBe(`${idp.url}/authorize`);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
    expect(url.searchParams.get('redirect_uri')).toBe(REDIRECT_URI);
    expect(url.searchParams.get('scope')?.split(' ')).toContain('openid');
    expect(url.searchParams.get('state')).toBe(transaction.state);
    expect(url.searchParams.get('nonce')).toBe(transaction.nonce);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(transaction.codeVerifier).toMatch(/^[A-Za-z0-9_-]{64}$/);
    expect(transaction.authorizationUrl).not.toContain(transaction.codeVerifier);
  });

  it('the provider rejects an openid authorization request with no nonce', async () => {
    const transaction = await beginLogin(configFor());
    const url = new URL(transaction.authorizationUrl);
    url.searchParams.delete('nonce');
    expect(() => idp.provider.beginAuthorization(authorizationParameters(url)))
      .toThrow(/OIDC requests require an unpredictable nonce/);
  });

  it('finishes login through the real token and JWKS endpoints', async () => {
    const result = await login();
    expect(result.claims).toMatchObject({
      iss: idp.url,
      sub: 'user-alice-0001',
      aud: CLIENT_ID,
      token_use: 'id',
      name: 'Alice Example',
      email: 'alice@lab.example',
      email_verified: true,
      groups: ['staff', 'admins'],
    });
    expect(result.tokens).toMatchObject({
      token_type: 'Bearer',
      expires_in: 300,
      scope: FULL_SCOPE,
    });
    expect(result.tokens.id_token).toBeTypeOf('string');
    expect(result.tokens.refresh_token).toBeTypeOf('string');
    expect(decodeJwt(result.tokens.id_token!).header).toMatchObject({ alg: 'RS256', typ: 'JWT' });
    expect(result.claims.at_hash).toBe(hashHalf(result.tokens.access_token));
  });

  it('rejects the wrong callback state before exchanging the code', async () => {
    const flow = await authorize();
    const wrongCallback = new URL(flow.callbackUrl);
    wrongCallback.searchParams.set('state', 'wrong-state-that-cannot-match');

    await expect(
      finishLogin(flow.config, flow.transaction, wrongCallback.toString()),
    ).rejects.toThrow(/state mismatch/);

    await expect(
      finishLogin(flow.config, flow.transaction, flow.callbackUrl),
    ).rejects.toThrow(/already consumed/);
  });

  it('rejects an ID token whose nonce belongs to another login transaction', async () => {
    const flow = await authorize();
    await expect(
      finishLogin(
        flow.config,
        { ...flow.transaction, nonce: 'different-transaction-nonce-value' },
        flow.callbackUrl,
      ),
    ).rejects.toThrow(/nonce mismatch/);
  });

  it('rejects a correctly signed ID token with the wrong at_hash', async () => {
    const flow = await authorize();
    await expect(withTokenTransform(
      (tokens) => rewriteIdToken(tokens, { at_hash: 'wrong-access-token-hash' }),
      () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
    )).rejects.toThrow(/at_hash mismatch/);
  });

  it('rejects a correctly signed ID token intended for another audience', async () => {
    const flow = await authorize();
    await expect(withTokenTransform(
      (tokens) => rewriteIdToken(tokens, { aud: 'another-relying-party' }),
      () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
    )).rejects.toMatchObject({ code: 'bad_audience' });
  });

  it('rejects a correctly signed token with access-token typ at the OIDC client', async () => {
    const flow = await authorize();
    await expect(withTokenTransform(
      (tokens) => rewriteIdToken(tokens, {}, 'at+jwt'),
      () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
    )).rejects.toThrow(/wrong token type in OIDC response/);
  });

  it('accepts conforming ID tokens when optional typ, token_use, or at_hash are absent', async () => {
    for (const variant of [
      { overrides: {}, typ: null as null },
      { overrides: { token_use: undefined }, typ: 'JWT' as const },
      { overrides: { at_hash: undefined }, typ: 'JWT' as const },
    ]) {
      const flow = await authorize();
      await expect(withTokenTransform(
        (tokens) => rewriteIdToken(tokens, variant.overrides, variant.typ),
        () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
      )).resolves.toMatchObject({ claims: { sub: 'user-alice-0001' } });
    }
  });

  it('requires a non-empty string sub and numeric iat', async () => {
    for (const overrides of [{ sub: undefined }, { sub: '' }, { iat: undefined }, { iat: 'now' }]) {
      const flow = await authorize();
      await expect(withTokenTransform(
        (tokens) => rewriteIdToken(tokens, overrides),
        () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
      )).rejects.toThrow(/sub|iat/);
    }
  });

  it('requires matching azp for a multi-audience ID token and validates azp whenever present', async () => {
    for (const overrides of [
      { aud: [CLIENT_ID, 'another-rp'], azp: undefined },
      { aud: [CLIENT_ID, 'another-rp'], azp: 'another-rp' },
      { aud: CLIENT_ID, azp: 'another-rp' },
    ]) {
      const flow = await authorize();
      await expect(withTokenTransform(
        (tokens) => rewriteIdToken(tokens, overrides),
        () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
      )).rejects.toThrow(/azp/);
    }
    const flow = await authorize();
    await expect(withTokenTransform(
      (tokens) => rewriteIdToken(tokens, { aud: [CLIENT_ID, 'another-rp'], azp: CLIENT_ID }),
      () => finishLogin(flow.config, flow.transaction, flow.callbackUrl),
    )).resolves.toMatchObject({ claims: { azp: CLIENT_ID } });
  });

  it('accepts the access token at its API audience and rejects the ID token there', async () => {
    const result = await login();
    const accessClaims = idp.provider.verifyAccessToken(result.tokens.access_token, ['orders:read']);
    expect(accessClaims).toMatchObject({
      sub: 'user-alice-0001',
      aud: idp.provider.resourceAudience,
      token_use: 'access',
    });

    let error: unknown;
    try {
      idp.provider.verifyAccessToken(result.tokens.id_token!, ['orders:read']);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(OAuthError);
    expect(error).toMatchObject({ error: 'invalid_token', status: 401 });
  });

  it('rejects an access token as an ID token because its audience and type are different', async () => {
    const result = await login();
    const decoded = decodeJwt(result.tokens.access_token);
    expect(decoded.header.typ).toBe('at+jwt');
    expect(decoded.payload.token_use).toBe('access');
    expect(decoded.payload.aud).toBe(idp.provider.resourceAudience);

    let error: unknown;
    try {
      verifyJwt(result.tokens.access_token, idp.provider.jwks, {
        issuer: idp.url,
        audience: CLIENT_ID,
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({ code: 'bad_audience' });
  });

  it('UserInfo returns only claims authorized by profile, email, and groups scopes', async () => {
    const result = await login();
    await expect(userInfo(result.tokens.access_token)).resolves.toEqual({
      sub: 'user-alice-0001',
      name: 'Alice Example',
      email: 'alice@lab.example',
      email_verified: true,
      groups: ['staff', 'admins'],
    });
  });

  it('UserInfo with only openid and API scope returns stable sub but filters profile claims', async () => {
    const result = await login('openid orders:read');
    expect(result.claims.sub).toBe('user-alice-0001');
    expect(result.claims).not.toHaveProperty('name');
    expect(result.claims).not.toHaveProperty('email');
    expect(result.claims).not.toHaveProperty('groups');
    await expect(userInfo(result.tokens.access_token)).resolves.toEqual({
      sub: 'user-alice-0001',
    });
  });
});
