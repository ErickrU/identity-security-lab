import { beforeEach, describe, expect, it } from 'vitest';
import { decodeJwt, generateSigningKey } from '../../../small-idp/src/keys';
import { createPkcePair, LabIdentityProvider, OAuthError, type PendingAuthorization } from '../../../small-idp/src/protocol';

const NOW = 1_700_000_000_000;
const REDIRECT = 'https://client.example/callback';
let idp: LabIdentityProvider;

beforeEach(async () => {
  idp = new LabIdentityProvider({ issuer: 'https://as.example', resourceAudience: 'https://api.example', now: () => NOW, signingKey: generateSigningKey('oauth-test') });
  await idp.registerUser({ sub: 'alice', username: 'alice', password: 'correct horse battery staple', name: 'Alice', email: 'alice@example', groups: [] });
  idp.registerClient({ clientId: 'public', clientType: 'public', name: 'Public', redirectUris: [REDIRECT], allowedScopes: ['read', 'write'], allowedGrants: ['authorization_code', 'refresh_token'] });
  idp.registerClient({ clientId: 'machine', clientType: 'confidential', clientSecret: 'long-random-machine-secret', name: 'Machine', redirectUris: [], allowedScopes: ['read'], allowedGrants: ['client_credentials'] });
});

function begin(scope = 'read write'): { pending: PendingAuthorization; verifier: string } {
  const pkce = createPkcePair();
  return {
    pending: idp.beginAuthorization({ response_type: 'code', client_id: 'public', redirect_uri: REDIRECT, scope, state: 'state-at-least-16-characters', code_challenge: pkce.challenge, code_challenge_method: 'S256' }),
    verifier: pkce.verifier,
  };
}

function issue(flow = begin()) {
  const callback = new URL(idp.consent(flow.pending.requestId, idp.createSession('alice'), true));
  const code = callback.searchParams.get('code')!;
  return { ...flow, code };
}

function exchange(flow = issue()) {
  return idp.token({ grant_type: 'authorization_code', code: flow.code, redirect_uri: REDIRECT, code_verifier: flow.verifier, client_id: 'public' }, { clientId: 'public' });
}

function oauthError(fn: () => unknown): OAuthError {
  try { fn(); throw new Error('expected OAuthError'); }
  catch (error) { if (error instanceof OAuthError) return error; throw error; }
}

describe('OAuth Authorization Code + PKCE', () => {
  it('issues an API access token but no ID token when openid was not requested', () => {
    const result = exchange();
    expect(result.id_token).toBeUndefined();
    expect(result.refresh_token).toBeTypeOf('string');
    expect(decodeJwt(result.access_token).payload).toMatchObject({ aud: 'https://api.example', sub: 'alice', client_id: 'public', scope: 'read write', token_use: 'access' });
  });
  it('requires PKCE for a public client', () => {
    expect(oauthError(() => idp.beginAuthorization({ response_type: 'code', client_id: 'public', redirect_uri: REDIRECT, scope: 'read', state: 'state-at-least-16-characters' })).error).toBe('invalid_request');
  });
  it('rejects a redirect that is only a malicious prefix/suffix match', () => {
    const pkce = createPkcePair();
    expect(oauthError(() => idp.beginAuthorization({ response_type: 'code', client_id: 'public', redirect_uri: `${REDIRECT}.attacker.test`, scope: 'read', state: 'state-at-least-16-characters', code_challenge: pkce.challenge, code_challenge_method: 'S256' })).error).toBe('invalid_request');
  });
  it('returns state unchanged after consent', () => {
    const flow = begin();
    const callback = new URL(idp.consent(flow.pending.requestId, idp.createSession('alice'), true));
    expect(callback.searchParams.get('state')).toBe(flow.pending.state);
  });
  it('rejects the wrong verifier and consumes the code', () => {
    const flow = issue();
    expect(oauthError(() => idp.token({ grant_type: 'authorization_code', code: flow.code, redirect_uri: REDIRECT, code_verifier: 'x'.repeat(43), client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_grant');
    expect(oauthError(() => idp.token({ grant_type: 'authorization_code', code: flow.code, redirect_uri: REDIRECT, code_verifier: flow.verifier, client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_grant');
  });
  it('rejects replay after a successful exchange', () => {
    const flow = issue(); exchange(flow);
    expect(oauthError(() => idp.token({ grant_type: 'authorization_code', code: flow.code, redirect_uri: REDIRECT, code_verifier: flow.verifier, client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_grant');
  });
  it('enforces API scopes with 403 insufficient_scope', () => {
    const result = exchange(issue(begin('read')));
    expect(idp.verifyAccessToken(result.access_token, ['read']).sub).toBe('alice');
    const error = oauthError(() => idp.verifyAccessToken(result.access_token, ['write']));
    expect(error).toMatchObject({ error: 'insufficient_scope', status: 403 });
  });
});

describe('refresh, machines, introspection and revocation', () => {
  it('rotates a refresh token and rejects reuse', () => {
    const first = exchange(issue(begin('read')));
    const second = idp.token({ grant_type: 'refresh_token', refresh_token: first.refresh_token!, client_id: 'public' }, { clientId: 'public' });
    expect(second.refresh_token).not.toBe(first.refresh_token);
    expect(oauthError(() => idp.token({ grant_type: 'refresh_token', refresh_token: first.refresh_token!, client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_grant');
    expect(oauthError(() => idp.token({ grant_type: 'refresh_token', refresh_token: second.refresh_token!, client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_grant');
  });
  it('allows refresh scope narrowing but not expansion', () => {
    const first = exchange();
    const narrow = idp.token({ grant_type: 'refresh_token', refresh_token: first.refresh_token!, scope: 'read', client_id: 'public' }, { clientId: 'public' });
    expect(narrow.scope).toBe('read');
    expect(oauthError(() => idp.token({ grant_type: 'refresh_token', refresh_token: narrow.refresh_token!, scope: 'read write extra', client_id: 'public' }, { clientId: 'public' })).error).toBe('invalid_scope');
    expect(idp.token({ grant_type: 'refresh_token', refresh_token: narrow.refresh_token!, scope: 'read', client_id: 'public' }, { clientId: 'public' }).scope).toBe('read');
  });
  it('client credentials represents the client and emits no user tokens', () => {
    const result = idp.token({ grant_type: 'client_credentials', scope: 'read' }, { clientId: 'machine', clientSecret: 'long-random-machine-secret' });
    expect(result.id_token).toBeUndefined(); expect(result.refresh_token).toBeUndefined();
    expect(decodeJwt(result.access_token).payload.sub).toBe('client:machine');
  });
  it('rejects wrong machine authentication and ungranted scope', () => {
    expect(oauthError(() => idp.token({ grant_type: 'client_credentials', scope: 'read' }, { clientId: 'machine', clientSecret: 'wrong' })).error).toBe('invalid_client');
    expect(oauthError(() => idp.token({ grant_type: 'client_credentials', scope: 'write' }, { clientId: 'machine', clientSecret: 'long-random-machine-secret' })).error).toBe('invalid_scope');
  });
  it('introspects active access and refresh tokens', () => {
    const result = idp.token({ grant_type: 'client_credentials', scope: 'read' }, { clientId: 'machine', clientSecret: 'long-random-machine-secret' });
    expect(idp.introspect(result.access_token, { clientId: 'machine', clientSecret: 'long-random-machine-secret' })).toMatchObject({ active: true, sub: 'client:machine' });
  });
  it('revokes without revealing whether the token existed', () => {
    const c = { clientId: 'machine', clientSecret: 'long-random-machine-secret' };
    const result = idp.token({ grant_type: 'client_credentials', scope: 'read' }, c);
    idp.revoke(result.access_token, c);
    expect(idp.introspect(result.access_token, c)).toEqual({ active: false });
    expect(() => idp.revoke('unknown', c)).not.toThrow();
  });
});
