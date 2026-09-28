import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startIdp, type RunningIdp } from './idp';
import { startResourceServer, configFromProvider, type RunningResourceServer } from './resource-server';
import { startRelyingParty, type RelyingPartyConfig, type RunningRelyingParty } from './rp';
import { pkceChallenge, type TokenResponse } from './protocol';

const HTTP_CODE_VERIFIER = 'h'.repeat(64);

let idp: RunningIdp;
let api: RunningResourceServer;

beforeAll(async () => {
  idp = await startIdp(0);
  api = await startResourceServer(configFromProvider(idp.provider), 0);
});

afterAll(async () => {
  await api?.stop();
  await idp?.stop();
});

function hiddenValue(html: string, name: string): string {
  const value = html.match(new RegExp(`name="${name}" value="([^"]+)"`))?.[1];
  if (!value) throw new Error(`${name} not found in HTML`);
  return value;
}

function requestId(html: string): string { return hiddenValue(html, 'request_id'); }
function csrfToken(html: string): string { return hiddenValue(html, 'csrf_token'); }

function cookieValue(setCookie: string | null, name: string): string {
  const value = setCookie?.match(new RegExp(`(?:^|,?\\s*)${name}=([^;]+)`))?.[1];
  if (!value) throw new Error(`${name} not found in Set-Cookie: ${setCookie}`);
  return `${name}=${value}`;
}

async function authorizeViaForms(client = 'orders-web', redirectUri = 'http://127.0.0.1:4001/callback'): Promise<{ callback: string; tokens: TokenResponse }> {
  const authorize = new URL(`${idp.url}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: 'code', client_id: client, redirect_uri: redirectUri,
    scope: 'openid profile email groups orders:read orders:write', state: 'state-value-at-least-16',
    nonce: 'nonce-value-at-least-16', code_challenge: pkceChallenge(HTTP_CODE_VERIFIER),
    code_challenge_method: 'S256',
  }).toString();
  const loginPage = await fetch(authorize);
  const loginHtml = await loginPage.text();
  const id = requestId(loginHtml);
  const csrf = csrfToken(loginHtml);
  const interactionCookie = cookieValue(loginPage.headers.get('set-cookie'), 'idp_interaction');
  const login = await fetch(`${idp.url}/login`, {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: interactionCookie },
    body: new URLSearchParams({ request_id: id, csrf_token: csrf, username: 'alice', password: 'correct horse battery staple' }),
  });
  const idpCookie = cookieValue(login.headers.get('set-cookie'), 'idp_session');
  const consentHtml = await login.text();
  expect(consentHtml).toContain('consent');
  const consent = await fetch(`${idp.url}/consent`, {
    method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `${idpCookie}; ${interactionCookie}` },
    body: new URLSearchParams({ request_id: id, csrf_token: csrfToken(consentHtml), decision: 'allow' }),
  });
  const callback = consent.headers.get('location')!;
  const code = new URL(callback).searchParams.get('code')!;
  const token = await fetch(`${idp.url}/token`, {
    method: 'POST', headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from('orders-web:orders-web-secret-for-local-lab').toString('base64')}`,
    },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: HTTP_CODE_VERIFIER }),
  });
  return { callback, tokens: await token.json() as TokenResponse };
}

describe('HTTP IdP and resource server', () => {
  it('publishes OIDC discovery and matching public JWKS', async () => {
    const discovery = await fetch(`${idp.url}/.well-known/openid-configuration`).then((r) => r.json()) as Record<string, unknown>;
    expect(discovery).toMatchObject({ issuer: idp.url, authorization_endpoint: `${idp.url}/authorize`, code_challenge_methods_supported: ['S256'] });
    const jwks = await fetch(String(discovery.jwks_uri)).then((r) => r.json()) as { keys: Array<Record<string, unknown>> };
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(jwks.keys[0]).not.toHaveProperty('d');
  });

  it('never redirects an invalid redirect_uri', async () => {
    const url = `${idp.url}/authorize?response_type=code&client_id=orders-web&redirect_uri=${encodeURIComponent('http://evil.example')}&scope=openid&state=${'s'.repeat(20)}&nonce=${'n'.repeat(20)}`;
    const response = await fetch(url, { redirect: 'manual' });
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  it('binds IdP login/consent forms to a separate browser cookie and CSRF token', async () => {
    const authorize = new URL(`${idp.url}/authorize`);
    authorize.search = new URLSearchParams({
      response_type: 'code', client_id: 'orders-web', redirect_uri: 'http://127.0.0.1:4001/callback',
      scope: 'openid', state: 'state-value-at-least-16', nonce: 'nonce-value-at-least-16',
      code_challenge: pkceChallenge(HTTP_CODE_VERIFIER), code_challenge_method: 'S256',
    }).toString();
    const page = await fetch(authorize);
    const body = await page.text();
    const form = new URLSearchParams({
      request_id: requestId(body), csrf_token: csrfToken(body),
      username: 'alice', password: 'correct horse battery staple',
    });
    // request_id and hidden token copied by an attacker are not enough: their browser binding differs.
    expect((await fetch(`${idp.url}/login`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form,
    })).status).toBe(400);
    const interaction = cookieValue(page.headers.get('set-cookie'), 'idp_interaction');
    form.set('csrf_token', 'wrong-csrf-token');
    expect((await fetch(`${idp.url}/login`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: interaction }, body: form,
    })).status).toBe(400);
  });

  it('runs browser login + consent + code exchange and uses the access token at the API', async () => {
    const { callback, tokens } = await authorizeViaForms();
    expect(new URL(callback).searchParams.get('state')).toBe('state-value-at-least-16');
    expect(tokens.id_token).toBeTypeOf('string');
    expect(tokens.refresh_token).toBeTypeOf('string');

    const orders = await fetch(`${api.url}/orders`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(orders.status).toBe(200);
    expect(await orders.json()).toMatchObject({ caller: { sub: 'user-alice-0001', client_id: 'orders-web' } });
    const create = await fetch(`${api.url}/orders`, { method: 'POST', headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(create.status).toBe(201);
    const admin = await fetch(`${api.url}/admin`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(admin.status).toBe(200);
  });

  it('API returns 401 for missing/ID tokens and 403 for insufficient scope', async () => {
    expect((await fetch(`${api.url}/orders`)).status).toBe(401);
    const { tokens } = await authorizeViaForms();
    expect((await fetch(`${api.url}/orders`, { headers: { authorization: `Bearer ${tokens.id_token}` } })).status).toBe(401);
    const machine = idp.provider.token(
      { grant_type: 'client_credentials', scope: 'orders:read' },
      { clientId: 'inventory-job', clientSecret: 'inventory-machine-secret-for-local-lab' },
    );
    expect((await fetch(`${api.url}/orders`, { method: 'POST', headers: { authorization: `Bearer ${machine.access_token}` } })).status).toBe(403);
  });

  it('teaches the offline-JWT revocation boundary: IdP sees revoked, independent API accepts until exp', async () => {
    const { tokens } = await authorizeViaForms();
    const auth = `Basic ${Buffer.from('orders-web:orders-web-secret-for-local-lab').toString('base64')}`;
    expect((await fetch(`${idp.url}/revoke`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.access_token }),
    })).status).toBe(200);
    const introspection = await fetch(`${idp.url}/introspect`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.access_token }),
    });
    expect(await introspection.json()).toEqual({ active: false });
    // The API has only cached public keys, not the IdP's private denylist: bounded by 5-minute exp.
    expect((await fetch(`${api.url}/orders`, { headers: { authorization: `Bearer ${tokens.access_token}` } })).status).toBe(200);
  });

  it('userinfo, refresh rotation, introspection, revocation and logout are real endpoints', async () => {
    const { tokens } = await authorizeViaForms();
    const userinfo = await fetch(`${idp.url}/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(await userinfo.json()).toMatchObject({ sub: 'user-alice-0001', email: 'alice@lab.example' });

    const auth = `Basic ${Buffer.from('orders-web:orders-web-secret-for-local-lab').toString('base64')}`;
    const refreshedResponse = await fetch(`${idp.url}/token`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token! }),
    });
    const refreshed = await refreshedResponse.json() as TokenResponse;
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);

    const introspection = await fetch(`${idp.url}/introspect`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: refreshed.refresh_token! }),
    });
    expect(await introspection.json()).toMatchObject({ active: true, token_type: 'refresh_token' });

    expect((await fetch(`${idp.url}/revoke`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: refreshed.refresh_token! }),
    })).status).toBe(200);
    const reused = await fetch(`${idp.url}/token`, {
      method: 'POST', headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshed.refresh_token! }),
    });
    expect(reused.status).toBe(400);
    expect((await fetch(`${idp.url}/logout`)).status).toBe(200);
  });
});

describe('real relying-party HTTP roundtrip', () => {
  let rp: RunningRelyingParty | undefined;
  afterAll(async () => { await rp?.stop(); });

  it('uses distinct loopback hostnames because cookies ignore port boundaries', async () => {
    expect(new URL(idp.url).hostname).toBe('localhost');
    expect(new URL(api.url).hostname).toBe('127.0.0.1');
    expect(new URL(idp.url).hostname).not.toBe(new URL(api.url).hostname);
  });

  it('binds state to a browser transaction, verifies ID token+nonce+at_hash, then creates a local session', async () => {
    const config: RelyingPartyConfig = {
      issuer: idp.url, clientId: 'test-rp', clientSecret: 'test-rp-secret-long-random',
      redirectUri: 'http://127.0.0.1:0/callback', scope: 'openid profile email groups orders:read',
      appName: 'Test RP', resourceApi: api.url,
    };
    rp = await startRelyingParty(config, 0);
    config.redirectUri = `${rp.url}/callback`;
    idp.provider.registerClient({
      clientId: config.clientId, clientType: 'confidential', clientSecret: config.clientSecret,
      name: config.appName, redirectUris: [config.redirectUri],
      allowedScopes: config.scope.split(' '), allowedGrants: ['authorization_code', 'refresh_token'],
    });

    const start = await fetch(`${rp.url}/login`, { redirect: 'manual' });
    const txCookie = cookieValue(start.headers.get('set-cookie'), 'login_tx');
    const authorize = await fetch(start.headers.get('location')!);
    const loginHtml = await authorize.text();
    const id = requestId(loginHtml);
    const csrf = csrfToken(loginHtml);
    const interactionCookie = cookieValue(authorize.headers.get('set-cookie'), 'idp_interaction');
    const login = await fetch(`${idp.url}/login`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: interactionCookie },
      body: new URLSearchParams({ request_id: id, csrf_token: csrf, username: 'alice', password: 'correct horse battery staple' }),
    });
    const idpCookie = cookieValue(login.headers.get('set-cookie'), 'idp_session');
    const consentHtml = await login.text();
    const consent = await fetch(`${idp.url}/consent`, {
      method: 'POST', redirect: 'manual', headers: { cookie: `${idpCookie}; ${interactionCookie}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ request_id: id, csrf_token: csrfToken(consentHtml), decision: 'allow' }),
    });

    const callback = await fetch(consent.headers.get('location')!, { redirect: 'manual', headers: { cookie: txCookie } });
    expect(callback.status).toBe(302);
    const appCookie = cookieValue(callback.headers.get('set-cookie'), 'app_session');
    const home = await fetch(`${rp.url}/`, { headers: { cookie: appCookie } });
    expect(await home.text()).toContain('Alice Example');
    const orders = await fetch(`${rp.url}/orders`, { headers: { cookie: appCookie } });
    expect(orders.status).toBe(200);
  });
});
