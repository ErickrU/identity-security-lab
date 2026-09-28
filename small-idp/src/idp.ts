import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type RequestListener, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { bearerToken, LabIdentityProvider, OAuthError, parseBasicClientAuthorization, type PendingAuthorization, type TokenRequest } from './protocol';
import { cookies, escapeHtml, formObject, html, json, readForm, redirect } from './http';

export const IDP_SESSION_COOKIE = 'idp_session';
export const IDP_INTERACTION_COOKIE = 'idp_interaction';
export const IDP_LOGOUT_CSRF_COOKIE = 'idp_logout_csrf';
export const DEFAULT_IDP_PORT = 4000;
const INTERACTION_LIFETIME_MS = 5 * 60 * 1000;
const MAX_BROWSER_INTERACTIONS = 10_000;

interface BrowserInteraction {
  browserId: string;
  csrfToken: string;
  expiresAt: number;
}

export interface RunningIdp {
  provider: LabIdentityProvider;
  server: Server;
  url: string;
  port: number;
  stop(): Promise<void>;
}

export function createIdpHandler(provider: LabIdentityProvider): RequestListener {
  // IdP forms need their own browser binding and CSRF secret. OAuth `state` belongs to the
  // client callback; it does not protect the authorization server's login/consent forms.
  const interactions = new Map<string, BrowserInteraction>();
  return (req, res) => void handle(req, res, provider, interactions).catch((error) => sendError(res, error));
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  provider: LabIdentityProvider,
  interactions: Map<string, BrowserInteraction>,
): Promise<void> {
  const url = new URL(req.url ?? '/', provider.issuer);

  if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    return json(res, 200, {
      issuer: provider.issuer,
      authorization_endpoint: `${provider.issuer}/authorize`,
      token_endpoint: `${provider.issuer}/token`,
      userinfo_endpoint: `${provider.issuer}/userinfo`,
      jwks_uri: `${provider.issuer}/jwks.json`,
      revocation_endpoint: `${provider.issuer}/revoke`,
      introspection_endpoint: `${provider.issuer}/introspect`,
      end_session_endpoint: `${provider.issuer}/logout`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['openid', 'profile', 'email', 'groups', 'orders:read', 'orders:write', 'inventory:read'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified', 'groups'],
    });
  }
  if (req.method === 'GET' && url.pathname === '/jwks.json') return json(res, 200, provider.jwks);
  if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, issuer: provider.issuer });

  if (req.method === 'GET' && url.pathname === '/authorize') {
    const now = Date.now();
    for (const [id, item] of interactions) if (item.expiresAt <= now) interactions.delete(id);
    if (interactions.size >= MAX_BROWSER_INTERACTIONS) {
      throw new OAuthError('temporarily_unavailable', 'too many active browser interactions; retry later', 503);
    }
    const pending = provider.beginAuthorization(formObject(url.searchParams));
    const interaction: BrowserInteraction = {
      browserId: randomToken(), csrfToken: randomToken(), expiresAt: Date.now() + INTERACTION_LIFETIME_MS,
    };
    interactions.set(pending.requestId, interaction);
    const interactionCookie = `${IDP_INTERACTION_COOKIE}=${interaction.browserId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300`;
    const user = provider.sessionUser(cookies(req)[IDP_SESSION_COOKIE]);
    return user
      ? html(res, 200, consentPage(pending, user.username, interaction.csrfToken), { 'set-cookie': interactionCookie })
      : html(res, 200, loginPage(pending, interaction.csrfToken), { 'set-cookie': interactionCookie });
  }

  if (req.method === 'POST' && url.pathname === '/login') {
    const form = await readForm(req);
    const requestId = form.get('request_id') ?? '';
    const interaction = requireInteraction(req, form, requestId, interactions);
    try {
      const sessionId = await provider.login(requestId, form.get('username') ?? '', form.get('password') ?? '');
      const pending = provider.getPending(requestId);
      const username = provider.sessionUser(sessionId)?.username ?? '';
      const secure = provider.issuer.startsWith('https:') ? '; Secure' : '';
      return html(res, 200, consentPage(pending, username, interaction.csrfToken), {
        'set-cookie': `${IDP_SESSION_COOKIE}=${encodeURIComponent(sessionId)}; HttpOnly; SameSite=Lax; Path=/${secure}`,
      });
    } catch (error) {
      const pending = provider.getPending(requestId);
      return html(res, 401, loginPage(pending, interaction.csrfToken, 'Invalid username or password. The response is intentionally generic.'));
    }
  }

  if (req.method === 'POST' && url.pathname === '/consent') {
    const form = await readForm(req);
    const requestId = form.get('request_id') ?? '';
    requireInteraction(req, form, requestId, interactions);
    interactions.delete(requestId);
    const location = provider.consent(
      requestId,
      cookies(req)[IDP_SESSION_COOKIE],
      form.get('decision') === 'allow',
    );
    return redirect(res, location, {
      'set-cookie': `${IDP_INTERACTION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
    });
  }

  if (req.method === 'POST' && url.pathname === '/token') {
    const form = await readForm(req);
    const basic = parseBasicClientAuthorization(req.headers.authorization);
    const credentials = basic ?? { clientId: form.get('client_id') ?? '', clientSecret: form.get('client_secret') ?? undefined };
    const grant = form.get('grant_type');
    let request: TokenRequest;
    if (grant === 'authorization_code') {
      request = {
        grant_type: grant, code: form.get('code') ?? '', redirect_uri: form.get('redirect_uri') ?? '',
        code_verifier: form.get('code_verifier') ?? undefined, client_id: form.get('client_id') ?? undefined,
      };
    } else if (grant === 'refresh_token') {
      request = {
        grant_type: grant, refresh_token: form.get('refresh_token') ?? '', scope: form.get('scope') ?? undefined,
        client_id: form.get('client_id') ?? undefined,
      };
    } else if (grant === 'client_credentials') {
      request = { grant_type: grant, scope: form.get('scope') ?? undefined, client_id: form.get('client_id') ?? undefined };
    } else {
      throw new OAuthError('unsupported_grant_type', 'supported grants: authorization_code, refresh_token, client_credentials');
    }
    return json(res, 200, provider.token(request, credentials));
  }

  if ((req.method === 'GET' || req.method === 'POST') && url.pathname === '/userinfo') {
    const token = bearerToken(req.headers.authorization);
    if (!token) throw new OAuthError('invalid_token', 'Bearer access token required', 401);
    return json(res, 200, provider.userInfo(token));
  }

  if (req.method === 'POST' && (url.pathname === '/revoke' || url.pathname === '/introspect')) {
    const form = await readForm(req);
    const basic = parseBasicClientAuthorization(req.headers.authorization);
    const credentials = basic ?? { clientId: form.get('client_id') ?? '', clientSecret: form.get('client_secret') ?? undefined };
    const token = form.get('token') ?? '';
    if (url.pathname === '/revoke') {
      provider.revoke(token, credentials);
      return json(res, 200, {});
    }
    return json(res, 200, provider.introspect(token, credentials));
  }

  if (req.method === 'GET' && url.pathname === '/logout') {
    const csrf = randomToken();
    return html(res, 200, page('Confirm IdP sign-out', `
      <p>This ends the IdP SSO session. Existing local application sessions are separate.</p>
      <form method="post" action="/logout">
        <input type="hidden" name="csrf_token" value="${csrf}">
        <button>Sign out of the IdP</button>
      </form>`), {
      'set-cookie': `${IDP_LOGOUT_CSRF_COOKIE}=${csrf}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300`,
    });
  }

  if (req.method === 'POST' && url.pathname === '/logout') {
    const form = await readForm(req);
    const expected = cookies(req)[IDP_LOGOUT_CSRF_COOKIE];
    const presented = form.get('csrf_token');
    if (!expected || !presented || !safeEqual(expected, presented)) {
      throw new OAuthError('invalid_request', 'logout requires the confirmation form from this browser');
    }
    provider.destroySession(cookies(req)[IDP_SESSION_COOKIE]);
    return html(res, 200, page('Signed out', '<p>The IdP session is gone. Local application sessions are separate.</p>'), {
      'set-cookie': [
        `${IDP_SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
        `${IDP_LOGOUT_CSRF_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
      ],
    });
  }

  json(res, 404, { error: 'not_found', endpoints: ['/.well-known/openid-configuration', '/jwks.json', '/authorize', '/token', '/userinfo', '/revoke', '/introspect', '/logout'] });
}

function loginPage(request: PendingAuthorization, csrfToken: string, error = ''): string {
  return page('Small IdP — sign in', `
    <p><strong>${escapeHtml(request.clientName)}</strong> asks this IdP to authenticate you.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    <form method="post" action="/login">
      <input type="hidden" name="request_id" value="${escapeHtml(request.requestId)}">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <label>Username <input name="username" value="alice" autocomplete="username"></label>
      <label>Password <input name="password" type="password" value="correct horse battery staple" autocomplete="current-password"></label>
      <button>Sign in</button>
    </form>
    <p class="note">Lab accounts: alice or bob; password shown in the field. Real IdPs never prefill passwords.</p>`);
}

function consentPage(request: PendingAuthorization, username: string, csrfToken: string): string {
  return page('Small IdP — consent', `
    <p>Signed in at the IdP as <strong>${escapeHtml(username)}</strong>.</p>
    <p><strong>${escapeHtml(request.clientName)}</strong> requests:</p>
    <ul>${request.scopes.map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`).join('')}</ul>
    <form method="post" action="/consent">
      <input type="hidden" name="request_id" value="${escapeHtml(request.requestId)}">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
      <button name="decision" value="allow">Allow</button>
      <button name="decision" value="deny">Deny</button>
    </form>
    <p class="note">Authentication (who you are) already happened. This screen is authorization delegation: may this client receive these scopes?</p>`);
}

function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>
    body{font:16px system-ui;max-width:680px;margin:3rem auto;padding:0 1rem;line-height:1.5}label{display:block;margin:1rem 0}
    input{display:block;width:100%;padding:.5rem}button{padding:.6rem 1rem;margin-right:.5rem}.error{color:#a00}.note{color:#555}code{background:#eee;padding:.15rem .3rem}
  </style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

function requireInteraction(
  req: IncomingMessage,
  form: URLSearchParams,
  requestId: string,
  interactions: Map<string, BrowserInteraction>,
): BrowserInteraction {
  const interaction = interactions.get(requestId);
  const browserId = cookies(req)[IDP_INTERACTION_COOKIE];
  const csrf = form.get('csrf_token');
  if (
    !interaction || interaction.expiresAt <= Date.now() || !browserId || !csrf ||
    !safeEqual(interaction.browserId, browserId) || !safeEqual(interaction.csrfToken, csrf)
  ) {
    if (interaction?.expiresAt && interaction.expiresAt <= Date.now()) interactions.delete(requestId);
    throw new OAuthError('invalid_request', 'login/consent form is not bound to this browser interaction');
  }
  return interaction;
}

function randomToken(): string { return randomBytes(32).toString('base64url'); }
function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left); const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function sendError(res: ServerResponse, error: unknown): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  if (error instanceof OAuthError) {
    const headers: Record<string, string> = {};
    if (error.status === 401) headers['www-authenticate'] = `Bearer error="${error.error}"`;
    return json(res, error.status, error.toJSON(), headers);
  }
  console.error(error);
  json(res, 500, { error: 'server_error', error_description: 'unexpected local IdP error' });
}

export async function startIdp(port = DEFAULT_IDP_PORT, host = 'localhost', provider?: LabIdentityProvider): Promise<RunningIdp> {
  let activeProvider = provider;
  let activeHandler = provider ? createIdpHandler(provider) : undefined;
  const server = createServer((req, res) => {
    if (!activeHandler) return json(res, 503, { error: 'initializing' });
    activeHandler(req, res);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const boundPort = (server.address() as AddressInfo).port;
  activeProvider ??= await LabIdentityProvider.withDefaults({ issuer: `http://${host}:${boundPort}` });
  activeHandler ??= createIdpHandler(activeProvider);
  return {
    provider: activeProvider, server, port: boundPort, url: activeProvider.issuer,
    stop: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function main(): Promise<void> {
  const running = await startIdp(Number(process.env.PORT ?? DEFAULT_IDP_PORT));
  console.log(`Small OAuth 2.0 / OpenID Connect provider: ${running.url}`);
  console.log(`  discovery  ${running.url}/.well-known/openid-configuration`);
  console.log(`  JWKS       ${running.url}/jwks.json`);
  console.log('  users      alice / bob — password: correct horse battery staple');
  console.log('  next       npm run rp   (or npm run api)');
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
