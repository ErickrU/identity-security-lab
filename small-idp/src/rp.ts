import { randomBytes } from 'node:crypto';
import { createServer, type RequestListener, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { beginLogin, finishLogin, type LoginTransaction, type OidcClientConfig } from './client';
import { cookies, escapeHtml, html, json, redirect } from './http';
import type { TokenResponse } from './protocol';

export const DEFAULT_RP_PORT = 4001;
const APP_SESSION_COOKIE = 'app_session';
const LOGIN_TX_COOKIE = 'login_tx';

interface LocalSession {
  sub: string;
  name: string;
  tokens: TokenResponse;
  expiresAt: number;
}

export interface RelyingPartyConfig extends OidcClientConfig {
  appName: string;
  resourceApi: string;
}

export interface RunningRelyingParty {
  server: Server;
  url: string;
  port: number;
  sessions: Map<string, LocalSession>;
  stop(): Promise<void>;
}

/**
 * A backend-for-frontend OIDC relying party. OAuth tokens stay server-side;
 * the browser gets only a local HttpOnly session cookie.
 */
export function createRelyingPartyHandler(config: RelyingPartyConfig): {
  handler: RequestListener;
  sessions: Map<string, LocalSession>;
} {
  const transactions = new Map<string, LoginTransaction>();
  const sessions = new Map<string, LocalSession>();

  const handler: RequestListener = (req, res) => void (async () => {
    const url = new URL(req.url ?? '/', config.redirectUri);
    const jar = cookies(req);
    const session = jar[APP_SESSION_COOKIE] ? sessions.get(jar[APP_SESSION_COOKIE]) : undefined;

    if (req.method === 'GET' && url.pathname === '/') {
      if (!session || session.expiresAt <= Date.now()) {
        return html(res, 200, page(config.appName, `<p>No local session.</p><p><a href="/login">Sign in through the small IdP</a></p>`));
      }
      return html(res, 200, page(config.appName, `
        <p>Local app session for <strong>${escapeHtml(session.name)}</strong> (<code>${escapeHtml(session.sub)}</code>).</p>
        <p>The browser has only an HttpOnly <code>${APP_SESSION_COOKIE}</code>. Access/refresh/ID tokens stay in this backend.</p>
        <ul><li><a href="/orders">Call the resource API with the access token</a></li>
        <li><a href="/logout">Local logout (IdP SSO session remains)</a></li>
        <li><a href="/federated-logout">Local + IdP logout</a></li></ul>`));
    }

    if (req.method === 'GET' && url.pathname === '/login') {
      const tx = await beginLogin(config);
      const txId = randomBytes(32).toString('base64url');
      transactions.set(txId, tx);
      return redirect(res, tx.authorizationUrl, {
        'set-cookie': `${LOGIN_TX_COOKIE}=${txId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300`,
      });
    }

    if (req.method === 'GET' && url.pathname === '/callback') {
      const txId = jar[LOGIN_TX_COOKIE];
      const tx = txId ? transactions.get(txId) : undefined;
      if (!tx) return json(res, 400, { error: 'missing_login_transaction', reason: 'state must be bound to this browser session' });
      transactions.delete(txId);
      const login = await finishLogin(config, tx, url.toString());
      const appSessionId = randomBytes(32).toString('base64url');
      sessions.set(appSessionId, {
        sub: String(login.claims.sub), name: String(login.claims.name ?? login.claims.sub),
        tokens: login.tokens, expiresAt: Date.now() + 8 * 60 * 60 * 1000,
      });
      return redirect(res, '/', {
        'set-cookie': [
          `${APP_SESSION_COOKIE}=${appSessionId}; HttpOnly; SameSite=Lax; Path=/`,
          `${LOGIN_TX_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`,
        ],
      });
    }

    if (req.method === 'GET' && url.pathname === '/orders') {
      if (!session) return redirect(res, '/login');
      const api = await fetch(`${config.resourceApi}/orders`, {
        headers: { authorization: `Bearer ${session.tokens.access_token}` },
      });
      const body = await api.text();
      res.writeHead(api.status, { 'content-type': api.headers.get('content-type') ?? 'application/json' });
      return res.end(body);
    }

    if (req.method === 'GET' && (url.pathname === '/logout' || url.pathname === '/federated-logout')) {
      if (jar[APP_SESSION_COOKIE]) sessions.delete(jar[APP_SESSION_COOKIE]);
      const clear = `${APP_SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
      if (url.pathname === '/federated-logout') return redirect(res, `${config.issuer}/logout`, { 'set-cookie': clear });
      return html(res, 200, page('Local logout', '<p>This app session is gone. The IdP session remains, so another authorization request signs in without a password.</p><p><a href="/login">Sign in again</a></p>'), { 'set-cookie': clear });
    }

    return json(res, 404, { error: 'not_found', routes: ['/', '/login', '/callback', '/orders', '/logout', '/federated-logout'] });
  })().catch((error) => {
    console.error(error);
    if (!res.headersSent) json(res, 400, { error: 'login_failed', error_description: error instanceof Error ? error.message : String(error) });
  });

  return { handler, sessions };
}

function page(title: string, body: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(title)}</title><style>body{font:16px system-ui;max-width:760px;margin:3rem auto;line-height:1.5}code{background:#eee;padding:.15rem .3rem}</style></head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
}

export async function startRelyingParty(config: RelyingPartyConfig, port = DEFAULT_RP_PORT, host = '127.0.0.1'): Promise<RunningRelyingParty> {
  const { handler, sessions } = createRelyingPartyHandler(config);
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const boundPort = (server.address() as AddressInfo).port;
  return {
    server, sessions, port: boundPort, url: `http://${host}:${boundPort}`,
    stop: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections(); server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

export function ordersRpConfig(issuer = 'http://localhost:4000', port = 4001, api = 'http://127.0.0.1:4100'): RelyingPartyConfig {
  return {
    issuer, clientId: 'orders-web', clientSecret: 'orders-web-secret-for-local-lab',
    redirectUri: `http://127.0.0.1:${port}/callback`,
    scope: 'openid profile email groups orders:read orders:write',
    appName: 'Orders relying party', resourceApi: api,
  };
}

export function reportsRpConfig(issuer = 'http://localhost:4000', port = 4002, api = 'http://127.0.0.1:4100'): RelyingPartyConfig {
  return {
    issuer, clientId: 'reports-web', clientSecret: 'reports-web-secret-for-local-lab',
    redirectUri: `http://127.0.0.1:${port}/callback`,
    scope: 'openid profile email groups orders:read',
    appName: 'Reports relying party', resourceApi: api,
  };
}

async function main(): Promise<void> {
  const port = Number(process.env.PORT ?? DEFAULT_RP_PORT);
  const config = ordersRpConfig(process.env.IDP_URL, port, process.env.API_URL);
  const running = await startRelyingParty(config, port);
  console.log(`OIDC relying party: ${running.url}`);
  console.log(`  IdP: ${config.issuer}`);
  console.log(`  open ${running.url}/`);
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}
