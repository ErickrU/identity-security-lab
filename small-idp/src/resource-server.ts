import { createServer, type IncomingMessage, type RequestListener, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { decodeJwt, verifyJwt, type Claims, type Jwks } from './keys';
import { bearerToken, LabIdentityProvider, OAuthError } from './protocol';
import { json } from './http';

export const DEFAULT_API_PORT = 4100;

export interface ResourceServerConfig {
  issuer: string;
  audience: string;
  jwks: Jwks;
  now?: () => number;
  /** Optional callback adds online revocation; omitting it demonstrates normal offline JWT verification. */
  isJtiRevoked?: (jti: string) => boolean;
}

export interface RunningResourceServer {
  server: Server;
  url: string;
  port: number;
  stop(): Promise<void>;
}

export function verifyApiToken(token: string, config: ResourceServerConfig, scopes: string[]): Claims {
  const claims = verifyJwt(token, config.jwks, {
    issuer: config.issuer, audience: config.audience, now: config.now,
  });
  if (decodeJwt(token).header.typ !== 'at+jwt' || claims.token_use !== 'access') {
    throw new OAuthError('invalid_token', 'this API accepts access tokens, not OIDC ID tokens', 401);
  }
  if (typeof claims.jti !== 'string') throw new OAuthError('invalid_token', 'jti is required', 401);
  if (config.isJtiRevoked?.(claims.jti)) throw new OAuthError('invalid_token', 'token is revoked', 401);
  const granted = typeof claims.scope === 'string' ? claims.scope.split(/\s+/) : [];
  const missing = scopes.filter((scope) => !granted.includes(scope));
  if (missing.length) throw new OAuthError('insufficient_scope', `requires ${missing.join(' ')}`, 403);
  return claims;
}

export function createResourceHandler(config: ResourceServerConfig): RequestListener {
  return (req, res) => void handle(req, res, config).catch((error) => sendError(res, error));
}

async function handle(req: IncomingMessage, res: ServerResponse, config: ResourceServerConfig): Promise<void> {
  const url = new URL(req.url ?? '/', config.audience);
  if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, audience: config.audience });

  const token = bearerToken(req.headers.authorization);
  if (!token) throw new OAuthError('invalid_token', 'send Authorization: Bearer <access_token>', 401);

  if (req.method === 'GET' && url.pathname === '/orders') {
    const claims = verifyApiToken(token, config, ['orders:read']);
    return json(res, 200, {
      orders: [{ id: 'order-42', item: 'learning lab', owner: claims.sub }],
      caller: { sub: claims.sub, client_id: claims.client_id, scope: claims.scope },
      verified: 'signature + issuer + audience + expiry + token type + required scope',
    });
  }
  if (req.method === 'POST' && url.pathname === '/orders') {
    const claims = verifyApiToken(token, config, ['orders:write']);
    return json(res, 201, { id: 'order-43', createdBy: claims.sub });
  }
  if (req.method === 'GET' && url.pathname === '/admin') {
    const claims = verifyApiToken(token, config, ['orders:read']);
    const groups = Array.isArray(claims.groups) ? claims.groups.map(String) : [];
    if (!groups.includes('admins')) throw new OAuthError('insufficient_permissions', 'valid token, but caller is not in admins', 403);
    return json(res, 200, { message: `admin area for ${String(claims.sub)}` });
  }
  json(res, 404, { error: 'not_found', routes: ['GET /orders', 'POST /orders', 'GET /admin'] });
}

function sendError(res: ServerResponse, error: unknown): void {
  if (error instanceof OAuthError) {
    return json(res, error.status, error.toJSON(), {
      'www-authenticate': `Bearer error="${error.error}", error_description="${error.error_description}"`,
    });
  }
  json(res, 401, { error: 'invalid_token', error_description: error instanceof Error ? error.message : String(error) }, {
    'www-authenticate': 'Bearer error="invalid_token"',
  });
}

export async function startResourceServer(config: ResourceServerConfig, port = DEFAULT_API_PORT, host = '127.0.0.1'): Promise<RunningResourceServer> {
  const server = createServer(createResourceHandler(config));
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const boundPort = (server.address() as AddressInfo).port;
  return {
    server, port: boundPort, url: `http://${host}:${boundPort}`,
    stop: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections(); server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

async function main(): Promise<void> {
  const issuer = (process.env.IDP_URL ?? 'http://localhost:4000').replace(/\/$/, '');
  const discovery = await fetch(`${issuer}/.well-known/openid-configuration`).then((r) => r.json()) as { issuer: string; jwks_uri: string };
  const jwks = await fetch(discovery.jwks_uri).then((r) => r.json()) as Jwks;
  const audience = process.env.API_AUDIENCE ?? `http://127.0.0.1:${process.env.PORT ?? DEFAULT_API_PORT}`;
  const running = await startResourceServer({ issuer: discovery.issuer, audience, jwks }, Number(process.env.PORT ?? DEFAULT_API_PORT));
  console.log(`OAuth resource server: ${running.url}`);
  console.log(`  trusts issuer ${discovery.issuer}`);
  console.log(`  audience      ${audience}`);
  console.log('  routes        GET/POST /orders, GET /admin');
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((error) => { console.error(error); process.exit(1); });
}

/** Convenient same-process config for tests/demos. */
export function configFromProvider(provider: LabIdentityProvider): ResourceServerConfig {
  return { issuer: provider.issuer, audience: provider.resourceAudience, jwks: provider.jwks };
}
