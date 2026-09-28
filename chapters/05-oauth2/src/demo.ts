import { randomBytes } from 'node:crypto';
import { decodeJwt, generateSigningKey } from '../../../small-idp/src/keys';
import {
  createPkcePair,
  LabIdentityProvider,
  OAuthError,
  type AuthorizationParameters,
  type PendingAuthorization,
  type TokenResponse,
} from '../../../small-idp/src/protocol';

const NOW_MS = Date.UTC(2026, 8, 28, 12, 0, 0);
const REDIRECT = 'https://printer.example/callback';
const PUBLIC_CLIENT = 'photo-printer';

function heading(title: string): void { console.log(`\n${title}\n${'─'.repeat(title.length)}`); }
function abbreviated(value: string): string { return `${value.slice(0, 8)}…${value.slice(-4)} (${value.length} chars)`; }
function reject(label: string, action: () => unknown): void {
  try { action(); console.log(`  ✗ ${label}: unexpectedly accepted`); process.exitCode = 1; }
  catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`  ✓ ${label}\n    → rejected: ${message}`);
  }
}

async function provider(): Promise<LabIdentityProvider> {
  const idp = new LabIdentityProvider({
    issuer: 'https://authorization.lab.example', resourceAudience: 'https://photos-api.lab.example',
    now: () => NOW_MS, signingKey: generateSigningKey('oauth-lab-2026'),
  });
  await idp.registerUser({
    sub: 'alice-001', username: 'alice', password: 'correct horse battery staple',
    name: 'Alice', email: 'alice@lab.example', groups: ['customers'],
  });
  idp.registerClient({
    clientId: PUBLIC_CLIENT, clientType: 'public', name: 'Photo Printer', redirectUris: [REDIRECT],
    allowedScopes: ['photos:read', 'photos:print'], allowedGrants: ['authorization_code', 'refresh_token'],
  });
  idp.registerClient({
    clientId: 'thumbnail-worker', clientType: 'confidential', clientSecret: 'machine-secret-generated-not-human',
    name: 'Thumbnail Worker', redirectUris: [], allowedScopes: ['photos:read'], allowedGrants: ['client_credentials'],
  });
  return idp;
}

function request(pkce: ReturnType<typeof createPkcePair>, overrides: Partial<AuthorizationParameters> = {}): AuthorizationParameters {
  return {
    response_type: 'code', client_id: PUBLIC_CLIENT, redirect_uri: REDIRECT,
    scope: 'photos:read photos:print', state: randomBytes(24).toString('base64url'),
    code_challenge: pkce.challenge, code_challenge_method: 'S256', ...overrides,
  };
}

function approve(idp: LabIdentityProvider, pending: PendingAuthorization, session: string, expectedClientState: string): string {
  const callback = new URL(idp.consent(pending.requestId, session, true));
  if (callback.searchParams.get('state') !== expectedClientState) throw new Error('client rejected state mismatch');
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('no code');
  return code;
}

function exchange(idp: LabIdentityProvider, code: string, verifier: string): TokenResponse {
  return idp.token(
    { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier, client_id: PUBLIC_CLIENT },
    { clientId: PUBLIC_CLIENT },
  );
}

async function main(): Promise<void> {
  const idp = await provider();

  heading('1. Authorization Code + PKCE: delegate, do not share a password');
  const pkce = createPkcePair();
  const clientState = randomBytes(24).toString('base64url');
  const pending = idp.beginAuthorization(request(pkce, { state: clientState }));
  console.log('  Photo Printer (client) sends alice (resource owner) to the authorization server:');
  console.log(`    client_id=${pending.clientId}`);
  console.log(`    redirect_uri=${pending.redirectUri}  (exact registration match)`);
  console.log(`    scope=${pending.scopes.join(' ')}  (requested delegation)`);
  console.log(`    state=${abbreviated(pending.state)}  (binds this browser transaction)`);
  console.log(`    code_challenge=${abbreviated(pending.codeChallenge!)} method=S256`);
  console.log('    The code_verifier stays in the client. Alice\'s password goes only to the authorization server.');

  const idpSession = await idp.login(pending.requestId, 'alice', 'correct horse battery staple');
  const code = approve(idp, pending, idpSession, clientState);
  console.log(`  Alice authenticates and consents. Browser returns one-use code=${abbreviated(code)} + state.`);
  const tokens = exchange(idp, code, pkce.verifier);
  console.log(`  Client exchanges code + verifier. Access token=${abbreviated(tokens.access_token)}.`);
  console.log(`  ID token present? ${Boolean(tokens.id_token)} (no: pure OAuth request omitted scope=openid)`);
  const access = decodeJwt(tokens.access_token).payload;
  console.log(`  Access claims: aud=${String(access.aud)}, sub=${String(access.sub)}, client_id=${String(access.client_id)}, scope=${String(access.scope)}`);
  console.log(`  Resource server check photos:read → ${String(idp.verifyAccessToken(tokens.access_token, ['photos:read']).sub)} allowed.`);

  heading('2. OAuth is delegated authorization, not login');
  console.log('  Resource owner      alice, who owns the photos');
  console.log('  Client              Photo Printer, which wants limited access');
  console.log('  Authorization server the IdP, which authenticates/asks consent/issues tokens');
  console.log('  Resource server     Photos API, which checks token audience + scope');
  console.log('  The access token answers “may this client call photos:read?” It is not a standard login assertion.');
  console.log('  Add scope=openid and verify the returned ID token when the client needs login: that is OIDC (chapter 06).');

  heading('3. Attacks become specific validation rules');
  reject('unregistered redirect URI', () => idp.beginAuthorization(request(createPkcePair(), {
    redirect_uri: 'https://printer.example.attacker.test/callback',
  })));
  console.log('    The authorization server does not redirect this error, so no code can reach the attacker.');

  const interceptedPkce = createPkcePair();
  const interceptedState = randomBytes(24).toString('base64url');
  const interceptedPending = idp.beginAuthorization(request(interceptedPkce, { state: interceptedState }));
  const interceptedCode = approve(idp, interceptedPending, idpSession, interceptedState);
  reject('stolen code with wrong PKCE verifier', () => exchange(idp, interceptedCode, 'x'.repeat(43)));
  reject('same code retried with correct verifier', () => exchange(idp, interceptedCode, interceptedPkce.verifier));
  console.log('    First redemption attempt consumes the code. PKCE turns code interception into useless bytes.');

  reject('authorization code replay', () => exchange(idp, code, pkce.verifier));

  const readOnlyPkce = createPkcePair();
  const readOnlyState = randomBytes(24).toString('base64url');
  const readOnlyPending = idp.beginAuthorization(request(readOnlyPkce, { scope: 'photos:read', state: readOnlyState }));
  const readOnly = exchange(idp, approve(idp, readOnlyPending, idpSession, readOnlyState), readOnlyPkce.verifier);
  reject('read-only token used for photos:print', () => idp.verifyAccessToken(readOnly.access_token, ['photos:print']));
  console.log('    Valid token + missing permission is 403 insufficient_scope, not failed authentication.');

  heading('4. Refresh tokens: renew, rotate, narrow');
  const oldRefresh = readOnly.refresh_token!;
  const refreshed = idp.token(
    { grant_type: 'refresh_token', refresh_token: oldRefresh, scope: 'photos:read', client_id: PUBLIC_CLIENT },
    { clientId: PUBLIC_CLIENT },
  );
  console.log(`  old=${abbreviated(oldRefresh)} → new=${abbreviated(refreshed.refresh_token!)}`);
  reject('new refresh token tries to expand scope (it is not consumed by this invalid request)', () => idp.token(
    { grant_type: 'refresh_token', refresh_token: refreshed.refresh_token!, scope: 'photos:read photos:delete', client_id: PUBLIC_CLIENT },
    { clientId: PUBLIC_CLIENT },
  ));
  reject('old refresh token reused (the whole family is now revoked)', () => idp.token(
    { grant_type: 'refresh_token', refresh_token: oldRefresh, client_id: PUBLIC_CLIENT }, { clientId: PUBLIC_CLIENT },
  ));
  reject('the newest descendant after family reuse detection', () => idp.token(
    { grant_type: 'refresh_token', refresh_token: refreshed.refresh_token!, client_id: PUBLIC_CLIENT }, { clientId: PUBLIC_CLIENT },
  ));
  console.log('  A refresh credential is long-lived authority: store server-side, rotate on every use, revoke family on reuse.');

  heading('5. Client Credentials: a machine, no user');
  const machine = idp.token(
    { grant_type: 'client_credentials', scope: 'photos:read' },
    { clientId: 'thumbnail-worker', clientSecret: 'machine-secret-generated-not-human' },
  );
  const machineClaims = decodeJwt(machine.access_token).payload;
  console.log(`  sub=${String(machineClaims.sub)} client_id=${String(machineClaims.client_id)} scope=${String(machineClaims.scope)}`);
  console.log(`  ID token? ${Boolean(machine.id_token)}  refresh token? ${Boolean(machine.refresh_token)}`);
  console.log('  No human authenticated. A machine token must never pretend to be alice. Workload roles/mTLS are alternatives.');

  heading('6. Introspection, revocation, and bearer theft');
  const clientCredentials = { clientId: 'thumbnail-worker', clientSecret: 'machine-secret-generated-not-human' };
  console.log(`  introspection before revoke → active=${String(idp.introspect(machine.access_token, clientCredentials).active)}`);
  idp.revoke(machine.access_token, clientCredentials);
  console.log(`  introspection after revoke  → active=${String(idp.introspect(machine.access_token, clientCredentials).active)}`);
  console.log('  This lab adds an online jti denylist. Normal self-contained JWT APIs trade instant revocation for offline verification.');
  console.log('  Bearer means whoever steals the bytes can use them. TLS protects transit; mTLS/DPoP binds tokens to a client key.');

  heading('7. What to remember');
  console.log('  OAuth delegates scoped API access. It does not standardize “who logged in”; OIDC adds that.');
  console.log('  Code + exact redirect + state + PKCE; short access token; rotating refresh token; scope at the API.');
  console.log('  Public clients have no secret. Client Credentials represents a workload, never a user.');
  console.log(process.exitCode ? '  Demo found an unexpected acceptance.' : '  Done. Every valid grant passed; every interception, replay and scope expansion failed.');
}

main().catch((error) => { console.error(error instanceof OAuthError ? error.toJSON() : error); process.exitCode = 1; });
