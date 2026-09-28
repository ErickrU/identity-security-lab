import {
  createPkcePair,
  LabIdentityProvider,
  OAuthError,
  type PendingAuthorization,
  type TokenResponse,
} from '../../../small-idp/src/protocol';
import {
  decodeJwt,
  generateSigningKey,
  jwksFor,
  signJwt,
  verifyJwt,
  type Claims,
  type SigningKey,
} from '../../../small-idp/src/keys';
import { FederationBroker, FederationError } from './federation';

const NOW_MS = Date.UTC(2026, 0, 15, 12, 0, 0);
const NOW_SEC = Math.floor(NOW_MS / 1000);
const IDP_ISSUER = 'https://login.lab.example';
const PARTNER_ISSUER = 'https://id.partner.example';
const SUPPLIER_ISSUER = 'https://id.supplier.example';
const ATTACKER_ISSUER = 'https://login.attacker.example';

interface AppClient {
  label: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

const APP_A: AppClient = {
  label: 'App A (Orders)',
  clientId: 'orders-web',
  clientSecret: 'orders-web-secret-for-local-lab',
  redirectUri: 'http://127.0.0.1:4001/callback',
};
const APP_B: AppClient = {
  label: 'App B (Reports)',
  clientId: 'reports-web',
  clientSecret: 'reports-web-secret-for-local-lab',
  redirectUri: 'http://127.0.0.1:4002/callback',
};
/** In a real RP this one-use verifier lives in its server-side login-transaction store. */
const pkceVerifiers = new Map<string, string>();

async function main(): Promise<void> {
  console.log('=== SSO and federation are different controls ===');
  console.log('SSO asks: how many authentication prompts does the user see?');
  console.log('Federation asks: which security domain vouches for the identity?\n');

  await demonstrateSso();
  demonstrateFederation();

  console.log('\nTakeaway: SSO reuses an IdP login; federation verifies another issuer and re-issues local credentials.');
}

async function demonstrateSso(): Promise<void> {
  console.log('--- Part 1: one IdP login, two independent app sessions ---');
  const idp = await LabIdentityProvider.withDefaults({
    issuer: IDP_ISSUER,
    resourceAudience: 'https://api.lab.example',
    now: () => NOW_MS,
    signingKey: generateSigningKey('workforce-idp-2026'),
  });

  let passwordPrompts = 0;
  const localSessions = new Map<string, string>();

  const requestA = beginAuthorization(idp, APP_A, 'state-app-a-000000000001', 'nonce-app-a-000000000001');
  passwordPrompts += 1;
  console.log(`1. ${APP_A.label} redirects to the IdP. The user enters a password (prompt ${passwordPrompts}).`);
  const idpSession = await idp.login(requestA.requestId, 'alice', 'correct horse battery staple');
  const tokensA = finishAuthorization(idp, requestA, idpSession, APP_A);
  const claimsA = verifyIdToken(tokensA, idp, APP_A, 'nonce-app-a-000000000001');
  localSessions.set(APP_A.clientId, `local:${String(claimsA.sub)}:app-a`);
  console.log('   IdP session created; App A creates its own local session.');

  const requestB = beginAuthorization(idp, APP_B, 'state-app-b-000000000001', 'nonce-app-b-000000000001');
  const userAtIdp = idp.sessionUser(idpSession);
  if (!userAtIdp) throw new Error('expected the browser IdP session to be valid');
  console.log(`2. ${APP_B.label} redirects to the same IdP. Its own domain cannot read the IdP cookie.`);
  console.log(`   The browser sends the IdP cookie to the IdP; it already represents ${userAtIdp.username}, so no password prompt.`);
  const tokensB = finishAuthorization(idp, requestB, idpSession, APP_B);
  const claimsB = verifyIdToken(tokensB, idp, APP_B, 'nonce-app-b-000000000001');
  localSessions.set(APP_B.clientId, `local:${String(claimsB.sub)}:app-b`);
  console.log(`   App B creates a different local session. Password prompts so far: ${passwordPrompts}.`);
  console.log(`   App-local sessions: A=${localSessions.has(APP_A.clientId)}, B=${localSessions.has(APP_B.clientId)}.`);

  console.log('3. Local logout at App A deletes only App A\'s session.');
  localSessions.delete(APP_A.clientId);
  console.log(`   A=${localSessions.has(APP_A.clientId)}, B=${localSessions.has(APP_B.clientId)}, IdP=${Boolean(idp.sessionUser(idpSession))}.`);

  console.log('4. App A redirects again while the IdP session still exists; it signs in silently and creates a new local session.');
  const requestAReturn = beginAuthorization(idp, APP_A, 'state-app-a-000000000002', 'nonce-app-a-000000000002');
  const returnedTokens = finishAuthorization(idp, requestAReturn, idpSession, APP_A);
  const returnedClaims = verifyIdToken(returnedTokens, idp, APP_A, 'nonce-app-a-000000000002');
  localSessions.set(APP_A.clientId, `local:${String(returnedClaims.sub)}:app-a-return`);
  console.log(`   Password prompts remain ${passwordPrompts}.`);

  console.log('5. IdP logout deletes the IdP session, not sessions already held by either app.');
  idp.destroySession(idpSession);
  console.log(`   A=${localSessions.has(APP_A.clientId)}, B=${localSessions.has(APP_B.clientId)}, IdP=${Boolean(idp.sessionUser(idpSession))}.`);

  const silentRequest = beginAuthorization(idp, APP_B, 'state-app-b-000000000002', 'nonce-app-b-000000000002');
  try {
    idp.consent(silentRequest.requestId, idpSession, true);
    throw new Error('expected silent login to fail after IdP logout');
  } catch (error) {
    if (!(error instanceof OAuthError) || error.error !== 'login_required') throw error;
    console.log('   → New silent login rejected: the IdP session is gone, so authentication is required.');
  }
  console.log('   Existing A/B sessions still work until each app logs out or its session expires. This is why SLO is hard.');
  localSessions.clear();
  console.log('   Both apps now perform local logout.\n');
}

function demonstrateFederation(): void {
  console.log('--- Part 2: verify upstream, map claims, re-issue locally ---');
  const partnerKey = generateSigningKey('partner-2026');
  const supplierKey = generateSigningKey('supplier-2026');
  const attackerKey = generateSigningKey('attacker-2026');
  const broker = new FederationBroker({
    issuer: 'https://broker.lab.example',
    signingKey: generateSigningKey('broker-2026'),
    now: () => NOW_MS,
    trustedUpstreams: [
      {
        issuer: PARTNER_ISSUER,
        clientId: 'lab-broker-at-partner',
        jwks: jwksFor([partnerKey]),
        groupMapping: { employees: 'reader', support: 'support-agent' },
      },
      {
        issuer: SUPPLIER_ISSUER,
        clientId: 'lab-broker-at-supplier',
        jwks: jwksFor([supplierKey]),
        groupMapping: { employees: 'external-reader' },
      },
    ],
    downstreamClients: [
      {
        clientId: 'local-orders-web',
        accessAudience: 'https://orders.lab.example/api',
        allowedScopes: ['openid', 'orders:read'],
      },
    ],
  });

  const upstreamToken = makeUpstreamIdToken({
    issuer: PARTNER_ISSUER,
    audience: 'lab-broker-at-partner',
    subject: 'partner-person-42',
    email: 'shared-address@example.test',
    groups: ['employees', 'admin'],
    key: partnerKey,
  });
  console.log('1. Partner signs an ID token for the broker. It claims groups [employees, admin].');

  const localTokens = broker.exchange({
    upstreamIssuer: PARTNER_ISSUER,
    upstreamIdToken: upstreamToken,
    downstreamClientId: 'local-orders-web',
    scopes: ['openid', 'orders:read'],
  });
  const localIdClaims = verifyJwt(localTokens.id_token, broker.jwks, {
    issuer: broker.issuer,
    audience: 'local-orders-web',
    now: () => NOW_MS,
    clockToleranceSec: 0,
  });
  const localAccessClaims = verifyJwt(localTokens.access_token, broker.jwks, {
    issuer: broker.issuer,
    audience: 'https://orders.lab.example/api',
    now: () => NOW_MS,
    clockToleranceSec: 0,
  });
  if (localIdClaims.token_use !== 'id' || localAccessClaims.token_use !== 'access') {
    throw new Error('broker emitted the wrong local token types');
  }
  console.log('2. Broker pins partner issuer, audience, and JWKS; verifies the ID token; then resolves/JIT-provisions an account by compound external identity.');
  console.log(`   Lookup key: {iss=${PARTNER_ISSUER}, sub=partner-person-42} → local sub ${localTokens.account.localSub}.`);
  console.log(`3. Explicit group mapping produces ${JSON.stringify(localTokens.mapped_groups)}; unallowlisted "admin" grants nothing.`);
  console.log(`4. Local app accepts a newly signed broker ID token: iss=${String(localIdClaims.iss)}, aud=${String(localIdClaims.aud)}.`);
  console.log(`   Local API accepts a separate broker access token: aud=${String(localAccessClaims.aud)}.`);
  console.log(`   Upstream token was re-issued, not forwarded: ${localTokens.id_token !== upstreamToken}.`);

  const attackerToken = makeUpstreamIdToken({
    issuer: ATTACKER_ISSUER,
    audience: 'lab-broker-at-partner',
    subject: 'attacker-person',
    email: 'shared-address@example.test',
    groups: ['employees', 'admin'],
    key: attackerKey,
  });
  try {
    broker.exchange({
      upstreamIssuer: ATTACKER_ISSUER,
      upstreamIdToken: attackerToken,
      downstreamClientId: 'local-orders-web',
      scopes: ['openid'],
    });
    throw new Error('expected an untrusted issuer to be rejected');
  } catch (error) {
    if (!(error instanceof FederationError)) throw error;
    console.log(`5. Same email from attacker issuer → rejected (${error.code}). Email is not an account key.`);
  }

  const supplierToken = makeUpstreamIdToken({
    issuer: SUPPLIER_ISSUER,
    audience: 'lab-broker-at-supplier',
    subject: 'partner-person-42',
    email: 'shared-address@example.test',
    groups: ['employees'],
    key: supplierKey,
  });
  const supplierLocal = broker.exchange({
    upstreamIssuer: SUPPLIER_ISSUER,
    upstreamIdToken: supplierToken,
    downstreamClientId: 'local-orders-web',
    scopes: ['openid'],
  });
  console.log(`6. Same bare sub from another trusted issuer → distinct local account: ${supplierLocal.account.localSub !== localTokens.account.localSub}.`);
  console.log('   Trust is a configured triangle: upstream IdP → broker → local relying party.');
}

function beginAuthorization(
  idp: LabIdentityProvider,
  client: AppClient,
  state: string,
  nonce: string,
): PendingAuthorization {
  const pkce = createPkcePair();
  const pending = idp.beginAuthorization({
    response_type: 'code',
    client_id: client.clientId,
    redirect_uri: client.redirectUri,
    scope: 'openid profile email',
    state,
    nonce,
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
  });
  pkceVerifiers.set(pending.requestId, pkce.verifier);
  return pending;
}

function finishAuthorization(
  idp: LabIdentityProvider,
  pending: PendingAuthorization,
  idpSession: string,
  client: AppClient,
): TokenResponse {
  const callback = new URL(idp.consent(pending.requestId, idpSession, true));
  if (callback.searchParams.get('state') !== pending.state) throw new Error(`${client.label} rejected mismatched state`);
  const code = callback.searchParams.get('code');
  if (!code) throw new Error(`${client.label} did not receive an authorization code`);
  const verifier = pkceVerifiers.get(pending.requestId);
  pkceVerifiers.delete(pending.requestId);
  if (!verifier) throw new Error(`${client.label} lost its PKCE login transaction`);
  return idp.token(
    { grant_type: 'authorization_code', code, redirect_uri: client.redirectUri, code_verifier: verifier },
    { clientId: client.clientId, clientSecret: client.clientSecret },
  );
}

function verifyIdToken(
  tokens: TokenResponse,
  idp: LabIdentityProvider,
  client: AppClient,
  expectedNonce: string,
): Claims {
  if (!tokens.id_token) throw new Error(`${client.label} did not receive an ID token`);
  const claims = verifyJwt(tokens.id_token, idp.jwks, {
    issuer: idp.issuer,
    audience: client.clientId,
    now: () => NOW_MS,
    clockToleranceSec: 0,
  });
  const { header } = decodeJwt(tokens.id_token);
  if (header.typ !== 'JWT' || claims.token_use !== 'id' || claims.nonce !== expectedNonce) {
    throw new Error(`${client.label} rejected the ID token's type or nonce`);
  }
  return claims;
}

function makeUpstreamIdToken(input: {
  issuer: string;
  audience: string;
  subject: string;
  email: string;
  groups: string[];
  key: SigningKey;
}): string {
  return signJwt({
    iss: input.issuer,
    sub: input.subject,
    aud: input.audience,
    iat: NOW_SEC,
    exp: NOW_SEC + 5 * 60,
    auth_time: NOW_SEC - 60,
    token_use: 'id',
    email: input.email,
    email_verified: true,
    groups: input.groups,
  }, input.key, 'JWT');
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
