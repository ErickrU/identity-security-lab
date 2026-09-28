import { createHash } from 'node:crypto';
import {
  beginLogin,
  discover,
  finishLogin,
  type LoginTransaction,
  type OidcClientConfig,
} from '../../../small-idp/src/client';
import { decodeJwt, verifyJwt, type Claims } from '../../../small-idp/src/keys';
import { startIdp, type RunningIdp } from '../../../small-idp/src/idp';
import { type AuthorizationParameters } from '../../../small-idp/src/protocol';

const CLIENT_ID = 'chapter-06-rp';
const CLIENT_SECRET = 'chapter-06-confidential-secret-for-local-use';
const REDIRECT_URI = 'http://chapter-06-rp.example.invalid/callback';
const SCOPE = 'openid profile email groups orders:read';

interface PreparedAuthorization {
  transaction: LoginTransaction;
  callbackUrl: string;
  idpSession: string;
}

function heading(title: string): void {
  console.log(`\n${title}\n${'─'.repeat(title.length)}`);
}

function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function showRejection(
  label: string,
  action: () => unknown | Promise<unknown>,
  expected: RegExp,
): Promise<void> {
  try {
    await action();
    console.log(`  ✗ ${label}: unexpectedly accepted`);
    process.exitCode = 1;
  } catch (error) {
    const message = errorMessage(error);
    if (!expected.test(message)) {
      console.log(`  ✗ ${label}: rejected for an unexpected reason: ${message}`);
      process.exitCode = 1;
      return;
    }
    console.log(`  ✓ ${label}\n    → rejected: ${message}`);
  }
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

function abbreviated(value: unknown): string {
  const text = String(value);
  return text.length <= 16 ? text : `${text.slice(0, 8)}…${text.slice(-4)}`;
}

function oidcHashHalf(value: string): string {
  const hash = createHash('sha256').update(value).digest();
  return hash.subarray(0, hash.length / 2).toString('base64url');
}

function printIdToken(idToken: string): void {
  const { header, payload } = decodeJwt(idToken);
  const abbreviatedToken = {
    header: { alg: header.alg, typ: header.typ, kid: header.kid },
    claims: {
      iss: payload.iss,
      sub: payload.sub,
      aud: payload.aud,
      exp: '<validated Unix timestamp>',
      iat: '<Unix timestamp>',
      auth_time: '<Unix timestamp>',
      nonce: abbreviated(payload.nonce),
      at_hash: abbreviated(payload.at_hash),
      token_use: payload.token_use,
      name: payload.name,
      email: payload.email,
      groups: payload.groups,
    },
  };
  console.log(JSON.stringify(abbreviatedToken, null, 2).split('\n').map((line) => `    ${line}`).join('\n'));
}

async function prepareAuthorization(
  running: RunningIdp,
  config: OidcClientConfig,
): Promise<PreparedAuthorization> {
  const transaction = await beginLogin(config);
  const authorizationUrl = new URL(transaction.authorizationUrl);
  const pending = running.provider.beginAuthorization(authorizationParameters(authorizationUrl));
  const idpSession = await running.provider.login(
    pending.requestId,
    'alice',
    'correct horse battery staple',
  );
  try {
    const callbackUrl = running.provider.consent(pending.requestId, idpSession, true);
    return { transaction, callbackUrl, idpSession };
  } catch (error) {
    running.provider.destroySession(idpSession);
    throw error;
  }
}

async function getUserInfo(endpoint: string, accessToken: string): Promise<Claims> {
  const response = await fetch(endpoint, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new Error(`userinfo failed: HTTP ${response.status}: ${await response.text()}`);
  }
  return response.json() as Promise<Claims>;
}

function registerClient(running: RunningIdp, config: OidcClientConfig): void {
  running.provider.registerClient({
    clientId: config.clientId,
    clientType: 'confidential',
    clientSecret: config.clientSecret,
    name: 'Chapter 06 relying party',
    redirectUris: [config.redirectUri],
    allowedScopes: config.scope.split(' '),
    allowedGrants: ['authorization_code', 'refresh_token'],
  });
}

async function main(): Promise<void> {
  const running = await startIdp(0);
  let happyIdpSession: string | undefined;

  try {
    const config: OidcClientConfig = {
      issuer: running.url,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      scope: SCOPE,
    };
    registerClient(running, config);

    heading('1. Discover the OpenID Provider over real HTTP');
    const metadata = await discover(config.issuer);
    console.log(`  configured issuer     ${config.issuer}`);
    console.log(`  discovered issuer     ${metadata.issuer}`);
    console.log(`  authorization endpoint ${metadata.authorization_endpoint}`);
    console.log(`  token endpoint         ${metadata.token_endpoint}`);
    console.log(`  JWKS URI               ${metadata.jwks_uri}`);
    console.log('  The issuer matched exactly. The RP will trust only keys from this issuer metadata.');

    heading('2. Begin Authorization Code + PKCE login');
    const transaction = await beginLogin(config);
    const authorizationUrl = new URL(transaction.authorizationUrl);
    console.log('  RP → browser → OP /authorize');
    console.log(`    response_type=${authorizationUrl.searchParams.get('response_type')}`);
    console.log(`    client_id=${authorizationUrl.searchParams.get('client_id')}`);
    console.log(`    redirect_uri=${authorizationUrl.searchParams.get('redirect_uri')} (exact; no listener needed)`);
    console.log(`    scope=${authorizationUrl.searchParams.get('scope')}  ← openid switches OAuth into OIDC`);
    console.log(`    state=${abbreviated(authorizationUrl.searchParams.get('state'))} (callback transaction)`);
    console.log(`    nonce=${abbreviated(authorizationUrl.searchParams.get('nonce'))} (ID-token binding)`);
    console.log(`    code_challenge=${abbreviated(authorizationUrl.searchParams.get('code_challenge'))} method=S256`);
    console.log('    PKCE verifier stays in the RP transaction store; it is not in this URL.');

    const pending = running.provider.beginAuthorization(authorizationParameters(authorizationUrl));
    console.log('  OP validated client, exact redirect URI, scopes, nonce, state, and PKCE challenge.');
    happyIdpSession = await running.provider.login(
      pending.requestId,
      'alice',
      'correct horse battery staple',
    );
    console.log('  Alice authenticated. The OP created its own SSO session (opaque value omitted).');
    const callbackUrl = running.provider.consent(pending.requestId, happyIdpSession, true);
    const callback = new URL(callbackUrl);
    console.log('  Alice allowed the scopes. OP → exact RP callback:');
    console.log(`    code=<one-time value omitted>&state=${abbreviated(callback.searchParams.get('state'))}`);

    heading('3. Exchange the code and verify the OIDC response');
    const login = await finishLogin(config, transaction, callbackUrl);
    requireCondition(login.tokens.id_token, 'OIDC response did not contain an ID token');
    requireCondition(login.tokens.refresh_token, 'authorization-code response did not contain a refresh token');
    console.log('  RP → OP /token over real HTTP: code + exact redirect URI + PKCE verifier + client authentication.');
    console.log('  ID token      received: signed JWT for this RP (complete value omitted)');
    console.log('  access token  received: signed JWT for the resource server (complete value omitted)');
    console.log('  refresh token received: opaque rotating credential (complete value omitted)');
    console.log('  Decoded ID-token header and selected claims (decoding alone is not verification):');
    printIdToken(login.tokens.id_token);

    const independentlyVerified = verifyJwt(login.tokens.id_token, running.provider.jwks, {
      issuer: metadata.issuer,
      audience: config.clientId,
    });
    requireCondition(independentlyVerified.sub === login.claims.sub, 'verified claims changed unexpectedly');
    requireCondition(login.claims.nonce === transaction.nonce, 'nonce did not match');
    requireCondition(
      login.claims.at_hash === oidcHashHalf(login.tokens.access_token),
      'at_hash did not bind the access token',
    );
    console.log('  ✓ JWKS key + pinned RS256 verified the signature');
    console.log('  ✓ iss, aud, and exp matched the configured OP, this RP, and current time');
    console.log('  ✓ typ/token_use identified an ID token');
    console.log('  ✓ nonce matched the one-use login transaction');
    console.log('  ✓ at_hash matched the access token returned beside this ID token');

    heading('4. Use the access token at UserInfo, not the ID token');
    const userInfo = await getUserInfo(metadata.userinfo_endpoint, login.tokens.access_token);
    console.log(`  UserInfo claims: ${JSON.stringify(userInfo)}`);
    requireCondition(login.claims.sub === userInfo.sub, 'ID token and UserInfo subjects differ');
    console.log(`  ✓ stable subject: ID token sub = UserInfo sub = ${String(userInfo.sub)}`);
    console.log('  This (issuer, sub) pair is the account key. Email is profile data, not identity storage key.');

    heading('5. The rejections are the protocol');
    const stateFlow = await prepareAuthorization(running, config);
    try {
      const wrongStateCallback = new URL(stateFlow.callbackUrl);
      wrongStateCallback.searchParams.set('state', 'attacker-state-that-does-not-match');
      await showRejection(
        'callback with the wrong state (before code exchange)',
        () => finishLogin(config, stateFlow.transaction, wrongStateCallback.toString()),
        /state mismatch/,
      );
      await showRejection(
        'retry original callback after the bad-state attempt consumed the RP transaction',
        () => finishLogin(config, stateFlow.transaction, stateFlow.callbackUrl),
        /already consumed/,
      );
      console.log('    One browser transaction gets one callback attempt, successful or not. Start a new login to retry.');
    } finally {
      running.provider.destroySession(stateFlow.idpSession);
    }

    await showRejection(
      'ID token presented to the API access-token verifier',
      () => running.provider.verifyAccessToken(login.tokens.id_token!, ['orders:read']),
      /invalid_token/,
    );

    const accessShape = decodeJwt(login.tokens.access_token);
    await showRejection(
      'access token verified as an ID token',
      () => {
        const claims = verifyJwt(login.tokens.access_token, running.provider.jwks, {
          issuer: config.issuer,
          audience: config.clientId,
        });
        if (accessShape.header.typ !== 'JWT' || claims.token_use !== 'id') {
          throw new Error('wrong token type: expected OIDC ID token');
        }
      },
      /aud .*does not include|wrong token type/,
    );
    console.log(`    Access-token shape was aud=${String(accessShape.payload.aud)}, typ=${String(accessShape.header.typ)}, token_use=${String(accessShape.payload.token_use)}.`);

    const nonceFlow = await prepareAuthorization(running, config);
    try {
      await showRejection(
        'genuine ID token checked against the wrong transaction nonce',
        () => finishLogin(
          config,
          { ...nonceFlow.transaction, nonce: 'different-server-side-transaction-nonce' },
          nonceFlow.callbackUrl,
        ),
        /nonce mismatch/,
      );
    } finally {
      running.provider.destroySession(nonceFlow.idpSession);
    }

    heading('6. OP authentication and the RP session are separate');
    const rpSessions = new Map<string, { sub: string }>();
    const rpCookie = 'opaque-local-rp-cookie';
    rpSessions.set(rpCookie, { sub: String(login.claims.sub) });
    console.log(`  Before OP logout: IdP session active=${Boolean(running.provider.sessionUser(happyIdpSession))}`);
    console.log(`  RP created an independent HttpOnly session for sub=${rpSessions.get(rpCookie)?.sub}.`);
    running.provider.destroySession(happyIdpSession);
    happyIdpSession = undefined;
    console.log(`  After OP logout:  IdP session active=${Boolean(running.provider.sessionUser(happyIdpSession))}`);
    console.log(`  Local RP session still active=${rpSessions.has(rpCookie)}.`);
    console.log('  Global logout needs explicit front-channel/back-channel coordination; one cookie cannot end every session.');

    heading('7. What to remember');
    console.log('  OAuth access token → API delegation. OIDC ID token → one RP authentication result.');
    console.log('  Verify signature + iss + aud/azp + exp + type + nonce (+ at_hash when returned).');
    console.log('  Use exact redirects, state, nonce, and PKCE. Key users by (issuer, sub).');
    console.log(process.exitCode
      ? '  Demo found an unexpected acceptance.'
      : '  Done. The valid flow passed; every wrong context was rejected.');
  } finally {
    running.provider.destroySession(happyIdpSession);
    await running.stop();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
