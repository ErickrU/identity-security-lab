import { beforeEach, describe, expect, it } from 'vitest';
import { createPkcePair, LabIdentityProvider, OAuthError } from '../../../small-idp/src/protocol';
import {
  decodeJwt,
  generateSigningKey,
  jwksFor,
  signJwt,
  verifyJwt,
  type Claims,
  type SigningKey,
} from '../../../small-idp/src/keys';
import { FederationBroker, FederationError, type FederationErrorCode } from './federation';

const NOW_MS = Date.UTC(2026, 0, 15, 12, 0, 0);
const NOW_SEC = Math.floor(NOW_MS / 1000);
const PARTNER_ISSUER = 'https://id.partner.example';
const SUPPLIER_ISSUER = 'https://id.supplier.example';
const ATTACKER_ISSUER = 'https://id.attacker.example';
const PARTNER_CLIENT_ID = 'broker-at-partner';
const SUPPLIER_CLIENT_ID = 'broker-at-supplier';

// Generate expensive RSA keys once. Tests assert behavior, not random token bytes.
const idpKey = generateSigningKey('workforce-idp-test');
const partnerKey = generateSigningKey('partner-test');
const supplierKey = generateSigningKey('supplier-test');
const brokerKey = generateSigningKey('broker-test');
const attackerKeyWithPartnerKid = generateSigningKey('partner-test');

interface UpstreamTokenOptions {
  issuer?: string;
  audience?: string | string[];
  subject?: unknown;
  email?: string;
  groups?: unknown;
  expiresAt?: number;
  notBefore?: number;
  issuedAt?: unknown;
  authorizedParty?: string;
  tokenUse?: string | null;
  typ?: 'JWT' | 'at+jwt' | null;
  key?: SigningKey;
}

function makeUpstreamToken(options: UpstreamTokenOptions = {}): string {
  const claims: Claims = {
    iss: options.issuer ?? PARTNER_ISSUER,
    sub: options.subject === undefined ? 'external-user-42' : options.subject,
    aud: options.audience ?? PARTNER_CLIENT_ID,
    iat: options.issuedAt === undefined ? NOW_SEC : options.issuedAt,
    exp: options.expiresAt ?? NOW_SEC + 300,
    email: options.email ?? 'person@example.test',
    email_verified: true,
    groups: options.groups ?? ['employees'],
  };
  if (options.tokenUse !== null) claims.token_use = options.tokenUse ?? 'id';
  if (options.authorizedParty !== undefined) claims.azp = options.authorizedParty;
  if (options.notBefore !== undefined) claims.nbf = options.notBefore;
  return signJwt(claims, options.key ?? partnerKey, options.typ === null ? undefined : (options.typ ?? 'JWT'));
}

function createBroker(): FederationBroker {
  return new FederationBroker({
    issuer: 'https://broker.local.example',
    signingKey: brokerKey,
    now: () => NOW_MS,
    tokenLifetimeSec: 300,
    trustedUpstreams: [
      {
        issuer: PARTNER_ISSUER,
        clientId: PARTNER_CLIENT_ID,
        jwks: jwksFor([partnerKey]),
        groupMapping: { employees: 'reader', support: 'support-agent' },
      },
      {
        issuer: SUPPLIER_ISSUER,
        clientId: SUPPLIER_CLIENT_ID,
        jwks: jwksFor([supplierKey]),
        groupMapping: { employees: 'external-reader' },
      },
    ],
    downstreamClients: [
      {
        clientId: 'local-web',
        accessAudience: 'https://local.example/api',
        allowedScopes: ['openid', 'orders:read'],
      },
      {
        clientId: 'local-reports',
        accessAudience: 'https://reports.local.example/api',
        allowedScopes: ['openid'],
      },
    ],
  });
}

function exchange(broker: FederationBroker, upstreamIdToken = makeUpstreamToken()) {
  return broker.exchange({
    upstreamIssuer: PARTNER_ISSUER,
    upstreamIdToken,
    downstreamClientId: 'local-web',
    scopes: ['openid', 'orders:read'],
  });
}

function captureFederationError(run: () => unknown): FederationError {
  try {
    run();
  } catch (error) {
    if (error instanceof FederationError) return error;
    throw error;
  }
  throw new Error('expected FederationError');
}

function expectFederationError(run: () => unknown, code: FederationErrorCode): void {
  expect(captureFederationError(run).code).toBe(code);
}

function captureOAuthError(run: () => unknown): OAuthError {
  try {
    run();
  } catch (error) {
    if (error instanceof OAuthError) return error;
    throw error;
  }
  throw new Error('expected OAuthError');
}

function callbackCode(callbackUrl: string, expectedState: string): string {
  const callback = new URL(callbackUrl);
  expect(callback.searchParams.get('state')).toBe(expectedState);
  const code = callback.searchParams.get('code');
  if (!code) throw new Error('authorization response did not contain a code');
  return code;
}

describe('web SSO and relying-party session independence', () => {
  it('uses one password login for two apps while keeping IdP and local sessions independent', async () => {
    const idp = await LabIdentityProvider.withDefaults({
      issuer: 'https://login.local.example',
      resourceAudience: 'https://resource.local.example',
      now: () => NOW_MS,
      signingKey: idpKey,
    });
    let passwordPrompts = 0;
    const localSessions = new Map<string, string>();

    const appAPkce = createPkcePair();
    const appARequest = idp.beginAuthorization({
      response_type: 'code', client_id: 'orders-web', redirect_uri: 'http://127.0.0.1:4001/callback',
      scope: 'openid profile', state: 'state-app-a-000000000001', nonce: 'nonce-app-a-000000000001',
      code_challenge: appAPkce.challenge, code_challenge_method: 'S256',
    });
    passwordPrompts += 1;
    const idpSession = await idp.login(appARequest.requestId, 'alice', 'correct horse battery staple');
    const appACode = callbackCode(idp.consent(appARequest.requestId, idpSession, true), appARequest.state);
    const appATokens = idp.token(
      { grant_type: 'authorization_code', code: appACode, redirect_uri: 'http://127.0.0.1:4001/callback', code_verifier: appAPkce.verifier },
      { clientId: 'orders-web', clientSecret: 'orders-web-secret-for-local-lab' },
    );
    if (!appATokens.id_token) throw new Error('App A expected an ID token');
    const appAClaims = verifyJwt(appATokens.id_token, idp.jwks, {
      issuer: idp.issuer, audience: 'orders-web', now: () => NOW_MS, clockToleranceSec: 0,
    });
    localSessions.set('app-a', `app-a:${String(appAClaims.sub)}`);

    const appBPkce = createPkcePair();
    const appBRequest = idp.beginAuthorization({
      response_type: 'code', client_id: 'reports-web', redirect_uri: 'http://127.0.0.1:4002/callback',
      scope: 'openid profile', state: 'state-app-b-000000000001', nonce: 'nonce-app-b-000000000001',
      code_challenge: appBPkce.challenge, code_challenge_method: 'S256',
    });
    expect(idp.sessionUser(idpSession)?.username).toBe('alice');
    const appBCode = callbackCode(idp.consent(appBRequest.requestId, idpSession, true), appBRequest.state);
    const appBTokens = idp.token(
      { grant_type: 'authorization_code', code: appBCode, redirect_uri: 'http://127.0.0.1:4002/callback', code_verifier: appBPkce.verifier },
      { clientId: 'reports-web', clientSecret: 'reports-web-secret-for-local-lab' },
    );
    if (!appBTokens.id_token) throw new Error('App B expected an ID token');
    const appBClaims = verifyJwt(appBTokens.id_token, idp.jwks, {
      issuer: idp.issuer, audience: 'reports-web', now: () => NOW_MS, clockToleranceSec: 0,
    });
    localSessions.set('app-b', `app-b:${String(appBClaims.sub)}`);

    expect(passwordPrompts).toBe(1);
    expect(appAClaims.sub).toBe(appBClaims.sub);
    expect(localSessions.get('app-a')).not.toBe(localSessions.get('app-b'));

    localSessions.delete('app-a');
    expect(localSessions.has('app-a')).toBe(false);
    expect(localSessions.has('app-b')).toBe(true);
    expect(idp.sessionUser(idpSession)?.sub).toBe(appAClaims.sub);

    // Model App A silently creating a replacement local session while the IdP cookie still works.
    localSessions.set('app-a', `app-a-return:${String(appAClaims.sub)}`);
    idp.destroySession(idpSession);
    expect(idp.sessionUser(idpSession)).toBeUndefined();
    expect(localSessions.has('app-a')).toBe(true);
    expect(localSessions.has('app-b')).toBe(true);

    const laterPkce = createPkcePair();
    const laterRequest = idp.beginAuthorization({
      response_type: 'code', client_id: 'reports-web', redirect_uri: 'http://127.0.0.1:4002/callback',
      scope: 'openid', state: 'state-app-b-000000000002', nonce: 'nonce-app-b-000000000002',
      code_challenge: laterPkce.challenge, code_challenge_method: 'S256',
    });
    expect(captureOAuthError(() => idp.consent(laterRequest.requestId, idpSession, true)).error).toBe('login_required');
  });
});

describe('FederationBroker', () => {
  let broker: FederationBroker;

  beforeEach(() => {
    broker = createBroker();
  });

  it('verifies a genuine upstream ID token and re-issues rather than forwards it', () => {
    const upstream = makeUpstreamToken();
    const result = exchange(broker, upstream);

    expect(result.id_token).not.toBe(upstream);
    expect(result.access_token).not.toBe(upstream);
    expect(result.token_type).toBe('Bearer');
    expect(result.expires_in).toBe(300);
  });

  it('rejects an issuer that is absent from the trust store', () => {
    const attackerToken = makeUpstreamToken({ issuer: ATTACKER_ISSUER, key: attackerKeyWithPartnerKid });
    expectFederationError(() => broker.exchange({
      upstreamIssuer: ATTACKER_ISSUER,
      upstreamIdToken: attackerToken,
      downstreamClientId: 'local-web',
      scopes: ['openid'],
    }), 'untrusted_issuer');
  });

  it('rejects a wrong iss claim even when a trusted key signed it', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ issuer: 'https://wrong.example' })), 'invalid_upstream_token');
  });

  it('rejects a token signed by a different key with the same kid', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ key: attackerKeyWithPartnerKid })), 'invalid_upstream_token');
  });

  it('rejects a token issued for a different upstream audience', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ audience: 'some-other-client' })), 'invalid_upstream_token');
  });

  it('rejects an expired upstream token without clock-skew grace', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ expiresAt: NOW_SEC })), 'invalid_upstream_token');
  });

  it('rejects an access token presented as an upstream ID token', () => {
    const accessToken = makeUpstreamToken({ tokenUse: 'access', typ: 'at+jwt' });
    expectFederationError(() => exchange(broker, accessToken), 'invalid_token_type');
  });

  it('rejects an ID claim set carried under the wrong JWT type', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ typ: 'at+jwt' })), 'invalid_token_type');
  });

  it('accepts conforming upstream ID tokens when optional typ and provider-specific token_use are absent', () => {
    expect(() => exchange(broker, makeUpstreamToken({ typ: null, tokenUse: null }))).not.toThrow();
  });

  it('requires numeric iat and matching azp for multi-audience upstream tokens', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ issuedAt: 'now' })), 'invalid_upstream_token');
    expectFederationError(() => exchange(broker, makeUpstreamToken({ audience: [PARTNER_CLIENT_ID, 'other'] })), 'invalid_upstream_token');
    expectFederationError(() => exchange(broker, makeUpstreamToken({ audience: [PARTNER_CLIENT_ID, 'other'], authorizedParty: 'other' })), 'invalid_upstream_token');
    expect(() => exchange(broker, makeUpstreamToken({ audience: [PARTNER_CLIENT_ID, 'other'], authorizedParty: PARTNER_CLIENT_ID }))).not.toThrow();
  });

  it('requires a non-empty string upstream subject', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ subject: 42 })), 'invalid_subject');
  });

  it('returns the same account for the same issuer and subject despite email changes', () => {
    const first = exchange(broker, makeUpstreamToken({ email: 'old@example.test' }));
    const second = exchange(broker, makeUpstreamToken({ email: 'new@example.test' }));

    expect(second.account.localSub).toBe(first.account.localSub);
    expect(broker.listFederatedAccounts()).toHaveLength(1);
    expect(broker.getFederatedAccount({ issuer: PARTNER_ISSUER, subject: 'external-user-42' })?.localSub)
      .toBe(first.account.localSub);
  });

  it('treats the same bare subject from another trusted issuer as a distinct account', () => {
    const partner = exchange(broker);
    const supplierToken = makeUpstreamToken({
      issuer: SUPPLIER_ISSUER,
      audience: SUPPLIER_CLIENT_ID,
      subject: 'external-user-42',
      key: supplierKey,
    });
    const supplier = broker.exchange({
      upstreamIssuer: SUPPLIER_ISSUER,
      upstreamIdToken: supplierToken,
      downstreamClientId: 'local-web',
      scopes: ['openid'],
    });

    expect(supplier.account.localSub).not.toBe(partner.account.localSub);
    expect(broker.listFederatedAccounts()).toHaveLength(2);
  });

  it('does not merge different subjects that present the same email', () => {
    const first = exchange(broker, makeUpstreamToken({ subject: 'subject-one', email: 'shared@example.test' }));
    const second = exchange(broker, makeUpstreamToken({ subject: 'subject-two', email: 'shared@example.test' }));

    expect(second.account.localSub).not.toBe(first.account.localSub);
  });

  it('maps only allowlisted upstream groups and never passes an unlisted admin group', () => {
    const result = exchange(broker, makeUpstreamToken({ groups: ['employees', 'support', 'admin', 'employees'] }));

    expect(result.mapped_groups).toEqual(['reader', 'support-agent']);
    expect(result.mapped_groups).not.toContain('admin');
  });

  it('rejects malformed group claims rather than coercing them', () => {
    expectFederationError(() => exchange(broker, makeUpstreamToken({ groups: 'employees admin' })), 'invalid_groups');
  });

  it('issues a downstream ID token with broker identity, local subject, audience, and signature', () => {
    const result = exchange(broker);
    const claims = verifyJwt(result.id_token, broker.jwks, {
      issuer: broker.issuer,
      audience: 'local-web',
      now: () => NOW_MS,
      clockToleranceSec: 0,
    });

    expect(decodeJwt(result.id_token).header.typ).toBe('JWT');
    expect(claims).toMatchObject({
      iss: broker.issuer,
      sub: result.account.localSub,
      aud: 'local-web',
      token_use: 'id',
      groups: ['reader'],
      federated_issuer: PARTNER_ISSUER,
    });
  });

  it('issues a separate downstream access token for the registered local API', () => {
    const result = exchange(broker);
    const claims = verifyJwt(result.access_token, broker.jwks, {
      issuer: broker.issuer,
      audience: 'https://local.example/api',
      now: () => NOW_MS,
      clockToleranceSec: 0,
    });

    expect(decodeJwt(result.access_token).header.typ).toBe('at+jwt');
    expect(claims).toMatchObject({
      sub: result.account.localSub,
      client_id: 'local-web',
      scope: 'openid orders:read',
      token_use: 'access',
      groups: ['reader'],
    });
  });

  it('fails downstream verification under the wrong audience', () => {
    const result = exchange(broker);
    expect(() => verifyJwt(result.id_token, broker.jwks, {
      issuer: broker.issuer,
      audience: 'another-local-client',
      now: () => NOW_MS,
      clockToleranceSec: 0,
    })).toThrow(/aud/);
  });

  it('rejects an unregistered downstream client', () => {
    expectFederationError(() => broker.exchange({
      upstreamIssuer: PARTNER_ISSUER,
      upstreamIdToken: makeUpstreamToken(),
      downstreamClientId: 'unregistered-client',
      scopes: ['openid'],
    }), 'unknown_downstream_client');
  });

  it('rejects downstream scope expansion', () => {
    expectFederationError(() => broker.exchange({
      upstreamIssuer: PARTNER_ISSUER,
      upstreamIdToken: makeUpstreamToken(),
      downstreamClientId: 'local-web',
      scopes: ['openid', 'local:admin'],
    }), 'invalid_scope');
  });

  it('never extends local token lifetime beyond the upstream token', () => {
    const result = exchange(broker, makeUpstreamToken({ expiresAt: NOW_SEC + 45 }));
    const claims = verifyJwt(result.id_token, broker.jwks, {
      issuer: broker.issuer,
      audience: 'local-web',
      now: () => NOW_MS,
      clockToleranceSec: 0,
    });

    expect(result.expires_in).toBe(45);
    expect(claims.exp).toBe(NOW_SEC + 45);
  });
});
