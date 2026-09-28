import { createHash, randomUUID } from 'node:crypto';
import {
  decodeJwt,
  generateSigningKey,
  jwksFor,
  signJwt,
  verifyJwt,
  type Claims,
  type Jwks,
  type SigningKey,
} from '../../../small-idp/src/keys';

export type FederationClock = () => number;

export interface TrustedUpstream {
  /** Exact OIDC issuer identifier. It is also the trust-store key. */
  issuer: string;
  /** Audience this broker registered at the upstream provider. */
  clientId: string;
  /** Pinned public keys obtained through trusted configuration. */
  jwks: Jwks;
  /** Explicit upstream-group to local-role mapping. Missing entries grant nothing. */
  groupMapping: Readonly<Record<string, string>>;
}

export interface DownstreamClient {
  clientId: string;
  accessAudience: string;
  allowedScopes: readonly string[];
}

export interface UpstreamIdentity {
  issuer: string;
  subject: string;
}

export interface FederatedAccount {
  localSub: string;
  upstreamIssuer: string;
  upstreamSubject: string;
}

export interface FederationExchangeRequest {
  /** Selects a preconfigured trust relationship; token claims never select keys. */
  upstreamIssuer: string;
  upstreamIdToken: string;
  downstreamClientId: string;
  scopes?: readonly string[];
}

export interface FederationTokenResponse {
  token_type: 'Bearer';
  id_token: string;
  access_token: string;
  expires_in: number;
  scope: string;
  mapped_groups: string[];
  account: FederatedAccount;
}

export interface FederationBrokerOptions {
  issuer: string;
  trustedUpstreams: readonly TrustedUpstream[];
  downstreamClients: readonly DownstreamClient[];
  signingKey?: SigningKey;
  now?: FederationClock;
  tokenLifetimeSec?: number;
}

export type FederationErrorCode =
  | 'untrusted_issuer'
  | 'invalid_upstream_token'
  | 'invalid_token_type'
  | 'invalid_subject'
  | 'invalid_groups'
  | 'unknown_downstream_client'
  | 'invalid_scope';

export class FederationError extends Error {
  constructor(
    readonly code: FederationErrorCode,
    message: string,
    readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'FederationError';
  }
}

interface StoredUpstream {
  issuer: string;
  clientId: string;
  jwks: Jwks;
  groupMapping: ReadonlyMap<string, string>;
}

interface StoredDownstream {
  clientId: string;
  accessAudience: string;
  allowedScopes: readonly string[];
}

const DEFAULT_TOKEN_LIFETIME_SEC = 5 * 60;

/**
 * A deliberately small federation broker.
 *
 * Trust configuration chooses the issuer, expected audience, and JWKS before
 * any token claims are trusted. A valid upstream ID token is converted into a
 * local account and newly signed local tokens; the upstream token is never
 * forwarded as a local credential.
 */
export class FederationBroker {
  readonly issuer: string;
  readonly signingKey: SigningKey;
  private readonly now: FederationClock;
  private readonly tokenLifetimeSec: number;
  private readonly upstreams = new Map<string, StoredUpstream>();
  private readonly downstreams = new Map<string, StoredDownstream>();
  private readonly accountsByExternalIdentity = new Map<string, FederatedAccount>();

  constructor(options: FederationBrokerOptions) {
    this.issuer = options.issuer.replace(/\/$/, '');
    if (!this.issuer) throw new Error('broker issuer is required');

    this.signingKey = options.signingKey ?? generateSigningKey('federation-broker');
    this.now = options.now ?? Date.now;
    this.tokenLifetimeSec = options.tokenLifetimeSec ?? DEFAULT_TOKEN_LIFETIME_SEC;
    if (!Number.isSafeInteger(this.tokenLifetimeSec) || this.tokenLifetimeSec <= 0) {
      throw new Error('tokenLifetimeSec must be a positive integer');
    }

    for (const upstream of options.trustedUpstreams) {
      if (!upstream.issuer || !upstream.clientId) throw new Error('upstream issuer and clientId are required');
      if (this.upstreams.has(upstream.issuer)) throw new Error(`duplicate upstream issuer: ${upstream.issuer}`);
      this.upstreams.set(upstream.issuer, {
        issuer: upstream.issuer,
        clientId: upstream.clientId,
        jwks: { keys: upstream.jwks.keys.map((key) => ({ ...key })) },
        groupMapping: new Map(Object.entries(upstream.groupMapping)),
      });
    }

    for (const downstream of options.downstreamClients) {
      if (!downstream.clientId || !downstream.accessAudience) {
        throw new Error('downstream clientId and accessAudience are required');
      }
      if (this.downstreams.has(downstream.clientId)) {
        throw new Error(`duplicate downstream client: ${downstream.clientId}`);
      }
      this.downstreams.set(downstream.clientId, {
        clientId: downstream.clientId,
        accessAudience: downstream.accessAudience,
        allowedScopes: [...new Set(downstream.allowedScopes)],
      });
    }
  }

  /** Public keys for local relying parties and resource servers. */
  get jwks(): Jwks {
    return jwksFor([this.signingKey]);
  }

  /** Look up a link only by the compound external identity, never by email. */
  getFederatedAccount(identity: UpstreamIdentity): FederatedAccount | undefined {
    const account = this.accountsByExternalIdentity.get(identityKey(identity.issuer, identity.subject));
    return account ? { ...account } : undefined;
  }

  listFederatedAccounts(): FederatedAccount[] {
    return [...this.accountsByExternalIdentity.values()].map((account) => ({ ...account }));
  }

  exchange(request: FederationExchangeRequest): FederationTokenResponse {
    const upstream = this.upstreams.get(request.upstreamIssuer);
    if (!upstream) {
      throw new FederationError('untrusted_issuer', `issuer is not in the broker trust store: ${request.upstreamIssuer}`);
    }

    const downstream = this.downstreams.get(request.downstreamClientId);
    if (!downstream) {
      throw new FederationError('unknown_downstream_client', `downstream client is not registered: ${request.downstreamClientId}`);
    }

    let claims: Claims;
    try {
      claims = verifyJwt(request.upstreamIdToken, upstream.jwks, {
        issuer: upstream.issuer,
        audience: upstream.clientId,
        now: this.now,
        clockToleranceSec: 0,
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new FederationError('invalid_upstream_token', `upstream ID token rejected: ${reason}`, error);
    }

    const { header } = decodeJwt(request.upstreamIdToken);
    // OIDC Core makes JOSE typ optional and does not define token_use. If this upstream profile
    // sends either, constrain it; absence is valid. Audience/authorized-party rules still apply.
    if (header.typ !== undefined && header.typ !== 'JWT') {
      throw new FederationError('invalid_token_type', 'federation accepts an OIDC ID token, not an access token');
    }
    if (claims.token_use !== undefined && claims.token_use !== 'id') {
      throw new FederationError('invalid_token_type', 'upstream token_use is not id');
    }
    if (typeof claims.sub !== 'string' || claims.sub.length === 0) {
      throw new FederationError('invalid_subject', 'upstream ID token requires a non-empty string sub claim');
    }
    if (typeof claims.iat !== 'number' || !Number.isFinite(claims.iat)) {
      throw new FederationError('invalid_upstream_token', 'upstream ID token requires a numeric iat claim');
    }
    const upstreamAudiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (claims.azp !== undefined && claims.azp !== upstream.clientId) {
      throw new FederationError('invalid_upstream_token', 'upstream azp does not name this broker client');
    }
    if (upstreamAudiences.length > 1 && claims.azp !== upstream.clientId) {
      throw new FederationError('invalid_upstream_token', 'multi-audience upstream ID token requires matching azp');
    }
    if (typeof claims.exp !== 'number') {
      throw new FederationError('invalid_upstream_token', 'upstream ID token requires a numeric exp claim');
    }

    const scopes = [...new Set(request.scopes ?? ['openid'])];
    if (!scopes.includes('openid')) {
      throw new FederationError('invalid_scope', 'openid is required when exchanging an upstream ID token');
    }
    const disallowedScopes = scopes.filter((scope) => !downstream.allowedScopes.includes(scope));
    if (disallowedScopes.length > 0) {
      throw new FederationError('invalid_scope', `downstream client may not request: ${disallowedScopes.join(' ')}`);
    }

    const upstreamGroups = readGroups(claims.groups);
    const mappedGroups = [...new Set(
      upstreamGroups
        .map((group) => upstream.groupMapping.get(group))
        .filter((group): group is string => group !== undefined),
    )];

    const account = this.resolveFederatedAccount({ issuer: upstream.issuer, subject: claims.sub });
    const nowSec = Math.floor(this.now() / 1000);
    const expiresAt = Math.min(nowSec + this.tokenLifetimeSec, claims.exp);
    if (expiresAt <= nowSec) {
      throw new FederationError('invalid_upstream_token', 'upstream ID token has no remaining lifetime');
    }

    const idClaims: Claims = {
      iss: this.issuer,
      sub: account.localSub,
      aud: downstream.clientId,
      iat: nowSec,
      exp: expiresAt,
      token_use: 'id',
      groups: mappedGroups,
      federated_issuer: upstream.issuer,
    };
    if (typeof claims.auth_time === 'number') idClaims.auth_time = claims.auth_time;

    const accessClaims: Claims = {
      iss: this.issuer,
      sub: account.localSub,
      aud: downstream.accessAudience,
      client_id: downstream.clientId,
      iat: nowSec,
      nbf: nowSec,
      exp: expiresAt,
      jti: randomUUID(),
      scope: scopes.join(' '),
      token_use: 'access',
      groups: mappedGroups,
    };

    return {
      token_type: 'Bearer',
      id_token: signJwt(idClaims, this.signingKey, 'JWT'),
      access_token: signJwt(accessClaims, this.signingKey, 'at+jwt'),
      expires_in: expiresAt - nowSec,
      scope: scopes.join(' '),
      mapped_groups: [...mappedGroups],
      account: { ...account },
    };
  }

  private resolveFederatedAccount(identity: UpstreamIdentity): FederatedAccount {
    const key = identityKey(identity.issuer, identity.subject);
    const existing = this.accountsByExternalIdentity.get(key);
    if (existing) return existing;

    const account: FederatedAccount = {
      localSub: localSubjectFor(key),
      upstreamIssuer: identity.issuer,
      upstreamSubject: identity.subject,
    };
    this.accountsByExternalIdentity.set(key, account);
    return account;
  }
}

function readGroups(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((group) => typeof group !== 'string')) {
    throw new FederationError('invalid_groups', 'groups must be an array of strings');
  }
  return [...new Set(value)];
}

function identityKey(issuer: string, subject: string): string {
  return JSON.stringify([issuer, subject]);
}

function localSubjectFor(compoundIdentityKey: string): string {
  const digest = createHash('sha256').update(compoundIdentityKey).digest('base64url');
  return `federated-${digest.slice(0, 24)}`;
}
