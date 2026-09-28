export interface RoleTrustContext {
  readonly expectedAudience: string;
  readonly aud: string;
  readonly amr: readonly string[];
}

export type PolicyDecision =
  | { readonly allowed: true; readonly reason: string }
  | { readonly allowed: false; readonly reason: string };

export type S3Action = 's3:ListBucket' | 's3:GetObject' | 's3:PutObject';

export interface S3AuthorizationRequest {
  readonly action: S3Action;
  /** The Cognito Identity ID injected into the role session's `sub` key. */
  readonly principalIdentityId: string;
  /** Required for object actions. */
  readonly key?: string;
  /** Required for ListBucket, matching the request's `s3:prefix`. */
  readonly prefix?: string;
  readonly nowEpochSeconds: number;
  readonly credentialsExpireAtEpochSeconds: number;
}

const allow = (reason: string): PolicyDecision => ({ allowed: true, reason });
const deny = (reason: string): PolicyDecision => ({ allowed: false, reason });

/** Model the two conditions on the Cognito Identity authenticated role. */
export function evaluateRoleTrust(context: RoleTrustContext): PolicyDecision {
  if (context.aud !== context.expectedAudience) {
    return deny('role trust rejected: aud does not name this identity pool');
  }

  if (!context.amr.includes('authenticated')) {
    return deny('role trust rejected: amr does not contain authenticated');
  }

  return allow('role trust accepted: aud and authenticated amr match');
}

/** The prefix produced by `${cognito-identity.amazonaws.com:sub}/*`. */
export function prefixForIdentity(identityId: string): string {
  if (identityId.trim().length === 0) {
    throw new Error('identity ID must not be empty');
  }

  return `${identityId}/`;
}

/**
 * Model credential expiry plus the authenticated role's two S3 statements.
 * Service-side SigV4 validation rejects expired credentials before IAM allows
 * or denies the resource; this function keeps both decisions visible together.
 */
export function authorizeS3(request: S3AuthorizationRequest): PolicyDecision {
  if (
    !Number.isFinite(request.nowEpochSeconds) ||
    !Number.isFinite(request.credentialsExpireAtEpochSeconds)
  ) {
    return deny('credentials rejected: invalid expiration time');
  }

  if (request.nowEpochSeconds >= request.credentialsExpireAtEpochSeconds) {
    return deny('credentials rejected: temporary AWS credentials are expired');
  }

  if (request.principalIdentityId.trim().length === 0) {
    return deny('IAM rejected: the role session has no Cognito identity ID');
  }

  const ownPrefix = prefixForIdentity(request.principalIdentityId);

  switch (request.action) {
    case 's3:ListBucket':
      if (request.prefix === undefined) {
        return deny('IAM rejected ListBucket: no s3:prefix was supplied');
      }
      return request.prefix.startsWith(ownPrefix)
        ? allow('IAM allowed ListBucket inside the caller identity prefix')
        : deny('IAM rejected ListBucket outside the caller identity prefix');

    case 's3:GetObject':
    case 's3:PutObject':
      if (request.key === undefined) {
        return deny(`IAM rejected ${request.action}: no object key was supplied`);
      }
      return request.key.startsWith(ownPrefix)
        ? allow(`IAM allowed ${request.action} inside the caller identity prefix`)
        : deny(`IAM rejected ${request.action} outside the caller identity prefix`);
  }
}
