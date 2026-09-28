export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Actor = 'human' | 'workload';

/** OIDC trust claims apply only to an OIDC-federated role, not service roles or Identity Center. */
export type AwsIdentity =
  | { kind: 'static-access-key'; wildcardPermissions: boolean }
  | { kind: 'service-role'; wildcardPermissions: boolean }
  | { kind: 'identity-center'; wildcardPermissions: boolean }
  | { kind: 'saml-role'; wildcardPermissions: boolean }
  | { kind: 'oidc-role'; oidcTrustAudience: boolean; oidcTrustSubject: boolean; wildcardPermissions: boolean };

export interface Architecture {
  name: string;
  actor: Actor;
  publicNetwork: boolean;
  transport: 'none' | 'tls-no-verify' | 'tls-verified';
  passwordStorage?: 'none' | 'plaintext' | 'fast-hash' | 'slow-hash' | 'managed-idp' | null;
  loginRateLimited?: boolean;
  privilegedHuman?: boolean;
  phishingResistantMfa?: boolean;
  bearerToken?: {
    storage: 'http-only-cookie' | 'memory' | 'local-storage' | 'server';
    accessLifetimeMinutes: number;
    refreshRotation: boolean;
  } | null;
  oauth?: {
    exactRedirectUris: boolean;
    state: boolean;
    pkceS256: boolean;
    publicClientHasSecret: boolean;
  } | null;
  oidc?: {
    nonce: boolean;
    verifiesIssuerAudienceExpiryAndType: boolean;
    apiRejectsIdTokens: boolean;
  } | null;
  federation?: {
    identityKey: 'issuer-subject' | 'email' | 'subject-only';
    mappedClaimsAllowlisted: boolean;
    lifecycleProvisioning: boolean;
  } | null;
  authorization?: {
    serverSide: boolean;
    objectLevel: boolean;
    tenantBoundary: boolean;
  } | null;
  aws?: AwsIdentity | null;
  logsSecrets: boolean;
  recoveryAtLeastAsStrongAsLogin: boolean;
}

export interface Finding {
  id: string;
  severity: Severity;
  boundary: string;
  threat: string;
  evidence: string;
  fix: string;
  chapter: string;
}

const finding = (
  id: string,
  severity: Severity,
  boundary: string,
  threat: string,
  evidence: string,
  fix: string,
  chapter: string,
): Finding => ({ id, severity, boundary, threat, evidence, fix, chapter });

/**
 * A compact design-review checklist expressed as code. It is not a scanner: inputs must come
 * from architecture/code evidence, and human abuse cases still matter. Each rule names a trust
 * boundary, concrete attack, evidence, control, and the chapter that demonstrates the mechanism.
 */
export function assess(a: Architecture): Finding[] {
  const out: Finding[] = [];

  // `undefined` means "not reviewed" and must never produce a clean report. Use explicit `null`
  // for a domain that genuinely does not apply, with the rationale kept in the architecture review.
  const gap = (id: string, domain: string, chapter: string): void => {
    out.push(finding(id, 'medium', 'review evidence', `${domain} control evidence is unknown`,
      `${domain} was omitted instead of marked configured or not-applicable`,
      `Verify the design/config/runtime evidence, or set this domain to null with a documented rationale.`, chapter));
  };
  if (a.passwordStorage === undefined) gap('GAP-001', 'password/authenticator storage', '01/09');
  if (a.bearerToken === undefined) gap('GAP-002', 'session/token handling', '01/03');
  if (a.oauth === undefined) gap('GAP-003', 'OAuth usage/applicability', '05');
  if (a.oidc === undefined) gap('GAP-004', 'OIDC usage/applicability', '06');
  if (a.federation === undefined) gap('GAP-005', 'federation usage/applicability', '07/08');
  if (a.authorization === undefined) gap('GAP-006', 'application authorization', '12');
  if (a.aws === undefined) gap('GAP-007', 'AWS identity usage/applicability', '10/11');

  if (a.publicNetwork && a.transport === 'none') out.push(finding(
    'NET-001', 'critical', 'network → endpoint', 'credential/session interception and response tampering',
    'public traffic has no TLS', 'Use TLS 1.2+ (prefer 1.3), HSTS, valid hostname chain; redirect or refuse HTTP.', '02',
  ));
  if (a.transport === 'tls-no-verify') out.push(finding(
    'NET-002', 'critical', 'network → endpoint', 'active man-in-the-middle impersonates the server',
    'TLS encryption is enabled but certificate/hostname verification is disabled', 'Trust the correct CA and verify SAN; never use curl -k or rejectUnauthorized:false in clients.', '02',
  ));

  if (a.passwordStorage === 'plaintext') out.push(finding(
    'AUTH-001', 'critical', 'user database', 'database/read access reveals every reusable password',
    'passwords are stored in plaintext/reversible form', 'Use a managed IdP or salted, tuned Argon2id/scrypt/bcrypt; never need the original password.', '01',
  ));
  if (a.passwordStorage === 'fast-hash') out.push(finding(
    'AUTH-002', 'high', 'user database', 'offline GPU password cracking after a breach',
    'MD5/SHA-family fast hash is used for passwords', 'Use a slow memory-hard password KDF with per-user salt and migration metadata.', '01',
  ));
  if (a.passwordStorage && a.passwordStorage !== 'none' && !a.loginRateLimited) out.push(finding(
    'AUTH-003', 'high', 'internet → login', 'online guessing and credential stuffing',
    'login attempts have no account/source-aware throttle', 'Rate-limit before the expensive hash, detect stuffing, return generic errors, add strong MFA.', '01/09',
  ));
  if (a.actor === 'human' && a.privilegedHuman && !a.phishingResistantMfa) out.push(finding(
    'AUTH-004', 'high', 'human → authenticator', 'phishing proxy steals password/TOTP/session',
    'privileged user lacks origin-bound MFA', 'Require passkeys or FIDO2 security keys; make recovery and enrollment equally strong.', '09',
  ));

  if (a.bearerToken?.storage === 'local-storage') out.push(finding(
    'TOK-001', 'high', 'browser origin → token', 'XSS or compromised dependency exfiltrates persistent bearer token',
    'bearer token is in localStorage', 'Prefer a BFF with HttpOnly/Secure/SameSite session cookie, or keep short tokens only in memory.', '01/03',
  ));
  if (a.bearerToken && a.bearerToken.accessLifetimeMinutes > 15) out.push(finding(
    'TOK-002', 'medium', 'token holder → API', 'stolen access token remains useful for a long period',
    `access-token lifetime is ${a.bearerToken.accessLifetimeMinutes} minutes`, 'Use 5–15 minute access tokens; refresh separately; consider sender-constraining with mTLS/DPoP.', '03/05',
  ));
  if (a.bearerToken && !a.bearerToken.refreshRotation) out.push(finding(
    'TOK-003', 'high', 'client storage → authorization server', 'stolen refresh token gives persistent access and reuse is invisible',
    'refresh tokens are reusable without rotation', 'Rotate every use, track token families, revoke family on reuse, protect server/OS storage.', '05',
  ));

  if (a.oauth && !a.oauth.exactRedirectUris) out.push(finding(
    'OAUTH-001', 'critical', 'authorization server → client callback', 'authorization code/token sent to attacker-controlled endpoint',
    'redirect URI uses wildcard/prefix matching', 'Pre-register and exact-compare redirect URIs before redirecting any response.', '05',
  ));
  if (a.oauth && !a.oauth.state) out.push(finding(
    'OAUTH-002', 'high', 'browser → client callback', 'login/authorization CSRF or transaction mix-up',
    'authorization request/callback has no browser-bound one-use state', 'Generate unpredictable state, store server-side with transaction, constant-time compare and consume once.', '05/06',
  ));
  if (a.oauth && !a.oauth.pkceS256) out.push(finding(
    'OAUTH-003', 'high', 'browser callback → token endpoint', 'intercepted authorization code is redeemed by another client instance',
    'Code flow has no PKCE S256', 'Use a fresh verifier and S256 challenge; require it for public and prefer it for confidential clients.', '05',
  ));
  if (a.oauth?.publicClientHasSecret) out.push(finding(
    'OAUTH-004', 'medium', 'distributed client binary → AS', 'extractable value is mistaken for client authentication',
    'SPA/mobile/CLI embeds a client secret', 'Register as public; remove fake secret; use PKCE and secure redirect mechanisms.', '05',
  ));

  if (a.oidc && !a.oidc.nonce) out.push(finding(
    'OIDC-001', 'high', 'authorization response → RP transaction', 'ID-token replay/substitution across login transactions',
    'OIDC request/ID-token validation omits nonce', 'Generate one-use nonce and compare the verified ID-token claim with the initiating transaction.', '06',
  ));
  if (a.oidc && !a.oidc.verifiesIssuerAudienceExpiryAndType) out.push(finding(
    'OIDC-002', 'critical', 'external issuer → relying party', 'attacker/wrong-client/expired token accepted as login',
    'RP does not verify signature plus exact iss/aud/exp/token type', 'Use maintained verifier with pinned issuer/algorithms/JWKS and exact audience/type/time checks.', '03/06',
  ));
  if (a.oidc && !a.oidc.apiRejectsIdTokens) out.push(finding(
    'OIDC-003', 'high', 'client token → resource API', 'ID token for a client is substituted as API authority',
    'API accepts ID tokens or does not enforce access-token profile/audience', 'API accepts only access tokens for its audience/type and required scopes.', '05/06',
  ));

  if (a.federation?.identityKey !== undefined && a.federation.identityKey !== 'issuer-subject') out.push(finding(
    'FED-001', 'critical', 'upstream IdP → local account link', 'external identity is merged with the wrong local account',
    `account key uses ${a.federation.identityKey}`, 'Key links by exact (issuer, subject); make account merge a fresh-authenticated workflow.', '07',
  ));
  if (a.federation && !a.federation.mappedClaimsAllowlisted) out.push(finding(
    'FED-002', 'critical', 'upstream claims → local authorization', 'partner-controlled group/role becomes local privilege',
    'upstream groups/roles are copied without per-issuer mapping', 'Allowlist/map claims per trusted issuer; unknown values grant nothing; authorize locally.', '07/12',
  ));
  if (a.federation && !a.federation.lifecycleProvisioning) out.push(finding(
    'FED-003', 'high', 'workforce directory → local accounts', 'departed/moved users retain stale local accounts or entitlements',
    'federated login is treated as deprovisioning', 'Use SCIM/reconciliation and explicit disable/session/token revocation; test joiner/mover/leaver.', '07',
  ));

  if (a.authorization && !a.authorization.serverSide) out.push(finding(
    'AUTHZ-001', 'critical', 'untrusted client → service', 'client bypasses UI-only authorization',
    'permissions are enforced only in browser/mobile code', 'Enforce at API/service/data boundary for every operation; client checks are UX only.', '12',
  ));
  if (a.authorization && !a.authorization.objectLevel) out.push(finding(
    'AUTHZ-002', 'critical', 'authenticated principal → object', 'BOLA/IDOR: change object ID to read/edit another user resource',
    'endpoint checks authentication/coarse role but not requested object relationship', 'Check owner/tenant/relationship/policy on list, detail, update and delete paths.', '12',
  ));
  if (a.authorization && !a.authorization.tenantBoundary) out.push(finding(
    'AUTHZ-003', 'critical', 'tenant → tenant data', 'cross-tenant data disclosure or modification',
    'tenant identity is not enforced at trusted query/storage boundary', 'Derive tenant from verified context; include it in every query/key/policy; never trust body tenant ID.', '12',
  ));

  if (a.aws?.kind === 'static-access-key') out.push(finding(
    'AWS-001', 'critical', 'source/CI/workstation → AWS', 'long-lived AWS credential theft',
    'workload/human uses a static IAM access key', 'Use workload IAM roles or Identity Center/federation; temporary credentials and short sessions.', '10',
  ));
  if (a.aws?.kind === 'oidc-role' && !a.aws.oidcTrustAudience) out.push(finding(
    'AWS-002', 'critical', 'external OIDC issuer → STS role', 'token minted for another relying party assumes AWS role',
    'OIDC role trust does not constrain audience', 'StringEquals the expected aud (for GitHub: sts.amazonaws.com / configured audience).', '10',
  ));
  if (a.aws?.kind === 'oidc-role' && !a.aws.oidcTrustSubject) out.push(finding(
    'AWS-003', 'critical', 'external OIDC issuer → STS role', 'any repository/tenant/workload at issuer can assume role',
    'OIDC trust does not constrain subject', 'Constrain exact repository/branch/environment/service account/tenant subject and protect its governance.', '10',
  ));
  if (a.aws?.wildcardPermissions) out.push(finding(
    'AWS-004', 'high', 'role session → AWS resources', 'compromise has account-wide blast radius',
    'role grants wildcard actions/resources without a justified boundary', 'Least actions/resources/conditions; separate roles; boundary/SCP/RCP; Access Analyzer and denial tests.', '10/11',
  ));

  if (a.logsSecrets) out.push(finding(
    'OPS-001', 'critical', 'application → telemetry/support', 'logs become a credential dump',
    'passwords, bearer/refresh/session tokens, private keys or AWS secrets reach logs', 'Structured redaction by default; log jti/fingerprint/failure code; restrict and expire logs.', '01/03/10',
  ));
  if (a.actor === 'human' && !a.recoveryAtLeastAsStrongAsLogin) out.push(finding(
    'AUTH-005', 'critical', 'support/recovery → account', 'attacker bypasses MFA/passkey through weaker recovery',
    'account recovery is weaker than normal sign-in/enrollment', 'Backup strong authenticators/codes, waiting period, notifications, recent auth for factor changes.', '09/13',
  ));

  return out.sort((x, y) => severityRank(x.severity) - severityRank(y.severity) || x.id.localeCompare(y.id));
}

export function severityCounts(findings: readonly Finding[]): Record<Severity, number> {
  const result: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) result[item.severity]++;
  return result;
}

function severityRank(value: Severity): number {
  return ({ critical: 0, high: 1, medium: 2, low: 3 })[value];
}
