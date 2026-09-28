import { describe, expect, it } from 'vitest';
import { assess, severityCounts, type Architecture } from './model';

const secure: Architecture = {
  name: 'secure baseline', actor: 'human', publicNetwork: true, transport: 'tls-verified',
  passwordStorage: 'managed-idp', loginRateLimited: true, privilegedHuman: true, phishingResistantMfa: true,
  bearerToken: { storage: 'server', accessLifetimeMinutes: 10, refreshRotation: true },
  oauth: { exactRedirectUris: true, state: true, pkceS256: true, publicClientHasSecret: false },
  oidc: { nonce: true, verifiesIssuerAudienceExpiryAndType: true, apiRejectsIdTokens: true },
  federation: { identityKey: 'issuer-subject', mappedClaimsAllowlisted: true, lifecycleProvisioning: true },
  authorization: { serverSide: true, objectLevel: true, tenantBoundary: true },
  aws: { kind: 'oidc-role', oidcTrustAudience: true, oidcTrustSubject: true, wildcardPermissions: false },
  logsSecrets: false, recoveryAtLeastAsStrongAsLogin: true,
};

const ids = (a: Architecture) => assess(a).map((f) => f.id);
const withChange = (patch: Partial<Architecture>): Architecture => ({ ...secure, ...patch });

describe('threat-model checklist', () => {
  it('treats omitted domains as evidence gaps, never a clean report', () => {
    const sparse: Architecture = {
      name: 'unknown design', actor: 'human', publicNetwork: true, transport: 'tls-verified',
      logsSecrets: false, recoveryAtLeastAsStrongAsLogin: true,
    };
    const result = assess(sparse);
    expect(result.length).toBeGreaterThan(0);
    expect(result.map((item) => item.id)).toEqual(expect.arrayContaining([
      'GAP-001', 'GAP-002', 'GAP-003', 'GAP-004', 'GAP-005', 'GAP-006', 'GAP-007',
    ]));
  });
  it('accepts explicit null as reviewed and not applicable', () => {
    const minimal: Architecture = {
      name: 'static public page', actor: 'workload', publicNetwork: true, transport: 'tls-verified',
      passwordStorage: null, bearerToken: null, oauth: null, oidc: null, federation: null,
      authorization: null, aws: null, logsSecrets: false, recoveryAtLeastAsStrongAsLogin: false,
    };
    expect(assess(minimal)).toEqual([]);
  });
  it('has no findings for the fully controlled reference architecture', () => expect(assess(secure)).toEqual([]));
  it('flags public plaintext transport', () => expect(ids(withChange({ transport: 'none' }))).toContain('NET-001'));
  it('flags TLS without certificate verification', () => expect(ids(withChange({ transport: 'tls-no-verify' }))).toContain('NET-002'));
  it('flags plaintext and fast password storage at different severities', () => {
    expect(assess(withChange({ passwordStorage: 'plaintext' })).find((f) => f.id === 'AUTH-001')?.severity).toBe('critical');
    expect(assess(withChange({ passwordStorage: 'fast-hash' })).find((f) => f.id === 'AUTH-002')?.severity).toBe('high');
  });
  it('flags no login rate limit', () => expect(ids(withChange({ loginRateLimited: false }))).toContain('AUTH-003'));
  it('flags privileged humans without phishing-resistant MFA', () => expect(ids(withChange({ phishingResistantMfa: false }))).toContain('AUTH-004'));
  it('does not require human MFA for a workload actor', () => expect(ids(withChange({ actor: 'workload', privilegedHuman: false, phishingResistantMfa: false }))).not.toContain('AUTH-004'));
  it('flags localStorage, long access lifetime and no refresh rotation separately', () => {
    const result = ids(withChange({ bearerToken: { storage: 'local-storage', accessLifetimeMinutes: 60, refreshRotation: false } }));
    expect(result).toEqual(expect.arrayContaining(['TOK-001', 'TOK-002', 'TOK-003']));
  });
  it('flags each OAuth transaction failure', () => {
    const result = ids(withChange({ oauth: { exactRedirectUris: false, state: false, pkceS256: false, publicClientHasSecret: true } }));
    expect(result).toEqual(expect.arrayContaining(['OAUTH-001', 'OAUTH-002', 'OAUTH-003', 'OAUTH-004']));
  });
  it('flags each OIDC verifier/token-type failure', () => {
    const result = ids(withChange({ oidc: { nonce: false, verifiesIssuerAudienceExpiryAndType: false, apiRejectsIdTokens: false } }));
    expect(result).toEqual(expect.arrayContaining(['OIDC-001', 'OIDC-002', 'OIDC-003']));
  });
  it('flags email and subject-only federation linking', () => {
    expect(ids(withChange({ federation: { ...secure.federation!, identityKey: 'email' } }))).toContain('FED-001');
    expect(ids(withChange({ federation: { ...secure.federation!, identityKey: 'subject-only' } }))).toContain('FED-001');
  });
  it('flags copied claims and missing lifecycle independently', () => {
    const result = ids(withChange({ federation: { identityKey: 'issuer-subject', mappedClaimsAllowlisted: false, lifecycleProvisioning: false } }));
    expect(result).toEqual(expect.arrayContaining(['FED-002', 'FED-003']));
  });
  it('flags browser-only, missing object, and missing tenant authorization', () => {
    const result = ids(withChange({ authorization: { serverSide: false, objectLevel: false, tenantBoundary: false } }));
    expect(result).toEqual(expect.arrayContaining(['AUTHZ-001', 'AUTHZ-002', 'AUTHZ-003']));
  });
  it('flags static AWS keys and wildcard permissions', () => {
    const result = ids(withChange({ aws: { kind: 'static-access-key', wildcardPermissions: true } }));
    expect(result).toEqual(expect.arrayContaining(['AWS-001', 'AWS-004']));
    expect(result).not.toEqual(expect.arrayContaining(['AWS-002', 'AWS-003']));
  });
  it('requires audience and subject only for OIDC-federated roles', () => {
    const result = ids(withChange({ aws: { kind: 'oidc-role', oidcTrustAudience: false, oidcTrustSubject: false, wildcardPermissions: false } }));
    expect(result).toEqual(expect.arrayContaining(['AWS-002', 'AWS-003']));
    expect(ids(withChange({ aws: { kind: 'service-role', wildcardPermissions: false } }))).not.toEqual(expect.arrayContaining(['AWS-002', 'AWS-003']));
    expect(ids(withChange({ aws: { kind: 'identity-center', wildcardPermissions: false } }))).not.toEqual(expect.arrayContaining(['AWS-002', 'AWS-003']));
  });
  it('flags secret logging and weak recovery', () => {
    const result = ids(withChange({ logsSecrets: true, recoveryAtLeastAsStrongAsLogin: false }));
    expect(result).toEqual(expect.arrayContaining(['OPS-001', 'AUTH-005']));
  });
  it('sorts critical before high before medium', () => {
    const findings = assess(withChange({ transport: 'none', phishingResistantMfa: false, bearerToken: { storage: 'server', accessLifetimeMinutes: 60, refreshRotation: true } }));
    expect(findings.map((f) => f.severity)).toEqual(['critical', 'high', 'medium']);
  });
  it('counts severities', () => {
    expect(severityCounts([
      { id: 'a', severity: 'critical', boundary: '', threat: '', evidence: '', fix: '', chapter: '' },
      { id: 'b', severity: 'high', boundary: '', threat: '', evidence: '', fix: '', chapter: '' },
      { id: 'c', severity: 'high', boundary: '', threat: '', evidence: '', fix: '', chapter: '' },
    ])).toEqual({ critical: 1, high: 2, medium: 0, low: 0 });
  });
  it('findings include actionable boundary/evidence/fix/chapter fields', () => {
    for (const item of assess(withChange({ transport: 'none' }))) {
      expect(item.boundary).not.toBe(''); expect(item.evidence).not.toBe(''); expect(item.fix).not.toBe(''); expect(item.chapter).not.toBe('');
    }
  });
});
