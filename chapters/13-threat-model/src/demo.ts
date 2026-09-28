import { assess, severityCounts, type Architecture, type Finding } from './model';

const insecureSpa: Architecture = {
  name: 'Insecure browser app copied from a tutorial', actor: 'human', publicNetwork: true,
  transport: 'tls-no-verify', passwordStorage: 'fast-hash', loginRateLimited: false,
  privilegedHuman: true, phishingResistantMfa: false,
  bearerToken: { storage: 'local-storage', accessLifetimeMinutes: 1440, refreshRotation: false },
  oauth: { exactRedirectUris: false, state: false, pkceS256: false, publicClientHasSecret: true },
  oidc: { nonce: false, verifiesIssuerAudienceExpiryAndType: false, apiRejectsIdTokens: false },
  federation: { identityKey: 'email', mappedClaimsAllowlisted: false, lifecycleProvisioning: false },
  authorization: { serverSide: true, objectLevel: false, tenantBoundary: false },
  aws: { kind: 'static-access-key', wildcardPermissions: true },
  logsSecrets: true, recoveryAtLeastAsStrongAsLogin: false,
};

const hardenedBff: Architecture = {
  name: 'Hardened BFF + managed IdP + scoped API', actor: 'human', publicNetwork: true,
  transport: 'tls-verified', passwordStorage: 'managed-idp', loginRateLimited: true,
  privilegedHuman: true, phishingResistantMfa: true,
  bearerToken: { storage: 'server', accessLifetimeMinutes: 10, refreshRotation: true },
  oauth: { exactRedirectUris: true, state: true, pkceS256: true, publicClientHasSecret: false },
  oidc: { nonce: true, verifiesIssuerAudienceExpiryAndType: true, apiRejectsIdTokens: true },
  federation: { identityKey: 'issuer-subject', mappedClaimsAllowlisted: true, lifecycleProvisioning: true },
  authorization: { serverSide: true, objectLevel: true, tenantBoundary: true },
  aws: { kind: 'oidc-role', oidcTrustAudience: true, oidcTrustSubject: true, wildcardPermissions: false },
  logsSecrets: false, recoveryAtLeastAsStrongAsLogin: true,
};

const machineOnAws: Architecture = {
  name: 'AWS workload using task/function role', actor: 'workload', publicNetwork: false,
  transport: 'tls-verified', passwordStorage: null, oauth: null, oidc: null, federation: null,
  bearerToken: { storage: 'memory', accessLifetimeMinutes: 5, refreshRotation: true },
  authorization: { serverSide: true, objectLevel: true, tenantBoundary: true },
  aws: { kind: 'service-role', wildcardPermissions: false },
  logsSecrets: false, recoveryAtLeastAsStrongAsLogin: false,
};

function print(findings: Finding[]): void {
  const counts = severityCounts(findings);
  console.log(`  findings: ${findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low})`);
  for (const f of findings) {
    console.log(`\n  [${f.severity.toUpperCase()}] ${f.id} · ${f.threat}`);
    console.log(`    boundary: ${f.boundary}`);
    console.log(`    evidence: ${f.evidence}`);
    console.log(`    fix:      ${f.fix}`);
    console.log(`    learn:    chapter ${f.chapter}`);
  }
}

function main(): void {
  console.log('13 · Threat model: follow trust boundaries, not product names');
  console.log('A finding needs an asset, actor, boundary, attack path, evidence and control.');

  for (const architecture of [insecureSpa, hardenedBff, machineOnAws]) {
    console.log(`\n${architecture.name}\n${'─'.repeat(architecture.name.length)}`);
    const findings = assess(architecture);
    print(findings);
    if (findings.length === 0) {
      console.log('  ✓ no checklist findings. This does NOT mean “secure”: validate implementation, dependencies, abuse cases, recovery, monitoring and operations.');
    }
  }

  console.log('\nPrioritize\n──────────');
  console.log('  1. Critical trust-boundary bypasses: no verifier, wrong issuer/audience, IDOR/tenant escape, leaked permanent key.');
  console.log('  2. High-probability account takeover: phishing, token storage, guessing, refresh theft, stale lifecycle.');
  console.log('  3. Reduce blast radius: short lifetimes, least privilege, per-resource checks, segmentation and tested revocation.');
  console.log('  4. Detect/respond: safe audit identity, anomaly signals, key/token revocation, owner and runbook.');
  console.log('  5. Re-run on design/code/dependency/identity-provider changes. Threat modeling is a loop, not a certificate.');
}

main();
