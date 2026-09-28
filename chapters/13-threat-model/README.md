# 13 · Threat model and decision guide: connect all the controls

> **TL;DR** — Start with assets, actors, data flows and **trust boundaries**, not a shopping list
>of services. For each boundary ask how an attacker can spoof identity, alter/replay messages,
>read secrets, bypass authorization, exhaust resources or erase attribution. Record concrete
>evidence and a control with an owner/test. Prioritize identity-boundary bypass, cross-tenant/object
>access, permanent credentials and recovery before low-impact hardening. The runnable checklist
>flags common mistakes across TLS, passwords, OAuth/OIDC, federation, JWT, application
>authorization and AWS IAM—but zero findings means “the checklist saw none,” never “secure.”

## Why it was invented

Security review by feature list fails. “We use HTTPS, SSO, JWT and MFA” does not answer:

- Does the client verify the TLS hostname, or call with `curl -k`?
- Is MFA phishable TOTP, origin-bound passkey, or bypassed by recovery?
- Does the API accept the OIDC ID token instead of an API access token?
- Does a valid token for Bob authorize Bob to read Alice's object?
- Can any GitHub repository at the issuer assume the AWS role because `sub` is missing?
- Does employee deprovisioning end local sessions and refresh credentials?

Threat modeling developed to make security an engineering activity before incidents. Early
structured risk methods grew from military/safety analysis; software security adopted attack
trees (Bruce Schneier, 1999), Microsoft's STRIDE and threat-modeling process around 1999–2004,
and data-flow/trust-boundary reviews. Modern practices add abuse cases, privacy threat models,
supply-chain analysis and continuous review.

The durable idea is simple: **draw where trust changes, then try to cross each line without the
intended proof or policy.** Controls are responses to named attacks, not badges.

## How it works

### 1. Scope the decision and assets

Write one sentence: “A customer uses a browser to view only their tenant's invoices; employees
administer refunds; a Lambda stores data in S3.” Then list assets by consequence:

| Asset | Failure that matters |
| --- | --- |
| password/passkey/TOTP secret | account takeover; credential reuse elsewhere |
| session/access/refresh token | impersonation until expiry/revocation |
| IdP/KDC/JWT signing key | impersonation across every relying party/service in trust domain |
| AWS access key/role session | AWS actions inside policy blast radius |
| tenant/customer data | confidentiality/integrity/regulatory breach |
| authorization policy/group mapping | privilege escalation across many users |
| recovery/admin interface | bypass stronger primary authentication |
| audit trail | attacker acts without attribution or poisons evidence |
| availability | login/API/KDC/IdP outage blocks business |

Do not label all data “high.” Priority needs relative consequence and realistic attack paths.

### 2. Identify actors and entry points

Actors include customer, employee, administrator, workload, partner IdP, third-party client,
support agent, CI workflow and AWS service—not only “user” and “attacker.” For each, record what
it legitimately controls: browser, device, OAuth client registration, upstream claims, repository
branch, session tags, request object IDs, network path.

Entry points include login, callback, token/userinfo/revoke endpoints, API routes, WebAuthn/MFA
enrollment/recovery, SAML ACS, IdP metadata/JWKS, SCIM, admin APIs, logs/support exports, CI
workflows, role trust, presigned URLs, S3 keys and queue messages.

### 3. Draw data flows and trust boundaries

A boundary is where one side must not take the other side's statement on faith:

```mermaid
flowchart LR
  B[Untrusted browser] -->|TLS + cookie/code| RP[RP / BFF]
  RP -->|authorization request| IDP[IdP / AS]
  IDP -->|signed ID/access token| RP
  RP -->|Bearer access token| API[Resource API]
  API -->|resource ID + verified identity| DB[(Tenant data)]
  API -->|SigV4 temporary role| AWS[AWS service]
  EXT[Partner IdP] -->|SAML/OIDC assertion| BROKER[Federation broker]
  CI[GitHub workflow] -->|OIDC token| STS[AWS STS]

  classDef boundary stroke:#b00,stroke-width:3px;
  B,EXT,CI boundary;
```

For every arrow write:

1. credential/proof (TLS certificate, cookie, code+PKCE, JWT signature, SAML signature, ticket,
   SigV4);
2. freshness/replay control (`state`, `nonce`, `exp`, code single-use, authenticator/replay cache);
3. audience/recipient binding (`aud`, redirect URI, ACS/Audience, SPN, role-trust `sub`);
4. authorization decision (scope, object owner/tenant, IAM action/resource/condition);
5. failure behavior, logging and revocation owner.

### 4. Generate threats

STRIDE is a prompt, not a score:

| STRIDE | Identity example | Control questions |
| --- | --- | --- |
| Spoofing | forged JWT/SAML, stolen cookie, email account-link takeover, wrong TLS server | which key/issuer/audience/subject proves identity? Is holder bound? |
| Tampering | edit group/role claim, OAuth redirect, request object ID, IAM tags | what signature/MAC/server lookup protects it? Who may mutate policy/tags? |
| Repudiation | shared admin account/session name, missing source identity | can audit map to stable actor and trusted session without logging secrets? |
| Information disclosure | bearer token in URL/log/localStorage, TLS disabled, broad S3 prefix | where do secrets/data appear and who can read telemetry/browser/storage? |
| Denial of service | password KDF flood, IdP/KDC outage, JWKS unknown-kid flood, account lockout | limits/cache/HA/backoff and safe degradation? |
| Elevation of privilege | IDOR, copied partner admin group, wildcard IAM role, `iam:PassRole` | is every operation/resource/tenant checked under least privilege? |

Add **replay**, **confused deputy**, **lifecycle**, **recovery**, **supply chain** and **abuse/economic**
cases explicitly; they do not fit neatly enough to leave implicit.

### 5. Turn each threat into a reviewable finding

A useful finding has:

```text
ID + severity
asset and trust boundary
attacker prerequisite and exact path
code/config/runtime evidence (not guess)
impact and blast radius
specific control/fix
owner and due date
verification test and detection/response signal
accepted residual risk, if any
```

“Use best practices” is not a fix. “At `/callback`, store 192-bit `state` server-side keyed by an
HttpOnly transaction cookie, constant-time compare, consume once; add wrong-state integration
test” is.

### 6. Prioritize by path, impact and blast radius

Do not multiply made-up 1–5 numbers and call the result truth. Ask:

- Can it cross authentication/tenant/account boundaries?
- Is exploitation remote, repeatable and unauthenticated?
- Does one compromise affect one session, one tenant, every customer or every AWS account?
- Is the credential permanent or five minutes?
- Is there prevention, detection and tested recovery?
- Does the attacker need a pre-existing privileged foothold?

Suggested order for this domain:

1. No/disabled verification, wrong issuer/audience/redirect, object/tenant authorization bypass,
   leaked permanent AWS/signing credential.
2. Recovery/MFA bypass, token exfiltration, code interception/replay, federation claim/link takeover.
3. Blast-radius reduction: short sessions, least privilege, scoped roles/tokens, network/data
   partitioning.
4. Availability, abuse controls, observability, key/token/session revocation and recovery drills.
5. Lower-impact hardening and operational consistency.

### 7. Verify controls and keep the model alive

A threat is not closed by a design sentence. Test the negative path:

- change one SAML/JWT byte; wrong issuer/audience/type; expired/not-yet-valid;
- wrong OAuth state/nonce/verifier/redirect; replay code/refresh token;
- Bob requests Alice's object; user crosses tenant; partner sends `admin` group;
- wrong CA/hostname/client certificate; old TLS version;
- wrong IAM principal/action/resource/tag/Region; missing MFA key; outside SCP/boundary/session cap;
- deprovision employee while sessions/tokens exist; recover account without normal factor.

Revisit on new IdP/client/tenant, auth method, privilege, data class, third party, AWS account,
network boundary, dependency or incident. Threat modeling is a loop, not a compliance artifact.

### Identity attack/control matrix

| Attack path | Essential prevention | Detection / response | Chapter |
| --- | --- | --- | --- |
| password DB stolen | salted slow memory-hard KDF; managed IdP | credential reset, breach notification, session invalidation | 01 |
| credential stuffing | rate limit, breached-password checks, strong MFA/passkey | anomalous failures/IP/device, account notification | 01/09 |
| network MITM | TLS 1.2+/1.3, trusted chain + SAN, HSTS | certificate/expiry monitoring | 02 |
| JWT claim edit / wrong token | strict algorithm/key/signature/iss/aud/time/type | safe reason/jti logs, key rotation/revocation | 03 |
| Kerberos replay/roasting/key theft | pre-auth, replay cache/time, random managed service keys | ticket anomalies, rotate service/krbtgt correctly | 04 |
| OAuth code theft/login CSRF | exact redirects, state, code one-use, PKCE S256 | failed verifier/replay rate, revoke grants | 05 |
| OIDC token substitution | ID/access separation, nonce, iss/aud/azp/type/at_hash | callback mismatch alerts, session/token revoke | 06 |
| federation account/group takeover | key by `(iss,sub)`, issuer/tenant allowlist, mapped claims | link/admin changes, SCIM disable, broker key response | 07 |
| SAML wrapping/replay | schema + signed-element extraction + Audience/Recipient/InResponseTo/time | request-ID/replay store, cert rotation | 08 |
| TOTP relay/recovery bypass | passkey/security key; replay/rate limit; strong enrollment/recovery | factor changes, push/code abuse, revoke sessions | 09 |
| AWS role assumption/overpermission | temporary roles, exact trust aud/sub, least IAM, boundaries/SCP/RCP | CloudTrail/GuardDuty/Access Analyzer; revoke trust/session path | 10/11 |
| BOLA/tenant escape | object/tenant policy in service/data layer | cross-tenant canaries/audit, incident isolation | 12 |
| secret in logs/supply chain | default redaction; minimal action permissions; SHA pinning/SBOM/review | secret scanning, rotate, provenance/alert | all |

## Run it

The code turns common architectural choices into named, ordered findings:

```bash
npm run 13
npx vitest run chapters/13-threat-model
```

It compares:

1. an intentionally unsafe browser tutorial architecture (TLS verification off, fast hash,
   localStorage day-long bearer, broken OAuth/OIDC/federation/authorization, static wildcard AWS
   key, secret logging, weak recovery);
2. a hardened BFF + managed IdP + scoped API;
3. an AWS workload with role credentials.

A finding includes boundary, attack, evidence, concrete control and chapter pointer. The hardened
examples print zero checklist findings plus the mandatory warning: **this is not proof of
security**. The engine knows only the facts passed into it and covers a deliberately finite list.

Code map:

| File | Purpose |
| --- | --- |
| `src/model.ts` | typed architecture facts and deterministic review rules (including unknown-evidence gaps) |
| `src/demo.ts` | unsafe vs hardened human app vs AWS workload report |
| `src/model.test.ts` | one or more tests per trust boundary/control and severity ordering |

### Use the checklist on a design

Copy the `Architecture` value, but fill each field from evidence. In the code, `undefined`
means **unknown** and emits a `GAP-*` finding; explicit `null` means reviewed and genuinely
not applicable (record the rationale in the design review). This prevents a sparse object from
silently producing a clean report.

- source/config path and line;
- deployed setting/read-only describe output;
- IdP/client registration/export;
- integration test result;
- policy simulation and real sandbox denial;
- owner/runbook.

If unknown, do not mark it secure. Add “verify X” as work; absence of evidence is not evidence of
absence.

## Scenarios

### Consumer web app

Assets: accounts, session/refresh tokens, personal data, recovery. Boundaries: browser↔BFF,
BFF↔IdP, BFF↔API, user↔object. Start with phishing/recovery, XSS/CSRF, callback mix-up and BOLA.
A BFF reduces token exposure but remains vulnerable to same-origin XSS actions and CSRF if cookie
controls fail.

### Multi-tenant SaaS with enterprise federation

Add tenant-admin IdP configuration, home-realm discovery, SAML/OIDC metadata/JWKS, claim mapping,
JIT/SCIM and support account linking. Highest risks: attacker registers their issuer for victim
tenant, email linking, copied `admin` group, cross-tenant query, stale departed user and IdP/broker
key compromise.

### AWS serverless API

Add API Gateway authorizer, Lambda role, DynamoDB/S3 and CI deployment role. Trace two identities:
end-user JWT controls application data; Lambda IAM role controls AWS API. Never treat “Lambda role
can GetItem” as “user may read this row.” Review GitHub OIDC trust, `iam:PassRole`, wildcard
resources, logs, reserved concurrency/abuse and production deletion protections.

### EKS

Separate: human access to Kubernetes API/RBAC; workload service-account identity; EKS Pod
Identity or IRSA to IAM; service-to-service mTLS/network policy; image/supply chain; Secrets;
cluster/node/control plane. “OIDC enabled” could refer to multiple opposite trust directions
(chapter 10 and start map), so name issuer, subject, audience, verifier and resulting authority.

### Incident: signing key or IdP compromised

Plan before it happens:

1. Identify affected issuers, `kid`s, clients/audiences, token max lifetimes and downstream caches.
2. Stop issuance/assumption, remove compromised key/trust carefully, publish replacement while
   preserving known-good rotation where possible.
3. Revoke refresh/session/token families and privileged app sessions; disable compromised account.
4. For IAM, edit role trust/permissions, disable keys, contain sessions via policy changes/SCP;
   investigate CloudTrail. Existing temporary credentials remain bounded by policy and expiry.
5. Query safe identifiers (`jti`, session/source identity, subject) without copying bearer secrets.
6. Restore with staged validation; notify; record timeline/root cause; add tests/detection.

Emergency rotation can create an outage. That is why ownership, cache behavior, overlap and
rollback are part of the threat model.

## Pros and cons

**Pros**

- Finds design bugs before code or deployment makes them expensive.
- Connects a control to a concrete attack and trust boundary.
- Makes assumptions/unknowns visible and testable.
- Prioritizes systemic blast-radius issues over cosmetic hardening.
- Creates shared language across product, security, identity, platform and operations.
- Produces negative tests and incident requirements, not only diagrams.

**Cons**

- Quality depends on accurate architecture/runtime evidence and attacker imagination.
- Can become stale paperwork or a compliance meeting if not tied to owners/tests/changes.
- Checklists miss novel/product-specific threats and can create false confidence.
- Severity is contextual; generic ratings can over/under-prioritize business impact.
- Deep models cost time; scope must match the decision and highest-value paths.
- It cannot replace code review, dependency management, penetration testing, runtime monitoring or
  incident exercises.

## Alternatives

These complement rather than replace one another:

| Technique | Best at | Gap |
| --- | --- | --- |
| architecture threat model / data-flow review | early trust-boundary and systemic design issues | implementation may diverge |
| abuse/misuse cases | product logic, fraud and human workflows | may omit protocol/infrastructure details |
| security code review | concrete implementation and validation bugs | may inherit a flawed architecture |
| SAST/secret/dependency/IaC scanning | repeatable known patterns at scale | context, auth flows and business authorization |
| fuzzing/property testing | parser/state-machine edge cases | needs good oracles and scope |
| penetration/red-team test | exploitable end-to-end paths and detection | point-in-time, limited coverage, later/expensive |
| formal methods | high-assurance protocol/policy invariants | expertise/model cost, implementation link |
| AWS IAM Access Analyzer / policy validation | AWS external access and policy findings | not application identity/object policy |
| attack trees | attacker goals and alternative paths | less natural for full data-flow inventory |
| PASTA/LINDDUN | risk-centric process / privacy threats | heavier process; choose for context |

## Pitfalls

| Pitfall | Result | Better approach |
| --- | --- | --- |
| start with “we use JWT/zero trust” | product name replaces threat/control reasoning | name issuer/verifier/audience/key/policy and attack |
| model only happy path | callback/recovery/logout/deprovision/admin bypass survives | draw error, replay, expiry, recovery and lifecycle flows |
| trust boundaries drawn at service boxes only | browser, CI, partner, logs and data rows disappear | draw every ownership/credential/tenant transition |
| list threats without evidence | speculative report no engineer can close | cite code/config/deployed read/test; label unknown |
| vague fixes | “use encryption/MFA/least privilege” cannot be reviewed | exact setting, algorithm, key, lifetime, policy, test and owner |
| assume authenticated means authorized | BOLA/tenant escape | operation + resource + tenant decision every path |
| assume MFA solves phishing | TOTP relay and weak recovery remain | passkey/security key and equal-strength recovery |
| score arithmetic treated as objective | false precision hides high-blast-radius paths | document prerequisites, impact, reach, duration, controls |
| no owner/deadline/verification | findings age indefinitely | owner, due date, regression test, detection signal |
| “accepted risk” with no expiry | permanent exception | named approver, rationale, compensating controls, review date |
| model never revisited | diagram no longer matches system | trigger on architecture/auth/provider/privilege/incidents |
| zero automated findings = secure | false assurance from incomplete facts/rules | manual review, implementation tests, runtime evidence, adversarial test |
| put secrets into model tickets/screenshots | security document becomes breach source | redact/token fingerprint, restricted evidence, secret manager references |

## Further reading

- NIST SP 800-154, *Guide to Data-Centric System Threat Modeling*: https://csrc.nist.gov/publications/detail/sp/800-154/draft
- NIST SP 800-30, *Guide for Conducting Risk Assessments*: https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final
- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10 (BOLA first): https://owasp.org/API-Security/
- Microsoft Threat Modeling / STRIDE: https://learn.microsoft.com/azure/security/develop/threat-modeling-tool-threats
- Adam Shostack, *Threat Modeling: Designing for Security* (2014).
- Bruce Schneier, *Attack Trees* (1999): https://www.schneier.com/academic/archives/1999/12/attack_trees.html
- MITRE ATT&CK: https://attack.mitre.org/
- CISA Secure by Design: https://www.cisa.gov/securebydesign
- AWS Well-Architected Security Pillar: https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
- AWS IAM Access Analyzer: https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
