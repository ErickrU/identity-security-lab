# Identity & Security Lab

A hands-on map of the identity/security terms that are usually explained as one tangled blob:
passwords and sessions, TLS/SSL/mTLS, opaque tokens and JWT, Kerberos, OAuth 2.0, OpenID Connect,
SSO and federation, SAML, MFA/TOTP/passkeys, AWS IAM vs IAM Identity Center, Cognito User vs
Identity Pools, RBAC/ABAC/ReBAC, and end-to-end threat modeling.

> **TL;DR** — Start at [00 · the map](chapters/00-start-here/). Every chapter answers the same
>questions: why was this invented, what exact problem does it solve, how do the messages/keys work,
>where do you meet it, what are its pros/cons/alternatives, and how does it fail. Every technical
>chapter has runnable code and tests. The shared [small IdP](small-idp/) implements OAuth Code+PKCE,
>refresh and client-credentials grants plus OIDC discovery/JWKS/ID tokens/UserInfo and a real
>relying party/resource API. The two AWS CDK labs synthesize offline; nothing deploys automatically.

## The map in one table

| Layer | Essential answer | Chapter / demo |
| --- | --- | --- |
| Baseline login | slow salted password hash + opaque server session + cookie/CSRF rules | [01](chapters/01-passwords-and-sessions/) |
| Secure channel | TLS certificate chain/name, handshake, confidentiality/integrity, mTLS | [02](chapters/02-tls/) |
| Token representation | opaque lookup vs signed JWT/JWKS, claims, attacks, rotation/revocation | [03](chapters/03-tokens-and-jwt/) |
| Managed-domain SSO | Kerberos AS→TGT→TGS→service ticket→mutual AP exchange | [04](chapters/04-kerberos/) |
| Delegated API authority | OAuth roles, Code+PKCE/state, access/refresh, client credentials | [05](chapters/05-oauth2/) |
| Federated login | OIDC = identity layer on OAuth; ID token/nonce/discovery/JWKS/UserInfo | [06](chapters/06-oidc/) |
| Trust vs experience | federation asks who vouches; SSO asks how many prompts; broker/SCIM/logout | [07](chapters/07-sso-and-federation/) |
| Enterprise federation | SAML metadata/AuthnRequest/signed Assertion/Audience/InResponseTo | [08](chapters/08-saml/) |
| Strong authentication | HOTP/TOTP from RFC vectors, QR enrollment, replay; passkeys/WebAuthn | [09](chapters/09-mfa-totp-passkeys/) |
| AWS workforce/workload | IAM policy evaluation, roles/STS, Identity Center, GitHub OIDC | [10](chapters/10-aws-iam-and-federation/) |
| AWS app users | Cognito User Pool JWTs vs Identity Pool temporary AWS credentials | [11](chapters/11-cognito-pools/) |
| What may happen | scopes vs groups/roles/permissions; RBAC, ABAC, ReBAC | [12](chapters/12-authorization/) |
| Whole-system review | trust-boundary threat model and runnable design checklist | [13](chapters/13-threat-model/) |

The most useful sentence in the repository:

```text
TLS protects the channel. Authentication proves who. Federation chooses who may vouch.
SSO reuses a login. OAuth delegates API authority. OIDC/SAML carry federated identity.
JWT is a token format. Authorization decides the action/resource. IAM decides AWS API requests.
```

## Quick start

Prerequisites: Node.js 20+ and npm. OpenSSL is needed for chapters 02 and 08 (macOS ships one;
`brew install openssl` if yours is missing).

```bash
npm install
npm run typecheck
npm test

npm run 03    # JWT anatomy + naive attacks vs strict verifier
npm run 04    # complete toy Kerberos exchange + failures
npm run 05    # OAuth Code+PKCE, refresh, machine flow
npm run 06    # real localhost OIDC discovery/token/JWKS/UserInfo flow
npm run 07    # SSO session boundaries + federation broker
npm run 09    # TOTP algorithm + replay window (use -- vectors / enroll too)
npm run 12    # RBAC vs ABAC vs ReBAC
npm run 13    # threat-model an unsafe and hardened architecture
```

### Run the small IdP in a browser

Three terminals:

```bash
npm run idp   # http://localhost:4000 — OAuth/OIDC provider (separate cookie host)
npm run api   # http://127.0.0.1:4100 — resource server
npm run rp    # http://127.0.0.1:4001 — relying-party BFF
```

Open http://127.0.0.1:4001. Use `alice` or `bob`, password
`correct horse battery staple`. The provider renders login and consent, the RP performs real
HTTP discovery/code/token/JWKS calls and keeps tokens server-side, and the API verifies its own
audience/type/scope. This is teaching code: localhost HTTP, in-memory state and ephemeral signing
keys. **Never deploy the small IdP.** Use a maintained provider.

### TLS and SAML

```bash
npm run 02:certs
npm run 02:server       # terminal 1
npm run 02:client       # terminal 2: trust, rogue CA, hostname, mTLS cases

npm run 08              # real signed SAML Assertion generated/verified with samlify
```

Chapter 08 intentionally disables XSD schema validation because the native validator is not a
project dependency; its README explains why production SAML **must** validate schema to resist XML
Signature Wrapping. Its signature, issuer, audience, recipient, request, time and tamper checks are
real.

## AWS labs: safe by default

Chapters 10 and 11 contain deployable CDK but tests and normal demos call no AWS API:

```bash
npm run 10             # offline IAM policy-evaluation scenarios
npm run 10:synth       # GitHub OIDC provider + nearly permissionless role template
npm run 11             # offline User Pool → Identity Pool → role → per-user S3 model
npm run 11:synth       # both Cognito pools + S3/IAM template
```

They are not deployed by this repository or CI. Their READMEs contain explicit optional sandbox
lifecycles. Before any deployment, check `aws sts get-caller-identity`; treat an unknown account as
production; do not use these lab deletion policies on persistent data. No production deletion or
safety-protection change is part of this project.

Chapter 10's `.github/workflows/aws-oidc-demo.yml` is manual-only and receives no AWS permission
until a reader explicitly deploys/configures its lab role. The role can only read its own trust
policy. The workflow action is pinned to a commit SHA and specifically verifies an IAM
`AccessDenied`, rather than treating every command failure as success.

## How to read a chapter

Every README follows one structure:

1. **TL;DR** — enough to choose/use/not-use it.
2. **Why it was invented** — the failure of the previous model and history.
3. **How it works** — roles, messages, keys, claims and who verifies each.
4. **Run it** — exact local commands and expected observations.
5. **Scenarios** — web/workforce/workload/AWS mappings.
6. **Pros and cons** — the price of the design.
7. **Alternatives** — same problem, different trade-off.
8. **Pitfalls** — mistake → concrete attack/failure → fix.
9. **Further reading** — RFCs/standards and primary service documentation.

Read by question, not necessarily in numeric order. If terms are blending together, go back to
[chapter 00](chapters/00-start-here/) and locate which layer each term belongs to.

## What is actually implemented

- A password/session JSON server: scrypt, generic login errors/decoy hash, rate limit, cookie flags,
  idle/absolute expiry, session rotation, CSRF synchronizer token, logout invalidation.
- Local CA/server/client/rogue certificates; TLS 1.2 floor/1.3 negotiation; chain + SAN checks;
  mutual TLS authorization.
- Compact RS256/ES256/HS256 JWS and strict JWT claims verifier; deliberately vulnerable `none` and
  RSA/HMAC-confusion verifier; opaque introspection/revocation store.
- Symmetric toy Kerberos with string-to-key, AS pre-auth, encrypted TGT, TGS ticket, AP mutual auth,
  skew/expiry/replay/service-binding checks.
- Small OAuth/OIDC provider and client: exact redirects, state/nonce, PKCE S256, single-use code,
  confidential/public clients, rotating refresh, client credentials, discovery/JWKS/UserInfo,
  introspection/revocation/logout, BFF sessions.
- Federation broker that pins upstream issuer/audience/JWKS, links by `(iss, sub)`, allowlist-maps
  groups and re-issues audience-specific local tokens.
- SAML SP/IdP metadata, Redirect AuthnRequest, POST signed Assertion, real XML signature validation,
  audience/destination/recipient/InResponseTo/time checks and attack cases.
- RFC 4226/6238 HOTP/TOTP and official vectors, replay-aware verifier, QR enrollment; detailed
  WebAuthn/passkey ceremonies.
- IAM evaluation subset with traces, GitHub OIDC CDK role trust, Cognito pool composition with
  identity-specific S3 role policy, and guarded optional live scripts.
- RBAC, ABAC (deny overrides), ReBAC graph/inheritance and claims-to-policy layering.
- Cross-chapter architecture threat checklist with named evidence/control findings.

## Repository layout

```text
chapters/00-start-here/                 map, comparisons, decision trees, glossary
chapters/01-... through 13-.../         one concept family per chapter
small-idp/                              shared OAuth 2.0 + OIDC provider/API/RP
.github/workflows/aws-oidc-demo.yml      optional manual GitHub→AWS OIDC lab
 docs/CHAPTER_TEMPLATE.md                chapter/content/code conventions
package.json                             pinned dependencies and all run commands
```

Dependencies are deliberately small and pinned exactly. Most cryptography/protocol code uses
Node built-ins so the mechanism remains visible. Production guidance is the opposite: use
maintained protocol/security libraries and managed identity services; do not copy teaching
cryptography/authentication servers into production.

## Boundaries and non-goals

- This is education, not professional security certification or a production IdP/KDC/IAM engine.
- The IAM evaluator models a documented subset and clearly lists differences from real IAM.
- Toy Kerberos uses JSON + AES-GCM, not ASN.1 and RFC wire-compatible encryption profiles.
- Local HTTP is used only for localhost OAuth/OIDC visibility; every real deployment requires
  verified TLS.
- No real employee/customer identity, credential or production resource is included.
- AWS deployment and destructive cleanup are always explicit reader actions, never test behavior.
- Dates/service features in prose should be checked against current primary documentation before
  production design; standards links are the durable source.

## Tests

```bash
npm test
```

Tests are offline/deterministic except local loopback servers and local OpenSSL processes. They
cover success and negative paths: wrong keys, signatures, issuer/audience/type/time, redirects,
state/nonce/PKCE, replay, scope, claim mapping, object/tenant policy, IAM boundaries and trust.
CDK assertion tests synthesize in memory; separate synth scripts inspect complete templates.

## Related project

[`jwt-on-aws`](https://github.com/ErickrU/jwt-on-aws) is the smaller deployable example: Cognito
issues real access tokens, API Gateway verifies one route natively and another through an
`aws-jwt-verify` Lambda authorizer, and the demo proves a forged group claim fails.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [the chapter template](docs/CHAPTER_TEMPLATE.md).
Keep TL;DR complete, then go deep; demonstrate a failure, not only a happy path; cite primary
standards; keep tests offline; do not add deployment side effects to tests.

## License

MIT — see [LICENSE](LICENSE).
