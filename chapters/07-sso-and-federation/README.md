# 07 · SSO and federation

> **TL;DR** — Single sign-on (SSO) answers **“how many authentication prompts?”** Federation answers **“who vouches for this identity?”** They are orthogonal. Web SSO works by redirecting each app to an identity provider (IdP), where the browser can reuse the IdP's own session cookie; each app still creates a separate local session. Federation extends trust across security domains, but only when a relying party or broker pins the upstream issuer, audience, and keys. Link accounts by `{issuer, subject}`, map claims through explicit policy, and issue local credentials instead of forwarding an upstream token blindly.

## Why it was invented

Early systems kept a password and session for every application. Users signed in repeatedly, password resets multiplied, and removing one employee meant finding every account. Enterprise SSO centralized authentication: Kerberos brought ticket-based SSO to networked organizations in the 1980s, so a workstation login could obtain service tickets without sending a password to every server.

That did not solve cross-organization trust or unrelated web domains. A cookie for `idp.example` is not readable by `app.example.net`, much less by a partner. Browser redirects supplied the bridge: an app sends the browser to an IdP, the browser sends only the IdP's cookie to that IdP, and the IdP returns a signed result for the app.

The standards evolved around those needs:

| Period | Development | Problem addressed |
|---|---|---|
| 1980s–2005 | Kerberos enterprise SSO; Kerberos V5 later standardized in RFC 4120 | Reuse a workstation login for services in a managed realm |
| Early 2000s | WS-Federation and related WS-* specifications | SOAP-era identity federation and passive browser sign-in |
| 2005 | SAML 2.0 became an OASIS Standard | Cross-domain enterprise web federation with signed XML assertions |
| 2005–2007 | OpenID 1.x/2.0 | User-chosen web identity providers; authentication without a shared app password |
| 2014 | OpenID Connect 1.0 | Authentication and identity claims on top of OAuth 2.0 using JSON/JOSE |

Centralization improves control, but it also creates a critical dependency. An IdP outage blocks new sign-ins and token renewal. An IdP or signing-key compromise can enable impersonation across every connected relying party. The IdP is both an availability dependency and a crown-jewel security boundary.

## How it works

### SSO and federation are orthogonal

| | One identity domain vouches | Another identity domain vouches (federation) |
|---|---|---|
| **A reusable login suppresses prompts (SSO)** | Corporate apps redirect to one corporate IdP, or services share a Kerberos realm | A user already signed in at a partner IdP enters a SaaS tenant through a broker without another password prompt |
| **No reusable login; a prompt occurs** | An app forces fresh authentication for a sensitive action | Social/partner login is accepted, but the upstream requires authentication on this visit |

Neither implies the other. Federation can still prompt. SSO can stay entirely inside one organization. A design must state both the trust path and the session behavior.

### Web SSO: redirects bridge domains

Unrelated sites cannot read each other's cookies. That isolation is a security property, not an SSO transport. Instead, the browser visits each domain in turn:

```mermaid
sequenceDiagram
  participant U as Browser
  participant A as App A
  participant I as Identity provider
  participant B as App B

  U->>A: Visit without App A session
  A-->>U: Redirect to IdP
  U->>I: Authorization request; no IdP session
  I->>U: Authenticate once; set IdP cookie
  I-->>U: Return signed result/code for App A
  U->>A: Callback
  A->>A: Verify result; create App A session
  U->>B: Visit without App B session
  B-->>U: Redirect to IdP
  U->>I: Authorization request + IdP cookie
  I-->>U: Return result without another password prompt
  U->>B: Callback
  B->>B: Verify result; create App B session
```

Three sessions can now exist:

1. The **IdP session** remembers primary authentication at the IdP.
2. The **App A session** represents App A's local authorization state.
3. The **App B session** represents App B's local authorization state.

They have different cookies, domains, lifetimes, and revocation rules. App A logout normally removes only App A's session. IdP logout prevents later silent authentication, but it does not reach backward and erase sessions already created by A and B.

OIDC Authorization Code Flow and SAML Web Browser SSO carry the result differently, but the browser-redirect and local-session pattern is the same. Browser privacy controls can constrain embedded or third-party-cookie techniques; top-level redirects do not require an app to read the IdP cookie.

### Federation: a configured trust triangle

Federation crosses an administrative boundary:

```text
upstream/home IdP  --signed assertion or ID token-->  broker/service provider
       |                                                   |
       +---- authenticates and manages the user            +---- issues a local session/token
                                                           |
                                                  downstream app or API
```

The three parties need explicit contracts:

- The upstream IdP authenticates a subject and signs claims.
- The broker or relying party pins the upstream `issuer`, expected `audience`, protocol, algorithms, and verification keys.
- The downstream app trusts the broker's issuer and keys, not every upstream issuer.

The broker in [`src/federation.ts`](src/federation.ts) follows that boundary:

1. Select a **preconfigured** upstream by exact issuer. A token-provided URL never chooses a JWKS endpoint.
2. Verify signature, algorithm, `iss`, broker-facing `aud`, and `exp` against that upstream's pinned JWKS.
3. Require OIDC Core `sub`, `iat`, `exp`; apply `aud`/`azp` rules. `typ` and provider-specific
   `token_use` are optional, but when present they must describe an ID token.
4. Resolve/JIT-provision a local account by the compound identity `{iss, sub}`.
5. Map upstream groups through an explicit per-upstream allowlist.
6. Mint new downstream ID and access JWTs with the broker's key, issuer, local subject, and registered audiences. Their lifetime cannot exceed the upstream token's remaining lifetime.

The upstream ID token is evidence presented to the broker. It is not forwarded as a local bearer credential. The local app trusts only the broker's JWKS and policy. The lab's `exchange()` method demonstrates verification and re-issuance in process; it is not a complete network implementation of OAuth Token Exchange (RFC 8693).

### External identity lookup: `{issuer, subject}`, not email

OIDC defines `sub` only within an issuer's namespace. The stable external key is therefore:

```text
(iss = "https://id.partner.example", sub = "248289761001")
```

A bare `sub` can collide across issuers. Email is worse: it can change, be recycled, vary in normalization, be unverified, or be asserted by an attacker-controlled issuer. Equal email strings are useful profile data only after explicit validation; they are not proof that two identities belong to the same person.

JIT account lookup/provisioning should use `{iss, sub}`. This creates one local account per external
identity; it does **not** link several identities together. Merging an external identity with an
existing local account is a separate, high-assurance account-linking workflow: authenticate both
accounts, require recent authentication, record the association, notify the user, and offer recovery. Home-realm discovery may ask for an email domain, organization slug, or tenant selection to choose a configured IdP, but that routing hint is still not an account key.

### Claims are input; authorization is local policy

Federated attributes cross a trust boundary. Names and email addresses are usually profile data. Groups, roles, tenant IDs, assurance levels, and entitlements affect authorization and need tighter rules.

This chapter maps only named upstream values, such as partner `employees` → local `reader`. Unknown values grant nothing. It never copies `admin` because the upstream says `admin`. Good mapping policy also constrains the issuer, tenant, claim type, allowed values, target role, and default behavior. The downstream resource server authorizes from the broker's verified local access token, not from decoded upstream JSON.

### Home-realm discovery and topology

When several IdPs are valid, the service must decide where to send the user. Common discovery inputs include a tenant-specific URL, organization code, previously selected IdP, and a verified domain mapped to an organization. Avoid an open `issuer=` parameter and avoid fetching discovery/JWKS from a token claim: both turn trust selection into attacker input.

| Topology | Shape | Benefits | Costs |
|---|---|---|---|
| Direct federation | Every relying party trusts every upstream | Fewer intermediaries; each party controls policy | Roughly `N × M` integrations, duplicated mappings, difficult key/metadata changes |
| Broker / hub-and-spoke | Upstreams trust a hub; apps trust the hub | Roughly `N + M` integrations, one local token shape, central policy | Hub outage and compromise have broad impact; mappings can hide upstream nuance |

Federation loops are possible when brokers point at one another. Track the original issuer and federation path, set hop limits, and reject a route that returns to an issuer already in the path.

### Authentication is not lifecycle provisioning

| Model | Trigger | What it does well | Gap |
|---|---|---|---|
| Just-in-time (JIT) provisioning | First successful federated login | Low setup cost; account appears when needed | A departed user may remain locally enabled; no login means no profile/group update |
| SCIM lifecycle provisioning | Directory pushes create/update/disable/group events | Pre-provisioning, deprovisioning, and group lifecycle independent of login | Another privileged integration, token, mapping, retry path, and reconciliation process |

SAML or OIDC answers authentication. SCIM answers lifecycle synchronization. They are often paired, not interchangeable. A directory stores users/groups and lifecycle data; an IdP performs authentication and issues assertions/tokens. One product may provide both roles, but the concepts and failure modes remain distinct.

### Why single logout is difficult

Single logout (SLO) must find and invalidate the IdP session, every relying-party session, native-app tokens, refresh tokens, API sessions, and possibly sessions at another broker. Front-channel logout depends on browser navigation, frames, and cookies. Back-channel logout needs registered endpoints, delivery, retries, and correlation. A device can be offline. One participant can fail.

Treat logout as a distributed revocation workflow, not an atomic delete. Use short lifetimes, refresh-token rotation/revocation, back-channel notifications where supported, local session controls, and a clear UI that distinguishes **log out of this app** from **log out of the identity provider**. High-risk account disablement also needs lifecycle and resource-side revocation; waiting for a user to log in again is not deprovisioning.

## Run it

From the repository root:

```bash
npm run 07
```

The in-process demo makes no network calls. It shows:

- one password entry at App A, then silent SSO at App B through the shared IdP session;
- separate App A, App B, and IdP sessions and their independent logout behavior;
- a trusted partner ID token being verified, group-mapped, and replaced with broker-signed local ID/access tokens;
- rejection of an attacker issuer with the same email, issuer-scoped JIT identity lookup, and refusal to promote an unallowlisted `admin` group.

Run this chapter's tests and the repository type check:

```bash
npx vitest run chapters/07-sso-and-federation
npx tsc
```

The tests are offline. They use a fixed clock and assert behavior rather than random key/token bytes.

| File | Purpose |
|---|---|
| [`src/federation.ts`](src/federation.ts) | Typed trust configuration, upstream verification, compound external-identity lookup/JIT account provisioning, claim mapping, and downstream re-issuance |
| [`src/demo.ts`](src/demo.ts) | Narrative SSO/session and federation walkthrough |
| [`src/federation.test.ts`](src/federation.test.ts) | SSO independence and positive/negative federation trust tests |

## Scenarios

| Scenario | Typical trust and session shape | Important policy |
|---|---|---|
| B2E workforce | Employees authenticate at a workforce IdP and reach many internal/SaaS apps with SSO | Joiner/mover/leaver lifecycle, phishing-resistant MFA, device/risk policy, privileged-role separation |
| B2B partner | Customer trusts selected partner IdPs directly or through a broker | Contracted issuer/tenant allowlist, partner-specific claim mapping, expiration and offboarding |
| B2C social login | Consumer app accepts Google, Apple, or another social IdP and creates its own account/session | Deliberate linking/recovery, minimal claims, issuer+subject identity, provider outage fallback |
| Multi-tenant SaaS | Each tenant configures one or more home IdPs; SaaS issues tenant-local sessions/tokens | Tenant-bound discovery, no cross-tenant linking, tenant-specific groups/domains, safe admin setup |

### AWS mapping

| AWS service/pattern | Mapping to this chapter |
|---|---|
| **IAM Identity Center** | Workforce SSO across AWS accounts and applications. Permission sets define centrally managed access that becomes account roles. An external IdP can authenticate users with SAML 2.0 while SCIM provisions users/groups and deprovisions lifecycle state. Its OIDC interfaces support client registration and device authorization; AWS CLI Identity Center sign-in can use browser-based PKCE or device authorization for constrained terminals. |
| **Amazon Cognito user pool** | A user directory and OIDC/OAuth issuer that can broker Google, Apple, other social providers, OIDC, and SAML upstreams. After federation it issues Cognito user-pool JWTs to the app—the same “verify upstream, map, issue local token” shape as this lab. |
| **Amazon Cognito identity pool** | Different from a user pool. It accepts identities from configured providers and obtains temporary AWS credentials for authorized roles. It is primarily an AWS-credential federation/authorization bridge, covered in chapter 11; it is not the user directory or ordinary app-session issuer. |
| **IAM SAML federation + AWS STS** | `AssumeRoleWithSAML` exchanges a trusted SAML assertion for temporary AWS role credentials. Trust policy and provider configuration define who may vouch and which role may be assumed. |
| **IAM OIDC federation + AWS STS** | An IAM OIDC provider and role trust policy let `AssumeRoleWithWebIdentity` exchange a verified web identity token for temporary AWS credentials. Pin provider, audience, subject, and other conditions rather than accepting any tenant. |
| **Amazon EKS OIDC** | Three ideas are easy to confuse: an EKS cluster's OIDC issuer signs Kubernetes service-account tokens; an IAM OIDC provider can trust that issuer for IRSA and STS; optional external OIDC user authentication to the Kubernetes API is a separate workforce-login path. None is automatically an application's end-user SSO system, and IAM/EKS access entries are another authorization layer. |

**Keep these boundaries explicit:**

- **IAM Identity Center vs IAM:** Identity Center supplies workforce sign-in, assignments, a portal, and permission sets across accounts/apps. IAM supplies AWS principals, roles, policies, and identity-provider trust within AWS authorization. Federated Identity Center sessions eventually use IAM roles, but IAM alone is not the workforce SSO lifecycle experience.
- **Cognito user pool vs identity pool:** a user pool authenticates users and issues app JWTs; an identity pool maps configured identities to temporary AWS credentials. They can be composed but solve different layers.
- **IdP vs directory:** a directory is the identity/lifecycle data source; an IdP authenticates and vouches with signed protocol messages. A single service can implement both.

Amazon employees may encounter names such as **Federate** and **Midway** in corporate sign-in/access paths. At the level appropriate for public discussion, they are workforce access touchpoints. This lab makes no claim about their internal architecture, protocols, controls, or policy.

## Pros and cons

**Pros**

- One strong authentication policy can protect many apps, reducing repeated password handling.
- Federation lets organizations retain control of their own identities and authentication factors.
- Central lifecycle, conditional access, audit, and claim mapping can be applied consistently.
- A broker reduces integration count and gives local apps one issuer and claim vocabulary.
- Short-lived, audience-bound local tokens reduce unnecessary sharing of upstream credentials.

**Cons**

- The IdP or broker becomes an availability dependency and a high-value attack target.
- A bad trust rule or compromised signing key has a much larger blast radius than one app account.
- Claim semantics, assurance, logout, recovery, and deprovisioning differ across domains.
- Direct federation scales poorly; brokerage centralizes operational and policy risk.
- Browser privacy controls, native clients, legacy apps, and partial logout make session behavior hard to explain.

## Alternatives

| Alternative | Choose it when |
|---|---|
| Separate local accounts | The app is isolated, federation cost exceeds benefit, and local credential/lifecycle operations are acceptable |
| Shared first-party session service | Apps are under one controlled domain/product and do not need cross-organization identity trust |
| Kerberos | Managed enterprise devices and services share realm infrastructure and ticket-based network SSO is the primary need |
| Direct SAML/OIDC federation | There are few counterparties and each relying party needs direct control over metadata and mappings |
| Federation broker | Many upstream IdPs and many local apps need a stable local issuer, discovery, and centralized mapping |
| OAuth Token Exchange (RFC 8693) | Services need a standardized security-token exchange/delegation endpoint, not merely browser authentication |
| Client certificates / workload identity | The actor is a service or device rather than a human; do not force human SSO concepts onto workloads |
| SCIM without login federation | Central lifecycle synchronization is needed while authentication remains local or uses another mechanism |

## Pitfalls

| Mistake | What it enables or breaks | Safer rule |
|---|---|---|
| Link accounts by email | Account takeover through unverified, changed, recycled, normalized, or attacker-issuer email | Key external identities by exact `{issuer, subject}`; make merges an authenticated workflow |
| Copy upstream groups/roles | Group injection and privilege escalation, especially for names such as `admin` | Per-issuer allowlist mapping; unknown values grant nothing |
| Accept any issuer or tenant | An attacker creates a tenant/IdP, signs a valid token, and becomes a trusted user | Configure exact issuers, tenants, audiences, algorithms, and keys |
| Let token `iss`, discovery URL, or request parameters choose JWKS | Server-side request forgery or attacker-selected verification keys | Select trust configuration first; compare token issuer afterward |
| Trust IdP-initiated login without transaction binding | Login CSRF/session swapping: a victim can be logged into the attacker's account | Prefer relying-party-initiated flows; bind state/nonce/request IDs and intended tenant |
| Treat JIT login as lifecycle provisioning | Departed users and stale entitlements remain active until another login—or forever | Use SCIM/reconciliation and explicit disable/revocation paths |
| Assume local logout is global | Other apps and the IdP remain signed in; users misunderstand exposure | State the logout scope; implement tested front/back-channel mechanisms where required |
| Build federation loops | Redirect storms, repeated token exchange, unclear original trust source | Record origin/path, reject repeats, and cap federation hops |
| Permit open post-login redirects or unvalidated `RelayState` | Token/code leakage and phishing through a trusted domain | Exact redirect URI allowlists and integrity-bound return state |
| Ignore upstream authentication strength | A weak or phishable upstream login becomes the easiest path into every downstream app | Contract and verify assurance context where meaningful; require step-up for sensitive actions |
| Centralize without isolation and recovery | IdP/broker compromise or outage creates a giant blast radius | Protect signing keys, least privilege, staged changes, monitoring, tested recovery, and break-glass controls |
| Confuse ID and access tokens | APIs accept identity claims intended for a client, bypassing audience/scope policy | Clients verify ID tokens; resource servers accept only access tokens for their own audience |
| Forward upstream bearer tokens to local services | Every service must trust every upstream and upstream privileges leak across boundaries | Re-issue short-lived, audience-specific local credentials after policy mapping |

## Further reading

**Protocol and security standards**

- [Kerberos V5 — RFC 4120](https://www.rfc-editor.org/rfc/rfc4120)
- [SAML 2.0 Core — OASIS Standard](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) and [SAML 2.0 Profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [WS-Federation 1.2 — OASIS Standard](https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), including issuer/subject identifiers and ID-token validation
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Authorization Framework — RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and [OAuth 2.0 Security Best Current Practice — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)
- [OAuth 2.0 Token Exchange — RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)
- [SCIM Protocol — RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) and [SCIM Core Schema — RFC 7643](https://www.rfc-editor.org/rfc/rfc7643)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) and [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)

**AWS primary documentation**

- [IAM Identity Center: external identity providers](https://docs.aws.amazon.com/singlesignon/latest/userguide/external-idps.html), [SCIM profiles](https://docs.aws.amazon.com/singlesignon/latest/developerguide/scim-profile-saml.html), and [OIDC API overview](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/Welcome.html)
- [AWS CLI: configure IAM Identity Center](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [Amazon Cognito user-pool federation](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-identity-federation.html) and [identity pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html)
- [IAM SAML federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html), [IAM OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html), [`AssumeRoleWithSAML`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html), and [`AssumeRoleWithWebIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
- [EKS IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) and [authenticate users with an OIDC identity provider](https://docs.aws.amazon.com/eks/latest/userguide/authenticate-oidc-identity-provider.html)
