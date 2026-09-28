# 11 · Cognito User Pools and Identity Pools

> **TL;DR** — A **User Pool** is a customer/user directory and authentication
> service. It verifies sign-in and issues OAuth/OIDC ID and access-token JWTs.
> An **Identity Pool** is an identity broker: it accepts proof from a User Pool
> or another provider and returns short-lived AWS credentials. It stores no
> passwords. Compose them only when a browser or mobile client must call AWS
> services directly; otherwise, keep AWS credentials behind an API backend.

## Why it was invented

A browser or mobile application sometimes needs direct access to S3, DynamoDB,
or another AWS API. Long-term IAM access keys cannot be embedded in an app: every
installation would share a recoverable secret, rotation would be difficult, and
a leaked key could outlive the user session. Cognito federated identities, now
called **Identity Pools**, were introduced with Amazon Cognito in 2014 to exchange
external identity proof for scoped, temporary AWS credentials.

That solved AWS credential vending, not customer account management. Applications
still needed registration, password handling, account recovery, MFA, and an
OAuth/OIDC issuer. OAuth 2.0 was standardized in 2012 and OpenID Connect in 2014;
Cognito **User Pools** arrived in 2016 to provide that managed user directory and
token issuer. Both products kept the Cognito name, even though their jobs and
outputs are different. The most common Cognito design error is treating them as
two versions of one pool.

This lab composes both services while preserving the boundary:

- The User Pool authenticates `alice` and `bob` and issues tokens for a public
  app client.
- The Identity Pool accepts a User Pool ID token and assigns a Cognito identity
  ID.
- Cognito Identity obtains temporary credentials for one authenticated IAM role.
- The role can list, read, and write only the S3 prefix named by that identity ID.
- The User Pool `admins` group remains an **application** group. It grants no AWS
  permission and has no Identity Pool role mapping.

## How it works

### Two services, different contracts

| Question | User Pool | Identity Pool |
|---|---|---|
| Primary job | User directory and authentication | Federation to temporary AWS credentials |
| Stores passwords? | Yes, when local users are used | No |
| OAuth/OIDC issuer? | Yes | No |
| Accepts identity proof? | Passwords, passkeys/MFA, social or enterprise federation | User Pool token, social/OIDC/SAML token, developer identity, or optional guest state |
| Main output | ID/access JWTs and a refresh token | Identity ID and temporary AWS credentials |
| Calls AWS APIs for the app? | No | Enables the app to sign allowed AWS requests |
| Authorization boundary | App/API verifies token and claims | IAM role trust and permissions |

A User Pool can be used without an Identity Pool. That is the normal shape when
a client calls an application API and the backend alone calls AWS services. An
Identity Pool can also use providers other than a User Pool. Composition is a
choice, not a required Cognito setup.

### Composition flow

```mermaid
sequenceDiagram
    participant C as Browser/mobile/CLI
    participant UP as Cognito User Pool
    participant IP as Cognito Identity Pool
    participant IAM as IAM/temporary credential service
    participant S3 as S3

    C->>UP: InitiateAuth(username, password)
    UP-->>C: ID JWT + access JWT + refresh token
    C->>IP: GetId(Logins = provider: ID JWT)
    IP-->>C: identity ID (region:uuid)
    C->>IP: GetCredentialsForIdentity(identity ID, Logins)
    IP->>IAM: Assume authenticated role
    IAM->>IAM: Check aud and authenticated amr
    IAM-->>IP: Short-lived access key, secret, session token
    IP-->>C: Temporary AWS credentials
    C->>S3: SigV4 PutObject(identity-id/file)
    S3->>S3: Substitute identity ID into IAM policy
    S3-->>C: Allow own prefix; deny another identity's prefix
```

The deployed lab uses the Identity Pool **enhanced flow**:

1. `InitiateAuth` sends credentials to the User Pool's public app client. The
   deliberately simple CLI client enables `USER_PASSWORD_AUTH`; it has no client
   secret.
2. The User Pool returns an ID-token JWT. Its `iss` identifies the User Pool and
   its token `aud` identifies the app client.
3. `GetId` receives that ID token in the `Logins` map under
   `cognito-idp.<region>.amazonaws.com/<user-pool-id>`. It validates the configured
   provider relationship and returns an Identity Pool identity ID.
4. `GetCredentialsForIdentity` receives the identity ID and provider login. The
   Identity Pool selects the authenticated role and obtains temporary credentials.
5. The client uses the three credential fields with AWS Signature Version 4
   (SigV4). It does **not** receive another application JWT.
6. S3 evaluates the role policy for every request. IAM substitutes the Cognito
   identity ID into the policy variable at authorization time.

The older **classic flow** enables `GetOpenIdToken`, then has the client call
`AssumeRoleWithWebIdentity` itself. This stack sets `allowClassicFlow: false` and
uses the simpler enhanced flow, where Cognito Identity chooses the configured
role and returns credentials from `GetCredentialsForIdentity`.

### Do not mix up the artifacts

| Artifact | Shape | Issuer/owner | Purpose | Is it a credential? |
|---|---|---|---|---|
| ID token | Signed JWT | User Pool | Identity/profile claims; provider proof for this lab | Bearer token, but not an AWS access key |
| Access token | Signed JWT | User Pool | OAuth scopes and API authorization | Bearer token for an API |
| Refresh token | Opaque bearer value | User Pool | Ask the User Pool for fresh ID/access tokens | Yes; do not send it to APIs |
| User Pool `sub` | UUID claim | User Pool | Stable user identifier inside that User Pool | No |
| Identity ID | `<region>:<uuid>` | Identity Pool | Identity record and IAM session context | No |
| `accessKeyId` + secret + session token | Three temporary values | AWS credential service through Cognito Identity | SigV4 signing for AWS APIs until expiration | Yes |

The User Pool ID token's `aud` is the **app client ID**. The IAM trust condition
`cognito-identity.amazonaws.com:aud` is a different context key whose value is
the **Identity Pool ID**. Neither value is interchangeable with a User Pool ID.

### Role trust is the first AWS boundary

The authenticated role trusts only Cognito Identity, only for this Identity Pool,
and only for an authenticated session:

```json
{
  "Principal": { "Federated": "cognito-identity.amazonaws.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "cognito-identity.amazonaws.com:aud": "<identity-pool-id>"
    },
    "ForAnyValue:StringLike": {
      "cognito-identity.amazonaws.com:amr": "authenticated"
    }
  }
}
```

Without `aud`, another Identity Pool could try to use the role. Without the
`authenticated` `amr` condition, a guest identity could cross the role boundary.
The `aud` and `amr` keys are static strings in this stack, so `CfnJson` is not
needed; the token appears in the condition **value**.

### Per-identity S3 isolation is the second boundary

Every authenticated user receives the same role, but each role session carries a
Cognito Identity context key. The policy keeps this IAM variable literal:

```text
${cognito-identity.amazonaws.com:sub}
```

For Cognito Identity credentials, that value is the Identity Pool identity ID.
The role permits:

```text
s3:ListBucket only when s3:prefix matches
  ${cognito-identity.amazonaws.com:sub}/*

s3:GetObject and s3:PutObject only on
  arn:...:s3:::<bucket>/${cognito-identity.amazonaws.com:sub}/*
```

The slash is a security boundary. A plain string-prefix check for `alice-id`
would also match `alice-id-attacker`; `${identity-id}/` does not. The stack uses a
normal literal string rather than `Fn::Sub`, so CloudFormation leaves the IAM
variable for request-time policy evaluation.

The bucket also blocks all public access, requires TLS, uses S3-managed encryption,
and has no role permission for `DeleteObject`, bucket administration, or another
identity's prefix.

### Groups and role mappings are separate decisions

User Pool groups appear in token claims such as `cognito:groups`; that does not
make an IAM role trust arbitrary group text. Identity Pool role selection can be
configured with `RoleMappings`:

- A **token** mapping can use Cognito role claims such as `cognito:preferred_role`.
- A **rules** mapping can select roles from configured claim comparisons.
- `AmbiguousRoleResolution` decides whether multiple/no clear matches are denied
  or fall back to the authenticated role.

Those mappings need explicit trusted-provider configuration, least-privilege
roles, and tests for ambiguous claims. This lab intentionally defines no role
mapping. `alice` may be in `admins`, but both users receive the same authenticated
role and remain isolated by identity ID. Use `cognito:groups` in an API's verified
application authorization only; do not turn an app group into broad AWS admin
permissions by assumption.

### Other Identity Pool modes

**Unauthenticated identities** let a guest obtain credentials before sign-in.
They require a separate unauthenticated role and a very small permission set.
This stack sets `allowUnauthenticatedIdentities: false`, has no guest role, and
requires `amr=authenticated` in trust.

**Developer-authenticated identities** let a trusted backend assert identities
from a custom system through `GetOpenIdTokenForDeveloperIdentity`. That API and
its developer credentials belong on the trusted backend, never in browser or
mobile code. Identity Pools can also accept supported social, OIDC, and SAML
providers. Each provider relationship and role path is part of the security
boundary.

### Direct AWS access changes the threat model

Temporary does not mean harmless. Browser or mobile code can be inspected, and a
compromised runtime can exfiltrate credentials until they expire. The IAM policy,
not UI logic, must contain the blast radius. CORS is not authorization. S3 object
names are attacker-controlled input. Logging, analytics, crash reports, and
`localStorage` must not receive tokens or AWS credential values.

Prefer an API backend when operations need business validation, cross-user data,
privileged transactions, central rate limits, or an audit decision richer than
IAM can express. Direct Identity Pool credentials are best for narrow,
high-volume client operations that IAM can describe safely, such as one user's
upload prefix.

## Run it

Everything except the live script is offline and deterministic. From the
repository root:

```bash
npx tsx chapters/11-cognito-pools/src/demo.ts
npx vitest run chapters/11-cognito-pools
npx tsc
```

The offline demo narrates successful composition and rejects a wrong Identity
Pool audience, unauthenticated `amr`, bob reading alice's prefix, and expired
credentials. `src/policy.ts` is a teaching simulator, not an IAM replacement.
The tests also synthesize the stack in memory and assert the security properties.

Synthesize the deployable template without contacting AWS:

```bash
cd chapters/11-cognito-pools
npx cdk synth --quiet
```

Inspect `cdk.out/LabCognitoPools.template.json`. Look for:

- one `AWS::Cognito::UserPool` and one `AWS::Cognito::IdentityPool`;
- `AllowUnauthenticatedIdentities: false`;
- `AWS::Cognito::IdentityPoolRoleAttachment` with only `authenticated`;
- `sts:AssumeRoleWithWebIdentity` plus exact `aud` and `amr` conditions;
- the literal `${cognito-identity.amazonaws.com:sub}/*` in both S3 statements.

### Optional live AWS lab — the reader deploys, not the tests

**This mutates an AWS account and can incur charges. Use a dedicated sandbox,
verify the selected account/Region and credentials, and never point this lab at
production.** The stack deliberately has deletion protection off and uses
`DESTROY` removal policies. No test or offline demo invokes these commands.

From this chapter directory, the exact lifecycle is:

```bash
npx cdk deploy --outputs-file cdk-outputs.json
npx tsx scripts/live-demo.ts --confirm-lab
npx cdk destroy
```

The explicit flag acknowledges that `scripts/live-demo.ts` mutates the deployed
lab. It reads `cdk-outputs.json`, creates or resets `alice` and `bob`, adds alice
to the application-only `admins` group, authenticates both users, runs
`GetId` → `GetCredentialsForIdentity`, and writes/reads one object under each
identity ID. It then asks bob to read alice's object and requires S3 to return
`AccessDenied`. It prints identity IDs and expiration times, but never prints a
full JWT, access key, secret key, or session token.

If deployment or the live demo fails, do not skip cleanup. Run `npx cdk destroy`
with the same account, Region, and profile used to deploy. Confirm the stack is
gone before discarding `cdk-outputs.json`.

### Code map

| File | Purpose |
|---|---|
| `bin/app.ts` | Environment-agnostic CDK entry point for `LabCognitoPools` |
| `lib/cognito-pools-stack.ts` | Pools, client, group, role trust/policy, bucket, role attachment, outputs |
| `src/policy.ts` | Offline trust and per-prefix authorization simulator |
| `src/demo.ts` | Safe narrated flow and denial cases; no AWS calls |
| `src/policy.test.ts` | Deterministic trust, prefix, cross-user, and expiry tests |
| `src/cognito-pools-stack.test.ts` | Offline synthesized-template security assertions |
| `scripts/live-demo.ts` | Explicitly invoked deployed-lab integration demo |

## Scenarios

### Use both pools

- A mobile photo app authenticates customers in a User Pool and uploads directly
  to `s3://bucket/<identity-id>/...` with an Identity Pool role.
- A browser app needs a narrow AWS AppSync, IoT, or S3 operation whose complete
  authorization boundary can be expressed in IAM.
- Existing social/OIDC users need temporary AWS credentials without receiving
  durable IAM users or keys.

### Use a User Pool only

- A web client calls API Gateway or an application backend with an access token;
  Lambda or the service role accesses AWS resources.
- The app needs registration, sign-in, account recovery, MFA, and OIDC tokens,
  but clients should never hold AWS credentials.
- API authorization uses verified scopes or claims. See
  [Chapter 03: Tokens and JWT](../03-tokens-and-jwt/README.md),
  [Chapter 05: OAuth 2.0](../05-oauth2/README.md), and
  [Chapter 06: OpenID Connect](../06-oidc/README.md).

### Do not use Cognito pools

- For employee/workforce access to AWS accounts and applications, use IAM
  Identity Center or the organization's workforce federation, not a customer
  User Pool.
- For service-to-service AWS access, use workload IAM roles, not customer
  identities.
- If every operation needs server-side business rules, expose an API and keep
  its execution-role credentials on the backend.
- Amazon corporate workforce mechanisms such as Federate/Midway solve a different
  problem; Cognito pools are not a substitute for employee identity systems.

AWS Amplify can configure User Pool sign-in, Identity Pool federation, credential
refresh, and client SDK calls behind higher-level APIs. That improves application
developer ergonomics but does not change the trust policy or IAM boundary.
Inspect the generated Cognito and IAM resources rather than treating Amplify as a
security boundary.

### AWS identity choices

| Service | Intended identity | Authenticates users? | Main output | Use it for |
|---|---|---|---|---|
| Cognito User Pool | Application customers | Yes | OIDC/OAuth tokens | Sign-up/sign-in and app/API identity |
| Cognito Identity Pool | Federated app users/guests | No password directory | Temporary AWS credentials | Narrow direct AWS access from an app |
| IAM Identity Center | Workforce | Federates workforce authentication | Workforce app/account sessions | Employee access to AWS accounts and business apps |
| IAM | Workloads and AWS principals | Evaluates AWS principal credentials/policies | Authorized AWS requests | Roles, policies, and service-to-service access |

[Chapter 10: AWS IAM and federation](../10-aws-iam-and-federation/) goes deeper
on AWS role federation. [Chapter 12: Authorization](../12-authorization/README.md)
compares authorization models. The sibling
[`jwt-on-aws`](https://github.com/ErickrU/jwt-on-aws) project demonstrates a User Pool
JWT issuer and API authorizers without adding an Identity Pool; this chapter
adds the separate AWS credential-broker side.

## Costs and cleanup

This lab is not guaranteed to be free. User Pool usage, optional messaging or
advanced features, S3 storage and requests, and supporting deployment resources
can be billed according to the account and Region. Check current Cognito and S3
pricing before deployment and use billing controls in a sandbox.

`npx cdk destroy` is destructive by design here:

- User Pool deletion permanently removes lab users and configuration.
- `autoDeleteObjects: true` empties the bucket, then `DESTROY` removes it.
- Identity Pool deletion removes its identity records and role attachment.
- The local `cdk-outputs.json` is not an AWS resource and is not removed by CDK.

Do not copy these lifecycle settings to persistent data. Production pools and
buckets normally need deletion protection, retention, backups/export planning,
and a tested recovery procedure.

## Pros and cons

**Pros**

- No long-term AWS key is embedded in a browser or mobile app.
- User authentication and AWS authorization remain separate, testable layers.
- Temporary credentials expire and carry IAM-enforced least privilege.
- One role plus a policy variable can isolate many identities without one IAM
  role per user.
- User Pools support managed account and token lifecycle features; Identity
  Pools support several external providers.

**Cons**

- Two IDs, two audience concepts, token refresh, credential refresh, and IAM role
  selection create real integration complexity.
- Direct credentials enlarge the untrusted client attack surface.
- IAM policies are easy to make broad and difficult to express for rich business
  rules.
- User Pool groups and Identity Pool role mappings are frequently confused.
- Identity merging, guest-to-authenticated transitions, provider changes, and
  account deletion require explicit data-ownership design.
- Managed service limits, pricing, and regional configuration become application
  dependencies.

## Alternatives

- **API backend (default alternative):** send a User Pool access token to API
  Gateway or your service. Verify issuer, client/audience, signature, expiration,
  `token_use=access`, and scopes. The backend uses its workload role and enforces
  business authorization. Choose this when direct AWS access is not essential.
- **Presigned S3 operations:** a trusted backend authorizes one operation and
  returns a short-lived presigned URL. This exposes less AWS capability than
  general temporary credentials and works well for bounded uploads/downloads.
- **Direct STS web identity:** a supported OIDC provider can federate to an IAM
  role with `AssumeRoleWithWebIdentity`. Choose it when you do not need Identity
  Pool identity records, provider aggregation, guest identities, or its enhanced
  credential flow.
- **IAM Identity Center:** use it for workforce access to AWS accounts and
  business applications. It is not a customer identity directory.
- **A different customer IdP:** use an external OIDC/SAML provider for sign-in;
  keep a backend architecture, or connect it to an Identity Pool only when the
  client truly needs AWS credentials.

## Pitfalls

1. **Trust policy missing `aud` or `amr`.** A different Identity Pool or a guest
   path may reach the role. Pin the Identity Pool ID and require
   `authenticated`.
2. **Broad unauthenticated role.** Guest credentials are real AWS credentials.
   This lab disables them. If enabled, use a separate role with minimal,
   abuse-resistant permissions and quotas.
3. **Sending an ID token to an API as an access token.** ID tokens describe the
   sign-in; access tokens carry OAuth authorization. APIs must verify `token_use`,
   issuer, client/audience, signature, time claims, and required scopes.
4. **Turning `admins` into AWS admin access.** An app's `cognito:groups` claim is
   not a safe shortcut to administrator IAM permissions. Configure and test
   explicit role mappings if they are truly required, including ambiguous-role
   resolution; otherwise authorize the group inside the application.
5. **No resource-level prefix policy.** A role that allows `bucket/*` lets every
   identity read every other identity. Bind list and object actions to the same
   `${cognito-identity.amazonaws.com:sub}/` boundary.
6. **Credentials in logs or browser storage.** Never print JWTs, secret access
   keys, or session tokens. Keep temporary values in memory, use the SDK's
   refresh support, and scrub telemetry and crash reports.
7. **Confusing Identity ID with User Pool `sub`.** They belong to different
   namespaces and can have different lifecycle/merge behavior. Store an explicit
   mapping on a trusted backend if the domain model needs both.
8. **Ignoring token and credential expiry.** Refreshing a User Pool token does
   not make old AWS credentials immortal. Refresh each layer through its proper
   API, handle revoked/disabled users, and fail closed on expiry.
9. **Using `USER_PASSWORD_AUTH` as a browser production design.** It exists here
   for a compact CLI. Public interactive apps normally use authorization code
   with PKCE, a managed UI, SRP, passkeys, or another flow appropriate to their
   threat model. A public client cannot protect a client secret.
10. **Assuming temporary credentials remove the need for revocation planning.**
    Already-issued credentials can remain usable until expiration. Keep sessions
    short and permissions narrow.
11. **Copying lab deletion settings.** `DESTROY` and automatic bucket emptying
    permanently delete data. Production needs retention, deletion protection,
    lifecycle ownership, and recovery testing.

## Further reading

- [Amazon Cognito user pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools.html)
- [Amazon Cognito identity pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html)
- [Identity Pool authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html)
- [Identity Pool IAM roles and role mappings](https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html)
- [IAM roles for web identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc.html)
- [Amazon S3 policy keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html)
- [OAuth 2.0, RFC 6749](https://www.rfc-editor.org/rfc/rfc6749)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
