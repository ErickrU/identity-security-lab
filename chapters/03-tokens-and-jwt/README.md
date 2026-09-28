# 03 · Tokens and JWT: opaque vs self-contained, and JWT done right

> **TL;DR** — A token is a credential presented instead of the original login proof. An opaque
> token is a random handle: the issuer must look it up, so revocation is instant. A JWT is a
> signed JSON statement: any service with the issuer's public key can verify it without calling
> the issuer, so it scales across APIs but normally remains usable until `exp`. JWT is signed,
> not encrypted; anyone holding it can read and use it. Verify the signature **and** `alg`, `kid`,
> `iss`, `aud`, `exp`, `nbf`, `iat`, token type and required claims. Use JWT when several systems
> need offline verification. Use an opaque session/token when instant revocation and simplicity
> matter more. Never write your own verifier in production; the code here exists to make every
> byte and every classic failure visible.

## Why it was invented

A token is older than JWT. Kerberos tickets (chapter 04) and SAML assertions (chapter 08) are
signed statements carried between systems. A web session cookie (chapter 01) is a reference
token. What changed around 2010 was the shape of software:

- OAuth 2.0 needed compact access credentials for browser, mobile and API clients.
- OpenID Connect needed a signed identity statement that fit naturally in JSON software.
- APIs were split into many services. Calling a central session database on every request was
  slow, fragile and hard across organisations.
- SAML's signed XML worked for enterprise browser SSO, but was large and difficult to handle in
  mobile clients and HTTP headers.

The JOSE family standardised the pieces:

| Year | Standard | What it defines |
| --- | --- | --- |
| 2009 | Microsoft Simple Web Token | an early compact name/value token; one ancestor of JWT |
| 2010–2011 | JSON Web Token / JOSE drafts | JSON claims plus URL-safe signing and encryption |
| May 2015 | RFC 7515, JWS | how bytes are digitally signed or MACed |
| May 2015 | RFC 7516, JWE | how bytes are encrypted |
| May 2015 | RFC 7517, JWK | JSON representation of cryptographic keys; a set is a JWKS |
| May 2015 | RFC 7518, JWA | algorithm identifiers such as `RS256`, `ES256`, `A256GCM` |
| May 2015 | RFC 7519, JWT | claims (`iss`, `sub`, `aud`, `exp`...) carried by JWS or JWE |
| 2016 | RFC 7797 | JWS with an unencoded payload, useful for signing existing bytes |
| 2020 | RFC 8725, JWT BCP | the verification rules learned from real attacks after 2015 |
| 2021 | RFC 9068 | a profile for JWT access tokens (`typ: at+jwt`) |

The central property is **verification without a round trip**. An issuer signs once with a
private key. Ten APIs verify independently with public keys from its JWKS. The issuer can be
unavailable for a while and existing tokens still work. That property is also the main cost:
the issuer cannot instantly retract an already-issued signed statement unless verifiers add a
state lookup again.

## How it works

### First: token is the category, JWT is one format

A token is any value whose possession stands for authority. Two broad designs:

| | Opaque / reference token | Self-contained token (JWT) |
| --- | --- | --- |
| What the client sees | random bytes, for example `RYk8...` | signed `header.payload.signature` |
| Where claims live | issuer database/cache | inside the token |
| Verification | call introspection or share a store | verify signature locally, then claims |
| Who can verify | issuer, or systems with store access | anyone with the public key |
| Revocation | delete a row; immediate | normally wait for `exp`; denylist adds a lookup |
| Privacy | contents hidden | payload readable by holder and logs |
| Size | often 32–64 bytes | typically 0.8–2 KB |
| Issuer availability | required for each introspection | not required until keys refresh |
| Good fit | one backend, high-value revocation, sensitive claims | many APIs, federation, intermittent issuer connectivity |

`src/opaque.ts` implements the left side: issue 32 random bytes, store `{sub, scope, exp}`, ask
`introspect(token)` on every use, and `revoke(token)` by deletion. `src/jws.ts` implements the
right side.

**Bearer** (RFC 6750) means “whoever bears these bytes may use them.” It is like cash, not like
a passport whose face is compared with its holder. TLS (chapter 02) protects the bytes in
transit. Browser and device storage protect them at the endpoints. mTLS or DPoP can turn a
bearer token into proof-of-possession later.

### Three tokens that are often confused

OAuth/OIDC commonly returns three values. Their purpose, not their encoding, distinguishes
them:

| Token | Audience | Answers | Typical format |
| --- | --- | --- | --- |
| ID token | the client application (`aud = client_id`) | “who just authenticated, and how?” | JWT, required by OIDC |
| Access token | a resource server/API | “which delegated capabilities may this client exercise?” | opaque or JWT; OAuth does not require either |
| Refresh token | the authorization server | “may this client mint a fresh token without another login?” | usually opaque, long-lived, stored/revoked server-side |

An API must not accept an ID token just because its signature is valid. That token was created
for the client, not the API; accepting it is token substitution. Chapters 05 and 06 run both
flows through a small local IdP.

### Anatomy of compact JWS

A common signed JWT is a compact JWS:

```text
base64url(UTF8(header JSON)) . base64url(UTF8(payload JSON)) . base64url(signature)
```

Example header:

```json
{ "alg": "RS256", "typ": "at+jwt", "kid": "kid-2026" }
```

Example payload:

```json
{
  "iss": "https://idp.lab.example",
  "sub": "user-alice-7d9f",
  "aud": "https://orders-api.lab.example",
  "exp": 1790597700,
  "nbf": 1790596795,
  "iat": 1790596800,
  "jti": "token-f9a8",
  "scope": "orders:read orders:write",
  "department": "engineering"
}
```

The signature covers the **encoded** header, a dot, and the encoded payload. With RS256:

```text
signature = RSA-PKCS1-v1_5-SHA256(privateKey, encodedHeader + "." + encodedPayload)
```

A verifier repeats the hash and checks the signature with the public key. One changed bit makes
it fail. Encoding is not security: paste either first part into a base64url decoder and it is
plain JSON.

### Claims: each closes a different substitution or replay door

| Claim | Meaning | Check |
| --- | --- | --- |
| `iss` | issuer: who made this statement | exact expected URL/string; never “any trusted-looking issuer” |
| `sub` | subject: stable identity at that issuer | required when the application needs a user; do not use mutable email as the key |
| `aud` | audience: which receiver(s) this was minted for | must contain **this** API/client; string or array |
| `exp` | expiration, Unix seconds | current time must be before it; keep access tokens short |
| `nbf` | not before | current time must be at/after it, with small clock tolerance |
| `iat` | issued at | must not be implausibly in the future; useful for session age rules |
| `jti` | unique token identifier | replay tracking/denylist key; not automatically checked by libraries |
| `scope` | OAuth delegated capabilities | resource/route must require the relevant scope |
| `nonce` | binds an OIDC ID token to one login request | client compares with the value stored before redirect (chapter 06) |
| `auth_time`, `acr`, `amr` | when/how authentication happened | step-up and MFA-freshness policy, if the issuer semantics are trusted |

A valid signature only says “this issuer wrote these bytes.” It does not say they are current,
meant for you, the correct token kind, or sufficient for this operation. Claims make those
statements, and verifier configuration supplies the expected values.

### Algorithms: symmetric vs asymmetric

`256` means SHA-256 in these names; it does not make the key type equivalent.

| Algorithm | Key arrangement | Who can sign? | Use |
| --- | --- | --- | --- |
| HS256 | one shared HMAC secret | **every verifier**; verification power equals signing power | one issuer/verifier under one trust boundary; rarely federation |
| RS256 | RSA private signs, public verifies | private-key holder only | widest JWT interoperability; Cognito and API Gateway common path |
| PS256 | RSA-PSS private/public | private-key holder only | newer probabilistic RSA signature; prefer when ecosystem supports it |
| ES256 | P-256 ECDSA private/public | private-key holder only | small keys/signatures; implementation nonce bugs can expose private keys |
| EdDSA | Ed25519/Ed448 private/public | private-key holder only | simple, fast, deterministic; ecosystem support varies |
| `none` | no key, no signature | anyone | only an explicitly unsecured closed context; never an authentication token |

For federated or multi-service verification, use asymmetric signing: APIs receive only public
keys and therefore cannot mint identities. Protect issuer private keys in KMS/HSM, rotate them,
and never put them in a repository. If HS256 is required, use at least 256 random bits from a
cryptographic RNG, store it in a secret manager, and remember every verifier can forge.

JWS is **signing**, not encryption. JWE encrypts a payload, but most applications should put
only identifiers and non-sensitive authorization hints in tokens anyway. Encryption hides data
from intermediaries; it does not fix revocation, audience, expiry or bearer theft, and every
receiver still sees the plaintext.

### JWKS, `kid`, and rotation

A JSON Web Key Set is a public document such as:

```json
{
  "keys": [
    { "kty": "RSA", "kid": "kid-2026", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB" }
  ]
}
```

The issuer publishes it at a configured/discovered HTTPS URL. The verifier:

1. reads `kid` from the header,
2. finds exactly that key in its cached, trusted JWKS,
3. checks `alg`/`use` match its policy,
4. verifies the signature,
5. validates claims.

`kid` is an index, not trust. A token must not choose a filesystem path, SQL query or arbitrary
URL from it. Never trust `jwk` (embedded key), `jku` (JWKS URL) or `x5u` (certificate URL) from an
untrusted token unless a separate, strict policy pins where those values may point. Otherwise
the attacker supplies the key that “proves” their own token, or turns the verifier into an SSRF
client.

Safe rotation:

1. publish old and new public keys,
2. let caches learn the new JWKS,
3. start signing with the new `kid`,
4. keep the old key longer than the longest token lifetime plus cache tolerance,
5. remove the old key.

On an unknown `kid`, a verifier may refetch once (rate-limited) for rotation; it must not try
every key or accept the token. API Gateway caches issuer keys for up to two hours, so overlap
matters.

### The strict verification order

`src/verify-strict.ts` follows this fail-closed order:

1. Parse exactly three base64url JSON parts.
2. Require `alg` in a **configuration allowlist**. The message never chooses policy.
3. Reject embedded/remote key-selection headers; require `kid`.
4. Load the key only from the configured JWKS or configured HMAC secret map. Match `alg`/`use`.
5. Verify the signature over the original encoded header and payload.
6. Require expected claims and their types.
7. Validate `exp`, `nbf`, `iat` with a small, configured clock tolerance.
8. Match `iss`, then require this receiver in `aud`.
9. Match an expected `typ` such as `at+jwt` when token kinds share an endpoint/key set.
10. Only now return claims to authorization code.

Use a maintained library instead of copying this implementation. A real library also handles
critical headers (`crit`), duplicate JSON members, Unicode edge cases, algorithm-specific key
requirements, key-cache concurrency and denial-of-service limits.

### Why the 2015 attacks worked

The demo keeps a deliberately broken verifier (`src/verify-naive.ts`) to reproduce them:

| Mistake | Attack | Result |
| --- | --- | --- |
| verifier honors `alg: none` | attacker edits payload and removes signature | admin token accepted |
| verifier accepts RS256 and HS256 using one generic `key` argument | attacker changes `alg` to HS256 and uses the **public** RSA PEM as the HMAC secret | public information signs admin tokens (CVE-2015-9235 family) |
| signature checked, `exp` ignored | replay an old genuine token | expired login lives forever |
| `aud` ignored | token for billing presented to orders | cross-service token substitution |
| `kid` ignored / `jwk` accepted | attacker chooses or embeds their key | self-signed identity accepted |
| signature retained after payload edit | both verifiers reject | demonstrates what signatures do protect when algorithms are configured correctly |

The fix is not “JWT is insecure.” The fix is to treat the token as hostile input and make every
expectation local configuration. RFC 8725 exists because the original format RFC could not
encode application policy.

### Revocation and logout

A resource server can verify a JWT while the issuer is offline because all the evidence is in
the token. Therefore an issuer-side “logout” cannot magically reach every verifier.

| Strategy | Revocation delay | Cost / trade-off |
| --- | --- | --- |
| short access JWT (5–15 min) + revocable rotating refresh token | access until `exp`; no new token after refresh revoked | normal OAuth design; bounded exposure and mostly stateless APIs |
| denylist by `jti` until `exp` | immediate | lookup per request or local replicated cache; state returns |
| user/token-version claim checked against user record | immediate for all older tokens | lookup per request; coarse (logs every device out) |
| key rotation/removal | immediate after caches refresh | revokes **every** token under that key; emergency only |
| opaque token + introspection | immediate | issuer/store on every request; often correct for high-value operations |
| sender-constrained token (mTLS/DPoP) | does not revoke; makes theft less useful | client must prove a key on every request |

Do not pretend logout revoked a long-lived JWT. Clear the client's copy, revoke the refresh token,
and let the short access token expire. For a “disable account now” requirement, add an online
status check or choose reference tokens.

### Browser storage

| Place | JavaScript can read? | Browser sends automatically? | Main threat / controls |
| --- | --- | --- | --- |
| `HttpOnly; Secure; SameSite` cookie | no | yes | CSRF → SameSite + CSRF token; XSS can still issue same-origin actions |
| `localStorage` | yes, persistently | no | one XSS/dependency compromise exfiltrates every token; avoid bearer tokens here |
| JavaScript memory | yes, until page reload | no | XSS can use it while present; smaller persistence window |
| backend-for-frontend (BFF) | browser gets only a session cookie; server holds OAuth tokens | cookie yes | strongest common web design; BFF handles refresh and API calls |
| OS keychain / secure storage | app process via protected API | no | best mobile/native default; rooted device still wins |

A cookie is not automatically safer or worse than a header; it changes XSS/CSRF exposure. Do
not put tokens in URLs: browser history, proxy logs, analytics and `Referer` headers copy them.

### Beyond bearer: bind the token to a key

- **OAuth mTLS** (RFC 8705): the access token contains a confirmation thumbprint. The API accepts
  it only on a TLS connection where the client proves the matching private key.
- **DPoP** (RFC 9449): the client signs a short-lived proof JWT over method, URL, timestamp,
  nonce and access-token hash. The server checks the public key matches the token's `cnf` claim.

A stolen access token alone is then insufficient. This reduces replay; it does not cure a
compromised client that can use the private key or ask it to sign.

## Run it

Everything is offline and uses only `node:crypto`:

```bash
npm run 03
npx vitest run chapters/03-tokens-and-jwt
```

The demo prints:

1. The same identity as an opaque token and a JWT: sizes, lookup vs signature, revoke vs `exp`.
2. The three JWT parts decoded, and the job of every registered claim.
3. A raw payload edit rejected, then five attacks accepted by the deliberately naive verifier
   and rejected with a named reason by the strict verifier.
4. Safe `kid` rotation with two simultaneous public keys.
5. Opaque revocation compared with JWT `jti` denylist, token-version and short-life strategies.
6. Browser storage choices and their XSS/CSRF trade-offs.

Code map:

| File | Purpose |
| --- | --- |
| `src/base64url.ts` | RFC 7515 encoding helpers |
| `src/opaque.ts` | reference token issue, introspection and revocation |
| `src/jws.ts` | compact JWS signing/verifying for RS256, ES256 and HS256; JWK export |
| `src/verify-naive.ts` | intentionally vulnerable verifier, never production code |
| `src/verify-strict.ts` | readable RFC 8725-style policy and claim checks |
| `src/demo.ts` | narrated comparison and attacks |
| `src/*.test.ts` | algorithm round trips, official invariants, attacks, clocks, claims and opaque lifecycle |

The production AWS counterpart is [jwt-on-aws](https://github.com/ErickrU/jwt-on-aws): Cognito
issues real tokens, API Gateway's native JWT authorizer verifies one route, an
`aws-jwt-verify` Lambda authorizer verifies another, and a demo forges a group claim to prove
that both reject it.

## Scenarios

**One web application.** Prefer the opaque session in chapter 01. Instant logout and fewer
protocol edges beat “stateless” when one backend already owns all requests.

**Microservices behind one identity provider.** A 5–15 minute access JWT is useful: each service
verifies against one JWKS without sharing a session database. Still put coarse authentication
at the gateway and resource-level authorization in the service (chapter 12).

**Partner/API ecosystem.** JWT access tokens profile the claims an external API can rely on.
Strict issuer/audience policy matters more because trust crosses organisations.

**Disconnected/edge verification.** A CDN, gateway or remote service can verify while the issuer
is unreachable. Decide whether bounded revocation delay is acceptable first.

### AWS mapping

| AWS service | JWT/token role | Important detail |
| --- | --- | --- |
| Cognito user pools | signs ID/access tokens and publishes per-pool JWKS | access token has `client_id` and `token_use=access`; ID token has `aud` and `token_use=id`; groups appear in `cognito:groups` |
| API Gateway HTTP API JWT authorizer | verifies OIDC/OAuth JWT before integration | checks `kid`/RSA signature, `iss`, `aud` or `client_id`, `exp`, `nbf`, `iat`, optional route `scope`; configure scopes to exclude ID tokens |
| Lambda authorizer | custom token verification/authorization | use AWS `aws-jwt-verify`; needed for nonstandard issuers, denylist/introspection or custom policy; extra invocation/caching decisions |
| Application Load Balancer OIDC auth | runs code flow, keeps a session, forwards `x-amzn-oidc-data` | that header is an ES256 JWT signed by the **ALB**, not the original IdP token; verify signer/key and ALB ARN before trusting it |
| STS `AssumeRoleWithWebIdentity` | consumes an OIDC JWT and returns temporary AWS credentials | IAM trust policy must constrain issuer, `aud` and `sub`; chapter 10's GitHub Actions example |
| EKS IRSA | service-account OIDC JWT exchanged at STS | cluster is issuer; `sub=system:serviceaccount:namespace:name`; role policy maps workload identity to AWS permissions |
| KMS asymmetric keys | private key never leaves KMS; call `Sign`, publish public JWK | protects issuer signing key; adds a KMS call/cost to issuance, not verification |
| Secrets Manager | stores HS256 secret or opaque-token/introspection credentials | all verifiers with HS256 secret can forge; asymmetric KMS is cleaner across services |
| CloudFront signed URL/cookie | non-JWT signed capability for private content | purpose-built token: resource/policy/expiry; do not replace every token with JWT |

## Pros and cons

**JWT pros**

- Local verification: no database/network call per request.
- Public-key distribution: verifiers cannot mint tokens.
- Standard claims and tooling across languages and organisations.
- Carries enough context for coarse authorization without another lookup.
- Key rotation works through JWKS and `kid`.

**JWT cons**

- No instant revocation without adding state.
- Payload is readable and often copied into logs; claims become a privacy/size problem.
- Bearer theft works until expiry unless sender-constrained.
- Validation has many independent rules; “the signature passed” is dangerously incomplete.
- Claims become stale. Permissions copied into a 24-hour token ignore changes for 24 hours.
- Every request carries roughly a kilobyte; cookie/header limits and gateway limits are real.
- Algorithm/key/token-kind confusion creates sharp edges that opaque handles avoid.

## Alternatives

| Alternative | Pick it when |
| --- | --- |
| opaque token + RFC 7662 introspection | revocation, confidentiality of claims or central policy must be immediate; issuer can handle the hot path |
| server-side session cookie (chapter 01) | one browser app and backend; simplest secure login/logout model |
| PASETO | you control both ends and want versioned, opinionated algorithms with fewer choices; interoperability is much smaller |
| Macaroons | delegated attenuation matters: each holder can add stricter caveats without contacting issuer |
| Biscuit | offline authorization logic and attenuating capabilities are central; accept a newer ecosystem |
| SAML assertion (chapter 08) | an enterprise counterparty requires browser SSO via SAML; not for API bearer use |
| Kerberos ticket (chapter 04) | managed intranet/domain with KDC, mutual authentication and transparent desktop SSO |
| CloudFront signed URL/cookie | grant temporary access to one CDN resource/path, not general identity |
| plain random API key | identify a machine/project in a simple first-party API; hash/store, scope, rotate and rate-limit it |

## Pitfalls

| Mistake | What it enables | Fix |
| --- | --- | --- |
| accepting `alg: none` | unsigned impersonation | algorithm allowlist in local config |
| mixing HS256 and RS256 with one generic key | public-key-as-HMAC-secret forgery | pin algorithm per issuer/key; modern library |
| checking signature but not `aud` | token substitution across APIs/clients | exact expected audience on every verifier |
| not checking `iss` | token from another tenant/issuer accepted | exact configured issuer and its JWKS |
| no `exp`, or multi-day access token | stolen/replayed token works for days | require short expiry; refresh separately |
| accepting ID tokens at APIs | identity token for client substituted as API authority | access-token profile/type/scope/token-use checks |
| trusting `jwk`, `jku`, `x5u` or raw `kid` paths from header | attacker key injection, SSRF, path/SQL injection | keys only from configured issuer/JWKS cache; sanitise `kid` lookup |
| weak human HS256 secret | offline dictionary cracking with hashcat, then forgery | 256 random bits in secret manager, or asymmetric signing |
| secrets/PII in payload | every holder, log and browser extension reads it | identifiers/minimal claims only; JWE only when truly required |
| bearer token in localStorage | XSS exfiltrates a persistent credential | BFF/HttpOnly cookie or memory; prevent XSS either way |
| token in URL | history, logs, analytics and referrers leak it | Authorization header or secure cookie |
| giant list of permissions in token | stale authorization, header-size failures | coarse scopes/groups; live resource decision in service/data layer |
| “logout” only deletes browser copy | stolen copy remains valid | revoke refresh token; short access expiry; online check if requirement demands it |
| no `typ` separation when several token kinds share keys | cross-JWT confusion | explicit token types/profiles and mutually exclusive validation rules (RFC 8725 §3.11–3.12) |
| logging full tokens | logs become reusable credentials | log issuer, subject hash, jti and failure code; redact token |
| decoding and calling it verification | arbitrary attacker JSON trusted | signature + all semantic checks; jwt.io's debugger decodes, it does not establish trust |

## Further reading

Primary sources first:

- RFC 7515 — JSON Web Signature (JWS): https://www.rfc-editor.org/rfc/rfc7515
- RFC 7516 — JSON Web Encryption (JWE): https://www.rfc-editor.org/rfc/rfc7516
- RFC 7517 — JSON Web Key (JWK): https://www.rfc-editor.org/rfc/rfc7517
- RFC 7518 — JSON Web Algorithms (JWA): https://www.rfc-editor.org/rfc/rfc7518
- RFC 7519 — JSON Web Token (JWT): https://www.rfc-editor.org/rfc/rfc7519
- RFC 8725 — JSON Web Token Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens: https://www.rfc-editor.org/rfc/rfc9068
- RFC 6750 — OAuth 2.0 Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750
- RFC 7662 / RFC 7009 — Token Introspection / Revocation.
- RFC 8705 / RFC 9449 — OAuth mTLS / DPoP sender-constrained tokens.
- Auth0, *Critical vulnerabilities in JSON Web Token libraries* (2015), the `none` and RSA/HMAC confusion disclosure: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- OWASP JSON Web Token Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet
- AWS, *Control access to HTTP APIs with JWT authorizers*: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html
- AWS Labs, `aws-jwt-verify`: https://github.com/awslabs/aws-jwt-verify
