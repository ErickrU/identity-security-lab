# Small OAuth 2.0 / OpenID Connect provider

This is the shared executable behind chapters 05–07. It is intentionally small enough to read,
but the security checks are real and tested.

> **Do not deploy it.** It uses in-memory state, a fresh signing key on every start, HTTP on
> localhost, fixed demo clients, and no production audit/rate-limit/HA/key-management layer. Use
> Cognito, IAM Identity Center, Keycloak, Auth0, Okta, Entra ID or another maintained provider.
>The point is to see every redirect, code, key, claim and comparison those products implement.

## Run the complete browser flow

```bash
# terminal 1: authorization server + OpenID Provider (localhost: cookies stay off the RP host)
npm run idp

# terminal 2: OAuth resource server
npm run api

# terminal 3: OIDC relying party / backend-for-frontend
npm run rp
```

Open http://127.0.0.1:4001. Sign in as `alice` or `bob`; both use
`correct horse battery staple`. Allow the requested scopes, then call `/orders` through the RP.
The browser receives only local HttpOnly cookies. The RP stores access, ID and refresh tokens
server-side. The IdP deliberately uses `localhost` while the RP uses `127.0.0.1`: cookies are
scoped by host (not port), so running both on `127.0.0.1` would leak each service's cookies to the
other port. Production uses separate HTTPS origins and `__Host-` cookies.

Tests run all three roles on random ports and drive the same redirects/forms without a browser:

```bash
npx vitest run small-idp
```

## Components

| File | Role |
| --- | --- |
| `src/protocol.ts` | authorization server / OpenID Provider rules, independent of HTTP |
| `src/keys.ts` | RS256 signing, JWKS publication and strict issuer/audience/time verification |
| `src/idp.ts` | discovery, JWKS, authorize/login/consent, token, userinfo, revoke, introspect, logout HTTP endpoints |
| `src/client.ts` | OIDC client: discovery, state/nonce/PKCE, token exchange, ID-token/`at_hash` verification |
| `src/resource-server.ts` | bearer access-token verification + scope/group checks |
| `src/rp.ts` | backend-for-frontend relying party with local sessions |
| `src/*.test.ts` | protocol, crypto, endpoint and full RP browser-flow tests |

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery: issuer, endpoints, capabilities |
| `GET /jwks.json` | current public verification keys; never the private key |
| `GET /authorize` | validate client, exact redirect URI, scopes, state, OIDC nonce, PKCE; then login/consent |
| `POST /login` | authenticate the resource owner; browser-interaction cookie + hidden CSRF token bind the form; create the IdP SSO session |
| `POST /consent` | require the same browser binding/CSRF token; approve/deny scopes; issue a one-minute code |
| `POST /token` | authorization-code, rotating-refresh-token and client-credentials grants |
| `GET/POST /userinfo` | OIDC claims selected by scopes; requires access token with `openid` |
| `POST /revoke` | immediately revokes refresh tokens and the IdP's online view of access tokens; an independent offline-JWT API still accepts an access token until `exp` |
| `POST /introspect` | active token metadata for authenticated clients |
| `GET` then `POST /logout` | confirmation + CSRF-protected deletion of the IdP session; RP sessions are separate |

## Security invariants visible in code

- Redirect URIs use exact string matching. A prefix/wildcard lets attackers steal codes.
- Authorization code is random, expires in 60 seconds, belongs to one client + redirect URI,
  and is deleted on its first token-exchange attempt.
- Every authorization-code client uses PKCE S256, including confidential backends. Public clients
  have no fake “secret”; confidential clients additionally authenticate.
- `state` binds the callback to the client browser transaction, which is consumed on the first
  callback attempt. Separately, IdP login/consent
  forms require an IdP interaction cookie plus hidden CSRF token; OAuth state does not protect IdP forms.
- The IdP uses `localhost`, while RP/API use `127.0.0.1`, because cookies do not respect port boundaries.
- Access tokens target the API audience and use `typ: at+jwt`; ID tokens target the client and
  use `typ: JWT`. The API rejects an ID token even though the signature is genuine.
- `nonce` binds the ID token to that OIDC request; `at_hash` binds ID and access tokens in one response.
- Refresh tokens are opaque, stored as SHA-256 digests, single-use and rotated. Spent-token
  tombstones identify reuse and revoke active descendants in that family; scope may narrow, never
  expand. Production needs durable, atomic shared storage rather than these in-memory maps.
- Refresh-token revocation is immediate at the issuer. Self-contained access-token revocation is
  deliberately visible as a trade-off: introspection/UserInfo sees the denylist, while the independent
  resource server has only JWKS and accepts the token until its five-minute `exp`.
- Client-credentials tokens represent `client:<client_id>` and never contain a human ID token.
- Passwords reuse chapter 01's salted scrypt implementation. Client secrets are already random
  high-entropy values, so storing a SHA-256 digest is sufficient.
- JWT verification pins RS256 and checks configured JWKS key, signature, issuer, audience,
  expiration/not-before and token type before claims are used.
- Token and authorization responses carry `Cache-Control: no-store`.

The tests intentionally try wrong redirect URIs, weak state, missing nonce/PKCE, unknown scopes,
wrong client secret, code replay, wrong verifier, scope escalation on refresh, ID token at API,
missing scope, CSRF-unbound IdP forms, refresh revocation, and the bounded access-JWT revocation delay.
