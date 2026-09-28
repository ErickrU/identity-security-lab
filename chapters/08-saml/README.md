# 08 · SAML 2.0: the enterprise federation protocol, with a real signed assertion you can read

> **TL;DR** — SAML 2.0 (OASIS, 2005) is how a web app (the Service Provider, SP)
> lets a company's Identity Provider (IdP) log its users in. The browser carries
> an XML `Assertion`, signed by the IdP, from the IdP to the SP. The SP checks
> the signature against a certificate it pinned from the IdP metadata, then
> checks Audience, Recipient, InResponseTo and the time window, then opens its
> own session. Use it when a customer or your employer says "we do SAML" (Okta,
> Entra ID, ADFS, Ping, Shibboleth, AWS IAM and Identity Center all speak it).
> Do not pick it for anything new: it has no API tokens, no mobile story, and
> XML Signature has a long list of implementation bugs. New designs use OIDC
> (chapter 06); SAML is what you meet in the enterprise, so you must read it.

## Why it was invented

Around 2000 a company had one directory (LDAP, Active Directory) and a growing
pile of web applications, more and more of them hosted by other companies.
Every app had its own login page and its own copy of the password. Two things
were broken:

1. **Cookies do not cross DNS domains.** A session at `hr.corp.example` means
   nothing at `expenses.vendor.example`. Web SSO across domains needs something
   the browser can carry from one site to the other. A signed message does it.
2. **Partners needed to trust each other's logins** without sharing passwords
   or directories. A university wanted its students to reach a publisher's
   library; a company wanted its staff inside its payroll vendor. The vendor
   should learn "this is alice, she is in group payroll-admins, says
   corp.example", and nothing else.

Timeline:

| Year | What |
|---|---|
| 2002 | SAML 1.0 (OASIS). Assertions and a browser/artifact profile. |
| 2003 | SAML 1.1. Meanwhile the Liberty Alliance builds ID-FF and Internet2 builds Shibboleth on SAML 1.x. |
| March 2005 | **SAML 2.0**, merging SAML 1.1, Liberty ID-FF 1.2 and Shibboleth ideas. This is the version everyone means. |
| 2003–2009 | WS-Federation, the Microsoft/IBM sibling built on WS-* and WS-Trust; ADFS spoke it first. Same idea, different XML. |
| 2014 | OpenID Connect 1.0 final: same roles, JSON and JWT instead of XML, designed for APIs and mobile too. |

SAML 2.0 has not changed since 2005 apart from errata. That stability is why it
is everywhere in enterprises, and why it looks the way it does.

## How it works

### Roles and trust

| Role | Name | Does |
|---|---|---|
| Identity Provider | IdP | authenticates the user, issues signed assertions |
| Service Provider | SP | the application; consumes assertions, opens a local session |
| User agent | the browser | carries messages between the two; never holds a secret |

Trust is **configured, not discovered**. Each side exports a metadata XML
document and the other side imports it once:

| In IdP metadata | Meaning |
|---|---|
| `entityID` | the IdP's name; must equal `<Issuer>` in every assertion |
| `SingleSignOnService` | URL(s) where AuthnRequests go, one per binding |
| `SingleLogoutService` | URL(s) for logout messages |
| `KeyDescriptor use="signing"` | the X.509 certificate whose public key verifies signatures |
| `NameIDFormat` | which subject identifier formats the IdP can emit |

| In SP metadata | Meaning |
|---|---|
| `entityID` | the SP's name; becomes `<Audience>` in assertions for it |
| `AssertionConsumerService` | the ACS URL where the browser POSTs the Response |
| `WantAssertionsSigned` | the SP refuses unsigned assertions |
| `AuthnRequestsSigned` | the SP signs its requests (optional, uncommon) |

The certificate in the metadata is a container for a public key. SAML does not
check who issued it, its hostname, or (usually) its expiry. The SP pins it.
Rotating it means re-exchanging metadata; that is a recurring operational pain.

### Bindings: how XML travels through a browser

| Binding | Encoding | Used for |
|---|---|---|
| HTTP-Redirect | XML → raw DEFLATE → base64 → URL-encode, in `?SAMLRequest=` | AuthnRequests (short); logout messages |
| HTTP-POST | XML → base64, in a hidden form field `SAMLResponse`, auto-submitted by JavaScript | Responses (too long for a URL) |
| HTTP-Artifact | a short random handle in the URL; the SP fetches the real message from the IdP over a back channel (SOAP) | rare today |

`RelayState` rides along with either message as an opaque string. The SP puts
"where to go after login" in it (like OIDC `state`).

### The messages

**SP-initiated** flow (the normal one):

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (alice)
    participant SP as SP orders.lab.example
    participant IdP as IdP idp.lab.example
    B->>SP: GET /orders/42 (no session)
    SP->>SP: build AuthnRequest, store its ID
    SP-->>B: 302 to IdP SSO URL ?SAMLRequest=deflate+base64(XML)&RelayState=/orders/42
    B->>IdP: GET /sso?SAMLRequest=...
    IdP->>IdP: parse request; Issuer is a known SP? ACS URL matches its metadata?
    IdP->>B: login page (password, MFA, Kerberos, passkey... not SAML's business)
    B->>IdP: credentials
    IdP->>IdP: build Response with Assertion, sign Assertion (XML-DSig), base64
    IdP-->>B: 200 HTML form: POST SAMLResponse + RelayState to ACS URL (auto-submit)
    B->>SP: POST /saml/acs SAMLResponse=...&RelayState=/orders/42
    SP->>SP: Status, signature vs pinned cert, Issuer, Audience, Destination, Recipient, InResponseTo, NotBefore/NotOnOrAfter
    SP->>SP: map attributes to local roles, create OWN session cookie
    SP-->>B: 302 /orders/42 + Set-Cookie
```

**IdP-initiated** flow: the user starts at a portal on the IdP, clicks a tile,
and the IdP POSTs an unsolicited Response (no `InResponseTo`) to the SP's ACS.
It is convenient and it weakens the SP's defences: the SP cannot tie the
response to a request it made, so a login CSRF (an attacker logging the victim
into the attacker's account, or the other way round) becomes possible. Many
SPs disable it or require `RelayState` allowlists.

### Anatomy of a Response

This is (abbreviated) what the demo prints:

```xml
<samlp:Response ID="_7cec…" Version="2.0" IssueInstant="…" Destination="https://orders.lab.example/saml/acs" InResponseTo="_9612…">
  <saml:Issuer>https://idp.lab.example</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_e32a…" Version="2.0" IssueInstant="…">
    <saml:Issuer>https://idp.lab.example</saml:Issuer>
    <ds:Signature>                       ← enveloped XML-DSig over THIS Assertion
      <ds:SignedInfo>
        <ds:Reference URI="#_e32a…">     ← points at the Assertion ID
          <ds:Transforms> enveloped-signature, exc-c14n </ds:Transforms>
          <ds:DigestMethod Algorithm="…#sha256"/> <ds:DigestValue>…</ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>…</ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIID…</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@lab.example</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="…+5min" Recipient="https://orders.lab.example/saml/acs" InResponseTo="_9612…"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="…" NotOnOrAfter="…+5min">
      <saml:AudienceRestriction><saml:Audience>https://orders.lab.example</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="…" SessionIndex="_b6b3…">
      <saml:AuthnContext><saml:AuthnContextClassRef>…:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>alice@lab.example</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>orders-admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

What each part is for, and who checks it:

| Element | Purpose | Checked by |
|---|---|---|
| `Response/@InResponseTo` | which AuthnRequest this answers | SP: must be an ID it issued and has not consumed |
| `Response/@Destination` | the ACS URL this was built for | SP: must be its own ACS URL |
| `Status` | Success or an error code | SP: no Success, no identity |
| `Issuer` | who says so | SP: must equal the IdP `entityID` from metadata |
| `ds:Signature` | integrity + authenticity of the Assertion (and/or the whole Response) | SP: verify with the pinned certificate, not with whatever `KeyInfo` carries |
| `Subject/NameID` | who the user is | SP: map to a local account |
| `SubjectConfirmation Method=bearer` | "whoever presents this is the subject" | this is why every guard below matters |
| `SubjectConfirmationData` | `Recipient`, `InResponseTo`, `NotOnOrAfter` on the bearer confirmation | SP: all three |
| `Conditions` | `NotBefore`/`NotOnOrAfter` window, `AudienceRestriction` | SP: window (with small skew), Audience = own `entityID` |
| `AuthnStatement` | when, how (`AuthnContextClassRef`), `SessionIndex` for logout | SP: may require an MFA context class |
| `AttributeStatement` | facts about the user | SP: map to roles by configuration |

Bearer is the important word. Unlike Kerberos (chapter 04), where the ticket is
bound to a key the client proves it holds, a SAML bearer assertion is valid for
whoever holds it. Short lifetime, Audience, Recipient and single-use
`InResponseTo` are the substitutes for proof of possession.

### XML Signature (XML-DSig)

The signature is *enveloped*: it lives inside the element it signs. To verify,
the SP removes the `ds:Signature` element (the enveloped-signature transform),
canonicalises the rest (Exclusive C14N: fixes whitespace, attribute order,
namespace declarations), hashes it, compares to `DigestValue`, then verifies
`SignatureValue` over `SignedInfo` with the public key.

Three choices of what to sign, all seen in the wild:

| Signed | Notes |
|---|---|
| Assertion only | most common (Okta, Entra ID, ADFS defaults) |
| Response only | protects the whole document but the assertion cannot be lifted out and verified alone |
| Both | safest; two signatures to read. Flip `wantMessageSigned` in `saml-lab.ts` to see it |

The verifier must decide **which** element it verified and then read the
identity **only from that element**. Reading from "the first Assertion in the
document" while verifying "the Assertion the Signature points to" is the XML
Signature Wrapping bug family (see Pitfalls). samlify extracts NameID and
attributes from the signed reference it verified, not from the document.

### XML Encryption

An IdP can additionally encrypt the assertion to the SP's public key
(`EncryptedAssertion`, XML-Enc). It hides attributes from the browser and from
logs. It is off in this lab; in practice it is uncommon except in government
and healthcare federations, and it doubles the certificate management.

### NameID formats

| Format | Value | Use |
|---|---|---|
| `emailAddress` | `alice@lab.example` | simple; breaks when emails change |
| `persistent` | opaque, stable per (IdP, SP) pair | privacy-preserving stable ID; the right default |
| `transient` | random per login | anonymous access (library subscriptions); the SP cannot link sessions |
| `unspecified` | whatever the IdP sends | "figure it out"; common in practice |

### Attributes and authorization

The IdP sends attributes; the SP decides what they mean. `groups=orders-admin`
grants refund rights only because the SP's configuration says so. An SP that
takes `role=admin` literally from any IdP it trusts has handed authorization to
every IdP administrator, including the ones at partner organisations.

### Single Logout

`LogoutRequest`/`LogoutResponse` messages let a logout at one SP propagate
through the IdP to every other SP with a session (using `SessionIndex`). In
practice it rarely works well: it needs every SP to implement it, each hop is a
browser redirect that can fail or be blocked, one dead SP stalls the chain, and
the user's local session at each SP is a plain cookie anyway. Most deployments
do "log out here, and show a link to the IdP logout page".

### Clock skew

`NotBefore`/`NotOnOrAfter` are checked against the SP's clock. A few seconds to
a couple of minutes of tolerance is normal; hours is a replay window. This lab
uses 30 seconds (`CLOCK_SKEW_MS`) and 5-minute assertions.

## Run it

From the repo root (needs `openssl` on PATH; OpenSSL 3 is fine):

```bash
npm run 08                       # narrated walkthrough
npx vitest run chapters/08-saml  # 15 offline tests
```

The demo prints, in order:

1. **Metadata** of both parties, with the certificate. Notice there is no
   secret in either document: metadata is public.
2. **AuthnRequest**: the 302 URL, then the decoded XML. Look at `ID`,
   `Issuer`, `Destination`, `AssertionConsumerServiceURL`.
3. **Response**: the full signed XML, then a line-by-line reading. Compare the
   `ds:Reference URI` with the `Assertion ID`, and the `X509Certificate` with
   the one in the IdP metadata: same bytes.
4. **Validation** at the SP and the extracted identity. Note which checks the
   library did and which ones our code did.
5. **Attack 1**: one byte changed in `NameID` → `FAILED_TO_VERIFY_SIGNATURE`.
   Then the signature deleted → same rejection.
6. **Attack 2**: the genuine response handed to a second SP →
   `ERR_WRONG_AUDIENCE`. Then replayed to the first SP → unknown `InResponseTo`.
7. A **SAML → OIDC glossary**.

Code map:

| File | What |
|---|---|
| `src/certs.ts` | runs `openssl req -x509 -newkey rsa:2048 …` in a temp dir, returns PEM strings, deletes the files |
| `src/saml-lab.ts` | IdP and SP construction, `createAuthnRequest`, `parseAuthnRequest`, `createLoginResponse`, `parseLoginResponse`, `prettyXml` |
| `src/demo.ts` | the walkthrough |
| `src/saml-lab.test.ts` | roundtrip, tamper, unsigned, rogue key, wrong audience, wrong InResponseTo, failure status |

> **Warning: schema validation is disabled in this lab.** samlify requires a
> schema validator and the real ones are native modules. `saml-lab.ts`
> registers one that accepts everything. Production SPs **must** validate the
> SAML XML schema before processing it. Schema validation is one mandatory
> structural defence against XML Signature Wrapping, not a complete one: also
> enforce unique IDs, reject duplicate/unexpected assertions, bind the verified
> signature reference to the exact node consumed, require the expected signed
> element, and disable DTD/external entities. Use
> `@authenio/samlify-xsd-schema-validator` or an equivalent, and read Pitfalls.

samlify specifics worth knowing (they generalise to other libraries):

- It verifies Status, the signature (against the metadata certificate, and it
  rejects a message whose `KeyInfo` certificate is not the pinned one), the
  Issuer, `SessionNotOnOrAfter` and the `Conditions` window.
- It does **not** check `Audience`, `Destination`, `Recipient` or
  `InResponseTo`. `parseLoginResponse` in `saml-lab.ts` does. Before trusting
  any SAML library, list which of the table above it checks for you.
- The attribute statement is built by us (`buildAttributeStatement`) and passed
  through `customTagReplacement`, because the built-in attribute template
  emits one value per attribute and we want multi-valued `groups`.

## Scenarios

**Enterprise SaaS.** Workday, Salesforce, Slack, Zoom, GitHub Enterprise, Atlassian,
ServiceNow: every one of them is an SP that accepts a customer's IdP. "SSO" in
their pricing pages means SAML (and, more recently, OIDC too). The customer's
IdP is Okta, Microsoft Entra ID, Ping, OneLogin, ADFS, or Google Workspace.

**Universities.** Shibboleth (SAML) plus federations like InCommon and eduGAIN:
thousands of universities and publishers exchange metadata through a central
registry, so a student at one university reaches a journal at a publisher with
a `transient` NameID and an `eduPersonScopedAffiliation=student@uni.example`
attribute. This is SAML at its best: large-scale, privacy-preserving, no new
passwords.

**AWS.**

| Service | SAML role | What happens |
|---|---|---|
| IAM SAML federation | AWS is the SP (`urn:amazon:webservices`) | the IdP assertion carries `https://aws.amazon.com/SAML/Attributes/Role` = `role-arn,provider-arn` pairs and `RoleSessionName`; the user POSTs it to `https://signin.aws.amazon.com/saml` for the console, or a CLI tool calls `sts:AssumeRoleWithSAML` with the base64 assertion to get temporary keys. Optional `PrincipalTag:*` attributes become session tags for ABAC. AWS validates the assertion against the certificate in the IAM SAML provider resource, which you must rotate when the IdP does. |
| IAM Identity Center with an external IdP | Identity Center is the SP for authentication | SAML carries login; **SCIM** (a separate REST protocol) provisions users and groups ahead of time, so permission sets can be assigned to groups before anyone logs in. SAML alone cannot create the group. |
| Cognito user pools | Cognito is the SP; then it is an OIDC OP | "SAML in, JWT out": the pool accepts the customer's SAML IdP, maps attributes to pool attributes, and issues ID/access/refresh tokens to your app. Your app never touches XML. Chapter 11. |
| Amazon corporate (Federate) | Amazon Federate is the corporate IdP | it supports SAML and OIDC for internal applications, in front of Midway authentication. Public knowledge only; details are internal. |

A note on mapping: in IAM SAML federation the IdP decides which roles a user
may assume (the `Role` attribute). That is authorization delegated to the IdP,
which is fine inside one organisation and dangerous with a partner IdP.
Identity Center's model (SCIM groups + permission sets on the AWS side) keeps
the decision on the SP side.

## Pros and cons

Pros

- Mature and ubiquitous in enterprises: 20 years of interoperability, every IdP
  and every enterprise SaaS speaks it.
- Rich, typed attribute statements; multi-valued groups are natural.
- Strong when configured well: signed assertions, pinned certificates, tight
  audience and time checks, optional encryption.
- Metadata makes the trust relationship explicit and auditable.
- Federations (eduGAIN) show it scales to thousands of parties.

Cons

- XML complexity: namespaces, canonicalisation, XPath. Hard to read, harder to
  parse safely.
- XML-DSig has a poor security record: signature wrapping, comment injection,
  XXE, algorithm confusion. Most libraries have had at least one critical bug.
- No mobile or API story: it is a browser redirect protocol with no access
  token. Calling an API "with SAML" means exchanging the assertion for
  something else (OAuth 2.0 SAML bearer grant, `AssumeRoleWithSAML`).
- Metadata and certificate rotation are manual and break logins when missed.
- IdP-initiated SSO weakens CSRF protections; many deployments still use it.
- Single Logout rarely works end to end.
- Verifying an assertion requires the whole document; you cannot hand a
  compact token to a downstream service the way you can with a JWT.

### SAML vs OIDC

| | SAML 2.0 | OpenID Connect |
|---|---|---|
| Format | XML, XML-DSig, optional XML-Enc | JSON, JWT (JWS, optional JWE) |
| Transport | browser redirect + form POST (bindings) | browser redirect + back-channel HTTPS (code flow) |
| Mobile / SPA / API | not designed for it | designed for it (PKCE, access tokens) |
| Discovery | metadata XML, exchanged manually | `/.well-known/openid-configuration` + JWKS, fetched |
| Key rotation | re-exchange metadata | publish new key in JWKS, clients pick it up |
| Token for APIs | none | access token (OAuth 2.0) |
| Who the token is for | `Audience` | `aud` |
| Binding answer to question | `InResponseTo` | `state` + `nonce` |
| Complexity | high (canonicalisation, XPath) | moderate (JWT validation rules) |
| Where you meet it | enterprise SaaS, universities, AWS console federation | consumer login, new products, mobile apps, APIs |

## Alternatives

- **OpenID Connect** (chapter 06) for anything new. Same roles and flow, JSON
  and JWT, works for mobile and APIs, far simpler to validate. Every modern IdP
  offers both; pick OIDC unless the counterparty only has SAML.
- **Kerberos** (chapter 04) on an intranet: transparent desktop SSO to
  internal services with proof of possession. It does not cross the internet or
  organisational boundaries; SAML was invented to go where Kerberos cannot.
- **WS-Federation** where legacy ADFS or SharePoint still require it. Treat it
  as SAML with different envelope XML, and migrate.
- **Cognito or Identity Center as a SAML-to-JWT bridge**: let a managed service
  do the XML, and consume JWTs in your code.

## Pitfalls

Each of these is a real bug class, and each one enables a real attack.

| Mistake | Attack it enables |
|---|---|
| Not validating the XML schema before parsing | **XML Signature Wrapping (XSW)**: the attacker keeps the genuine signed `Assertion` (say inside `Extensions` or `SubjectConfirmationData`) and adds a forged one where the parser looks first. The signature verifies (on the genuine one), the identity is read from the forged one. Schema validation rejects the extra elements; reading identity only from the verified reference closes it too. |
| Parsing `NameID` text by concatenating text nodes | **Comment injection** (Duo Labs, 2018, CVE-2017-11427 and friends). The IdP signs `alice@lab.example<!---->.attacker.example`; canonicalisation keeps the comment in the signed bytes so the signature stays valid, but a parser that returns only the first text node yields `alice@lab.example`. An attacker who can register `alice@lab.example.attacker.example`… impersonates alice. Fix: use the library's fixed extraction; never re-implement XML text handling. |
| Accepting an unsigned assertion, or verifying the Response but reading an unsigned Assertion inside it | Forge any assertion. `WantAssertionsSigned=true` and a library that fails closed when no signature is present. The demo shows the stripped-signature case being rejected. |
| Not checking `Audience` | An assertion issued for `billing` logs the attacker into `orders`. The demo shows it rejected; it would be accepted by an SP that skips the check, and samlify does not do it for you. |
| Not checking `InResponseTo` (or accepting IdP-initiated responses everywhere) | **Replay** within the validity window, and **login CSRF**: the attacker plants their own login in the victim's browser. Store issued request IDs with a TTL, consume them once. |
| Not checking `Recipient` / `Destination` | **Token substitution** between two ACS URLs of the same SP, or between SPs sharing an `entityID`. |
| Ignoring `NotOnOrAfter`, or a clock skew of hours | Bearer assertions live forever; any leaked assertion is a working credential. |
| Trusting attributes for authorization without an SP-side mapping | `role=admin` from any trusted IdP becomes admin here. Partners' IdP admins become your admins. |
| Verifying with the certificate in the message `KeyInfo` instead of the pinned metadata certificate | Anyone signs with any key and includes its certificate; the signature "verifies". samlify rejects a `KeyInfo` certificate that is not in metadata (`ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA`, tested here). |
| Allowing `SigAlg` or `SignatureMethod` chosen by the message without an allowlist | Downgrade to SHA-1, or to a "none"-like algorithm in buggy libraries. Pin RSA-SHA256 or better. |
| Parsing XML with external entities enabled | **XXE**: file disclosure and SSRF from the SP's parser. Disable DTDs and external entities. (samlify's xmldom parser does not resolve external entities and treats parse errors as fatal.) |
| Letting the AuthnRequest's `AssertionConsumerServiceURL` decide where the Response goes, without cross-checking metadata | The IdP posts assertions to an attacker's ACS. `parseAuthnRequest` here rejects a mismatch. |
| Using `emailAddress` as the account key | Email changes and re-assignment link the wrong person to an account. Prefer `persistent` NameID, or a stable immutable attribute. |

## Further reading

Primary sources first.

- OASIS, *Assertions and Protocols for SAML V2.0* (saml-core-2.0-os), 2005.
  https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- OASIS, *Bindings for SAML V2.0* (saml-bindings-2.0-os).
  https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
- OASIS, *Profiles for SAML V2.0* (saml-profiles-2.0-os): the Web Browser SSO Profile is section 4.1.
  https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
- OASIS, *Metadata for SAML V2.0* and *Security and Privacy Considerations for SAML V2.0*.
  https://docs.oasis-open.org/security/saml/v2.0/
- W3C, *XML Signature Syntax and Processing*. https://www.w3.org/TR/xmldsig-core1/
- Somorovsky et al., *On Breaking SAML: Be Whoever You Want to Be*, USENIX Security 2012 (the XSW paper).
  https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- Duo Labs, *Duo Finds SAML Vulnerabilities Affecting Multiple Implementations*, 2018 (comment injection).
  https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
- OWASP, *SAML Security Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- AWS, *Using SAML-based federation for API access to AWS* and `AssumeRoleWithSAML`.
  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html
- AWS, *IAM Identity Center: connect to an external identity provider* (SAML + SCIM).
  https://docs.aws.amazon.com/singlesignon/latest/userguide/manage-your-identity-source-idp.html
- samlify documentation. https://samlify.js.org/
