# 04 · Kerberos: SSO before the web, with a toy implementation you can read

> **TL;DR** — Kerberos lets a user authenticate once to a trusted Key Distribution Center
> (KDC), receive a Ticket Granting Ticket (TGT), and trade it for short-lived tickets to many
> services. The password never goes to those services. Each service verifies its ticket locally
> with a key shared only with the KDC, and can prove its own identity back to the client. This is
> why signing into a Windows domain once opens file shares, SQL Server and intranet sites. Its
> price is central trust, strict DNS/time/key management and an intranet-shaped operational
> model. Use it in Active Directory or an existing managed realm. For new internet/web federation,
> use OIDC or SAML; for workload-to-workload identity, consider mTLS/SPIFFE or cloud roles.

## Why it was invented

MIT's Project Athena in the 1980s had thousands of students, shared Unix workstations and
services spread across an untrusted campus network. The common authentication models failed:

- Send the password to every service: every file server, print server and mail server can steal
  it; sniffing the LAN steals it too.
- Give each service a different password: users cannot manage dozens, and there is no SSO.
- Trust the workstation to send a username: anyone can claim to be anyone.
- Ask one central server on every application request: that server becomes latency and
  availability on every path.
- Authenticate only the client: a fake server can collect credentials or return malicious data.

Kerberos adapted the Needham–Schroeder symmetric-key protocol (1978): introduce a trusted third
party that shares a key with every principal, then let it issue encrypted, short-lived tickets.
The name comes from Cerberus, the three-headed guard dog: client, service and KDC.

| Year | Milestone |
| --- | --- |
| 1978 | Roger Needham and Michael Schroeder publish a symmetric-key authentication protocol with a trusted server |
| 1983–1988 | MIT Project Athena develops Kerberos; versions 1–3 stay internal |
| 1989 | Kerberos V4 becomes the first widely deployed version |
| 1993 | Kerberos V5 standardised as RFC 1510: extensible crypto, cross-realm, addresses/flags, delegation |
| 2000 | Windows 2000 adopts Kerberos V5 as the default Active Directory domain protocol |
| 2005 | RFC 4120 replaces RFC 1510; RFC 4121 defines Kerberos with GSS-API |
| 2006+ | AES profiles replace DES/RC4; modern profiles include RFC 3962 and RFC 8009 |

Kerberos solves **authentication and SSO inside a managed security domain**. It does not define
a web login page, user provisioning, an API scope model, or general internet federation.

## How it works

### Vocabulary first

| Term | Meaning | Example |
| --- | --- | --- |
| realm | administrative trust domain, conventionally uppercase DNS | `LAB.EXAMPLE` |
| principal | named identity | `alice@LAB.EXAMPLE` |
| service principal (SPN) | service identity: service/host@realm | `HTTP/orders.lab.example@LAB.EXAMPLE` |
| KDC | trusted service holding principal keys | Authentication Service + Ticket Granting Service |
| AS | verifies the user's long-term key, issues TGT | first exchange after password unlock/login |
| TGS | accepts TGT, issues one service ticket | called once per service/ticket lifetime |
| TGT | ticket addressed to `krbtgt/REALM`; proves prior login to TGS | visible in `klist` |
| keytab | file/secure store containing a service's long-term symmetric key | readable only by that service account |
| ticket cache | user's TGT and service tickets | memory, kernel cache, file; `klist`/`kdestroy` |
| authenticator | fresh timestamp + client identity encrypted with a ticket session key | makes a reusable ticket request single-use |
| AP-REQ / AP-REP | client-to-service ticket exchange and optional mutual proof | happens before the application protocol |

Kerberos is symmetric. The KDC knows a key for alice, a separate key for each service, and a
special `krbtgt` key. There are no public keys in base Kerberos. That shapes its trust:

- A service can verify tickets for itself because it shares its key with the KDC.
- A service cannot decrypt a ticket for another service because that service has another key.
- Compromising `krbtgt` compromises the whole realm; it can forge any TGT.
- Unlike JWT public-key verification, a Kerberos verifier's service key can also forge tickets
  **for that service**. Protect keytabs like passwords.

### The three exchanges

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (alice)
    participant AS as KDC / AS
    participant TGS as KDC / TGS
    participant S as orders service

    Note over C: password → string2key locally; password is discarded
    C->>AS: AS-REQ: alice, krbtgt/REALM, nonce,<br/>PA-ENC-TIMESTAMP encrypted with alice long-term key
    AS->>AS: decrypt timestamp with stored alice key; check ±5 min
    AS-->>C: AS-REP:<br/>TGT encrypted with krbtgt key +<br/>TGT session key encrypted with alice key
    Note over C: password-derived key no longer needed; cache TGT

    C->>TGS: TGS-REQ: TGT + authenticator encrypted with TGT session key,<br/>target HTTP/orders, nonce
    TGS->>TGS: open TGT; check expiry; check authenticator identity/time
    TGS-->>C: TGS-REP:<br/>service ticket encrypted with orders keytab key +<br/>service session key encrypted with TGT session key

    C->>S: AP-REQ: service ticket + authenticator encrypted with service session key
    S->>S: open ticket with keytab; expiry, sname, identity, skew, replay cache
    S-->>C: AP-REP: client's timestamp encrypted with service session key
    Note over C,S: mutual authentication; use the session or GSS-API protection
```

#### 1. AS exchange: password proof → TGT

At account creation, KDC and client derive the same long-term key:

```text
K_alice = string2key(password, realm + principal)
```

At login (`kinit`), the client encrypts its current timestamp with `K_alice` and sends that as
`PA-ENC-TIMESTAMP`. The KDC decrypts it with the stored key and checks the clock. The password
itself never crosses the network.

The reply has two encrypted boxes:

- **TGT**, encrypted with `K_krbtgt`: `{alice, realm, K_alice_tgs, authTime, endTime}`. Alice
  cannot read or edit it. The TGS can.
- **AS-REP encrypted part**, encrypted with `K_alice`: `{K_alice_tgs, nonce, endTime}`. Alice
  opens this and learns the TGT session key.

The nonce binds response to request. Encryption authenticates the KDC indirectly: only the KDC
and alice's key can produce a decryptable answer. The client now forgets the password-derived
key and caches TGT + session key.

**Why pre-authentication?** Without `PA-ENC-TIMESTAMP`, anyone can request alice's AS-REP. The
reply contains ciphertext under a password-derived key, giving an offline password oracle:
guess password, derive key, try decrypting until the known structure appears. That is AS-REP
roasting. Pre-auth forces the requester to prove the key before receiving crackable material.

#### 2. TGS exchange: TGT → service ticket

For each service, the client sends:

- the opaque TGT,
- an authenticator `{alice, currentTime}` encrypted with the TGT session key,
- target SPN and a new nonce.

The TGS opens the TGT with `K_krbtgt`, learns its session key, opens the authenticator, compares
the identities, expiry and clock, and emits:

- **service ticket**, encrypted with `K_orders`: `{alice, HTTP/orders, K_alice_orders, times}`;
- **TGS reply part**, encrypted with `K_alice_tgs`, giving alice `K_alice_orders`.

This is the reason for a TGT: the long-term password key is exposed only once. One TGT buys many
service tickets without password prompts. The KDC remains needed when acquiring/renewing tickets,
not for every request to every service.

#### 3. AP exchange: service ticket → local session

The client sends the service ticket and a fresh authenticator encrypted with
`K_alice_orders`. Orders opens the ticket with its keytab, then the authenticator with the
session key inside. It checks:

- ticket SPN is itself;
- ticket time is valid;
- authenticator client equals ticket client;
- client clock is within the normal five-minute skew;
- `(client, timestamp, service)` is not already in its replay cache.

The service never calls the KDC. For mutual authentication it returns the client's timestamp
encrypted with `K_alice_orders` (`AP-REP`). A fake orders server cannot open the ticket and
therefore cannot produce the proof.

The real protocol then uses GSS-API to expose the authenticated principal and optionally signs
(`integrity`) or encrypts (`privacy`) application messages with derived session keys.

### Why timestamps and replay caches both exist

A service ticket is reusable for hours. The authenticator makes each presentation fresh. A
five-minute clock window absorbs normal skew but also creates a five-minute replay window, so
the service remembers authenticators it has already accepted for at least that long. Timestamp
without replay cache is replayable; replay cache without synchronized clocks grows forever.

Real authenticators add microseconds and sequence/subkeys because two legitimate requests may
occur in the same second. This toy uses millisecond timestamps for readability.

### DNS, SPNs and names

The client asks for a service by SPN, not IP. `HTTP/orders.example` and
`HTTP/alias.example` are different principals even if DNS points both at one machine. Common
“Kerberos is broken” failures are really:

- DNS canonicalizes to a name with no SPN;
- duplicate SPN exists on two accounts;
- load-balanced alias lacks an SPN or the keytab is not shared correctly;
- reverse DNS changes the expected name;
- client and KDC disagree on realm mapping.

An SPN is a security identity. Register it on exactly the account whose key the service holds.

### Cross-realm trust and delegation

Realms can share cross-realm `krbtgt` keys. A client follows a chain of TGTs from its home realm
to a service realm. Every hop is an explicit trust relationship; transitivity and direction
must be understood.

Delegation lets a front-end call a back-end *as the user*. Kerberos supports forwarded TGTs and
S4U extensions in Active Directory:

- **Unconstrained delegation** gives a service enough material to impersonate users broadly;
  compromise is severe.
- **Constrained delegation** limits target services.
- **Resource-based constrained delegation** lets the back-end declare which front-ends may act
  for users and is generally safer.

This is the same “confused deputy” question seen in OAuth: who is acting, for whom, toward which
audience?

### Kerberos ticket vs JWT

| | Kerberos service ticket | JWT |
| --- | --- | --- |
| Typical setting | managed realm/intranet | web, mobile, APIs, federation |
| Cryptography | symmetric service key shared with KDC | usually asymmetric issuer private / verifier public |
| Verifier can forge? | tickets for itself, yes | with public key, no |
| Contents | encrypted from client; service can read | signed, normally readable by holder |
| Issuer contacted per request | no | no |
| Audience binding | SPN and service encryption key | `aud` claim |
| Freshness | ticket times + per-use authenticator + replay cache | `exp`/`nbf`/`iat`; bearer token normally reusable |
| Mutual authentication | built-in AP-REP | not from bearer JWT alone; mTLS/DPoP adds holder proof |
| Revocation | ticket expires; disable account stops new tickets; existing tickets may remain | token expires; denylist/introspection for immediate effect |
| Infrastructure assumptions | KDC reachable for tickets, DNS, synchronized clocks, keytabs | HTTPS/JWKS, issuer/audience configuration, clocks |
| Browser/mobile fit | indirect via SPNEGO, weak outside managed devices | native ecosystem via OAuth/OIDC |

## Run it

Everything runs in one process with Node built-ins. It is faithful in message shape, not wire
compatible with a real KDC: JSON replaces ASN.1, AES-GCM replaces Kerberos AES profiles.

```bash
npm run 04
npx vitest run chapters/04-kerberos
```

The demo shows:

1. `kinit`: the AS-REQ contains encrypted time, never a password; AS-REP returns TGT + session key.
2. TGS: the same TGT obtains an orders ticket without another password.
3. AP: orders verifies offline and returns mutual proof.
4. Exact failures for wrong password, replay, 10-minute skew, wrong service, expired and forged
   tickets.

Code map:

| File | Purpose |
| --- | --- |
| `src/crypto.ts` | string-to-key, random keys, AES-256-GCM encrypted boxes |
| `src/kerberos.ts` | KDC AS/TGS, client ticket cache, service keytab/replay cache, AS/TGS/AP message types |
| `src/demo.ts` | narrated happy path and attacks |
| `src/crypto.test.ts` | derivation, encryption, random IV, wrong key/tamper |
| `src/kerberos.test.ts` | protocol, cache, time, binding, replay and forgery |

Compare with real tools on a machine joined/configured for a realm:

```bash
kinit alice@EXAMPLE.COM     # get TGT
klist                       # list TGT and service tickets
kvno HTTP/app.example.com   # ask TGS for one service ticket
kdestroy                    # delete the local cache; it does not retract copies already stolen
```

## Scenarios

### Where you meet it

| Scenario | What Kerberos does |
| --- | --- |
| Windows Active Directory sign-in | password unlocks/derives domain credentials; domain controller KDC issues TGT; PAC inside AD tickets carries authorization data |
| SMB file shares, printers, SQL Server | client gets `cifs/host` or `MSSQLSvc/host:port` ticket; service maps principal/groups to ACLs |
| Browser intranet SSO | HTTP `Negotiate` (SPNEGO, RFC 4559) carries a Kerberos AP exchange; managed browsers allow configured intranet origins |
| Linux/macOS in a realm | MIT/Heimdal clients, PAM and GSS-API; `kinit`, `klist`, `kdestroy`; keytabs for daemons |
| PostgreSQL and other databases | GSSAPI/Kerberos authenticates without a DB password; database maps principal to role |
| Hadoop/legacy big-data platforms | “Kerberized” cluster: service principals/keytabs for NameNode, DataNode, YARN; delegation tokens reduce repeated KDC use |
| NFSv4 | RPCSEC_GSS provides Kerberos authentication/integrity/privacy (`krb5`, `krb5i`, `krb5p`) |

SPNEGO does not turn Kerberos into general internet federation. It works well when the device is
domain-managed, DNS/SPNs are controlled and the browser knows which sites may receive credentials.
OIDC/SAML work across unrelated devices and organisations through explicit redirects.

### AWS mapping

| AWS service | Kerberos relationship |
| --- | --- |
| AWS Directory Service for Microsoft Active Directory | managed Active Directory/domain controllers; provides the KDC for Windows workloads and trusts |
| AD Connector | proxy to existing on-premises AD rather than storing identities in AWS |
| Amazon RDS / Aurora integrations | supported engines/configurations can authenticate database users through AWS Managed Microsoft AD or self-managed AD; exact engine/edition/region support differs—verify before design |
| Amazon FSx for Windows File Server | joins Active Directory; SMB clients use Kerberos and AD ACLs |
| Amazon EMR | can configure Kerberos for intra-cluster components and users; KDC may be cluster-dedicated or external AD depending architecture |
| EC2 Windows domain join | instances join Managed AD / AD Connector / self-managed AD; users and services receive normal domain tickets |
| AWS IAM / STS | not Kerberos: SigV4 and temporary role credentials solve cloud API authentication; Identity Center federates workforce access (chapter 10) |

At Amazon-corporate scale, Kerberos is publicly known as part of managed workstation/domain
sign-in patterns. This lab makes no claim about private implementation details. Web applications
normally sit behind higher-level corporate SSO/federation, because browser/mobile and partner
boundaries are where OIDC/SAML fit.

## Pros and cons

**Pros**

- Password never goes to application services; compromise of one service does not reveal it.
- One login obtains tickets for many services: mature, transparent SSO.
- Mutual authentication is part of the normal AP exchange.
- Services verify locally; KDC is not on every request path.
- Short-lived tickets, audience/service binding, authenticators and replay caches are built in.
- Deep OS, Active Directory, GSS-API, SMB, SQL and enterprise integration.
- Cross-realm and constrained delegation can express sophisticated enterprise trust.

**Cons**

- KDC is the realm's crown jewel and required to start/renew access; build it highly available.
- Symmetric keys/keytabs must be distributed, protected and rotated on every service.
- Five-minute skew makes reliable time synchronization mandatory.
- DNS/SPN/realm configuration is unforgiving; aliases and load balancers create operational work.
- Designed for managed domains. Firewalls, NAT, unmanaged mobile/browser clients and unrelated
  organisations make deployment awkward (possible does not mean pleasant).
- Account disable/password reset does not necessarily invalidate already-issued tickets.
- Delegation is powerful and easy to over-grant.
- Service-account password keys enable offline roasting if passwords are weak.

## Alternatives

| Alternative | Pick it when |
| --- | --- |
| OIDC (chapters 05–07) | new web/mobile/API login and federation; JSON/JWT, HTTPS, discovery |
| SAML (chapter 08) | existing enterprise SaaS/customer IdP requires browser federation |
| mTLS + SPIFFE/SPIRE (chapter 02) | workloads need short-lived machine identities across Kubernetes/services; no human SSO |
| cloud IAM roles / AWS STS (chapter 10) | workloads or workforce need temporary cloud API credentials |
| passkeys/WebAuthn (chapter 09) | humans need phishing-resistant internet login without a shared password |
| LDAP bind | directory lookup and sometimes legacy auth; simple bind sends a reusable password to the server (only over TLS) and gives no service ticket/mutual SSO |
| NTLM | legacy Windows compatibility only; challenge-response but weaker, no modern delegation, relay-prone; disable where Kerberos works |
| SSH certificates | administrators/services need command-line host/user authentication, not application-wide SSO |

## Pitfalls

| Mistake / compromise | Attack or outage | Mitigation |
| --- | --- | --- |
| service account has a human password | **Kerberoasting**: any authenticated user requests its ticket and guesses password offline | group Managed Service Accounts / long random generated keys, AES, rotation, least privilege |
| pre-auth disabled | **AS-REP roasting**: request password-encrypted reply and crack offline | require pre-auth for every normal user; use stronger pre-auth such as PKINIT where appropriate |
| `krbtgt` key stolen | **Golden Ticket**: forge TGTs for any identity/privilege/lifetime | secure DCs, monitor anomalies, rotate `krbtgt` twice after compromise (two keys may validate during transition) |
| one service key stolen | **Silver Ticket**: forge tickets for that service without KDC logs | isolate/rotate keytabs, managed accounts, service-side authorization/audit |
| ticket cache stolen | **Pass-the-ticket**: bearer reuses ticket until expiry | protect LSASS/caches, Credential Guard, short lifetimes, privileged tiering; ticket authenticator does not help if attacker controls the session key too |
| NT hash reused as Kerberos key | **Overpass-the-hash** / pass-the-key | disable legacy RC4 where possible, protect credentials, modern AES keys and endpoint controls |
| unconstrained delegation | compromised front-end steals forwarded TGTs and impersonates users broadly | resource-based/constrained delegation, mark sensitive accounts non-delegable |
| replay cache absent | captured AP-REQ works again inside skew window | replay cache at every accepting service for at least the skew window |
| clock skew too large / NTP insecure | all logins fail, or replay window grows | authenticated/redundant time, alert before five-minute boundary; never “fix” by allowing hours |
| duplicate/missing SPN | fallback to NTLM, wrong account receives ticket, login failure | inventory SPNs, one owner per SPN, monitor NTLM fallback |
| keytab copied to many hosts forever | one host compromise impersonates every replica indefinitely | dedicated identity, restricted file permissions, short rotation, secrets distribution/HSM where supported |
| long ticket/renewal lifetime | stolen ticket survives account action for too long | choose bounded lifetimes; re-auth for privileged actions; purge caches on response |
| KDC exposed as single instance | realm login/ticket outage | multiple domain controllers/KDCs, DNS discovery, monitoring and tested recovery |
| authorize only from claimed principal | authenticated low-privilege user becomes overpowered | map identity to current ACL/group/resource policy separately (chapter 12) |

## Further reading

- RFC 4120 — Kerberos Network Authentication Service (V5): https://www.rfc-editor.org/rfc/rfc4120
- RFC 4121 — Kerberos V5 GSS-API mechanism: https://www.rfc-editor.org/rfc/rfc4121
- RFC 4559 — SPNEGO-based Kerberos/NTLM HTTP authentication (`Negotiate`): https://www.rfc-editor.org/rfc/rfc4559
- RFC 3962 / RFC 8009 — AES encryption profiles for Kerberos.
- RFC 6113 — Kerberos pre-authentication framework.
- RFC 6806 — FAST/pre-authentication strengthening and KDC referrals.
- Needham & Schroeder, *Using Encryption for Authentication in Large Networks of Computers* (1978).
- MIT Kerberos documentation: https://web.mit.edu/kerberos/krb5-latest/doc/
- Microsoft, *Kerberos authentication overview* and *Service Principal Names*: https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview
- Microsoft, *How the Kerberos version 5 authentication protocol works*: https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview
- AWS Directory Service documentation: https://docs.aws.amazon.com/directoryservice/
