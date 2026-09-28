# 09 · MFA: TOTP from the RFC, and why passkeys are the real fix

> **TL;DR** — A password is one secret, and it leaks: phishing, reuse, breaches. MFA adds a
> proof from another category (something you have or are), so the stolen password is not enough.
> TOTP (RFC 6238) is the 6-digit code in your authenticator app: `HMAC(secret, floor(unixTime / 30))`
> truncated to six digits, computed by phone and server from a secret shared once via a QR code.
> Free, offline, far better than nothing, but a phishing proxy relays it in real time. Passkeys
> (FIDO2 / WebAuthn) sign a server challenge with a key bound to the site's domain, so a look-alike
> domain gets a useless signature. TOTP is the floor, passkeys or security keys the goal, SMS never the only factor.

## Why it was invented

Passwords fail in ways that no hashing algorithm fixes, because the failure happens before
the password reaches your database:

| Failure | What happens | Why a password alone cannot resist it |
|---|---|---|
| Phishing | The user types the real password into a fake page | The secret is the same wherever it is typed |
| Reuse and credential stuffing | One site leaks, bots try the same pair on every other site | Users pick one password for many sites |
| Breaches and offline cracking | A dump of hashes is cracked at billions of guesses per second | Weak passwords fall no matter how slow the hash is |
| Malware and infostealers | A keylogger or a stolen browser profile hands over the password | The client is not trusted |

A second factor from another category makes the stolen password insufficient:

| Category | "Something you..." | Examples | Typical failure |
|---|---|---|---|
| Knowledge | know | password, PIN, security questions | copied: phishing, breaches, guessing |
| Possession | have | phone with an authenticator app, security key, smart card | stolen, borrowed, or the phone number is hijacked (SIM swap) |
| Inherence | are | fingerprint, face | rarely a factor on its own; on phones and laptops it unlocks a possession factor locally |

Two proofs from the same category (password plus security question) are not MFA. They fall
to the same attack.

The history is a slow move from proprietary hardware to open algorithms to public-key
cryptography:

| Year | Milestone | Why it mattered |
|---|---|---|
| 1986 | Security Dynamics ships the SecurID token (later RSA SecurID) | A keyfob shows a new number every 60 s. It proves possession, but the algorithm is secret and every vendor needs its own server |
| 2004 | OATH, the Initiative for Open Authentication | Vendors agree to standardise so any token works with any server |
| 2005 | RFC 4226, HOTP | An HMAC over a counter, truncated to digits. Open, tiny, any device can compute it |
| 2010 | Google Authenticator | A free app replaces the keyfob. Its `otpauth://` QR code becomes the de facto enrollment format |
| 2011 | RFC 6238, TOTP | HOTP where the counter is the clock. No counter to keep in sync |
| 2013 | FIDO Alliance launches; U2F (Google and Yubico) follows in 2014 | A USB key signs a challenge bound to the origin. The first widely deployed phishing-resistant factor |
| 2017 | NIST SP 800-63B | SMS and voice codes become "RESTRICTED": allowed, but you must offer something better |
| 2018 | Google reports zero successful phishing on its 85,000+ employees since moving them to security keys | Evidence, not theory |
| 2019 | WebAuthn becomes a W3C Recommendation; with CTAP2 it forms FIDO2 | Built into every browser and OS. Touch ID and Windows Hello become authenticators, not only USB keys |
| 2022 | Passkeys: Apple, Google and Microsoft commit to synced WebAuthn credentials | Losing the phone no longer means losing the key. Passkeys can replace the password, not only add to it |

## How it works

### TOTP end to end

```mermaid
sequenceDiagram
    participant P as Phone (authenticator app)
    participant U as User's browser
    participant S as Server
    Note over S: Enrollment, once
    S->>S: secret = 20 random bytes, stored encrypted
    S->>U: QR code = otpauth://totp/Lab:alice?secret=BASE32&issuer=Lab&...
    U->>P: scan
    Note over P,S: Both now hold the secret. Nothing else is ever exchanged.
    U->>S: first code (proves the phone got the right secret and its clock is right)
    Note over P,S: Login, later
    P->>P: T = floor(now / 30); code = HOTP(secret, T)
    U->>S: password + code
    S->>S: compute codes for T-1, T, T+1; constant-time compare
    S->>S: matched counter at or below lastUsedCounter? reject (replay)
    S->>S: atomically update lastUsedCounter only if stored value is lower;<br/>issue session only if exactly one update wins; count attempts (5 per step)
    S-->>U: session
```

Step by step, with the numbers the demo prints for 2024-01-01T00:00:00Z and the RFC test
secret `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (ASCII `12345678901234567890`):

1. **Shared secret at enrollment.** The server draws 20 random bytes (160 bits, the size
   RFC 4226 recommends) and shows them once, base32-encoded, inside a URL:
   `otpauth://totp/Identity%20Lab:alice%40example.com?secret=GEZD...&issuer=Identity%20Lab&algorithm=SHA1&digits=6&period=30`.
   The QR code is just that URL. Base32 (RFC 4648) is used because a person can read it
   aloud: no `0`/`O` or `1`/`l` confusion, case does not matter. Ask for one valid code
   before you switch MFA on: it proves the phone scanned the right secret and has the right time.
   Keep the defaults, SHA-1, 6 digits, 30 s: several apps ignore other values and their codes
   would never match. HMAC-SHA-1 is not affected by the SHA-1 collision attacks; the weakness
   of TOTP is elsewhere (see below).
2. **The counter is the clock** (RFC 6238 section 4.2): `T = floor((unixTime - T0) / X)`
   with `X = 30 s` and `T0 = 0`. At 2024-01-01T00:00:00Z, `T = 1704067200 / 30 = 56802240`.
   Everyone inside the same 30 s gets the same `T`.
3. **HMAC of the counter** (RFC 4226 section 5.3, step 1). `T` is written as 8 big-endian
   bytes, `000000000362bbc0`, and fed to HMAC-SHA-1 with the secret as key:
   `62553abc450d8c4c557f86aa7a7c68adbdd768c0`.
4. **Dynamic truncation** (section 5.4). The low nibble of the last byte (`c0` → `0`) picks an
   offset. The four bytes there, `62 55 3a bc`, with the top bit cleared, form a 31-bit
   integer: `0x62553abc = 1649752764`. Masking the top bit avoids signed/unsigned trouble.
5. **Modulo 10^6, left-padded** (step 3): `1649752764 mod 1000000 = 752764`. A result like
   `070309` keeps its leading zero, it is a six-character string, not a number.
6. **Verification.** The server computes the codes for `T-1`, `T` and `T+1`, compares in
   constant time, refuses any matched counter at or below the last one this user logged in
   with, stores the matched counter, and counts failed attempts.

`src/hotp.ts` has each of these steps commented with the RFC section it implements.

Why each rule in step 6 exists:

| Rule | Why | Without it |
|---|---|---|
| Window of ±1 step | Phones drift, people type slowly. RFC 6238 section 5.2 recommends accepting at most one step back. ±1 means three codes are valid at any moment and a code stays usable for up to 90 s | Users get "invalid code" at every step boundary and support tickets push the window to ±5 |
| Rate limit code entry | Six digits is a space of 1,000,000, and three are valid. One guess succeeds with probability 3 in a million. That is only safe if guesses are scarce: about 5 attempts per user per step, then lock and alert | A bot walks in after roughly 333,000 tries, minutes at web speed |
| Store the last used counter atomically | The code is valid for the whole window. Use a compare-and-set/transaction: update only where stored counter is lower, and issue a session only if exactly one write wins. Two concurrent requests that both read the old value must not both succeed | Without state it is replayable for 90 s; without atomic update, a race accepts the same code twice |
| Constant-time compare | `===` stops at the first different character. Hard to exploit for six digits over a network, but free to fix | A theoretical digit-by-digit oracle |
| Secret encrypted at rest | TOTP is symmetric. The server's copy IS the factor. Decrypt only inside the verifier, never log it, never let the `otpauth://` URL reach analytics or a GET parameter | One database dump removes MFA for every user, silently |
| Backup codes hashed like passwords | They are short, so use a slow hash (argon2id, scrypt), one use each, show them once, regenerate the whole set when one is used | A dump of backup codes is a dump of MFA bypasses |
| "Remember this device" expires | A remembered-device token is an MFA bypass by design. Bind it to the user, cap it (30 days), revoke on password change, list and revoke it in settings, never honour it for admin actions | A stolen cookie bypasses MFA forever |

### Why TOTP is still phishable

Nothing in the code says which site it is for. `HMAC(secret, time)` is the same whether the
user types it into `bank.example` or `bank-example.com`. A real-time proxy (adversary-in-the-
middle kits such as Evilginx or Modlishka) sits between the user and the real site, shows the
real login page, forwards the password and the code within the 30 s window, and keeps the
session cookie the real site sends back. The server saw a correct password and a correct
code. It cannot tell who typed them. This is the property passkeys fix.

### MFA methods compared

| Method | Phishing-resistant | Cost | UX | Typical failure modes |
|---|---|---|---|---|
| SMS one-time code | No | Per message | Familiar, works on any phone | SIM swap and port-out fraud, SS7 interception, recycled numbers, delivery delays, roaming. NIST 800-63B: RESTRICTED |
| Email one-time code | No | Free | No app needed | Only as strong as the mailbox, which usually also resets the password. One compromise, two factors |
| TOTP app (this chapter) | No: real-time relay | Free | Open any app, type 6 digits | Clock drift, lost phone without backup codes, QR screenshots, shared secret on the server |
| Push approval | No: a proxy relays the prompt too | App and service | One tap | MFA fatigue / prompt bombing; number matching and context (location, app) fix that part |
| Hardware TOTP token | No | Device | No phone needed | Battery life; seeds are provisioned by the vendor (the 2011 RSA breach leaked SecurID seeds); same relay attack |
| FIDO2 security key | Yes | About 25–70 USD per key | Touch or tap; needs USB or NFC | Lost key: enroll two. Not every device has a port |
| Passkey, device-bound | Yes | Free | Biometric or PIN | Lost device = lost credential: enroll more than one |
| Passkey, synced | Yes | Free | Biometric or PIN, follows you to new devices | Recovery is your platform account's security; cross-ecosystem use goes through a QR + Bluetooth handshake |

### Passkeys, FIDO2 and WebAuthn

Vocabulary first, because the specs use it precisely:

| Term | Meaning |
|---|---|
| Relying Party (RP) | Your site. The **RP ID** is its domain, for example `example.com`; keys are scoped to it |
| Origin | Scheme + host + port the browser is really on, `https://app.example.com`. The browser writes it, the page cannot |
| Authenticator | What holds private keys: a platform one (Touch ID, Windows Hello, Android) or a roaming one (security key, a phone used over Bluetooth) |
| Credential | A key pair created for one RP. The server gets the public key and a **credential ID** |
| Challenge | Random bytes from the server, used once, signed by the authenticator |
| Attestation | At registration: a statement about the authenticator model, signed by its maker. Most passkeys send `none` |
| Assertion | At login: the signature over the challenge and context. This is what proves possession |
| User presence (UP) / user verification (UV) | UP: someone touched the key. UV: they proved who they are locally, with a biometric or PIN |
| Discoverable (resident) credential | Stored on the authenticator with the user handle, so login can start without a username |
| Sign count | A counter the authenticator increments per signature. A regression suggests a cloned key. Synced passkeys often report 0 |
| Synced vs device-bound | Synced: iCloud Keychain, Google Password Manager, 1Password, Bitwarden. Device-bound: security keys, some platform keys. Flags **BE** (backup eligible) and **BS** (backed up) tell the server which one it got |

**Registration ceremony** (`navigator.credentials.create`):

1. The server sends `PublicKeyCredentialCreationOptions`: a fresh random challenge (at least
   16 bytes), `rp: { id: "example.com", name }`, `user: { id, name, displayName }` where `id`
   is a random handle, not the email, allowed algorithms (ES256 first), and
   `authenticatorSelection: { residentKey: "preferred", userVerification: "required" }`.
2. The browser builds `clientDataJSON = { type: "webauthn.create", challenge, origin }`. The
   origin is filled in by the browser from the page it is really showing.
3. The authenticator asks for UV (face, fingerprint, PIN), generates a new key pair scoped to
   the RP ID, and returns an attestation object: authenticator data (SHA-256 of the RP ID,
   flags UP/UV/BE/BS, sign count, credential ID, public key in COSE format) and an
   attestation statement.
4. The server checks: challenge matches the one it issued and has not been used; origin is
   in its allowlist; `rpIdHash` equals SHA-256 of its RP ID; UP set, UV set if required;
   algorithm allowed. Then it stores the credential.

**Authentication ceremony** (`navigator.credentials.get`):

1. The server sends a challenge, its RP ID, `userVerification: "required"`, and either the
   user's credential IDs or nothing (discoverable flow, or the browser's autofill
   `mediation: "conditional"`).
2. The authenticator looks up credentials **by RP ID**. On `examp1e.com` there is none for
   `example.com`, so there is nothing to offer and nothing to steal.
3. After UV, it signs `authenticatorData || SHA-256(clientDataJSON)` with the private key and
   returns the assertion: authenticator data, client data, signature, user handle.
4. The server finds the public key by credential ID, checks `type: "webauthn.get"`,
   challenge, origin, `rpIdHash`, the flags, verifies the signature, and compares the sign
   count. If either stored or new count is non-zero and the new count is not greater, treat
   it as a possible-clone signal and apply RP risk policy; it is not a universal mandatory
   login failure. A persistent zero (common for synced passkeys) supplies no clone signal.
   Update the stored count only when it increases.

Why this resists phishing, in one sentence each:

- The key is scoped to the RP ID and the browser only offers matching credentials, so a
  look-alike domain cannot even ask.
- The origin is inside the signed data, so a signature obtained on the wrong site fails on the
  right one.
- The challenge is single use, so a captured assertion cannot be replayed.
- The server holds public keys only, so a database breach gives nothing to log in with.
- Verification is local: the biometric never leaves the device, and there is no biometric
  database to breach.

What the server stores per credential: credential ID, public key (COSE), algorithm, sign
count, user handle, transports, BE/BS flags, the authenticator's AAGUID, a friendly name and
creation date. No secret.

What passkeys do not fix: account recovery (still the weakest door), a stolen session cookie
after login, and the fact that with synced passkeys your platform account becomes the root
of trust. NIST's 2024 supplement to SP 800-63B accepts synced passkeys at AAL2; device-bound
authenticators with UV can reach AAL3.

## Run it

Everything runs offline. `enroll` is the one command that talks to something else: your phone.

```bash
# usage plus a narrated demo: fixed secret, fake clock, every decision explained
npm run 09

# the RFC 6238 Appendix B and RFC 4226 Appendix D vectors, computed here next to the expected values
npm run 09 -- vectors

# a real enrollment: scan the QR code with Google Authenticator, Authy, 1Password, Microsoft
# Authenticator... then compare the code on the phone with the one printed for 60 s
npm run 09 -- enroll alice@example.com          # add --big if the small QR code will not scan

# stateless math/interoperability check only: no persistent replay state or rate limiter
# A production endpoint must pass lastUsedCounter and atomically compare-and-set it.
npm run 09 -- verify <secret> <code>
npm run 09 -- verify GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ 752764   # the demo's code, expect a rejection today

# tests: RFC vectors, base32, window, replay, otpauth URL
npx vitest run chapters/09-mfa-totp-passkeys
```

What you will see in the demo, and what to look at:

```
1) The code changes every 30 s: counter = floor(unixTime / 30), code = HOTP(secret, counter)
  2024-01-01T00:00:00Z   counter 56802240   code 752764
  2024-01-01T00:00:29Z   counter 56802240   code 752764   (same step, same code)
  2024-01-01T00:00:30Z   counter 56802241   code 195529
   How the first one was computed (RFC 4226 section 5.3 and 5.4):
     counter as 8 bytes   000000000362bbc0
     HMAC-SHA-1           62553abc450d8c4c557f86aa7a7c68adbdd768c0
     offset               last nibble = 0 → bytes 0..3
     31-bit integer       0x62553abc = 1649752764
     mod 10^6             752764
2) A previous code is accepted once
  2024-01-01T00:00:33Z   user types 752764, generated in step 56802240 (the previous step)
  → accepted: matched counter 56802240 (current -1, the previous step)
3) The same code again is a replay, even though the window still covers it
  → rejected: this code (or a newer one) was already used, replay
4) A code from two steps ago is outside the window
  → rejected: no counter in [56802241, 56802243] produces this code
```

- In `vectors`, every row must say `ok`. These are the numbers printed in the RFCs; matching
  them is what makes this code interoperable with every authenticator app.
- In `enroll`, the code on the phone and the code on screen must be identical and flip at the
  same second. If they differ, the phone's clock is off. No network traffic happened between
  them: same secret, same time, same math.
- In `verify`, read which counter matched. A code typed a few seconds after the boundary
  matches `current -1`: that is the window at work.

Code map:

| File | What it teaches |
|---|---|
| `src/base32.ts` | RFC 4648 base32. Lenient decode: case, spaces, dashes and missing padding are fine, anything else is an error |
| `src/hotp.ts` | RFC 4226, one commented line per RFC step, plus `hotpSteps()` that returns every intermediate value |
| `src/totp.ts` | RFC 6238 counter, `verifyTotp()` with window, replay refusal and constant-time compare, `otpauthUrl()`, `generateSecret()` |
| `src/rfc-vectors.ts` | The official test vectors, shared by tests and the `vectors` command |
| `src/totp-cli.ts` | `enroll`, `verify`, `vectors`, and the narrated demo |
| `src/*.test.ts` | Offline, deterministic: fixed clock, fixed secret |

`qrcode-terminal` is the one dependency, so `enroll` can draw a scannable QR code in the
terminal. Everything cryptographic is `node:crypto`.

## Scenarios

**A consumer web app.** Password plus TOTP is the floor: it costs nothing and stops
credential stuffing dead. Offer passkeys as the default upgrade, keep backup codes hashed,
and never let SMS reset a stronger factor.

**Operators and administrators.** Hardware security keys, two per person, no SMS or email
fallback, MFA re-checked for every privileged action. This is the population phishing kits
are written for.

**Automation and CLIs.** Machines do not do MFA; humans getting short-lived credentials do.
Require MFA at the moment a person mints a session, then let the session (not the human)
call the API.

**AWS mapping**

| Where | What exists | Notes |
|---|---|---|
| Cognito user pools | MFA off, optional or required (`MfaConfiguration`: `OFF`, `OPTIONAL`, `ON`); methods: SMS, TOTP authenticator app, email (Essentials/Plus plans) | TOTP enrollment is `AssociateSoftwareToken` → a base32 `SecretCode` → **you** build the `otpauth://` URL and QR, exactly as `otpauthUrl()` does → `VerifySoftwareToken` with a first code → `SetUserMFAPreference`. Sign-in answers a `SOFTWARE_TOKEN_MFA` challenge |
| Cognito passkeys | `USER_AUTH` "choice-based" flow: the user picks `WEB_AUTHN`, `EMAIL_OTP`, `SMS_OTP`, password or SRP | Passkeys here are a passwordless first factor. Register with `StartWebAuthnRegistration` / `CompleteWebAuthnRegistration`; the RP ID must be your domain |
| Cognito remembered devices | Device tracking `Always` / `User opt-in`; `ChallengeRequiredOnNewDevice` lets remembered devices skip MFA | The "remember this device" tradeoff from the table above, as a checkbox |
| Cognito adaptive authentication (Plus plan) | Risk score per sign-in; require MFA on medium or high risk | Risk-based auth needs a strong factor to step up to |
| IAM users and root | Virtual MFA (TOTP: the QR code IAM shows is an `otpauth://` URL), FIDO2 security keys and passkeys, hardware TOTP tokens; up to 8 devices per identity | AWS has been enforcing MFA on root users since 2024, management accounts first. Do not enroll this lab's CLI as your real virtual MFA: the secret would sit in plaintext on disk |
| IAM Identity Center | Prompt modes: context-aware (only when the sign-in context changes), always-on, or off. Types: TOTP apps, FIDO2 security keys and built-in authenticators (Touch ID, Windows Hello; this is where synced passkeys show up). Policy for users with no device: require registration, block, or allow | With an external IdP (Okta, Entra ID) over SAML, MFA is the IdP's job and these settings do not apply |
| STS and IAM policies | `aws sts get-session-token --serial-number arn:aws:iam::111122223333:mfa/alice --token-code 123456` mints credentials whose context has `aws:MultiFactorAuthPresent = true` and `aws:MultiFactorAuthAge`. A role trust policy can require it; the CLI's `mfa_serial` profile setting prompts for the code | The condition key is **absent**, not `false`, for long-term access keys. A Deny with `"Bool": {"aws:MultiFactorAuthPresent": "false"}` therefore does not deny them; use `"BoolIfExists"` |

The policy pattern that actually requires MFA:

```json
{
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } }
}
```

**Amazon corporate**, at the level of public knowledge: employee sign-in (Midway) is built on
FIDO hardware security keys, the phishing-resistant row of the table, not on one-time codes.

## Pros and cons

Pros

- TOTP: an open RFC, free, offline. The phone needs no network and no phone number.
- TOTP: interoperable with everything: any authenticator app, IAM virtual MFA, Cognito,
  Identity Center, every IdP.
- TOTP: small enough to implement and audit yourself. The HOTP and TOTP functions in this
  chapter are under 100 lines together.
- Passkeys: phishing-resistant by construction: keys scoped to the RP ID, origin in the signature.
- Passkeys: no shared secret. The server stores public keys, so a breach yields nothing to log in with.
- Passkeys: two factors in one gesture (the device plus a local biometric or PIN), faster than
  any code, and built into every browser and OS.

Cons

- TOTP: phishable in real time by a proxy. It proves possession of the secret, not the site.
- TOTP: symmetric. The server's copy of the secret is the factor; a breach of it is silent.
- TOTP: clock dependence, and a lost phone locks the user out unless backup codes exist.
- TOTP: friction. Open an app, read six digits, type them before they flip.
- Passkeys: recovery moves to the platform account (Apple, Google, Microsoft, a password
  manager), which becomes the root of trust.
- Passkeys: cross-ecosystem use (an iPhone passkey on a Windows PC) works, but through a QR
  code and Bluetooth proximity. Clunky.
- Passkeys: synced ones cannot prove which hardware holds them; enterprises wanting
  attestation still need security keys.
- Passkeys: users and support staff are still learning what they are, and the "add a passkey"
  and "recover account" flows become the target.

## Alternatives

| Instead of | Consider | When |
|---|---|---|
| Password + TOTP | Passkeys as the only credential (passwordless) | New consumer or workforce apps. Keep a recovery path at least as strong as the passkey |
| TOTP | FIDO2 hardware security keys, two per person | Administrators, root accounts, anyone with production access. The key cannot be exported or synced |
| A password at all | Magic links by email | Low-value apps. It is possession of the mailbox, not MFA. Phishable, and the link leaks into logs and mail scanners |
| Always-on MFA prompts | Risk-based / adaptive authentication (Cognito adaptive auth, Identity Center context-aware) | To prompt less often. It decides *when* to ask, it is not itself a factor |
| Push approval | Push with number matching and context | When you already ship a mobile app. Kills prompt bombing |
| Your own MFA | Federate to an IdP that enforces it (chapters 06, 07, 08) and check the `amr` / `acr` claims | Workforce apps: one enrollment, one policy, one place to audit |
| TOTP | Smart cards, PIV/CAC, client certificates | Government and regulated environments with an existing PKI |

## Pitfalls

| Pitfall | Attack it enables | Fix |
|---|---|---|
| No rate limit on code entry | Online brute force: one in 333,333 per guess, minutes at bot speed | About 5 attempts per user per step, then lock and alert; count per account and per source |
| Accepting a code twice | Replay within the window by whoever saw the code, including a concurrent double-submit race | Atomically compare-and-set last used counter; the pure `verifyTotp` helper checks a supplied value, but the CLI does not persist it |
| Window of ±5 "to stop the tickets" | Eleven valid codes; a stolen code lives for five minutes | ±1 and NTP on the server. Show "code expires in N s" to the user |
| Secret in plaintext, in logs, or the `otpauth://` URL in analytics | One dump disables MFA for everyone, silently | Encrypt at rest (KMS envelope), decrypt only in the verifier, never log the URL, never send it as a GET parameter |
| Backup codes stored in plaintext or reusable | A leaked backup code is a permanent bypass | Hash with a slow algorithm, single use, shown once, regenerate the set |
| SMS as the only factor, or as the recovery path | SIM swap, port-out fraud, SS7 interception: the number is the account | Offer TOTP and passkeys; never let SMS reset a stronger factor |
| "Remember this device" forever | A stolen cookie bypasses MFA for good | Cap at 30 days, bind to user and device, revoke on password change, list in settings, never for admin actions |
| MFA enrollment not protected, or MFA optional until enrolled | After a password compromise the attacker enrolls their own device (done to dormant accounts in 2022) | Enroll at first login, require the current factor or a fresh re-auth to add or remove one, notify on every change |
| Account recovery that bypasses MFA | Help-desk social engineering resets the factor; several large 2023 breaches started this way | Recovery at least as strong as the factor: backup codes, a second passkey, identity checks with a waiting period and notifications |
| No re-authentication for sensitive actions | A hijacked session changes the email, adds a factor, or pays out | Step-up: a fresh MFA within a few minutes for security settings and money |
| Push approval without number matching | MFA fatigue: prompt bombing until the user taps "approve" (used against Uber in 2022) | Number matching, location and app context, a cap on prompts, alert on repeated denials |
| Treating TOTP as phishing-proof | Adversary-in-the-middle relay steals the session after a "successful" MFA | Passkeys or security keys for anyone worth phishing; bind sessions to the device where you can |
| WebAuthn server skipping origin, `rpIdHash` or challenge checks | Cross-origin or replayed assertions accepted | Use a maintained server library; check all three on every ceremony; challenges are single use |
| Comparing codes with `===` | Timing side channel on the code | `timingSafeEqual` (a few lines, done here) |
| AWS: `"Bool": {"aws:MultiFactorAuthPresent": "false"}` in a Deny | Long-term access keys bypass the MFA requirement because the key is absent, not false | `"BoolIfExists"` |

## Further reading

- [RFC 4226, HOTP](https://www.rfc-editor.org/rfc/rfc4226) — sections 5.3 and 5.4 are the algorithm, Appendix D the vectors used here.
- [RFC 6238, TOTP](https://www.rfc-editor.org/rfc/rfc6238) — section 4 the counter, section 5.2 the window and resynchronisation advice, Appendix B the vectors.
- [RFC 4648, base16/base32/base64](https://www.rfc-editor.org/rfc/rfc4648) — section 6 and the section 10 test vectors.
- [Key Uri Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) — the `otpauth://` URL, from the Google Authenticator wiki.
- [NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html) — the RESTRICTED status of SMS, the definition of verifier-impersonation (phishing) resistance, AAL levels; and the 2024 supplement on syncable authenticators.
- [Web Authentication: An API for accessing Public Key Credentials, Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/) — the registration and authentication ceremonies, section 7 is the server-side verification checklist.
- [passkeys.dev](https://passkeys.dev/) — implementation guidance and device support matrix, maintained by the FIDO Alliance and W3C WebAuthn community.
- [FIDO Alliance: CTAP 2 specifications](https://fidoalliance.org/specifications/) — how browsers talk to roaming authenticators.
- [CISA: Implementing Phishing-Resistant MFA (2022)](https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf) — the threat model behind "phishing-resistant".
- [Amazon Cognito: Adding MFA to a user pool](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html) and [passkey sign-in](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-authentication-flow-methods.html).
- [IAM: Using multi-factor authentication](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html) and the [`aws:MultiFactorAuthPresent` condition key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-multifactorauthpresent).
- [IAM Identity Center: Multi-factor authentication](https://docs.aws.amazon.com/singlesignon/latest/userguide/enable-mfa.html).
