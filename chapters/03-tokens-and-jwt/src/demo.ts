import { generateKeyPairSync } from 'node:crypto';
import { encodeJson } from './base64url';
import {
  decodeJwt,
  jwkFromPublicKey,
  signJwt,
  tokenWithPayload,
  type Jwks,
  type JwtPayload,
} from './jws';
import { OpaqueTokenStore } from './opaque';
import { verifyEmbeddedJwkNaive, verifyNaive } from './verify-naive';
import { JwtVerificationError, verifyStrict, type StrictVerifyOptions } from './verify-strict';

const NOW_MS = Date.UTC(2026, 8, 28, 12, 0, 0);
const NOW = Math.floor(NOW_MS / 1000);
const ISSUER = 'https://idp.lab.example';
const AUDIENCE = 'https://orders-api.lab.example';

function heading(title: string): void {
  console.log(`\n${title}\n${'─'.repeat(title.length)}`);
}

function short(value: string, length = 80): string {
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}

function strictResult(token: string, options: StrictVerifyOptions): string {
  try {
    const payload = verifyStrict(token, options);
    return `ACCEPTED sub=${String(payload.sub)} role=${String(payload.role)}`;
  } catch (error) {
    const reason = error instanceof JwtVerificationError ? error.code : String(error);
    return `rejected: ${reason}`;
  }
}

function naiveResult(token: string, key: string): string {
  try {
    const payload = verifyNaive(token, key);
    return `ACCEPTED role=${String(payload.role)} (BUG when this token should fail)`;
  } catch (error) {
    return `rejected: ${error instanceof Error ? error.message : String(error)}`;
  }
}

function attack(label: string, token: string, publicPem: string, strict: StrictVerifyOptions): void {
  console.log(`\n  ${label}`);
  console.log(`    naive   → ${naiveResult(token, publicPem)}`);
  console.log(`    strict  → ${strictResult(token, strict)}`);
}

function main(): void {
  const rsa2025 = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsa2026 = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicPem = rsa2026.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const jwks: Jwks = { keys: [jwkFromPublicKey(rsa2026.publicKey, 'kid-2026', 'RS256')] };
  const strict: StrictVerifyOptions = {
    algorithms: ['RS256'],
    jwks,
    issuer: ISSUER,
    audience: AUDIENCE,
    expectedType: 'at+jwt',
    now: () => NOW_MS,
    clockToleranceSec: 30,
  };

  const claims: JwtPayload = {
    iss: ISSUER,
    sub: 'user-alice-7d9f',
    aud: AUDIENCE,
    exp: NOW + 15 * 60,
    nbf: NOW - 5,
    iat: NOW,
    jti: 'token-f9a8',
    scope: 'orders:read orders:write',
    role: 'editor',
    department: 'engineering',
  };
  const genuine = signJwt({ alg: 'RS256', typ: 'at+jwt', kid: 'kid-2026' }, claims, rsa2026.privateKey);

  heading('1. A token is a credential; JWT is only one token format');
  const opaqueStore = new OpaqueTokenStore(() => NOW_MS);
  const opaque = opaqueStore.issue({ sub: 'user-alice-7d9f', scope: 'orders:read orders:write' });
  console.log(`  opaque token  (${opaque.length} chars)  ${opaque}`);
  console.log(`    verify → issuer lookup / introspection: ${JSON.stringify(opaqueStore.introspect(opaque))}`);
  console.log(`  JWT           (${genuine.length} chars)  ${short(genuine)}`);
  console.log(`    verify → locally with the issuer's public JWKS: ${strictResult(genuine, strict)}`);
  console.log('\n  opaque: only its issuer knows what it means; delete its row for instant revocation.');
  console.log('  JWT: every service with the public key verifies it offline; it normally lives until exp.');

  heading('2. JWT anatomy: readable JSON plus a signature');
  const decoded = decodeJwt(genuine);
  const [headerPart, payloadPart, signaturePart] = genuine.split('.');
  console.log(`  header     ${headerPart}\n${JSON.stringify(decoded.header, null, 4).replace(/^/gm, '    ')}`);
  console.log(`\n  payload    ${short(payloadPart, 72)}\n${JSON.stringify(decoded.payload, null, 4).replace(/^/gm, '    ')}`);
  console.log(`\n  signature  ${short(signaturePart, 72)}`);
  console.log('\n  iss=who signed · sub=who · aud=which API · exp/nbf/iat=time window');
  console.log('  jti=token id · scope=delegated capability · role/department=application claims');
  console.log('  Decoding proved nothing. Verification signs exactly "base64url(header).base64url(payload)".');

  heading('3. Attack the deliberately naive verifier');
  console.log('  The naive verifier trusts attacker-controlled header.alg and checks no claims.');
  console.log('  The strict verifier pins policy in configuration, finds kid in a trusted JWKS, then checks claims.');

  const editedPayload = { ...claims, role: 'admin' };
  const simpleEdit = tokenWithPayload(genuine, editedPayload);
  console.log('\n  0) Edit role but keep the genuine signature (signatures do stop this basic attack)');
  console.log(`    naive   → ${naiveResult(simpleEdit, publicPem)}`);
  console.log(`    strict  → ${strictResult(simpleEdit, strict)}`);

  const none = signJwt({ alg: 'none', typ: 'at+jwt', kid: 'kid-2026' }, editedPayload);
  attack('1) Edit role AND say alg=none', none, publicPem, strict);
  console.log('    cause: accepting "none" lets the attacker remove the only proof.');

  const confused = signJwt(
    { alg: 'HS256', typ: 'at+jwt', kid: 'kid-2026' },
    editedPayload,
    publicPem, // public information, misused as a shared HMAC secret
  );
  attack('2) RS256→HS256 key confusion; use the public RSA PEM as an HMAC secret', confused, publicPem, strict);
  console.log('    cause: anyone has the public key; with HS256, anyone holding the verifier key can also sign.');

  const expired = signJwt(
    { alg: 'RS256', typ: 'at+jwt', kid: 'kid-2026' },
    { ...claims, exp: NOW - 3600 },
    rsa2026.privateKey,
  );
  attack('3) A genuine but expired token', expired, publicPem, strict);
  console.log('    cause: a valid signature says "the issuer wrote this", not "it is still valid".');

  const wrongAudience = signJwt(
    { alg: 'RS256', typ: 'at+jwt', kid: 'kid-2026' },
    { ...claims, aud: 'https://billing-api.lab.example' },
    rsa2026.privateKey,
  );
  attack('4) Token substitution: a real token issued for billing is sent to orders', wrongAudience, publicPem, strict);
  console.log('    cause: without aud, one service accepts credentials meant for another.');

  const attackerJwk = jwkFromPublicKey(rsa2025.publicKey, 'attacker-key', 'RS256');
  const injected = signJwt(
    { alg: 'RS256', typ: 'at+jwt', kid: 'attacker-key', jwk: attackerJwk },
    editedPayload,
    rsa2025.privateKey,
  );
  console.log('\n  5) Embed an attacker key in header.jwk and choose an unknown kid');
  try {
    const accepted = verifyEmbeddedJwkNaive(injected);
    console.log(`    naive   → ACCEPTED role=${String(accepted.role)} (BUG: header supplied its own trust key)`);
  } catch (error) {
    console.log(`    naive   → rejected unexpectedly: ${String(error)}`);
    process.exitCode = 1;
  }
  console.log(`    strict  → ${strictResult(injected, strict)}`);
  console.log('    cause: a message cannot provide its own trust anchor; jku/x5u URLs also create SSRF/key-swap risks.');

  heading('4. Rotation: kid chooses among keys the issuer already published');
  const rotatingJwks: Jwks = {
    keys: [
      jwkFromPublicKey(rsa2025.publicKey, 'kid-2025', 'RS256'),
      jwkFromPublicKey(rsa2026.publicKey, 'kid-2026', 'RS256'),
    ],
  };
  const oldToken = signJwt({ alg: 'RS256', typ: 'at+jwt', kid: 'kid-2025' }, claims, rsa2025.privateKey);
  const bothKeys = { ...strict, jwks: rotatingJwks };
  console.log(`  old token + both keys  → ${strictResult(oldToken, bothKeys)}`);
  console.log(`  new token + both keys  → ${strictResult(genuine, bothKeys)}`);
  console.log(`  old token after removal → ${strictResult(oldToken, strict)}`);
  console.log('  Safe rotation: publish old+new, start signing with new, wait beyond max token life, remove old.');
  console.log('  JWKS caches must refetch on an unknown kid; never turn unknown kid into "try any key".');

  heading('5. Revocation: the stateless trade-off is real');
  console.log(`  opaque before revoke → ${JSON.stringify(opaqueStore.introspect(opaque))}`);
  opaqueStore.revoke(opaque);
  console.log(`  opaque after revoke  → ${JSON.stringify(opaqueStore.introspect(opaque))} (instant)`);
  console.log(`  JWT after "logout"   → ${strictResult(genuine, strict)} (still cryptographically valid)`);
  const deniedJtis = new Set(['token-f9a8']);
  console.log(`  denylist by jti      → ${deniedJtis.has(String(claims.jti)) ? 'rejected' : 'accepted'} (requires a lookup until exp)`);
  const userTokenVersion = 4;
  const tokenVersion = 3;
  console.log(`  token-version check  → ${tokenVersion < userTokenVersion ? 'rejected: older than the user record' : 'accepted'} (also a lookup)`);
  console.log('  Normal design: access JWT 5–15 min, refresh token stored/revocable at the issuer. See chapter 05.');

  heading('6. Browser storage: choose which attack you are containing');
  console.log('  place                 JavaScript reads it?   auto-sent?   main risk / defence');
  console.log('  HttpOnly cookie       no                     yes          CSRF → SameSite + CSRF token');
  console.log('  localStorage          yes, persistent        no           XSS steals it → avoid for bearer tokens');
  console.log('  JS memory             yes, until reload      no           XSS can use it now; smallest persistence window');
  console.log('  backend-for-frontend  browser gets cookie    yes          strongest web default; backend holds OAuth tokens');
  console.log('\n  A bearer token belongs to whoever holds its bytes. TLS protects transit; storage and XSS/CSRF controls protect endpoints.');

  heading('Done');
  console.log('  JWT is useful when many services must verify one issuer without calling it each time.');
  console.log('  It is not encryption, not automatic revocation, and not authorization by itself.');
  console.log('  The deployed AWS version of this chapter: https://github.com/ErickrU/jwt-on-aws');
}

main();
