/**
 * 02 · A tiny PKI for the lab, made with the system `openssl`.
 *
 * Two independent certificate authorities, each with a server certificate for
 * `localhost` and a client certificate for `alice`:
 *
 *   Lab CA   ── signs ──▶ server (CN=localhost, SAN DNS:localhost, IP:127.0.0.1)
 *            ── signs ──▶ client (CN=alice)
 *   Rogue CA ── signs ──▶ rogue server (same name, same SAN, different signer)
 *            ── signs ──▶ rogue client (also CN=alice)
 *
 * The rogue pair exists to make one point: a certificate is only worth what
 * the CA that signed it is worth to the party verifying it. Same names, same
 * fields, valid dates, and still rejected, because the verifier never agreed
 * to trust the rogue CA.
 *
 * `scripts/make-certs.sh` does the same thing in bash for `npm run 02:certs`.
 * Keep the two in sync; the tests use this file with a temporary directory.
 *
 * Why an `openssl` config file instead of `-addext` on the command line:
 * `-addext` only arrived in OpenSSL 1.1.1 and `x509 -req` ignores it; an
 * `-extfile` works everywhere and lets us see every extension in one place.
 */
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/** One key pair with its certificate, as files and as PEM strings. */
export interface Credential {
  keyPath: string;
  certPath: string;
  /** PEM. Private: never log it, never send it. */
  key: string;
  /** PEM. Public: this is what goes over the wire in the handshake. */
  cert: string;
}

export interface LabPki {
  dir: string;
  ca: Credential;
  server: Credential;
  client: Credential;
  rogueCa: Credential;
  rogueServer: Credential;
  rogueClient: Credential;
}

/** Lifetime of every lab certificate. Short on purpose: nothing here should outlive the lesson. */
export const VALIDITY_DAYS = 1;

/** True when `openssl` can be executed. Tests skip themselves when it cannot. */
export function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function openssl(args: string[], cwd: string): string {
  // execFileSync, not exec: arguments are passed as an array, nothing goes through a shell.
  return execFileSync('openssl', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
}

/** A random 128-bit serial. Serial numbers must be unique per CA; RFC 5280 says so, browsers enforce it. */
function randomSerial(): string {
  return '0x' + randomBytes(16).toString('hex');
}

/**
 * Minimal `openssl req` config. `openssl req` insists on a config file with a
 * `distinguished_name` section even when `-subj` provides the subject; using our
 * own file avoids depending on whatever the system default config says.
 *
 * `[ca_ext]` holds the extensions of a certificate authority: `CA:TRUE` is what
 * lets a certificate sign other certificates, `pathlen:0` says it may only sign
 * end-entity certificates (no intermediates below it).
 */
const REQ_CONFIG = `[req]
distinguished_name = dn
prompt = no

[dn]
CN = placeholder-overridden-by-subj

[ca_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
`;

/**
 * Extensions of a server certificate. The client checks the hostname against
 * `subjectAltName`, not against CN (RFC 6125; browsers stopped reading CN in
 * 2017). `extendedKeyUsage = serverAuth` says "this key is for being a server":
 * a client cert cannot be reused to impersonate a server.
 */
function serverExtensions(): string {
  return `basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
`;
}

/** Extensions of a client certificate. `clientAuth` only: it cannot be used to run a server. */
function clientExtensions(): string {
  return `basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
`;
}

function read(dir: string, name: string): Credential {
  const keyPath = join(dir, `${name}-key.pem`);
  const certPath = join(dir, `${name}.pem`);
  return { keyPath, certPath, key: readFileSync(keyPath, 'utf8'), cert: readFileSync(certPath, 'utf8') };
}

/** Generate a P-256 private key. ECDSA: small, fast, and what most of the public web uses today. */
function makeKey(dir: string, name: string): void {
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-out', `${name}-key.pem`], dir);
}

/** A self-signed root: the CA signs its own certificate. Nobody vouches for a root; you choose to trust it. */
function makeCa(dir: string, name: string, cn: string): void {
  makeKey(dir, name);
  openssl(
    [
      'req', '-x509', '-new',
      '-key', `${name}-key.pem`,
      '-out', `${name}.pem`,
      '-days', String(VALIDITY_DAYS),
      '-subj', `/CN=${cn}`,
      '-config', 'req.cnf',
      '-extensions', 'ca_ext',
      '-set_serial', randomSerial(),
    ],
    dir,
  );
}

/**
 * Issue a certificate: the subject makes a key and a signing request (CSR),
 * the CA verifies whatever it verifies (here: nothing, it is our lab) and signs
 * the request together with the extensions IT decides on. The private key
 * never leaves the subject; the CA only ever sees the public half.
 */
function issue(dir: string, name: string, cn: string, ca: string, extensions: string): void {
  makeKey(dir, name);
  writeFileSync(join(dir, `${name}.ext`), extensions);
  openssl(['req', '-new', '-key', `${name}-key.pem`, '-out', `${name}.csr`, '-subj', `/CN=${cn}`, '-config', 'req.cnf'], dir);
  openssl(
    [
      'x509', '-req',
      '-in', `${name}.csr`,
      '-CA', `${ca}.pem`,
      '-CAkey', `${ca}-key.pem`,
      '-set_serial', randomSerial(),
      '-days', String(VALIDITY_DAYS),
      '-extfile', `${name}.ext`,
      '-out', `${name}.pem`,
    ],
    dir,
  );
}

/**
 * Build the whole lab PKI into `dir` (created if needed, files overwritten).
 * Takes well under a second with EC keys.
 */
export function generateLabPki(dir: string): LabPki {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'req.cnf'), REQ_CONFIG);

  makeCa(dir, 'ca', 'Lab CA');
  issue(dir, 'server', 'localhost', 'ca', serverExtensions());
  issue(dir, 'client', 'alice', 'ca', clientExtensions());

  makeCa(dir, 'rogue-ca', 'Rogue CA');
  issue(dir, 'rogue-server', 'localhost', 'rogue-ca', serverExtensions());
  issue(dir, 'rogue-client', 'alice', 'rogue-ca', clientExtensions());

  return {
    dir,
    ca: read(dir, 'ca'),
    server: read(dir, 'server'),
    client: read(dir, 'client'),
    rogueCa: read(dir, 'rogue-ca'),
    rogueServer: read(dir, 'rogue-server'),
    rogueClient: read(dir, 'rogue-client'),
  };
}

/** Load a PKI that `npm run 02:certs` (or `generateLabPki`) already wrote to `dir`. */
export function loadLabPki(dir: string): LabPki {
  return {
    dir,
    ca: read(dir, 'ca'),
    server: read(dir, 'server'),
    client: read(dir, 'client'),
    rogueCa: read(dir, 'rogue-ca'),
    rogueServer: read(dir, 'rogue-server'),
    rogueClient: read(dir, 'rogue-client'),
  };
}

/** Human-readable summary of a certificate, straight from openssl (what `npm run 02:certs` prints). */
export function describeCert(certPath: string): string {
  return openssl(['x509', '-in', certPath, '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName,extendedKeyUsage'], '.');
}
