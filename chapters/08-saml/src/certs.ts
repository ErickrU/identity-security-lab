/**
 * Key material for the lab IdP.
 *
 * SAML signs XML with an RSA (or EC) key and publishes the matching X.509
 * certificate in the IdP metadata. Nothing else in the certificate matters to
 * SAML: the SP does not check the CA, the hostname or the expiry the way TLS
 * does. It compares the certificate in the message with the one it pinned from
 * metadata and then verifies the signature with the public key inside it.
 *
 * We generate a fresh key pair every run with the system `openssl` binary,
 * in a temporary directory that is deleted right after reading the PEM files.
 * Nothing is written inside the repository, so nothing can be committed by
 * accident (the root .gitignore also ignores *.pem and **\/certs/).
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface KeyMaterial {
  /** PEM private key (PKCS#8). Stays on the IdP. Never log it. */
  privateKey: string;
  /** PEM X.509 certificate. Public: published in the IdP metadata. */
  certificate: string;
}

/** True when `openssl` can be executed from PATH. Tests use it to skip. */
export function opensslAvailable(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Generate a 2048-bit RSA key and a self-signed certificate valid for one day.
 *
 * Equivalent shell command:
 *   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
 *     -days 1 -subj /CN=lab-idp
 */
export function generateSigningKeyPair(commonName = 'lab-idp'): KeyMaterial {
  const dir = mkdtempSync(join(tmpdir(), 'saml-lab-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  try {
    execFileSync(
      'openssl',
      [
        'req', '-x509',
        '-newkey', 'rsa:2048',
        '-nodes', // no passphrase on the key: this is a throwaway lab key
        '-keyout', keyPath,
        '-out', certPath,
        '-days', '1',
        '-subj', `/CN=${commonName}`,
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    return {
      privateKey: readFileSync(keyPath, 'utf8'),
      certificate: readFileSync(certPath, 'utf8'),
    };
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stderr?: Buffer };
    if (e.code === 'ENOENT') {
      throw new Error(
        'openssl was not found on PATH. This chapter generates the IdP signing key with it. ' +
          'Install OpenSSL (macOS: `brew install openssl`, Debian/Ubuntu: `apt install openssl`) and retry.',
      );
    }
    const stderr = e.stderr ? e.stderr.toString().trim() : '';
    throw new Error(`openssl failed to generate the lab key pair${stderr ? `: ${stderr}` : ''}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
