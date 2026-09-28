/**
 * 02 · What a TLS client must refuse, what it must accept, and what mutual TLS adds.
 *
 * Offline and deterministic: the PKI is generated into a temp dir with the
 * system openssl (skipped with a message when openssl is missing), servers
 * bind to port 0 on 127.0.0.1, every request is a fresh handshake.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, type ConnectionOptions } from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateLabPki, opensslAvailable, type LabPki } from './certs';
import { chainOf, tlsGet, type TlsFailure } from './client';
import { startTlsServer, type RunningServer } from './server';

const haveOpenssl = opensslAvailable();
if (!haveOpenssl) console.warn('02 · openssl not found on PATH: skipping the TLS tests');

/** Codes OpenSSL gives when the issuer of the peer certificate is not trusted. Which one depends on what the server sent. */
const UNTRUSTED_ISSUER = ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'];

async function failureOf(p: Promise<unknown>): Promise<TlsFailure> {
  try {
    await p;
  } catch (err) {
    return err as TlsFailure;
  }
  throw new Error('expected the TLS connection to be refused, but it succeeded');
}

/** Raw tls.connect, for the cases where https would not even let us ask (old protocol versions). */
function rawHandshake(options: ConnectionOptions): Promise<string | null> {
  return new Promise((resolve, reject) => {
    let socket: ReturnType<typeof connect>;
    try {
      socket = connect(options, () => {
        const protocol = socket.getProtocol();
        socket.end();
        resolve(protocol);
      });
    } catch (err) {
      return reject(err);
    }
    socket.on('error', reject);
  });
}

describe.skipIf(!haveOpenssl)('02 · TLS', () => {
  let dir: string;
  let pki: LabPki;
  let lab: RunningServer;
  let rogue: RunningServer;
  /** What the lab server logged about its handshakes. */
  const serverLog: string[] = [];

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'lab-02-tls-'));
    pki = generateLabPki(dir);
    lab = await startTlsServer({ key: pki.server.key, cert: pki.server.cert, clientCa: pki.ca.cert, log: (l) => serverLog.push(l) }, 0);
    rogue = await startTlsServer({ key: pki.rogueServer.key, cert: pki.rogueServer.cert, clientCa: pki.rogueCa.cert, log: () => {} }, 0);
  });

  afterAll(async () => {
    await lab?.stop();
    await rogue?.stop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  describe('the PKI openssl produced', () => {
    it('server cert: CN=localhost, SAN with localhost and 127.0.0.1, signed by the lab CA, 1 day', async () => {
      const { X509Certificate } = await import('node:crypto');
      const cert = new X509Certificate(pki.server.cert);
      const ca = new X509Certificate(pki.ca.cert);
      expect(cert.subject).toBe('CN=localhost');
      expect(cert.issuer).toBe('CN=Lab CA');
      expect(cert.subjectAltName).toContain('DNS:localhost');
      expect(cert.subjectAltName).toContain('IP Address:127.0.0.1');
      expect(cert.checkIssued(ca)).toBe(true);
      expect(cert.verify(ca.publicKey)).toBe(true);
      expect(cert.ca).toBe(false);
      expect(ca.ca).toBe(true);
      const lifetimeMs = new Date(cert.validTo).getTime() - new Date(cert.validFrom).getTime();
      expect(lifetimeMs).toBe(24 * 60 * 60 * 1000);
    });

    it('rogue server cert looks identical (same subject, same SAN) but is signed by another key', async () => {
      const { X509Certificate } = await import('node:crypto');
      const real = new X509Certificate(pki.server.cert);
      const fake = new X509Certificate(pki.rogueServer.cert);
      const ca = new X509Certificate(pki.ca.cert);
      expect(fake.subject).toBe(real.subject);
      expect(fake.subjectAltName).toBe(real.subjectAltName);
      expect(fake.issuer).toBe('CN=Rogue CA');
      expect(fake.verify(ca.publicKey)).toBe(false);
    });
  });

  describe('server authentication (what every HTTPS client does)', () => {
    it('rejects the lab server with the default trust store: the lab CA is not in it', async () => {
      const failure = await failureOf(tlsGet({ host: '127.0.0.1', port: lab.port, path: '/' }));
      expect(UNTRUSTED_ISSUER).toContain(failure.code);
    });

    it('accepts the lab server when the client trusts the lab CA, over TLS 1.3', async () => {
      const res = await tlsGet({ host: '127.0.0.1', port: lab.port, path: '/', ca: pki.ca.cert });
      expect(res.status).toBe(200);
      expect(res.protocol).toBe('TLSv1.3');
      expect(res.body.protocol).toBe('TLSv1.3');
      expect(res.body.clientCertificatePresented).toBe(false);
      expect(res.body.clientCertificateAuthorized).toBe(false);
      // The chain the client built: leaf issued by the root it was told to trust.
      const chain = chainOf(res.peer);
      expect(chain.map((c) => c.subject.CN)).toEqual(['localhost', 'Lab CA']);
      expect(chain[0].issuer.CN).toBe('Lab CA');
      expect(chain[0].subjectaltname).toContain('DNS:localhost');
    });

    it('sends SNI: the server learns which hostname the client wanted', async () => {
      const res = await tlsGet({ host: '127.0.0.1', port: lab.port, path: '/', ca: pki.ca.cert, servername: 'localhost' });
      expect(res.status).toBe(200);
      expect(res.body.servername).toBe('localhost');
    });

    it('rejects a valid-looking certificate from a CA the client does not trust (the rogue server)', async () => {
      const failure = await failureOf(tlsGet({ host: '127.0.0.1', port: rogue.port, path: '/', ca: pki.ca.cert }));
      expect(UNTRUSTED_ISSUER).toContain(failure.code);
      // ...and the rogue server is perfectly happy to serve anyone who trusts the rogue CA.
      const res = await tlsGet({ host: '127.0.0.1', port: rogue.port, path: '/', ca: pki.rogueCa.cert });
      expect(res.status).toBe(200);
    });

    it('rejects a hostname that is not in the SAN, even with a trusted chain', async () => {
      const failure = await failureOf(
        tlsGet({ host: '127.0.0.1', port: lab.port, path: '/', ca: pki.ca.cert, servername: 'nothere.example' }),
      );
      expect(failure.code).toBe('ERR_TLS_CERT_ALTNAME_INVALID');
      expect(failure.message).toContain('nothere.example');
    });
  });

  describe('mutual TLS on /mtls (the server authenticates the client too)', () => {
    it('401 without a client certificate', async () => {
      const res = await tlsGet({ host: '127.0.0.1', port: lab.port, path: '/mtls', ca: pki.ca.cert });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('client_certificate_required');
    });

    it("200 with alice's certificate issued by the lab CA, and the server knows her CN", async () => {
      const res = await tlsGet({
        host: '127.0.0.1',
        port: lab.port,
        path: '/mtls',
        ca: pki.ca.cert,
        cert: pki.client.cert,
        key: pki.client.key,
      });
      expect(res.status).toBe(200);
      expect(res.body.cn).toBe('alice');
      expect(res.body.issuer).toBe('CN=Lab CA');
      // The server knew all this at handshake time, before any HTTP was read.
      expect(serverLog.some((l) => l.includes('CN=alice issued by CN=Lab CA: authorized'))).toBe(true);
    });

    it('401 with a client certificate that says CN=alice but was signed by the rogue CA', async () => {
      const res = await tlsGet({
        host: '127.0.0.1',
        port: lab.port,
        path: '/mtls',
        ca: pki.ca.cert,
        cert: pki.rogueClient.cert,
        key: pki.rogueClient.key,
      });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe('client_certificate_not_trusted');
      expect(res.body.reason).toContain('Rogue CA');
    });

    it('/ still reports the client cert when one is presented (authorized or not)', async () => {
      const good = await tlsGet({ host: '127.0.0.1', port: lab.port, path: '/', ca: pki.ca.cert, cert: pki.client.cert, key: pki.client.key });
      expect(good.body.clientCertificatePresented).toBe(true);
      expect(good.body.clientCertificateAuthorized).toBe(true);
      const bad = await tlsGet({ host: '127.0.0.1', port: lab.port, path: '/', ca: pki.ca.cert, cert: pki.rogueClient.cert, key: pki.rogueClient.key });
      expect(bad.body.clientCertificatePresented).toBe(true);
      expect(bad.body.clientCertificateAuthorized).toBe(false);
    });
  });

  describe('protocol versions (minVersion TLSv1.2)', () => {
    it('accepts a client that can do at most TLS 1.2', async () => {
      const protocol = await rawHandshake({ host: '127.0.0.1', port: lab.port, ca: pki.ca.cert, maxVersion: 'TLSv1.2' });
      expect(protocol).toBe('TLSv1.2');
    });

    it('refuses a client that can do at most TLS 1.1 with a protocol_version alert', async () => {
      // SECLEVEL=0 lets OUR client offer the old protocols at all (OpenSSL 3 disables
      // them at the default level; without it the client gives up before dialling,
      // ERR_SSL_NO_PROTOCOLS_AVAILABLE). The server, at its default level and
      // minVersion TLSv1.2, answers the ClientHello with alert 70, protocol_version.
      const failure = await failureOf(
        rawHandshake({
          host: '127.0.0.1',
          port: lab.port,
          ca: pki.ca.cert,
          minVersion: 'TLSv1',
          maxVersion: 'TLSv1.1',
          ciphers: 'DEFAULT:@SECLEVEL=0',
        }),
      );
      expect(failure.code).toBe('ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION');
    });
  });
});
