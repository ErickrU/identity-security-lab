/**
 * 02 · A client that tries to connect in every way that should fail, and the
 * ways that should work, and says why each time.
 *
 *   (a) default trust store              → rejected: the lab CA is not in it
 *   (b) trusting the lab CA              → 200, and we print the negotiated protocol, cipher and chain
 *   (c) a server with a rogue cert       → rejected: right name, wrong signer
 *   (d) wrong hostname (SNI mismatch)    → rejected: the name is not in the SAN
 *   (e) /mtls without, with, with rogue  → 401, 200 CN=alice, 401
 *
 * Run `npm run 02:server` in one terminal and `npm run 02:client` in another.
 * The script exits 0 only if every case ended the way TLS says it should.
 */
import { X509Certificate } from 'node:crypto';
import { existsSync } from 'node:fs';
import { request, type RequestOptions } from 'node:https';
import type { DetailedPeerCertificate, TLSSocket } from 'node:tls';
import { loadLabPki, type LabPki } from './certs';
import { CERTS_DIR, DEFAULT_PORT, dn, startTlsServer } from './server';

export interface TlsGetResult {
  status: number;
  body: any;
  protocol: string | null;
  cipher: string;
  /** Leaf certificate with `issuerCertificate` links up to the root. */
  peer: DetailedPeerCertificate;
}

/** An error thrown before HTTP started: the handshake, or the certificate checks, failed. */
export interface TlsFailure {
  code: string;
  message: string;
}

/**
 * One GET over a fresh TLS connection (`agent: false`: no connection reuse, so
 * every call is a full handshake and the cases stay independent).
 * Resolves with the response; rejects with `{code, message}` when TLS refused.
 */
export function tlsGet(options: RequestOptions): Promise<TlsGetResult> {
  return new Promise((resolve, reject) => {
    // ALPNProtocols is a tls.connect option that https.request forwards but @types/node does not list; hence the cast.
    const alpn = { ALPNProtocols: ['http/1.1'] } as RequestOptions;
    const req = request({ method: 'GET', agent: false, ...alpn, ...options }, (res) => {
      const socket = res.socket as TLSSocket;
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString();
        resolve({
          status: res.statusCode ?? 0,
          body: text ? JSON.parse(text) : undefined,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher().name,
          peer: socket.getPeerCertificate(true),
        });
      });
    });
    req.on('error', (err: NodeJS.ErrnoException) => reject({ code: err.code ?? 'UNKNOWN', message: err.message } satisfies TlsFailure));
    req.end();
  });
}

/** Leaf → ... → root, following `issuerCertificate` until a cert is its own issuer. */
export function chainOf(leaf: DetailedPeerCertificate): DetailedPeerCertificate[] {
  const chain: DetailedPeerCertificate[] = [];
  let cert: DetailedPeerCertificate | undefined = leaf;
  while (cert && !chain.includes(cert)) {
    chain.push(cert);
    cert = cert.issuerCertificate === cert ? undefined : cert.issuerCertificate;
  }
  return chain;
}

function printChain(leaf: DetailedPeerCertificate): void {
  chainOf(leaf).forEach((cert, i) => {
    const role = i === 0 ? 'leaf' : cert.issuerCertificate === cert ? 'root (self-signed, trusted because WE said so)' : 'intermediate';
    console.log(`    [${i}] ${role}`);
    console.log(`        subject  ${dn(cert.subject)}`);
    console.log(`        issuer   ${dn(cert.issuer)}`);
    console.log(`        valid    ${cert.valid_from} → ${cert.valid_to}`);
    if (cert.subjectaltname) console.log(`        SAN      ${cert.subjectaltname}`);
    console.log(`        sha256   ${cert.fingerprint256}`);
  });
}

function describeX509(pem: string): string {
  const c = new X509Certificate(pem);
  return `subject ${c.subject.replace(/\n/g, ', ')} · issuer ${c.issuer.replace(/\n/g, ', ')} · SAN ${c.subjectAltName ?? '(none)'} · valid to ${c.validTo}`;
}

interface Outcome {
  name: string;
  expected: string;
  got: string;
  ok: boolean;
}

const outcomes: Outcome[] = [];
function record(name: string, expected: string, got: string, ok: boolean): void {
  outcomes.push({ name, expected, got, ok });
  console.log(`  ${ok ? '✓' : '✗'} ${ok ? 'as expected' : 'UNEXPECTED'}: ${got}\n`);
}

async function expectFailure(name: string, expected: string, codes: string[], options: RequestOptions, why: string): Promise<void> {
  try {
    const res = await tlsGet(options);
    record(name, expected, `connected and got HTTP ${res.status}`, false);
  } catch (err) {
    const f = err as TlsFailure;
    if (f.code === 'ECONNREFUSED') throw err; // no server at all: not a TLS lesson, stop
    console.log(`  → rejected before HTTP: ${f.code}`);
    console.log(`    ${f.message.split('\n')[0]}`);
    console.log(`    why: ${why}`);
    record(name, expected, f.code, codes.includes(f.code));
  }
}

export async function runDemo(host: string, port: number, pki: LabPki): Promise<boolean> {
  console.log(`02 · TLS · client cases against https://${host}:${port}\n`);

  // (a) ------------------------------------------------------------------
  console.log('(a) connect with the default trust store (what a browser or curl does out of the box)');
  await expectFailure(
    'a: default trust store',
    'rejected',
    ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'],
    { host, port, path: '/' },
    'the server cert is signed by "Lab CA", which is in no operating system or browser trust store. ' +
      'Trust is not in the certificate; it is in the verifier\'s list of CAs.',
  );

  // (b) ------------------------------------------------------------------
  console.log('(b) connect trusting the lab CA (ca: ca.pem), the way a company laptop trusts its internal CA');
  try {
    const res = await tlsGet({ host, port, path: '/', ca: pki.ca.cert });
    console.log(`  → HTTP ${res.status} over ${res.protocol}, cipher ${res.cipher}`);
    console.log(`    server saw: SNI=${res.body.servername ?? '(none)'}, ALPN=${res.body.alpn ?? '(none)'}, client cert presented=${res.body.clientCertificatePresented}`);
    console.log('    certificate chain the client verified:');
    printChain(res.peer);
    console.log('    why it works: leaf CN=localhost is signed by Lab CA; Lab CA is in OUR ca list; SAN contains the name we dialled;');
    console.log('    dates are valid; the server proved it holds the private key (CertificateVerify). All five, or no connection.');
    const modern = res.protocol === 'TLSv1.2' || res.protocol === 'TLSv1.3';
    record('b: trusting the lab CA', '200 over TLS 1.2+', `HTTP ${res.status} over ${res.protocol}`, res.status === 200 && modern);
  } catch (err) {
    if ((err as TlsFailure).code === 'ECONNREFUSED') throw err;
    record('b: trusting the lab CA', '200 over TLS 1.2+', `rejected: ${(err as TlsFailure).code}`, false);
  }

  // (c) ------------------------------------------------------------------
  console.log('(c) a second server presenting a certificate from a ROGUE CA, client still trusts only the lab CA');
  console.log(`    rogue cert: ${describeX509(pki.rogueServer.cert)}`);
  console.log(`    real  cert: ${describeX509(pki.server.cert)}`);
  const rogue = await startTlsServer({ key: pki.rogueServer.key, cert: pki.rogueServer.cert, clientCa: pki.rogueCa.cert, log: () => {} }, 0);
  try {
    await expectFailure(
      'c: rogue CA',
      'rejected',
      ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'],
      { host: '127.0.0.1', port: rogue.port, path: '/', ca: pki.ca.cert },
      'same CN, same SAN, valid dates, well-formed: everything an attacker can copy. The one thing they cannot copy is a ' +
        'signature from a CA we trust. A certificate is exactly as trustworthy as its issuer.',
    );
  } finally {
    await rogue.stop();
  }

  // (d) ------------------------------------------------------------------
  console.log('(d) hostname mismatch: dial 127.0.0.1 but ask for (and verify) the name nothere.example');
  await expectFailure(
    'd: hostname mismatch',
    'rejected',
    ['ERR_TLS_CERT_ALTNAME_INVALID'],
    { host: '127.0.0.1', port, path: '/', ca: pki.ca.cert, servername: 'nothere.example' },
    'the chain is fine, but the certificate is for DNS:localhost, IP:127.0.0.1 only. Without this check a valid cert for ' +
      'evil.example would let a MITM pose as bank.example. Clients match the SAN list (RFC 6125); CN is ignored.',
  );

  // (e) ------------------------------------------------------------------
  console.log('(e) mutual TLS on /mtls: now the server verifies US');
  console.log('  (e1) no client certificate');
  {
    const res = await tlsGet({ host, port, path: '/mtls', ca: pki.ca.cert });
    console.log(`  → HTTP ${res.status}: ${res.body.reason ?? ''}`);
    record('e1: /mtls without client cert', '401', `HTTP ${res.status}`, res.status === 401);
  }
  console.log("  (e2) alice's certificate and private key (cert issued by the lab CA)");
  {
    const res = await tlsGet({ host, port, path: '/mtls', ca: pki.ca.cert, cert: pki.client.cert, key: pki.client.key });
    console.log(`  → HTTP ${res.status}: ${res.body.note ?? res.body.reason ?? ''}`);
    if (res.status === 200) console.log(`    server identified us as CN=${res.body.cn} (issuer ${res.body.issuer}), sha256 ${res.body.fingerprint256}`);
    console.log('    why: the client signed the handshake transcript with its private key (CertificateVerify); the server checked');
    console.log('    the signature against the cert, and the cert against its CA list. Nothing secret went over the wire.');
    record('e2: /mtls with alice', '200 CN=alice', `HTTP ${res.status} CN=${res.body.cn}`, res.status === 200 && res.body.cn === 'alice');
  }
  console.log('  (e3) a rogue client certificate that also says CN=alice, signed by the rogue CA');
  {
    const res = await tlsGet({ host, port, path: '/mtls', ca: pki.ca.cert, cert: pki.rogueClient.cert, key: pki.rogueClient.key });
    console.log(`  → HTTP ${res.status}: ${res.body.reason ?? ''}`);
    console.log('    why: the server does not care what the certificate SAYS, only who SIGNED it. Same rule as (c), other direction.');
    record('e3: /mtls with rogue client cert', '401', `HTTP ${res.status}`, res.status === 401);
  }

  // Summary -----------------------------------------------------------------
  console.log('summary');
  const width = Math.max(...outcomes.map((o) => o.name.length));
  for (const o of outcomes) console.log(`  ${o.ok ? '✓' : '✗'} ${o.name.padEnd(width)}  expected ${o.expected}, got ${o.got}`);
  return outcomes.every((o) => o.ok);
}

async function main(): Promise<void> {
  if (!existsSync(CERTS_DIR + '/server.pem')) {
    console.error(`No certificates in ${CERTS_DIR}. Run: npm run 02:certs`);
    process.exit(1);
  }
  const pki = loadLabPki(CERTS_DIR);
  const host = process.env.HOST ?? 'localhost';
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  let ok: boolean;
  try {
    ok = await runDemo(host, port, pki);
  } catch (err) {
    const e = err as NodeJS.ErrnoException & TlsFailure;
    if (e.code === 'ECONNREFUSED') {
      console.error(`\nNothing is listening on ${host}:${port}. Start the server first: npm run 02:server`);
    } else {
      console.error(err);
    }
    process.exit(1);
  }
  process.exit(ok ? 0 : 1);
}

if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
