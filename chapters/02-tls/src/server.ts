/**
 * 02 · An HTTPS server that explains its own handshakes.
 *
 *   GET /       plain TLS: anyone whose client trusts the lab CA gets in.
 *               Returns what was negotiated and whether a client cert came along.
 *   GET /mtls   mutual TLS: only a client certificate signed by the lab CA gets 200.
 *               Otherwise 401 with the reason (none presented, or untrusted issuer).
 *
 * The server asks every client for a certificate (`requestCert: true`) but does
 * not drop the connection when there is none or it does not verify
 * (`rejectUnauthorized: false`). That is what lets one listener show both modes:
 * the route decides, by reading `socket.authorized`. In a real deployment that
 * only serves machines, set `rejectUnauthorized: true` and let the handshake
 * itself fail; a client without a good certificate then never reaches HTTP at all.
 *
 * `createTlsServer()` builds the server (tests bind it to port 0);
 * `npm run 02:server` runs it on 4443 with the certs from `npm run 02:certs`.
 */
import { existsSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import type { PeerCertificate, SecureVersion, TLSSocket } from 'node:tls';
import { loadLabPki } from './certs';

export const DEFAULT_PORT = 4443;
export const CERTS_DIR = join(__dirname, '..', 'certs');

export interface TlsServerOptions {
  /** Server private key, PEM. */
  key: string | Buffer;
  /** Server certificate, PEM. Real servers append their intermediates here. */
  cert: string | Buffer;
  /** CA(s) the server trusts for CLIENT certificates. Unrelated to who signed the server cert. */
  clientCa: string | Buffer;
  /** Oldest protocol accepted. Default TLS 1.2: 1.0 and 1.1 are deprecated by RFC 8996. */
  minVersion?: SecureVersion;
  /** Teaching output. Default console.log; tests pass () => {}. */
  log?: (line: string) => void;
}

/** What `GET /` answers: the facts of this connection's handshake. */
export interface HandshakeReport {
  protocol: string | null;
  cipher: { name: string; version: string };
  /** Hostname the client asked for in the ClientHello (SNI). Sent in clear text; null when the client sent none (IP address dials). */
  servername: string | null;
  /** Application protocol negotiated in the handshake (http/1.1, h2), null when the client offered none. */
  alpn: string | null;
  clientCertificatePresented: boolean;
  clientCertificateAuthorized: boolean;
  note: string;
}

/** Subject or issuer of a certificate as one readable line: "CN=alice" or "CN=x, O=y". */
export function dn(name: PeerCertificate['subject'] | undefined): string {
  if (!name) return '(none)';
  return Object.entries(name)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('+') : v}`)
    .join(', ');
}

/** Node returns `{}` when the peer sent no certificate, `null` when the socket is gone. */
function presentedCert(socket: TLSSocket): PeerCertificate | undefined {
  const cert = socket.getPeerCertificate();
  return cert && Object.keys(cert).length > 0 ? cert : undefined;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body, null, 2));
}

export function createTlsServer(options: TlsServerOptions): Server {
  const log = options.log ?? ((line: string) => console.log(line));

  const server = createServer({
    key: options.key,
    cert: options.cert,
    ca: options.clientCa,
    minVersion: options.minVersion ?? 'TLSv1.2',
    requestCert: true,
    rejectUnauthorized: false,
  });

  // Fires once per connection when the handshake is complete. Everything TLS
  // decided is known here, before a single byte of HTTP has been read.
  server.on('secureConnection', (socket: TLSSocket) => {
    const cipher = socket.getCipher();
    log(
      `→ handshake done: ${socket.getProtocol()}, cipher ${cipher.name}, ` +
        `SNI ${socket.servername ?? '(none)'}, ALPN ${socket.alpnProtocol || '(none)'}`,
    );
    const cert = presentedCert(socket);
    if (!cert) {
      log('  client certificate: none. Fine for /, not enough for /mtls');
    } else if (socket.authorized) {
      log(`  client certificate: ${dn(cert.subject)} issued by ${dn(cert.issuer)}: authorized (signed by a CA this server trusts)`);
    } else {
      log(
        `  client certificate: ${dn(cert.subject)} issued by ${dn(cert.issuer)}: NOT authorized ` +
          `(${socket.authorizationError}). The name says alice; the signature says nothing we trust`,
      );
    }
  });

  server.on('tlsClientError', (err: NodeJS.ErrnoException) => {
    // Handshakes that never completed. "socket hang up" is a client that walked
    // away after seeing our certificate (untrusted CA, hostname mismatch); a
    // protocol error is a client that offered only versions we refuse.
    log(`→ handshake failed: ${err.code ?? ''} ${err.message} (client aborted, or offered nothing we accept)`);
  });

  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    const socket = req.socket as TLSSocket;
    const url = new URL(req.url ?? '/', 'https://localhost');

    if (req.method !== 'GET') return sendJson(res, 405, { error: 'method_not_allowed' });

    if (url.pathname === '/') {
      const cert = presentedCert(socket);
      const report: HandshakeReport = {
        protocol: socket.getProtocol(),
        cipher: { name: socket.getCipher().name, version: socket.getCipher().version },
        servername: typeof socket.servername === 'string' ? socket.servername : null,
        alpn: socket.alpnProtocol || null,
        clientCertificatePresented: cert !== undefined,
        clientCertificateAuthorized: socket.authorized,
        note: 'You verified me (my cert chains to a CA you trust). I have not verified you: this route accepts anyone.',
      };
      return sendJson(res, 200, report);
    }

    if (url.pathname === '/mtls') {
      const cert = presentedCert(socket);
      if (!cert) {
        return sendJson(res, 401, {
          error: 'client_certificate_required',
          reason: 'You did not present a client certificate during the handshake.',
          how: 'Connect with cert + key issued by the lab CA (chapters/02-tls/certs/client.pem).',
        });
      }
      if (!socket.authorized) {
        return sendJson(res, 401, {
          error: 'client_certificate_not_trusted',
          reason: `Your certificate (${dn(cert.subject)}, issued by ${dn(cert.issuer)}) does not chain to a CA I trust: ${socket.authorizationError}.`,
          how: 'Anyone can mint a certificate that says CN=alice. Only one signed by my CA counts.',
        });
      }
      return sendJson(res, 200, {
        authenticated: true,
        cn: cert.subject.CN,
        subject: dn(cert.subject),
        issuer: dn(cert.issuer),
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        fingerprint256: cert.fingerprint256,
        note: 'Authenticated by the TLS layer: you proved possession of the private key of a certificate my CA signed.',
      });
    }

    return sendJson(res, 404, { error: 'not_found', routes: ['/', '/mtls'] });
  });

  return server;
}

export interface RunningServer {
  server: Server;
  port: number;
  url: string;
  stop: () => Promise<void>;
}

/** Listen on `host` (default 127.0.0.1). Port 0 asks the OS for a free one (tests, demo). */
export async function startTlsServer(options: TlsServerOptions, port: number, host = '127.0.0.1'): Promise<RunningServer> {
  const server = createTlsServer(options);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });
  const { port: boundPort } = server.address() as AddressInfo;
  return {
    server,
    port: boundPort,
    url: `https://${host}:${boundPort}`,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

async function main(): Promise<void> {
  if (!existsSync(join(CERTS_DIR, 'server.pem'))) {
    console.error(`No certificates in ${CERTS_DIR}. Run: npm run 02:certs`);
    process.exit(1);
  }
  const pki = loadLabPki(CERTS_DIR);
  const port = Number(process.env.PORT ?? DEFAULT_PORT);
  const { url } = await startTlsServer({ key: pki.server.key, cert: pki.server.cert, clientCa: pki.ca.cert }, port, '0.0.0.0');
  console.log(`02 · TLS · listening on ${url.replace('0.0.0.0', 'localhost')}`);
  console.log(`  certificate: CN=localhost issued by the lab CA in ${pki.ca.certPath}`);
  console.log(`  try:  curl https://localhost:${port}/                     (fails: your curl does not trust the lab CA)`);
  console.log(`        curl --cacert ${pki.ca.certPath} https://localhost:${port}/`);
  console.log(`        curl --cacert ${pki.ca.certPath} https://localhost:${port}/mtls   (401: no client cert)`);
  console.log(`        curl --cacert ${pki.ca.certPath} --cert ${pki.client.certPath} --key ${pki.client.keyPath} https://localhost:${port}/mtls`);
  console.log(`  or:   npm run 02:client\n`);
}

// `npm run 02:server` (tsx, CommonJS). Under vitest, or when client.ts imports
// this file, the block must not run, hence the guards.
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
