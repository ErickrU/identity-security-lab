import { decrypt, encrypt, randomKey, stringToKey, type EncryptedBlob, type Key } from './crypto';

export type Clock = () => number;
export const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
export const DEFAULT_TICKET_LIFETIME_MS = 10 * 60 * 60 * 1000;

export class KerberosError extends Error {
  constructor(readonly code: string, message: string) {
    super(`${code}: ${message}`);
    this.name = 'KerberosError';
  }
}

interface PreAuthTimestamp { ctime: number }
interface Authenticator { cname: string; ctime: number; nonce: string }
interface TgtContents {
  cname: string;
  realm: string;
  sessionKey: string;
  authTime: number;
  endTime: number;
}
interface ServiceTicketContents {
  cname: string;
  realm: string;
  sname: string;
  sessionKey: string;
  authTime: number;
  endTime: number;
}
interface ReplyPart {
  sessionKey: string;
  nonce: string;
  endTime: number;
  sname: string;
}

export interface AsReq {
  cname: string;
  sname: string;
  nonce: string;
  /** RFC 4120 PA-ENC-TIMESTAMP: client time encrypted with the password-derived long-term key. */
  paEncTimestamp: EncryptedBlob;
}
export interface AsRep { ticket: EncryptedBlob; encPart: EncryptedBlob }
export interface TgsReq {
  ticket: EncryptedBlob;
  authenticator: EncryptedBlob;
  sname: string;
  nonce: string;
}
export interface TgsRep { ticket: EncryptedBlob; encPart: EncryptedBlob }
export interface ApReq { ticket: EncryptedBlob; authenticator: EncryptedBlob }
export interface ApRep { encPart: EncryptedBlob; principal: string }

export interface KdcOptions {
  now?: Clock;
  ticketLifetimeMs?: number;
}

/**
 * A Key Distribution Center: Authentication Service (AS) + Ticket Granting Service (TGS).
 * It is the trusted third party because it holds a key for every principal.
 */
export class Kdc {
  readonly krbtgtPrincipal: string;
  private readonly users = new Map<string, Key>();
  private readonly services = new Map<string, Key>();
  private readonly krbtgtKey = randomKey();
  private readonly now: Clock;
  private readonly ticketLifetimeMs: number;

  constructor(readonly realm: string, options: KdcOptions = {}) {
    this.krbtgtPrincipal = `krbtgt/${realm}`;
    this.now = options.now ?? Date.now;
    this.ticketLifetimeMs = options.ticketLifetimeMs ?? DEFAULT_TICKET_LIFETIME_MS;
  }

  addUser(cname: string, password: string): void {
    this.users.set(cname, stringToKey(password, saltFor(this.realm, cname)));
  }

  /** Create/register a service key. The returned copy is installed in that service's keytab. */
  addService(sname: string, key: Key = randomKey()): Key {
    this.services.set(sname, Buffer.from(key));
    return Buffer.from(key);
  }

  /** RFC 4120 AS exchange: prove the password-derived key once, receive a TGT. */
  authenticationService(req: AsReq): AsRep {
    if (req.sname !== this.krbtgtPrincipal) {
      throw new KerberosError('KDC_ERR_S_PRINCIPAL_UNKNOWN', `AS tickets must target ${this.krbtgtPrincipal}`);
    }
    const clientKey = this.users.get(req.cname);
    // One generic error for unknown principal and wrong password avoids user enumeration.
    if (!clientKey) throw new KerberosError('KDC_ERR_PREAUTH_FAILED', 'unknown client or wrong password');

    let preAuth: PreAuthTimestamp;
    try {
      preAuth = decrypt<PreAuthTimestamp>(clientKey, req.paEncTimestamp);
    } catch {
      throw new KerberosError('KDC_ERR_PREAUTH_FAILED', 'unknown client or wrong password');
    }
    requireFresh(preAuth.ctime, this.now(), 'KRB_AP_ERR_SKEW');

    const sessionKey = randomKey();
    const authTime = this.now();
    const endTime = authTime + this.ticketLifetimeMs;
    // TGT: client cannot read or change this. Only the TGS knows krbtgtKey.
    const ticket = encrypt(this.krbtgtKey, {
      cname: req.cname,
      realm: this.realm,
      sessionKey: toWire(sessionKey),
      authTime,
      endTime,
    } satisfies TgtContents);
    // Client can read this because it proved the long-term/password key.
    const encPart = encrypt(clientKey, {
      sessionKey: toWire(sessionKey), nonce: req.nonce, endTime, sname: this.krbtgtPrincipal,
    } satisfies ReplyPart);
    return { ticket, encPart };
  }

  /** RFC 4120 TGS exchange: present TGT + fresh authenticator, receive a ticket for one service. */
  ticketGrantingService(req: TgsReq): TgsRep {
    let tgt: TgtContents;
    try {
      tgt = decrypt<TgtContents>(this.krbtgtKey, req.ticket);
    } catch {
      throw new KerberosError('KRB_AP_ERR_MODIFIED', 'TGT was modified or not issued by this realm');
    }
    if (tgt.realm !== this.realm) throw new KerberosError('KRB_AP_ERR_BADMATCH', 'TGT belongs to another realm');
    if (tgt.endTime <= this.now()) throw new KerberosError('KRB_AP_ERR_TKT_EXPIRED', 'TGT has expired');

    const tgtSessionKey = fromWire(tgt.sessionKey);
    let authenticator: Authenticator;
    try {
      authenticator = decrypt<Authenticator>(tgtSessionKey, req.authenticator);
    } catch {
      throw new KerberosError('KRB_AP_ERR_BAD_INTEGRITY', 'TGS authenticator does not match the TGT session key');
    }
    if (authenticator.cname !== tgt.cname) throw new KerberosError('KRB_AP_ERR_BADMATCH', 'authenticator client does not match TGT client');
    requireFresh(authenticator.ctime, this.now(), 'KRB_AP_ERR_SKEW');

    const serviceKey = this.services.get(req.sname);
    if (!serviceKey) throw new KerberosError('KDC_ERR_S_PRINCIPAL_UNKNOWN', `service ${req.sname} is not registered`);

    const serviceSessionKey = randomKey();
    const authTime = this.now();
    const endTime = Math.min(tgt.endTime, authTime + this.ticketLifetimeMs);
    const ticket = encrypt(serviceKey, {
      cname: tgt.cname,
      realm: tgt.realm,
      sname: req.sname,
      sessionKey: toWire(serviceSessionKey),
      authTime,
      endTime,
    } satisfies ServiceTicketContents);
    const encPart = encrypt(tgtSessionKey, {
      sessionKey: toWire(serviceSessionKey), nonce: req.nonce, endTime, sname: req.sname,
    } satisfies ReplyPart);
    return { ticket, encPart };
  }
}

interface CachedServiceTicket {
  ticket: EncryptedBlob;
  sessionKey: Key;
  endTime: number;
}

export interface ClientOptions { now?: Clock }

/** The user's ticket cache (`klist` shows the real version). */
export class Client {
  private tgt?: EncryptedBlob;
  private tgtSessionKey?: Key;
  private tgtEndTime = 0;
  private readonly serviceTickets = new Map<string, CachedServiceTicket>();
  private readonly now: Clock;

  constructor(readonly cname: string, readonly realm: string, private readonly kdc: Kdc, options: ClientOptions = {}) {
    this.now = options.now ?? Date.now;
  }

  /** `kinit`: password derives a key locally. The request contains encrypted time, never the password. */
  kinit(password: string): AsReq {
    const clientKey = stringToKey(password, saltFor(this.realm, this.cname));
    const nonceValue = nonce();
    const request: AsReq = {
      cname: this.cname,
      sname: this.kdc.krbtgtPrincipal,
      nonce: nonceValue,
      paEncTimestamp: encrypt(clientKey, { ctime: this.now() } satisfies PreAuthTimestamp),
    };
    const reply = this.kdc.authenticationService(request);
    let part: ReplyPart;
    try {
      part = decrypt<ReplyPart>(clientKey, reply.encPart);
    } catch {
      throw new KerberosError('KRB_AP_ERR_BAD_INTEGRITY', 'AS reply cannot be decrypted with the password-derived key');
    }
    if (part.nonce !== nonceValue || part.sname !== this.kdc.krbtgtPrincipal) {
      throw new KerberosError('KRB_AP_ERR_BADMATCH', 'AS reply does not answer this request');
    }
    this.tgt = reply.ticket;
    this.tgtSessionKey = fromWire(part.sessionKey);
    this.tgtEndTime = part.endTime;
    return request; // returned only so the teaching demo can inspect the wire shape
  }

  getServiceTicket(sname: string): CachedServiceTicket {
    const cached = this.serviceTickets.get(sname);
    if (cached && cached.endTime > this.now()) return cached;
    if (!this.tgt || !this.tgtSessionKey || this.tgtEndTime <= this.now()) {
      throw new KerberosError('KRB_AP_ERR_TKT_EXPIRED', 'no valid TGT; run kinit again');
    }
    const nonceValue = nonce();
    const reply = this.kdc.ticketGrantingService({
      ticket: this.tgt,
      authenticator: encrypt(this.tgtSessionKey, { cname: this.cname, ctime: this.now(), nonce: nonce() } satisfies Authenticator),
      sname,
      nonce: nonceValue,
    });
    const part = decrypt<ReplyPart>(this.tgtSessionKey, reply.encPart);
    if (part.nonce !== nonceValue || part.sname !== sname) {
      throw new KerberosError('KRB_AP_ERR_BADMATCH', 'TGS reply does not answer this request');
    }
    const result = { ticket: reply.ticket, sessionKey: fromWire(part.sessionKey), endTime: part.endTime };
    this.serviceTickets.set(sname, result);
    return result;
  }

  /** Build the AP-REQ separately so the lab can replay it and prove the service catches that. */
  buildApRequest(sname: string): { request: ApReq; sessionKey: Key; ctime: number } {
    const cached = this.getServiceTicket(sname);
    const ctime = this.now();
    return {
      request: { ticket: cached.ticket, authenticator: encrypt(cached.sessionKey, { cname: this.cname, ctime, nonce: nonce() } satisfies Authenticator) },
      sessionKey: cached.sessionKey,
      ctime,
    };
  }

  /** AP exchange and mutual authentication: server proves it decrypted our ticket by returning our time encrypted. */
  authenticateTo(service: Service): string {
    const built = this.buildApRequest(service.sname);
    const reply = service.acceptApRequest(built.request);
    const proof = decrypt<{ ctime: number; sname: string }>(built.sessionKey, reply.encPart);
    if (proof.ctime !== built.ctime || proof.sname !== service.sname) {
      throw new KerberosError('KRB_AP_ERR_MUT_FAIL', 'service did not return the expected encrypted timestamp');
    }
    return reply.principal;
  }
}

export interface ServiceOptions { now?: Clock }

/** A service principal with a keytab. It verifies KDC tickets offline; no KDC call on the request path. */
export class Service {
  /** Replay fingerprint → time it can be forgotten. */
  private readonly replayCache = new Map<string, number>();
  private readonly now: Clock;

  constructor(readonly sname: string, private readonly keytabKey: Key, options: ServiceOptions = {}) {
    this.now = options.now ?? Date.now;
  }

  get replayCacheSize(): number { return this.replayCache.size; }

  acceptApRequest(req: ApReq): ApRep {
    let ticket: ServiceTicketContents;
    try {
      ticket = decrypt<ServiceTicketContents>(this.keytabKey, req.ticket);
    } catch {
      throw new KerberosError('KRB_AP_ERR_MODIFIED', `ticket was modified or not encrypted for ${this.sname}`);
    }
    if (ticket.sname !== this.sname) throw new KerberosError('KRB_AP_ERR_NOT_US', `ticket is for ${ticket.sname}, not ${this.sname}`);
    if (ticket.endTime <= this.now()) throw new KerberosError('KRB_AP_ERR_TKT_EXPIRED', 'service ticket has expired');

    const sessionKey = fromWire(ticket.sessionKey);
    let authenticator: Authenticator;
    try {
      authenticator = decrypt<Authenticator>(sessionKey, req.authenticator);
    } catch {
      throw new KerberosError('KRB_AP_ERR_BAD_INTEGRITY', 'AP authenticator does not match the ticket session key');
    }
    if (authenticator.cname !== ticket.cname) throw new KerberosError('KRB_AP_ERR_BADMATCH', 'authenticator client does not match ticket client');
    if (typeof authenticator.nonce !== 'string' || !authenticator.nonce) throw new KerberosError('KRB_AP_ERR_BAD_INTEGRITY', 'authenticator nonce is missing');
    requireFresh(authenticator.ctime, this.now(), 'KRB_AP_ERR_SKEW');

    // Real Kerberos uses ctime+cusec; our random nonce plays the same uniqueness role so two
    // legitimate requests in one millisecond do not collide. Entries only live for the skew window.
    const now = this.now();
    for (const [id, expiresAt] of this.replayCache) if (expiresAt <= now) this.replayCache.delete(id);
    const replayId = `${authenticator.cname}:${authenticator.ctime}:${authenticator.nonce}`;
    if (this.replayCache.has(replayId)) throw new KerberosError('KRB_AP_ERR_REPEAT', 'authenticator was already used');
    this.replayCache.set(replayId, now + MAX_CLOCK_SKEW_MS);

    // AP-REP proves the service knew its keytab key (to open ticket), then the session key (to make this proof).
    return {
      principal: ticket.cname.includes('@') ? ticket.cname : `${ticket.cname}@${ticket.realm}`,
      encPart: encrypt(sessionKey, { ctime: authenticator.ctime, sname: this.sname }),
    };
  }
}

export function saltFor(realm: string, principal: string): string {
  return `${realm}${principal}`;
}

function requireFresh(clientTime: number, serverTime: number, code: string): void {
  if (!Number.isFinite(clientTime) || Math.abs(serverTime - clientTime) > MAX_CLOCK_SKEW_MS) {
    throw new KerberosError(code, `clock difference exceeds ${MAX_CLOCK_SKEW_MS / 60_000} minutes`);
  }
}

function toWire(key: Key): string { return key.toString('base64'); }
function fromWire(key: string): Key { return Buffer.from(key, 'base64'); }
function nonce(): string { return randomKey().subarray(0, 16).toString('base64url'); }
