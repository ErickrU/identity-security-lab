import { encrypt, randomKey } from './crypto';
import { Client, Kdc, KerberosError, MAX_CLOCK_SKEW_MS, Service, type ApReq } from './kerberos';
import { beforeEach, describe, expect, it } from 'vitest';

const REALM = 'LAB.EXAMPLE';
const ORDERS = 'http/orders.lab.example';
const LDAP = 'ldap/dir.lab.example';

let now: number;
let kdc: Kdc;
let alice: Client;
let orders: Service;
let ldap: Service;

beforeEach(() => {
  now = 1_700_000_000_000;
  kdc = new Kdc(REALM, { now: () => now });
  kdc.addUser('alice', 'correct horse battery staple');
  const ordersKey = kdc.addService(ORDERS);
  const ldapKey = kdc.addService(LDAP);
  alice = new Client('alice', REALM, kdc, { now: () => now });
  orders = new Service(ORDERS, ordersKey, { now: () => now });
  ldap = new Service(LDAP, ldapKey, { now: () => now });
});

function codeOf(fn: () => unknown): string {
  try {
    fn();
    throw new Error('expected KerberosError');
  } catch (error) {
    expect(error).toBeInstanceOf(KerberosError);
    return (error as KerberosError).code;
  }
}

describe('successful AS → TGS → AP exchanges', () => {
  it('kinit sends encrypted pre-auth, never a password field', () => {
    const request = alice.kinit('correct horse battery staple');
    expect(request).not.toHaveProperty('password');
    expect(request).toMatchObject({ cname: 'alice', sname: `krbtgt/${REALM}` });
    expect(request.paEncTimestamp).toHaveProperty('tag');
  });

  it('gets a service ticket and authenticates with mutual AP-REP proof', () => {
    alice.kinit('correct horse battery staple');
    expect(alice.authenticateTo(orders)).toBe(`alice@${REALM}`);
  });

  it('caches a still-valid service ticket', () => {
    alice.kinit('correct horse battery staple');
    const first = alice.getServiceTicket(ORDERS);
    now += 60_000;
    expect(alice.getServiceTicket(ORDERS)).toBe(first);
  });

  it('can use one TGT to get tickets for different services', () => {
    alice.kinit('correct horse battery staple');
    expect(alice.authenticateTo(orders)).toBe(`alice@${REALM}`);
    now += 1;
    expect(alice.authenticateTo(ldap)).toBe(`alice@${REALM}`);
  });
});

describe('pre-authentication and time', () => {
  it('rejects a wrong password with the same generic pre-auth error', () => {
    expect(codeOf(() => alice.kinit('wrong'))).toBe('KDC_ERR_PREAUTH_FAILED');
    const unknown = new Client('unknown', REALM, kdc, { now: () => now });
    expect(codeOf(() => unknown.kinit('anything'))).toBe('KDC_ERR_PREAUTH_FAILED');
  });

  it('accepts exactly the five-minute skew boundary and rejects beyond it', () => {
    const boundary = new Client('alice', REALM, kdc, { now: () => now + MAX_CLOCK_SKEW_MS });
    expect(() => boundary.kinit('correct horse battery staple')).not.toThrow();
    const tooFar = new Client('alice', REALM, kdc, { now: () => now + MAX_CLOCK_SKEW_MS + 1 });
    expect(codeOf(() => tooFar.kinit('correct horse battery staple'))).toBe('KRB_AP_ERR_SKEW');
  });

  it('requires a fresh TGT before requesting service tickets', () => {
    expect(codeOf(() => alice.getServiceTicket(ORDERS))).toBe('KRB_AP_ERR_TKT_EXPIRED');
  });

  it('rejects an expired TGT at the TGS', () => {
    const short = new Kdc(REALM, { now: () => now, ticketLifetimeMs: 1_000 });
    short.addUser('alice', 'pw');
    short.addService(ORDERS);
    const client = new Client('alice', REALM, short, { now: () => now });
    client.kinit('pw');
    now += 1_001;
    expect(codeOf(() => client.getServiceTicket(ORDERS))).toBe('KRB_AP_ERR_TKT_EXPIRED');
  });
});

describe('service ticket binding, integrity and replay', () => {
  it('rejects the same AP-REQ twice', () => {
    alice.kinit('correct horse battery staple');
    const built = alice.buildApRequest(ORDERS);
    expect(orders.acceptApRequest(built.request).principal).toBe(`alice@${REALM}`);
    expect(codeOf(() => orders.acceptApRequest(built.request))).toBe('KRB_AP_ERR_REPEAT');
  });

  it('accepts two distinct authenticators created in the same millisecond', () => {
    alice.kinit('correct horse battery staple');
    const first = alice.buildApRequest(ORDERS);
    const second = alice.buildApRequest(ORDERS); // same ctime, different cryptographic nonce
    expect(orders.acceptApRequest(first.request).principal).toBe(`alice@${REALM}`);
    expect(orders.acceptApRequest(second.request).principal).toBe(`alice@${REALM}`);
    expect(orders.replayCacheSize).toBe(2);
  });

  it('evicts replay fingerprints after the clock-skew window', () => {
    alice.kinit('correct horse battery staple');
    orders.acceptApRequest(alice.buildApRequest(ORDERS).request);
    expect(orders.replayCacheSize).toBe(1);
    now += MAX_CLOCK_SKEW_MS + 1;
    orders.acceptApRequest(alice.buildApRequest(ORDERS).request);
    expect(orders.replayCacheSize).toBe(1);
  });

  it('rejects a ticket at a different service', () => {
    alice.kinit('correct horse battery staple');
    const built = alice.buildApRequest(ORDERS);
    expect(codeOf(() => ldap.acceptApRequest(built.request))).toBe('KRB_AP_ERR_MODIFIED');
  });

  it('rejects an expired service ticket even if its authenticator is fresh enough', () => {
    const short = new Kdc(REALM, { now: () => now, ticketLifetimeMs: 1_000 });
    short.addUser('alice', 'pw');
    const key = short.addService(ORDERS);
    const client = new Client('alice', REALM, short, { now: () => now });
    const service = new Service(ORDERS, key, { now: () => now });
    client.kinit('pw');
    const built = client.buildApRequest(ORDERS);
    now += 1_001;
    expect(codeOf(() => service.acceptApRequest(built.request))).toBe('KRB_AP_ERR_TKT_EXPIRED');
  });

  it('rejects an authenticator with the wrong client name', () => {
    alice.kinit('correct horse battery staple');
    const built = alice.buildApRequest(ORDERS);
    const changed: ApReq = {
      ticket: built.request.ticket,
      authenticator: encrypt(built.sessionKey, { cname: 'mallory', ctime: built.ctime, nonce: 'changed-client' }),
    };
    expect(codeOf(() => orders.acceptApRequest(changed))).toBe('KRB_AP_ERR_BADMATCH');
  });

  it('rejects an AP authenticator outside the five-minute skew window', () => {
    alice.kinit('correct horse battery staple');
    const built = alice.buildApRequest(ORDERS);
    now += MAX_CLOCK_SKEW_MS + 1;
    expect(codeOf(() => orders.acceptApRequest(built.request))).toBe('KRB_AP_ERR_SKEW');
  });

  it('rejects a forged or modified ticket', () => {
    const forged: ApReq = {
      ticket: encrypt(randomKey(), {
        cname: 'mallory', realm: REALM, sname: ORDERS, sessionKey: randomKey().toString('base64'),
        authTime: now, endTime: now + 60_000,
      }),
      authenticator: encrypt(randomKey(), { cname: 'mallory', ctime: now, nonce: 'forged' }),
    };
    expect(codeOf(() => orders.acceptApRequest(forged))).toBe('KRB_AP_ERR_MODIFIED');
  });
});
