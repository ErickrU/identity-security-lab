import { encrypt, randomKey } from './crypto';
import { Client, Kdc, KerberosError, Service, type ApReq } from './kerberos';

const REALM = 'LAB.EXAMPLE';
const ORDERS = 'http/orders.lab.example';
const LDAP = 'ldap/dir.lab.example';

function heading(title: string): void {
  console.log(`\n${title}\n${'─'.repeat(title.length)}`);
}

function rejection(label: string, fn: () => unknown): void {
  try {
    fn();
    console.log(`  ✗ ${label}: unexpectedly accepted`);
    process.exitCode = 1;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log(`  ✓ ${label}\n    → rejected: ${message}`);
  }
}

function main(): void {
  let kdcTime = Date.UTC(2026, 8, 28, 12, 0, 0);
  let clientTime = kdcTime;
  const kdc = new Kdc(REALM, { now: () => kdcTime });
  kdc.addUser('alice', 'correct horse battery staple');
  const ordersKey = kdc.addService(ORDERS);
  const ldapKey = kdc.addService(LDAP);
  const orders = new Service(ORDERS, ordersKey, { now: () => kdcTime });
  const ldap = new Service(LDAP, ldapKey, { now: () => kdcTime });
  const alice = new Client('alice', REALM, kdc, { now: () => clientTime });

  heading('1. kinit: prove one password-derived key, receive a Ticket Granting Ticket');
  const asReq = alice.kinit('correct horse battery staple');
  console.log('  client → KDC / Authentication Service (AS-REQ)');
  console.log(`    cname=${asReq.cname}  sname=${asReq.sname}  nonce=${asReq.nonce.slice(0, 10)}…`);
  console.log(`    PA-ENC-TIMESTAMP={iv:${asReq.paEncTimestamp.iv.slice(0, 8)}…, ct:…, tag:…}`);
  console.log(`    password field present? ${'password' in asReq ? 'YES (bug)' : 'no'}`);
  console.log('  The password stayed in the client. Both client and KDC derived the same long-term key.');
  console.log('  Decrypting the timestamp proved that key; ±5-minute time checking stops replay.');
  console.log('  AS-REP returned: TGT encrypted for krbtgt + a TGT session key encrypted for alice.');

  heading('2. Ask the Ticket Granting Service for one service ticket');
  const serviceTicket = alice.getServiceTicket(ORDERS);
  console.log(`  target=${ORDERS}  valid until=${new Date(serviceTicket.endTime).toISOString()}`);
  console.log('  The request carried TGT + a fresh authenticator encrypted with the TGT session key.');
  console.log('  No password was re-entered. That is why the TGT exists: one login, many services (SSO).');
  console.log('  The returned ticket is encrypted with orders\' keytab key; alice cannot edit or inspect it.');

  heading('3. AP exchange: authenticate to orders, then authenticate orders back');
  const principal = alice.authenticateTo(orders);
  console.log(`  orders accepted ${principal}`);
  console.log('  Orders decrypted the ticket using only its keytab, then checked the fresh authenticator.');
  console.log('  It did NOT call the KDC. Tickets are offline-verifiable, like JWTs, but use shared keys.');
  console.log('  AP-REP returned alice\'s timestamp encrypted with the session key: mutual authentication.');
  console.log('  Alice now knows the service was able to open a ticket only the real orders service should open.');

  heading('4. The failures are the protocol');
  const wrongPassword = new Client('alice', REALM, kdc, { now: () => clientTime });
  rejection('wrong password / PA-ENC-TIMESTAMP', () => wrongPassword.kinit('wrong-password'));
  console.log('    Pre-auth matters: without it, anyone could request an AS-REP encrypted with alice\'s');
  console.log('    password-derived key and crack it offline (AS-REP roasting).');

  // Build once, consume once, replay the exact bytes.
  clientTime += 1_000;
  const replayable = alice.buildApRequest(ORDERS);
  orders.acceptApRequest(replayable.request);
  rejection('same AP-REQ replayed', () => orders.acceptApRequest(replayable.request));
  console.log('    The service replay cache remembers cname+ctime for the clock-skew window.');

  const skewed = new Client('alice', REALM, kdc, { now: () => kdcTime + 10 * 60 * 1000 });
  rejection('client clock 10 minutes ahead', () => skewed.kinit('correct horse battery staple'));
  console.log('    Kerberos uses timestamps to avoid an extra challenge round trip, so NTP is infrastructure.');

  clientTime += 1_000;
  const forOrders = alice.buildApRequest(ORDERS);
  rejection('orders ticket presented to LDAP', () => ldap.acceptApRequest(forOrders.request));
  console.log('    LDAP has a different keytab key; it cannot decrypt an orders ticket. The sname is bound too.');

  const shortKdc = new Kdc(REALM, { now: () => kdcTime, ticketLifetimeMs: 2_000 });
  shortKdc.addUser('alice', 'correct horse battery staple');
  const shortKey = shortKdc.addService(ORDERS);
  const shortClient = new Client('alice', REALM, shortKdc, { now: () => kdcTime });
  const shortService = new Service(ORDERS, shortKey, { now: () => kdcTime });
  shortClient.kinit('correct horse battery staple');
  const expiring = shortClient.buildApRequest(ORDERS);
  kdcTime += 2_001;
  rejection('expired service ticket', () => shortService.acceptApRequest(expiring.request));

  const forged: ApReq = {
    ticket: encrypt(randomKey(), {
      cname: 'mallory', realm: REALM, sname: ORDERS,
      sessionKey: randomKey().toString('base64'), authTime: kdcTime, endTime: kdcTime + 60_000,
    }),
    authenticator: encrypt(randomKey(), { cname: 'mallory', ctime: kdcTime, nonce: 'forged' }),
  };
  rejection('forged ticket signed/encrypted with an attacker key', () => shortService.acceptApRequest(forged));
  console.log('    A ticket is trusted only because it decrypts and authenticates under the service keytab key.');

  heading('5. What to remember');
  console.log('  Password → local long-term key → AS only. TGT → TGS repeatedly. Service ticket → one service.');
  console.log('  Authenticator = fresh proof + replay defence. AP-REP = mutual authentication.');
  console.log('  Kerberos is excellent inside a managed domain. OIDC/SAML fit browsers and organisation boundaries.');
  console.log(process.exitCode ? '\n  Demo found an unexpected acceptance.' : '\n  Done. Every genuine exchange passed; every wrong key, time, service and replay failed.');
}

main();
