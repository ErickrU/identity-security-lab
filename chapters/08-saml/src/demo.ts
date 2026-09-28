/**
 * 08 · SAML 2.0 walkthrough. Run: npm run 08
 *
 * One IdP (https://idp.lab.example) and one SP (https://orders.lab.example),
 * SP-initiated web SSO over the HTTP-Redirect (request) and HTTP-POST
 * (response) bindings. Then two attacks that must fail, and a glossary.
 *
 * Nothing leaves this process: there is no browser and no HTTP server. The
 * "browser" is us copying a URL and a form field from one side to the other.
 */
import { generateSigningKeyPair } from './certs';
import {
  createIdentityProvider,
  createServiceProvider,
  createAuthnRequest,
  parseAuthnRequest,
  createLoginResponse,
  parseLoginResponse,
  prettyXml,
  encodeSamlResponse,
  SP_ENTITY_ID,
  SP_ACS_URL,
  type LabUser,
} from './saml-lab';

const line = '─'.repeat(78);
function section(title: string): void {
  console.log(`\n${line}\n${title}\n${line}`);
}
function note(text: string): void {
  console.log(`  ${text}`);
}
function xml(text: string, truncate = 72): void {
  console.log(prettyXml(text, { truncateTextOver: truncate }).split('\n').map((l) => `    ${l}`).join('\n'));
}

async function main(): Promise<void> {
  console.log('SAML 2.0: the enterprise federation protocol, with a real signed assertion you can read.');
  console.log('Everything below runs in this process. No network, no browser; we play the browser.');

  // ------------------------------------------------------------------------
  section('0. Key material for the IdP');
  const keys = generateSigningKeyPair('lab-idp');
  note('Generated a fresh RSA-2048 key and a self-signed X.509 certificate with openssl (valid 1 day).');
  note('The private key stays at the IdP. The certificate goes into the IdP metadata: every SP pins it.');
  note('SAML does not care who issued the certificate. It is a container for a public key, nothing more.');

  const idp = createIdentityProvider({ keys });
  const sp = createServiceProvider({ entityID: SP_ENTITY_ID, acsUrl: SP_ACS_URL });

  // ------------------------------------------------------------------------
  section('a. Metadata: how the two parties learn to trust each other');
  note('Trust in SAML is configured, not discovered. Each side imports the other side\'s metadata XML once.');
  console.log('\n  IdP metadata (what the IdP hands to every SP):');
  xml(idp.getMetadata(), 60);
  note('');
  note('entityID            the IdP\'s name. Must equal <Issuer> in every assertion it sends.');
  note('SingleSignOnService where the SP sends the browser with an AuthnRequest (one URL per binding).');
  note('SingleLogoutService where logout messages go. Optional, and the part that works least well.');
  note('NameIDFormat        how the subject will be identified (here: an email address).');
  note('KeyDescriptor       the X.509 certificate. The SP verifies signatures with the public key in it.');

  console.log('\n  SP metadata (what the SP hands to the IdP):');
  xml(sp.getMetadata(), 60);
  note('');
  note('entityID                 the SP\'s name. Becomes <Audience> in assertions meant for it.');
  note('AssertionConsumerService the ACS URL: where the browser POSTs the SAML Response.');
  note('WantAssertionsSigned     the SP refuses unsigned assertions. Keep this true.');

  // ------------------------------------------------------------------------
  section('b. SP-initiated flow, step 1: the SP builds an AuthnRequest');
  note('alice opens https://orders.lab.example/orders/42 without a session. The SP sends her to the IdP.');
  const authnRequest = createAuthnRequest(sp, idp, '/orders/42');
  note('HTTP 302 Location (HTTP-Redirect binding: XML → deflate → base64 → URL-encode):');
  console.log(`\n    ${authnRequest.redirectUrl.slice(0, 110)}…\n`);
  note(`SAMLRequest parameter, ${authnRequest.samlRequestParam.length} chars. RelayState=/orders/42 remembers where to return.`);
  note('Decoded, the SAMLRequest is this XML:');
  console.log();
  xml(authnRequest.xml);
  note('');
  note(`ID                          ${authnRequest.id}`);
  note('                            random; the SP stores it and will demand it back as InResponseTo.');
  note('Issuer                      the SP entityID. "This request comes from orders".');
  note('Destination                 the IdP SSO URL the SP took from the IdP metadata.');
  note('AssertionConsumerServiceURL where the SP wants the answer. The IdP must cross-check it with metadata.');
  note('NameIDPolicy                the identifier format the SP wants for the user.');
  note('The request is not signed (allowed; it contains no secret). Some IdPs require signed requests.');

  // ------------------------------------------------------------------------
  section('c. Step 2: the IdP authenticates alice and issues a signed Response');
  const parsedRequest = await parseAuthnRequest(idp, sp, authnRequest.redirectUrl);
  note(`IdP parsed the request: issuer=${parsedRequest.issuer}, id=${parsedRequest.id}`);
  note('IdP checks: is this Issuer a registered SP? Does the ACS URL match that SP\'s metadata? Yes and yes.');
  note('IdP authenticates alice (password + MFA, a Kerberos ticket, a passkey... SAML does not care how).');
  const alice: LabUser = { email: 'alice@lab.example', groups: ['staff', 'orders-admin'] };
  const response = await createLoginResponse(idp, sp, parsedRequest, alice, authnRequest.relayState);
  note('IdP builds a <samlp:Response> with one <saml:Assertion>, signs the assertion, base64-encodes the XML');
  note(`and returns an HTML form that auto-POSTs SAMLResponse (+ RelayState) to ${response.acsUrl}.`);
  note(`SAMLResponse form field: ${response.samlResponse.length} base64 chars. Decoded:`);
  console.log();
  xml(response.xml);
  console.log();
  note('Read it top to bottom:');
  note('Response/@InResponseTo        echoes the AuthnRequest ID. Ties this answer to that question.');
  note('Response/@Destination         the ACS URL. The SP must check it is its own.');
  note('Issuer                        the IdP entityID, on the Response and again on the Assertion.');
  note('Status/StatusCode             Success. Anything else and there is no assertion to read.');
  note('Assertion/@ID                 what the signature Reference URI="#..." points at.');
  note('ds:Signature                  enveloped XML-DSig: canonicalise the Assertion (minus the signature),');
  note('                              SHA-256 digest it, RSA-sign the SignedInfo. KeyInfo carries the X.509');
  note('                              certificate; the SP only accepts it if it matches the pinned metadata cert.');
  note('Subject/NameID                who alice is, in the requested format (emailAddress).');
  note('SubjectConfirmation/@Method   bearer: whoever presents this assertion is alice. Hence the guards:');
  note('  SubjectConfirmationData     Recipient (= ACS URL), InResponseTo (= request ID), NotOnOrAfter (5 min).');
  note('Conditions                    NotBefore/NotOnOrAfter validity window + AudienceRestriction = SP entityID.');
  note('AuthnStatement                when and how alice authenticated (AuthnContextClassRef), SessionIndex for SLO.');
  note('AttributeStatement            email and groups. The SP maps these to its own roles; it does not trust');
  note('                              them blindly for authorization decisions it did not configure.');

  // ------------------------------------------------------------------------
  section('d. Step 3: the SP validates the Response and opens a local session');
  const pendingRequests = new Set<string>([authnRequest.id]); // what a real SP keeps in a store with a TTL
  const identity = await parseLoginResponse(sp, idp, response.samlResponse, { requestId: authnRequest.id });
  pendingRequests.delete(authnRequest.id);
  note('samlify checked: Status, XML-DSig signature against the pinned IdP certificate, Issuer, Conditions window.');
  note('Our SP code checked: Audience, Destination, Recipient, InResponseTo, SubjectConfirmation NotOnOrAfter.');
  note('  (samlify leaves those to the application. Many libraries do. Know which ones yours does.)');
  console.log();
  console.log('    → identity accepted:');
  console.log(`      NameID       ${identity.nameID}`);
  console.log(`      email        ${identity.email}`);
  console.log(`      groups       ${identity.groups.join(', ')}`);
  console.log(`      issuer       ${identity.issuer}`);
  console.log(`      sessionIndex ${identity.sessionIndex}`);
  console.log(`      valid until  ${identity.notOnOrAfter}`);
  console.log();
  note('The SP now creates its OWN session cookie for alice and redirects to RelayState (/orders/42).');
  note('The assertion is consumed once and thrown away. It is not a session and never reused as one.');
  note('Groups → roles happens here, in SP config: "orders-admin" ⇒ can refund. The IdP never knows SP roles.');

  // ------------------------------------------------------------------------
  section('e. Attack 1: tamper with the NameID inside the signed assertion');
  const tamperedXml = response.xml.replace(
    'alice@lab.example</saml:NameID>',
    'ceo@lab.example</saml:NameID>',
  );
  note('mallory intercepts the form POST and edits one value: NameID alice@lab.example → ceo@lab.example.');
  note('Then re-encodes the XML and lets the POST continue.');
  try {
    await parseLoginResponse(sp, idp, encodeSamlResponse(tamperedXml), { requestId: authnRequest.id });
    console.log('    !!! ACCEPTED. This must never print.');
    process.exitCode = 1;
  } catch (err) {
    console.log(`\n    → rejecting: ${(err as Error).message}`);
    note('The digest of the canonicalised Assertion no longer matches DigestValue. One byte is enough.');
  }

  note('');
  note('Variant: mallory deletes the whole <ds:Signature> element instead.');
  const unsignedXml = response.xml.replace(/<ds:Signature xmlns:ds="http:\/\/www.w3.org\/2000\/09\/xmldsig#">[\s\S]*?<\/ds:Signature>/, '');
  try {
    await parseLoginResponse(sp, idp, encodeSamlResponse(unsignedXml), { requestId: authnRequest.id });
    console.log('    !!! ACCEPTED. This must never print.');
    process.exitCode = 1;
  } catch (err) {
    console.log(`\n    → rejecting: ${(err as Error).message}`);
    note('WantAssertionsSigned=true means "no signature" is a failure, not a pass. Check your library defaults.');
  }

  // ------------------------------------------------------------------------
  section('f. Attack 2: present the assertion to the wrong SP (audience)');
  const billing = createServiceProvider({
    entityID: 'https://billing.lab.example',
    acsUrl: 'https://billing.lab.example/saml/acs',
  });
  note('A second SP, https://billing.lab.example, trusts the same IdP.');
  note('mallory takes the genuine, correctly signed Response meant for orders and POSTs it to billing.');
  note('The signature is valid. The issuer is trusted. The clock is fine. Is that enough?');
  try {
    await parseLoginResponse(billing, idp, response.samlResponse);
    console.log('    !!! ACCEPTED. This must never print.');
    process.exitCode = 1;
  } catch (err) {
    console.log(`\n    → rejecting: ${(err as Error).message}`);
    note('AudienceRestriction says who the assertion is for. An SP that skips this check accepts any');
    note('assertion the IdP ever issued to anyone. Destination and Recipient close the same door.');
  }

  note('');
  note('Variant: replay the genuine Response to orders a second time.');
  try {
    if (!pendingRequests.has(authnRequest.id)) {
      throw new Error(`ERR_UNKNOWN_REQUEST: InResponseTo ${authnRequest.id} does not match any pending request`);
    }
    await parseLoginResponse(sp, idp, response.samlResponse, { requestId: authnRequest.id });
    console.log('    !!! ACCEPTED. This must never print.');
    process.exitCode = 1;
  } catch (err) {
    console.log(`\n    → rejecting: ${(err as Error).message}`);
    note('The SP removed the request ID from its pending set after the first success. A bearer assertion');
    note('is valid for 5 minutes; InResponseTo bookkeeping is what makes it single-use.');
  }

  // ------------------------------------------------------------------------
  section('g. SAML term → OIDC term');
  const rows: Array<[string, string, string]> = [
    ['SAML 2.0', 'OpenID Connect', 'Same job'],
    ['Identity Provider (IdP)', 'OpenID Provider (OP)', 'authenticates users, issues tokens'],
    ['Service Provider (SP)', 'Relying Party (RP) / client', 'consumes tokens, opens sessions'],
    ['Assertion (XML)', 'id_token (JWT)', 'signed statement about the user'],
    ['Attributes', 'claims', 'facts about the user'],
    ['NameID', 'sub', 'stable subject identifier'],
    ['entityID (IdP)', 'issuer (iss)', 'who signed this'],
    ['entityID (SP) / Audience', 'client_id / aud', 'who this is for'],
    ['Metadata XML', 'discovery document + JWKS', 'endpoints and keys'],
    ['AuthnRequest', 'authorization request', 'please authenticate this user'],
    ['ACS URL', 'redirect_uri', 'where the answer goes'],
    ['RelayState', 'state', 'where to return after login'],
    ['InResponseTo', 'nonce (+ state)', 'binds answer to question'],
    ['XML-DSig', 'JWS', 'signature format'],
    ['HTTP-POST / Redirect binding', 'response_mode', 'how the message travels'],
    ['(nothing)', 'access_token', 'SAML has no token for calling APIs'],
  ];
  const widths = [0, 1, 2].map((i) => Math.max(...rows.map((r) => r[i].length)));
  for (const [i, row] of rows.entries()) {
    console.log('  ' + row.map((cell, c) => cell.padEnd(widths[c])).join('   '));
    if (i === 0) console.log('  ' + widths.map((w) => '-'.repeat(w)).join('   '));
  }

  console.log();
  console.log(process.exitCode ? 'Done, with unexpected acceptances above. Fix them.' : 'Done. Every genuine message was accepted; every attack was rejected.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
