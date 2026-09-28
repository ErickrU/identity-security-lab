/**
 * Offline, deterministic tests for the SAML lab. No network: the "browser" is
 * a string handed from one function to the next.
 *
 * Needs `openssl` on PATH to generate the IdP key pair; skips otherwise.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { generateSigningKeyPair, opensslAvailable, type KeyMaterial } from './certs';
import {
  createIdentityProvider,
  createServiceProvider,
  createAuthnRequest,
  parseAuthnRequest,
  createLoginResponse,
  parseLoginResponse,
  decodeRedirectMessage,
  encodeSamlResponse,
  buildAttributeStatement,
  prettyXml,
  IDP_ENTITY_ID,
  IDP_SSO_URL,
  SP_ENTITY_ID,
  SP_ACS_URL,
  type IdentityProvider,
  type ServiceProvider,
  type LabUser,
} from './saml-lab';

const hasOpenssl = opensslAvailable();
const test = hasOpenssl ? it : it.skip;
if (!hasOpenssl) {
  console.warn('08-saml: openssl not found on PATH, skipping the tests that need a signing key');
}

const alice: LabUser = { email: 'alice@lab.example', groups: ['staff', 'orders-admin'] };

describe('08 · SAML 2.0 (samlify, in-process IdP and SP)', () => {
  let keys: KeyMaterial;
  let idp: IdentityProvider;
  let sp: ServiceProvider;

  beforeAll(() => {
    if (!hasOpenssl) return;
    keys = generateSigningKeyPair();
    idp = createIdentityProvider({ keys });
    sp = createServiceProvider({ entityID: SP_ENTITY_ID, acsUrl: SP_ACS_URL });
  });

  test('openssl produces a PEM key and certificate', () => {
    expect(keys.privateKey).toMatch(/-----BEGIN (RSA )?PRIVATE KEY-----/);
    expect(keys.certificate).toMatch(/-----BEGIN CERTIFICATE-----/);
  });

  test('AuthnRequest: redirect URL decodes to XML with the SP as Issuer and the IdP SSO URL as Destination', () => {
    const req = createAuthnRequest(sp, idp, '/orders/42');
    const url = new URL(req.redirectUrl);
    expect(`${url.origin}${url.pathname}`).toBe(IDP_SSO_URL);
    expect(url.searchParams.get('RelayState')).toBe('/orders/42');

    const xml = decodeRedirectMessage(url.searchParams.get('SAMLRequest')!);
    expect(xml).toBe(req.xml);
    expect(xml).toMatch(/^<samlp:AuthnRequest /);
    expect(xml).toContain(`<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>`);
    expect(xml).toContain(`Destination="${IDP_SSO_URL}"`);
    expect(xml).toContain(`AssertionConsumerServiceURL="${SP_ACS_URL}"`);
    expect(xml).toContain(`ID="${req.id}"`);
    expect(req.id).toMatch(/^_[0-9a-f-]{36}$/);
  });

  test('IdP parses the AuthnRequest and recovers ID, Issuer and ACS URL', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsed = await parseAuthnRequest(idp, sp, req.redirectUrl);
    expect(parsed.id).toBe(req.id);
    expect(parsed.issuer).toBe(SP_ENTITY_ID);
    expect(parsed.destination).toBe(IDP_SSO_URL);
    expect(parsed.acsUrl).toBe(SP_ACS_URL);
  });

  test('IdP refuses an AuthnRequest whose Issuer is not the registered SP', async () => {
    const stranger = createServiceProvider({ entityID: 'https://stranger.example', acsUrl: SP_ACS_URL });
    const req = createAuthnRequest(stranger, idp);
    await expect(parseAuthnRequest(idp, sp, req.redirectUrl)).rejects.toThrow(/ERR_UNKNOWN_ISSUER/);
  });

  test('roundtrip: signed Response is accepted and yields NameID, email and groups', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    expect(res.acsUrl).toBe(SP_ACS_URL);
    expect(res.xml).toContain('<ds:Signature');
    expect(res.xml).toContain('<ds:X509Certificate>');
    expect(res.xml).toContain(`InResponseTo="${req.id}"`);
    expect(res.xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(Buffer.from(res.samlResponse, 'base64').toString('utf8')).toBe(res.xml);

    const identity = await parseLoginResponse(sp, idp, res.samlResponse, { requestId: req.id });
    expect(identity.nameID).toBe('alice@lab.example');
    expect(identity.email).toBe('alice@lab.example');
    expect(identity.groups).toEqual(['staff', 'orders-admin']);
    expect(identity.issuer).toBe(IDP_ENTITY_ID);
    expect(identity.audience).toBe(SP_ENTITY_ID);
    expect(identity.inResponseTo).toBe(req.id);
    expect(identity.sessionIndex).toMatch(/^_/);
  });

  test('a single-valued attribute comes back as a one-element array', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, { email: 'bob@lab.example', groups: ['staff'] });
    const identity = await parseLoginResponse(sp, idp, res.samlResponse, { requestId: req.id });
    expect(identity.groups).toEqual(['staff']);
  });

  test('tampered NameID is rejected: the assertion signature no longer verifies', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    const tampered = res.xml.replace('alice@lab.example</saml:NameID>', 'ceo@lab.example</saml:NameID>');
    expect(tampered).not.toBe(res.xml);
    await expect(
      parseLoginResponse(sp, idp, encodeSamlResponse(tampered), { requestId: req.id }),
    ).rejects.toThrow(/FAILED_TO_VERIFY_SIGNATURE/);
  });

  test('tampered attribute (groups) is rejected too', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    const tampered = res.xml.replace('>staff<', '>superuser<');
    expect(tampered).not.toBe(res.xml);
    await expect(
      parseLoginResponse(sp, idp, encodeSamlResponse(tampered), { requestId: req.id }),
    ).rejects.toThrow(/FAILED_TO_VERIFY_SIGNATURE/);
  });

  test('a Response with the signature stripped is rejected (WantAssertionsSigned)', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    const unsigned = res.xml.replace(/<ds:Signature[\s\S]*?<\/ds:Signature>/, '');
    expect(unsigned).not.toContain('<ds:Signature');
    await expect(
      parseLoginResponse(sp, idp, encodeSamlResponse(unsigned), { requestId: req.id }),
    ).rejects.toThrow(/FAILED_TO_VERIFY_SIGNATURE/);
  });

  test('a Response signed by an unknown key is rejected even if the XML is self-consistent', async () => {
    const rogueIdp = createIdentityProvider({ keys: generateSigningKeyPair('rogue-idp') }); // same entityID, other key
    const req = createAuthnRequest(sp, rogueIdp);
    const parsedReq = await parseAuthnRequest(rogueIdp, sp, req.redirectUrl);
    const res = await createLoginResponse(rogueIdp, sp, parsedReq, alice);

    // The SP trusts `idp` (its pinned certificate), not whatever certificate the message carries.
    await expect(
      parseLoginResponse(sp, idp, res.samlResponse, { requestId: req.id }),
    ).rejects.toThrow(/ERROR_UNMATCH_CERTIFICATE_DECLARATION_IN_METADATA/);
  });

  test('a Response meant for SP A is rejected by SP B (AudienceRestriction)', async () => {
    const billing = createServiceProvider({
      entityID: 'https://billing.lab.example',
      acsUrl: 'https://billing.lab.example/saml/acs',
    });
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    // Genuine signature, trusted issuer, fresh: still not for billing.
    await expect(parseLoginResponse(billing, idp, res.samlResponse)).rejects.toThrow(/ERR_WRONG_AUDIENCE/);
    // And it is accepted by the SP it was issued for.
    await expect(parseLoginResponse(sp, idp, res.samlResponse, { requestId: req.id })).resolves.toBeDefined();
  });

  test('a Response answering a request the SP never made is rejected (InResponseTo)', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    await expect(
      parseLoginResponse(sp, idp, res.samlResponse, { requestId: '_some-other-request' }),
    ).rejects.toThrow(/ERR_UNEXPECTED_IN_RESPONSE_TO/);
  });

  test('a Response with a failure Status carries no identity', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    const failed = res.xml.replace(
      'urn:oasis:names:tc:SAML:2.0:status:Success',
      'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed',
    );
    await expect(
      parseLoginResponse(sp, idp, encodeSamlResponse(failed), { requestId: req.id }),
    ).rejects.toThrow(/ERR_FAILED_STATUS/);
  });

  test('fails closed when Destination or bearer confirmation constraints are missing/malformed', async () => {
    const req = createAuthnRequest(sp, idp);
    const parsedReq = await parseAuthnRequest(idp, sp, req.redirectUrl);
    const res = await createLoginResponse(idp, sp, parsedReq, alice);

    // Destination is on the unsigned Response in this profile: this specifically exercises our check.
    const noDestination = res.xml.replace(` Destination="${SP_ACS_URL}"`, '');
    await expect(parseLoginResponse(sp, idp, encodeSamlResponse(noDestination), { requestId: req.id }))
      .rejects.toThrow(/ERR_WRONG_DESTINATION/);

    // These fields are inside the signed Assertion, so tampering is rejected by the signature first.
    // The parser also requires them after a valid signature (defence against a malformed trusted IdP response).
    const variants = [
      res.xml.replace(` Recipient="${SP_ACS_URL}"`, ''),
      res.xml.replace(` InResponseTo="${req.id}"\/>`, '/>'),
      res.xml.replace(/NotOnOrAfter="[^"]+" Recipient=/, 'NotOnOrAfter="not-a-date" Recipient='),
      res.xml.replace('urn:oasis:names:tc:SAML:2.0:cm:bearer', 'urn:lab:wrong-method'),
    ];
    for (const malformed of variants) {
      await expect(parseLoginResponse(sp, idp, encodeSamlResponse(malformed), { requestId: req.id })).rejects.toThrow();
    }
  });

  it('buildAttributeStatement escapes values and emits one AttributeValue per value', () => {
    const xml = buildAttributeStatement({ email: ['a&b@lab.example'], groups: ['x', '<admin>'] });
    expect(xml).toContain('<saml:Attribute Name="email"');
    expect(xml).toContain('a&amp;b@lab.example');
    expect(xml).toContain('&lt;admin&gt;');
    expect(xml.match(/<saml:AttributeValue /g)).toHaveLength(3);
    expect(xml).not.toContain('<admin>');
  });

  it('prettyXml indents nested elements and keeps text elements on one line', () => {
    const out = prettyXml('<a><b x="1"><c>text</c><d/></b></a>');
    expect(out).toBe(['<a>', '  <b x="1">', '    <c>text</c>', '    <d/>', '  </b>', '</a>'].join('\n'));
  });
});
