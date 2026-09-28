/**
 * SAML 2.0 lab: one Identity Provider (IdP), one or more Service Providers
 * (SP), built with samlify. Everything runs in-process; there is no network.
 *
 * Roles:
 *   IdP  https://idp.lab.example      authenticates users, signs assertions
 *   SP   https://orders.lab.example   consumes assertions, opens local sessions
 *
 * The functions below wrap samlify so the demo and the tests read like the
 * protocol: create an AuthnRequest, parse it at the IdP, issue a signed
 * Response, validate it at the SP.
 */
import * as samlify from 'samlify';
import { randomUUID } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import type { KeyMaterial } from './certs';

// ---------------------------------------------------------------------------
// !!! WARNING: XML SCHEMA VALIDATION IS DISABLED IN THIS LAB !!!
//
// samlify refuses to parse anything until a schema validator is registered.
// The real validators are native modules (libxml / xmllint) that we do not want
// as dependencies of a learning repo, so we register a validator that accepts
// everything.
//
// PRODUCTION MUST VALIDATE THE SCHEMA. It is one mandatory structural defence
// against XML Signature Wrapping (XSW), alongside unique-ID enforcement,
// duplicate-element rejection, binding the verified signature reference to the
// exact node consumed, an expected signed-element policy, and disabled DTD/entities.
// ---------------------------------------------------------------------------
samlify.setSchemaValidator({ validate: () => Promise.resolve('skipped') });

const { namespace } = samlify.Constants;

export type IdentityProvider = samlify.IdentityProviderInstance;
export type ServiceProvider = samlify.ServiceProviderInstance;

export const IDP_ENTITY_ID = 'https://idp.lab.example';
export const IDP_SSO_URL = 'https://idp.lab.example/sso';
export const IDP_SLO_URL = 'https://idp.lab.example/slo';
export const SP_ENTITY_ID = 'https://orders.lab.example';
export const SP_ACS_URL = 'https://orders.lab.example/saml/acs';

/** How long an assertion is valid once issued. Real IdPs use 5 minutes or less. */
export const ASSERTION_LIFETIME_MS = 5 * 60 * 1000;
/** Tolerated clock difference between IdP and SP, in each direction. */
export const CLOCK_SKEW_MS = 30 * 1000;

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

export interface IdpOptions {
  keys: KeyMaterial;
  entityID?: string;
  ssoUrl?: string;
  sloUrl?: string;
}

/**
 * The IdP publishes: its entityID, its SSO endpoint(s), the NameID formats it
 * can emit, and the certificate SPs must use to verify its signatures.
 */
export function createIdentityProvider(opts: IdpOptions): IdentityProvider {
  const entityID = opts.entityID ?? IDP_ENTITY_ID;
  const ssoUrl = opts.ssoUrl ?? IDP_SSO_URL;
  const sloUrl = opts.sloUrl ?? IDP_SLO_URL;
  return samlify.IdentityProvider({
    entityID,
    privateKey: opts.keys.privateKey,
    signingCert: opts.keys.certificate,
    // Signed AuthnRequests are optional in the spec and rare in practice
    // (the request carries no secrets and the IdP authenticates the user anyway).
    wantAuthnRequestsSigned: false,
    nameIDFormat: [namespace.format.emailAddress],
    singleSignOnService: [
      { Binding: namespace.binding.redirect, Location: ssoUrl, isDefault: true },
      { Binding: namespace.binding.post, Location: ssoUrl },
    ],
    singleLogoutService: [{ Binding: namespace.binding.redirect, Location: sloUrl }],
  });
}

export interface SpOptions {
  entityID: string;
  acsUrl: string;
  /**
   * Ask the IdP to sign the whole <Response> in addition to the <Assertion>.
   * Off by default so the demo prints one signature instead of two.
   */
  wantMessageSigned?: boolean;
}

/**
 * The SP publishes: its entityID (which becomes the assertion Audience), its
 * Assertion Consumer Service URL (where the browser posts the Response) and
 * what it requires from the IdP (signed assertions).
 */
export function createServiceProvider(opts: SpOptions): ServiceProvider {
  return samlify.ServiceProvider({
    entityID: opts.entityID,
    authnRequestsSigned: false,
    wantAssertionsSigned: true,
    wantMessageSigned: opts.wantMessageSigned ?? false,
    nameIDFormat: [namespace.format.emailAddress],
    assertionConsumerService: [
      { Binding: namespace.binding.post, Location: opts.acsUrl, isDefault: true },
    ],
    // samlify adds the first value to NotBefore and the second to NotOnOrAfter.
    clockDrifts: [-CLOCK_SKEW_MS, CLOCK_SKEW_MS],
  });
}

// ---------------------------------------------------------------------------
// Step 1: SP creates an AuthnRequest (HTTP-Redirect binding)
// ---------------------------------------------------------------------------

export interface AuthnRequestResult {
  /** The request ID. The SP stores it to check InResponseTo later. */
  id: string;
  /** Where the SP redirects the browser (302 Location header). */
  redirectUrl: string;
  /** The raw SAMLRequest query parameter: deflate + base64 + URL-encoding. */
  samlRequestParam: string;
  /** The decoded <samlp:AuthnRequest> XML. */
  xml: string;
  relayState?: string;
}

export function createAuthnRequest(sp: ServiceProvider, idp: IdentityProvider, relayState?: string): AuthnRequestResult {
  const { id, context: redirectUrl } = sp.createLoginRequest(idp, 'redirect', relayState ? { relayState } : {});
  const url = new URL(redirectUrl);
  const samlRequestParam = url.searchParams.get('SAMLRequest');
  if (!samlRequestParam) throw new Error('samlify did not produce a SAMLRequest parameter');
  return { id, redirectUrl, samlRequestParam, xml: decodeRedirectMessage(samlRequestParam), relayState };
}

/** HTTP-Redirect binding: URL-decode (done by URL parsing), base64-decode, raw-inflate. */
export function decodeRedirectMessage(samlParam: string): string {
  return inflateRawSync(Buffer.from(samlParam, 'base64')).toString('utf8');
}

// ---------------------------------------------------------------------------
// Step 2: IdP parses the AuthnRequest
// ---------------------------------------------------------------------------

/** What samlify returns after parsing a request; passed back when building the Response. */
export type RequestInfo = Awaited<ReturnType<IdentityProvider['parseLoginRequest']>>;

export interface ParsedAuthnRequest {
  id: string;
  issuer: string;
  destination: string;
  acsUrl: string;
  nameIDFormat?: string;
  requestInfo: RequestInfo;
}

/**
 * The IdP receives the browser at its SSO URL and reads the request. It learns
 * who is asking (Issuer), which request it answers (ID) and where the browser
 * must be sent back (AssertionConsumerServiceURL, cross-checked with metadata).
 */
export async function parseAuthnRequest(idp: IdentityProvider, sp: ServiceProvider, redirectUrl: string): Promise<ParsedAuthnRequest> {
  const url = new URL(redirectUrl);
  const query: Record<string, string> = {};
  url.searchParams.forEach((value, key) => { query[key] = value; });
  const parsed = await idp.parseLoginRequest(sp, 'redirect', { query });
  const request = (parsed.extract.request ?? {}) as Record<string, string>;
  const issuer = String(parsed.extract.issuer ?? '');
  const nameIDPolicy = (parsed.extract.nameIDPolicy ?? {}) as Record<string, string>;

  // samlify inflated and parsed the request (and would have verified a
  // signature if we required one). It does not compare the Issuer of a request
  // with anything, so the IdP does: metadata is the trust anchor, the message
  // is just a claim.
  if (issuer !== sp.entityMeta.getEntityID()) {
    throw new Error(`ERR_UNKNOWN_ISSUER: AuthnRequest issued by ${issuer}, expected ${sp.entityMeta.getEntityID()}`);
  }
  const acsFromMetadata = sp.entityMeta.getAssertionConsumerService('post');
  if (request.assertionConsumerServiceUrl && request.assertionConsumerServiceUrl !== acsFromMetadata) {
    // Never send the assertion where the request says. Only where the metadata says.
    throw new Error(`ERR_ACS_MISMATCH: request asks for ${request.assertionConsumerServiceUrl}, metadata says ${acsFromMetadata}`);
  }
  return {
    id: request.id,
    issuer,
    destination: request.destination,
    acsUrl: String(acsFromMetadata),
    nameIDFormat: nameIDPolicy.format,
    requestInfo: parsed,
  };
}

// ---------------------------------------------------------------------------
// Step 3: IdP authenticates the user and issues a signed Response
// ---------------------------------------------------------------------------

export interface LabUser {
  email: string;
  groups: string[];
}

export interface LoginResponseResult {
  /** The Response ID. */
  id: string;
  /** Base64 of the signed XML: the SAMLResponse form field of the HTTP-POST binding. */
  samlResponse: string;
  /** The signed XML, decoded, exactly as the SP will receive it. */
  xml: string;
  /** Where the browser must POST the form: the SP's ACS URL. */
  acsUrl: string;
  relayState?: string;
}

/**
 * Our own Response template, so every element is visible in one place.
 * samlify fills the {Tags} (XML-escaping the values) and then signs the
 * <saml:Assertion> with an enveloped XML-DSig signature.
 *
 * Kept readable here, compacted before use: whitespace between elements would
 * otherwise be part of the signed bytes too.
 */
const RESPONSE_TEMPLATE = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{ID}" Version="2.0" IssueInstant="{IssueInstant}" Destination="{Destination}" InResponseTo="{InResponseTo}">
  <saml:Issuer>{Issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="{StatusCode}"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{AssertionID}" Version="2.0" IssueInstant="{IssueInstant}">
    <saml:Issuer>{Issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="{NameIDFormat}">{NameID}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{SubjectConfirmationDataNotOnOrAfter}" Recipient="{SubjectRecipient}" InResponseTo="{InResponseTo}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{ConditionsNotBefore}" NotOnOrAfter="{ConditionsNotOnOrAfter}">
      <saml:AudienceRestriction>
        <saml:Audience>{Audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{AuthnInstant}" SessionIndex="{SessionIndex}" SessionNotOnOrAfter="{SessionNotOnOrAfter}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>{AuthnContextClassRef}</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    {AttributeStatement}
  </saml:Assertion>
</samlp:Response>`;

const ATTRIBUTE_NAME_FORMAT_BASIC = 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic';

export function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** <saml:AttributeStatement> with one <saml:Attribute> per name, one <saml:AttributeValue> per value. */
export function buildAttributeStatement(attributes: Record<string, string[]>): string {
  const body = Object.entries(attributes)
    .map(([name, values]) => {
      const valueXml = values
        .map((v) => `<saml:AttributeValue xsi:type="xs:string">${escapeXml(v)}</saml:AttributeValue>`)
        .join('');
      return `<saml:Attribute Name="${escapeXml(name)}" NameFormat="${ATTRIBUTE_NAME_FORMAT_BASIC}">${valueXml}</saml:Attribute>`;
    })
    .join('');
  return `<saml:AttributeStatement>${body}</saml:AttributeStatement>`;
}

export function compactXml(xml: string): string {
  return xml.replace(/>\s+</g, '><').trim();
}

export async function createLoginResponse(
  idp: IdentityProvider,
  sp: ServiceProvider,
  request: ParsedAuthnRequest,
  user: LabUser,
  relayState?: string,
): Promise<LoginResponseResult> {
  const now = new Date();
  const notOnOrAfter = new Date(now.getTime() + ASSERTION_LIFETIME_MS);
  const sessionNotOnOrAfter = new Date(now.getTime() + 8 * 60 * 60 * 1000);
  const acsUrl = String(sp.entityMeta.getAssertionConsumerService('post'));
  const responseId = '_' + randomUUID();
  const assertionId = '_' + randomUUID();

  const tags = {
    ID: responseId,
    AssertionID: assertionId,
    IssueInstant: now.toISOString(),
    Issuer: idp.entityMeta.getEntityID(),
    Destination: acsUrl,
    InResponseTo: request.id,
    StatusCode: samlify.Constants.StatusCode.Success,
    NameIDFormat: namespace.format.emailAddress,
    NameID: user.email,
    SubjectRecipient: acsUrl,
    SubjectConfirmationDataNotOnOrAfter: notOnOrAfter.toISOString(),
    ConditionsNotBefore: now.toISOString(),
    ConditionsNotOnOrAfter: notOnOrAfter.toISOString(),
    Audience: sp.entityMeta.getEntityID(),
    AuthnInstant: now.toISOString(),
    SessionIndex: '_' + randomUUID(),
    SessionNotOnOrAfter: sessionNotOnOrAfter.toISOString(),
    AuthnContextClassRef: namespace.authnContextClassRef.passwordProtectedTransport,
  };

  const attributeStatement = buildAttributeStatement({ email: [user.email], groups: user.groups });
  // The attribute XML goes in first with a plain replace (it is XML, not text),
  // then samlify's replaceTagsByValue fills and escapes the scalar values.
  const unsignedXml = samlify.SamlLib.replaceTagsByValue(
    compactXml(RESPONSE_TEMPLATE).replace('{AttributeStatement}', attributeStatement),
    tags,
  );

  // samlify only reads `extract.request.id` from this (for InResponseTo).
  const requestInfo = { extract: request.requestInfo.extract };
  const result = await idp.createLoginResponse(sp, requestInfo, 'post', { email: user.email }, {
    relayState,
    // samlify hands us its default template; we return our own. It then signs.
    customTagReplacement: () => ({ id: responseId, context: unsignedXml }),
  });

  return {
    id: responseId,
    samlResponse: result.context,
    xml: Buffer.from(result.context, 'base64').toString('utf8'),
    acsUrl: 'entityEndpoint' in result ? result.entityEndpoint : acsUrl,
    relayState,
  };
}

// ---------------------------------------------------------------------------
// Step 4: SP validates the Response and extracts the identity
// ---------------------------------------------------------------------------

export interface VerifiedIdentity {
  nameID: string;
  email: string;
  groups: string[];
  attributes: Record<string, string[]>;
  issuer: string;
  audience: string;
  inResponseTo: string;
  sessionIndex?: string;
  notOnOrAfter: string;
}

export interface ParseExpectations {
  /** The AuthnRequest ID the SP issued and stored. Omit for IdP-initiated SSO. */
  requestId?: string;
}

function asArray(value: string | string[] | undefined | null): string[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * samlify checks, in this order: XML (schema: skipped here), Status=Success,
 * the XML-DSig signature against the IdP certificate from metadata, the Issuer,
 * and the Conditions time window.
 *
 * It leaves the rest to the application. Those checks are not optional; every
 * one of them closes a real attack:
 *   Audience      = our entityID     else a token for another SP works here
 *   Destination   = our ACS URL      else a message meant elsewhere works here
 *   Recipient     = our ACS URL      same, on the bearer confirmation
 *   InResponseTo  = a request we made  else replay and unsolicited responses
 *   NotOnOrAfter  in the future      else the bearer token lives forever
 */
export async function parseLoginResponse(
  sp: ServiceProvider,
  idp: IdentityProvider,
  samlResponseBase64: string,
  expected: ParseExpectations = {},
): Promise<VerifiedIdentity> {
  const parsed = await sp.parseLoginResponse(idp, 'post', { body: { SAMLResponse: samlResponseBase64 } });
  const ex = parsed.extract;

  const spEntityId = sp.entityMeta.getEntityID();
  const acsUrl = String(sp.entityMeta.getAssertionConsumerService('post'));
  const response = (ex.response ?? {}) as Record<string, string>;

  // One assertion, at the top level. A second one is a wrapping attempt.
  const assertions = samlify.Extractor.extract(parsed.samlContent, [
    { key: 'assertion', localPath: ['Response', 'Assertion'], attributes: [], context: true },
  ]).assertion;
  if (typeof assertions !== 'string') {
    throw new Error('ERR_UNEXPECTED_ASSERTION_COUNT: expected exactly one <Assertion> under <Response>');
  }
  const confirmationFields = samlify.Extractor.extract(assertions, [
    {
      key: 'confirmation',
      localPath: ['Assertion', 'Subject', 'SubjectConfirmation', 'SubjectConfirmationData'],
      attributes: ['NotOnOrAfter', 'Recipient', 'InResponseTo'],
    },
    {
      key: 'confirmationMethod',
      localPath: ['Assertion', 'Subject', 'SubjectConfirmation'],
      attributes: ['Method'],
    },
  ]);
  const confirmationRaw = confirmationFields.confirmation;
  const methodRaw = confirmationFields.confirmationMethod;
  if (!confirmationRaw || typeof confirmationRaw !== 'object' || Array.isArray(confirmationRaw)) {
    throw new Error('ERR_SUBJECT_CONFIRMATION: expected exactly one bearer SubjectConfirmationData');
  }
  const subjectConfirmationCount = assertions.match(/<saml:SubjectConfirmation\b/g)?.length ?? 0;
  if (subjectConfirmationCount !== 1 || typeof methodRaw !== 'string') {
    throw new Error('ERR_SUBJECT_CONFIRMATION: expected exactly one SubjectConfirmation');
  }
  const confirmation = confirmationRaw as Record<string, string>;
  const method = methodRaw;
  if (method !== 'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
    throw new Error(`ERR_SUBJECT_CONFIRMATION_METHOD: ${method || '(missing)'}`);
  }

  const audiences = asArray(ex.audience);
  if (!audiences.includes(spEntityId)) {
    throw new Error(`ERR_WRONG_AUDIENCE: assertion is for [${audiences.join(', ')}], we are ${spEntityId}`);
  }
  if (response.destination !== acsUrl) {
    throw new Error(`ERR_WRONG_DESTINATION: ${response.destination || '(missing)'} is not our ACS ${acsUrl}`);
  }
  if (confirmation.recipient !== acsUrl) {
    throw new Error(`ERR_WRONG_RECIPIENT: ${confirmation.recipient || '(missing)'} is not our ACS ${acsUrl}`);
  }
  if (expected.requestId !== undefined) {
    if (response.inResponseTo !== expected.requestId) {
      throw new Error(`ERR_UNEXPECTED_IN_RESPONSE_TO: response answers ${response.inResponseTo || '(missing)'}, we asked ${expected.requestId}`);
    }
    if (confirmation.inResponseTo !== expected.requestId) {
      throw new Error(`ERR_UNEXPECTED_IN_RESPONSE_TO: subject confirmation answers ${confirmation.inResponseTo || '(missing)'}`);
    }
  }
  if (!confirmation.notOnOrAfter) {
    throw new Error('ERR_SUBJECT_CONFIRMATION_EXPIRED: NotOnOrAfter is missing');
  }
  const confirmationExpiry = Date.parse(confirmation.notOnOrAfter);
  if (!Number.isFinite(confirmationExpiry)) {
    throw new Error(`ERR_SUBJECT_CONFIRMATION_EXPIRED: invalid NotOnOrAfter ${confirmation.notOnOrAfter}`);
  }
  if (confirmationExpiry + CLOCK_SKEW_MS <= Date.now()) {
    throw new Error(`ERR_SUBJECT_CONFIRMATION_EXPIRED: ${confirmation.notOnOrAfter}`);
  }

  const attributes: Record<string, string[]> = {};
  for (const [name, value] of Object.entries(ex.attributes ?? {})) {
    attributes[name] = asArray(value);
  }
  const nameID = ex.nameID ?? '';
  if (!nameID) throw new Error('ERR_MISSING_NAMEID');

  return {
    nameID,
    email: attributes.email?.[0] ?? nameID,
    groups: attributes.groups ?? [],
    attributes,
    issuer: String(ex.issuer ?? ''),
    audience: spEntityId,
    inResponseTo: response.inResponseTo ?? '',
    sessionIndex: ((ex.sessionIndex ?? {}) as Record<string, string>).sessionIndex,
    notOnOrAfter: ((ex.conditions ?? {}) as Record<string, string>).notOnOrAfter ?? '',
  };
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

export interface PrettyXmlOptions {
  /** Shorten text longer than this (base64 blobs) so the structure stays readable. */
  truncateTextOver?: number;
}

/** Light indentation. Good enough to read SAML; not a general XML formatter. Display only. */
export function prettyXml(xml: string, opts: PrettyXmlOptions = {}): string {
  const lines = compactXml(xml)
    .replace(/<([\w:.-]+)([^>]*)><\/\1>/g, '<$1$2/>') // <a b="c"></a> → <a b="c"/>
    .replace(/></g, '>\n<')
    .split('\n');
  const out: string[] = [];
  let depth = 0;
  for (const rawLine of lines) {
    let line = rawLine;
    if (opts.truncateTextOver) {
      line = line.replace(/>([^<]{1,})</, (_m, text: string) =>
        text.length > opts.truncateTextOver!
          ? `>${text.slice(0, 40)}…${text.slice(-16)} (${text.length} chars)<`
          : `>${text}<`,
      );
    }
    const isClosing = /^<\//.test(line);
    const isSelfClosing = /\/>$/.test(line);
    const isDeclaration = /^<[?!]/.test(line);
    const opensAndCloses = /^<[^/][^>]*>[^<]*<\/[^>]+>$/.test(line);
    if (isClosing) depth = Math.max(0, depth - 1);
    out.push('  '.repeat(depth) + line);
    if (!isClosing && !isSelfClosing && !isDeclaration && !opensAndCloses) depth++;
  }
  return out.join('\n');
}

/** Base64 helpers for the HTTP-POST binding, named for what they carry. */
export function decodeSamlResponse(base64: string): string {
  return Buffer.from(base64, 'base64').toString('utf8');
}
export function encodeSamlResponse(xml: string): string {
  return Buffer.from(xml, 'utf8').toString('base64');
}
