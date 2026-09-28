/**
 * Chapter 10: a small simulator of IAM policy evaluation logic.
 *
 * It is the real algorithm, simplified: the single-account flow from the IAM User Guide
 * ("Policy evaluation logic") plus the cross-account rule, over the subset of the policy
 * language that people actually meet: Effect, Action/NotAction, Resource/NotResource,
 * Principal (in resource policies), Condition with the common operators, and policy
 * variables such as `${aws:PrincipalTag/dept}`.
 *
 * What it deliberately leaves out: resource control policies (RCPs), ACLs, service-linked
 * quirks (KMS key policies, S3 Block Public Access), IP and date operators, multivalued
 * context keys (ForAllValues / ForAnyValue). Resource-policy principal semantics are intentionally
 * conservative and simplified: real IAM distinguishes grants to users, role ARNs, and assumed-role
 * session ARNs when applying boundaries/session policies; this simulator does not. It also does not
 * model anonymous requests or account-principal delegation. The README points to the real rules.
 *
 * Nothing here talks to AWS. It is offline, deterministic and fully unit-tested.
 */

// ---------------------------------------------------------------- the policy language (our subset)

export type Effect = 'Allow' | 'Deny';
type OneOrMany<T> = T | readonly T[];

/** `Principal` of a resource-based policy. `"*"` means everyone, including anonymous callers. */
export type PrincipalElement = '*' | { readonly AWS: OneOrMany<string> };

export type ConditionValue = OneOrMany<string | boolean | number>;
/** operator → context key → expected value(s). `{ StringEquals: { 'aws:PrincipalTag/dept': 'finance' } }` */
export type ConditionBlock = Readonly<Record<string, Readonly<Record<string, ConditionValue>>>>;

export interface Statement {
  readonly Sid?: string;
  readonly Effect: Effect;
  /** Only meaningful in resource-based policies (bucket policies, trust policies, key policies). */
  readonly Principal?: PrincipalElement;
  readonly Action?: OneOrMany<string>;
  readonly NotAction?: OneOrMany<string>;
  readonly Resource?: OneOrMany<string>;
  readonly NotResource?: OneOrMany<string>;
  readonly Condition?: ConditionBlock;
}

export interface PolicyDocument {
  readonly Version?: '2012-10-17';
  readonly Statement: readonly Statement[];
}

// ---------------------------------------------------------------- the request

export interface Principal {
  /**
   * Who is calling. `arn:aws:iam::111111111111:user/alice`, `arn:aws:iam::111111111111:role/app`,
   * `arn:aws:sts::111111111111:assumed-role/app/session-name` or `arn:aws:iam::111111111111:root`.
   * The account is read from the ARN.
   */
  readonly arn: string;
  /** Tags on the user or role, or session tags passed at AssumeRole time. Become `aws:PrincipalTag/<key>`. */
  readonly tags?: Readonly<Record<string, string>>;
}

export interface Resource {
  readonly arn: string;
  /** The account that owns the resource. S3 ARNs do not carry it, so it is explicit. */
  readonly account: string;
  /** Tags on the resource. Become `aws:ResourceTag/<key>`. */
  readonly tags?: Readonly<Record<string, string>>;
}

export interface Request {
  readonly principal: Principal;
  /** `s3:GetObject`, `iam:CreateUser`, ... */
  readonly action: string;
  readonly resource: Resource;
  /**
   * Extra request context, as the service would fill it in: `aws:RequestedRegion`,
   * `aws:MultiFactorAuthPresent`, `aws:SecureTransport`, `sts:ExternalId`, `aws:SourceIp`...
   * A key that is not here is "not present in the request context", which matters for conditions.
   */
  readonly context?: Readonly<Record<string, string | boolean | number>>;
  /** Policies attached to the user, its groups, or the role. */
  readonly identityPolicies?: readonly PolicyDocument[];
  /** The bucket policy, queue policy, key policy... of the resource. */
  readonly resourcePolicy?: PolicyDocument;
  /** The permissions boundary attached to the user or role, if any. */
  readonly permissionsBoundary?: PolicyDocument;
  /**
   * Service control policies of the caller's account, one entry per level of the Organizations tree
   * above it (root, each OU, the account itself). Within a level the Allows are a union; across
   * levels they intersect: every level must allow. That is why `FullAWSAccess` has to stay attached
   * at every level when you only want to add Deny statements.
   */
  readonly scps?: readonly ScpLevel[];
  /** The policy passed to AssumeRole / GetFederationToken, if any. */
  readonly sessionPolicy?: PolicyDocument;
}

export interface ScpLevel {
  /** `root`, `ou:workloads`, `account`... only used in the trace. */
  readonly name: string;
  readonly policies: readonly PolicyDocument[];
}

// ---------------------------------------------------------------- the answer

export type PolicyType = 'identity' | 'resource' | 'permissions-boundary' | 'scp' | 'session';

export interface MatchedStatement {
  readonly policyType: PolicyType;
  /** Index of the document within its list (identity policies, the SCPs of one level); 0 for single documents. */
  readonly policyIndex: number;
  /** For SCPs: the name of the Organizations level the policy is attached to. */
  readonly scpLevel?: string;
  readonly statementIndex: number;
  /** The Sid, or `statement[<index>]` when there is none. */
  readonly sid: string;
  readonly effect: Effect;
}

export type DecisionCode =
  | 'explicit-deny'
  | 'scp-implicit-deny'
  | 'permissions-boundary-implicit-deny'
  | 'session-policy-implicit-deny'
  | 'cross-account-implicit-deny'
  | 'implicit-deny'
  | 'identity-policy-allow'
  | 'resource-policy-allow'
  | 'cross-account-allow';

export interface Decision {
  readonly decision: 'Allow' | 'Deny';
  readonly code: DecisionCode;
  /** One sentence a human can act on. */
  readonly reason: string;
  /** Every statement, in every policy type, that applied to this request (Allow and Deny). */
  readonly matchedStatements: readonly MatchedStatement[];
  /** One line per step of the evaluation, in the order IAM performs them. */
  readonly trace: readonly string[];
}

// ---------------------------------------------------------------- request context

/** Lower-cased context key → string value. Condition keys are case-insensitive; values are not. */
export type Context = ReadonlyMap<string, string>;

const ARN_SEGMENTS = 6; // arn:partition:service:region:account:resource

/** Splits an ARN into its six segments. The resource segment keeps any further colons. */
export function arnSegments(arn: string): string[] | undefined {
  const parts = arn.split(':');
  if (parts.length < ARN_SEGMENTS || parts[0] !== 'arn') return undefined;
  return [...parts.slice(0, ARN_SEGMENTS - 1), parts.slice(ARN_SEGMENTS - 1).join(':')];
}

/** The account id inside an IAM or STS ARN. Throws for anything else: a principal always has one. */
export function accountOf(principalArn: string): string {
  const account = arnSegments(principalArn)?.[4];
  if (!account || !/^\d{12}$/.test(account)) {
    throw new Error(`cannot read an account id from principal ARN ${principalArn}`);
  }
  return account;
}

/**
 * `arn:aws:sts::111111111111:assumed-role/Dev/alice` → `arn:aws:iam::111111111111:role/Dev`.
 * A role named in a resource policy matches every session of that role; this is how.
 */
export function roleArnOfSession(principalArn: string): string | undefined {
  const segments = arnSegments(principalArn);
  if (!segments || segments[2] !== 'sts') return undefined;
  const match = /^assumed-role\/([^/]+)\/.+$/.exec(segments[5]);
  return match ? `arn:${segments[1]}:iam::${segments[4]}:role/${match[1]}` : undefined;
}

/** What the service would put in the request context before evaluating any policy. */
export function buildContext(request: Request): Context {
  const ctx = new Map<string, string>();
  const put = (key: string, value: string | boolean | number): void => {
    ctx.set(key.toLowerCase(), String(value));
  };
  // `request.context` models service-supplied keys such as RequestedRegion. Put it first so a
  // caller cannot spoof the simulator-derived principal/resource ARN, account, or tag keys.
  for (const [key, value] of Object.entries(request.context ?? {})) put(key, value);
  const principalAccount = accountOf(request.principal.arn);
  put('aws:PrincipalArn', request.principal.arn);
  put('aws:PrincipalAccount', principalAccount);
  put('aws:ResourceAccount', request.resource.account);
  for (const [key, value] of Object.entries(request.principal.tags ?? {})) put(`aws:PrincipalTag/${key}`, value);
  for (const [key, value] of Object.entries(request.resource.tags ?? {})) put(`aws:ResourceTag/${key}`, value);
  return ctx;
}

// ---------------------------------------------------------------- wildcards and policy variables

const VARIABLE = /\$\{([^}]+)\}/g;

/**
 * Replaces `${key}` with the context value. Returns `undefined` when a variable is missing from
 * the context: the statement then does not match, so an Allow grants nothing and a Deny denies
 * nothing. Wildcard characters inside a substituted value are escaped (`${*}`, `${?}`, `${$}`,
 * the same escapes the policy language offers) so a tag value of `*` stays a literal star.
 */
export function substituteVariables(template: string, ctx: Context): string | undefined {
  let missing = false;
  const out = template.replace(VARIABLE, (whole, name: string) => {
    if (name === '*' || name === '?' || name === '$') return whole; // literal escapes, kept for globToRegExp
    const value = ctx.get(name.toLowerCase());
    if (value === undefined) {
      missing = true;
      return '';
    }
    return value.replace(/[*?$]/g, (ch) => `\${${ch}}`);
  });
  return missing ? undefined : out;
}

/** Removes the `${*}` `${?}` `${$}` escapes, for operators that compare literally. */
export function literalOf(escaped: string): string {
  return escaped.replace(/\$\{([*?$])\}/g, '$1');
}

/** IAM wildcards: `*` any run of characters, `?` one character. `${*}` `${?}` `${$}` are literals. */
export function globToRegExp(pattern: string, caseInsensitive = false): RegExp {
  let source = '^';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    const escape = /^\$\{([*?$])\}/.exec(pattern.slice(i));
    if (escape) {
      source += `\\${escape[1]}`;
      i += escape[0].length - 1;
    } else if (ch === '*') {
      source += '.*';
    } else if (ch === '?') {
      source += '.';
    } else {
      source += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`${source}$`, caseInsensitive ? 'is' : 's');
}

/** Action names are case-insensitive: `s3:getobject` is `s3:GetObject`. */
export function actionMatches(pattern: string, action: string): boolean {
  return globToRegExp(pattern, true).test(action);
}

/**
 * The Resource element: case-sensitive, and we let `*` run across ARN segments, so
 * `arn:aws:s3:::lab-docs/*` matches every key under the bucket, however many slashes it has.
 */
export function resourceMatches(pattern: string, arn: string): boolean {
  return pattern === '*' || globToRegExp(pattern).test(arn);
}

/**
 * The ArnLike / ArnEquals operators: each of the six colon-delimited segments is matched on its own,
 * so a `*` in the account segment cannot swallow the resource segment. (ArnEquals and ArnLike behave
 * identically in IAM; both accept wildcards.)
 */
export function arnLike(pattern: string, arn: string): boolean {
  const want = arnSegments(pattern);
  const have = arnSegments(arn);
  if (!want || !have) return false;
  return want.every((segment, i) => globToRegExp(segment).test(have[i]));
}

// ---------------------------------------------------------------- conditions

const NEGATED = /Not(Equals|Like)/;

interface ParsedOperator {
  readonly base: string;
  readonly ifExists: boolean;
}

function parseOperator(operator: string): ParsedOperator {
  if (operator === 'Null') return { base: operator, ifExists: false };
  const ifExists = operator.endsWith('IfExists');
  return { base: ifExists ? operator.slice(0, -'IfExists'.length) : operator, ifExists };
}

function toArray<T>(value: OneOrMany<T>): readonly T[] {
  return Array.isArray(value) ? (value as readonly T[]) : [value as T];
}

/** One operator, one key, the actual value present in the context. */
function compare(base: string, actual: string, expected: readonly string[]): boolean {
  switch (base) {
    case 'StringEquals':
      return expected.some((v) => literalOf(v) === actual);
    case 'StringNotEquals':
      return !expected.some((v) => literalOf(v) === actual);
    case 'StringEqualsIgnoreCase':
      return expected.some((v) => literalOf(v).toLowerCase() === actual.toLowerCase());
    case 'StringNotEqualsIgnoreCase':
      return !expected.some((v) => literalOf(v).toLowerCase() === actual.toLowerCase());
    case 'StringLike':
      return expected.some((v) => globToRegExp(v).test(actual));
    case 'StringNotLike':
      return !expected.some((v) => globToRegExp(v).test(actual));
    case 'ArnEquals':
    case 'ArnLike':
      return expected.some((v) => arnLike(v, actual));
    case 'ArnNotEquals':
    case 'ArnNotLike':
      return !expected.some((v) => arnLike(v, actual));
    case 'Bool':
      return expected.some((v) => literalOf(v).toLowerCase() === actual.toLowerCase());
    case 'NumericEquals':
      return expected.some((v) => Number(literalOf(v)) === Number(actual));
    case 'NumericNotEquals':
      return !expected.some((v) => Number(literalOf(v)) === Number(actual));
    case 'NumericLessThan':
      return expected.some((v) => Number(actual) < Number(literalOf(v)));
    case 'NumericLessThanEquals':
      return expected.some((v) => Number(actual) <= Number(literalOf(v)));
    case 'NumericGreaterThan':
      return expected.some((v) => Number(actual) > Number(literalOf(v)));
    case 'NumericGreaterThanEquals':
      return expected.some((v) => Number(actual) >= Number(literalOf(v)));
    default:
      // Fail closed and loudly: an operator we do not model must not silently become "true".
      throw new Error(`unsupported condition operator ${base}`);
  }
}

/**
 * Every operator block must hold, and inside a block every key must hold (AND); the values of one
 * key are alternatives (OR). Missing keys: a positive operator is false, a negated operator
 * (`StringNotEquals`, `ArnNotLike`...) is true, and `...IfExists` is true. That last rule is the
 * whole point of the MFA scenario in the demo.
 */
export function conditionHolds(block: ConditionBlock | undefined, ctx: Context): boolean {
  if (!block) return true;
  for (const [operator, keys] of Object.entries(block)) {
    const { base, ifExists } = parseOperator(operator);
    for (const [key, rawExpected] of Object.entries(keys)) {
      const actual = ctx.get(key.toLowerCase());
      if (base === 'Null') {
        const wantMissing = toArray(rawExpected).some((v) => String(v).toLowerCase() === 'true');
        if ((actual === undefined) !== wantMissing) return false;
        continue;
      }
      if (actual === undefined) {
        if (ifExists || NEGATED.test(base)) continue;
        return false;
      }
      // Values may themselves contain policy variables: "aws:ResourceTag/dept": "${aws:PrincipalTag/dept}".
      const expected = toArray(rawExpected)
        .map((v) => substituteVariables(String(v), ctx))
        .filter((v): v is string => v !== undefined);
      if (!compare(base, actual, expected)) return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------- does a statement apply?

/** Resource-policy `Principal`: exact ARN, the role behind a session, the account (`root` ARN or bare id), or `*`. */
export function principalMatches(element: PrincipalElement | undefined, principal: Principal): boolean {
  if (element === undefined) return false;
  const ids = element === '*' ? ['*'] : toArray(element.AWS);
  const account = accountOf(principal.arn);
  const accepted = new Set([principal.arn, roleArnOfSession(principal.arn), `arn:aws:iam::${account}:root`, account]);
  return ids.some((id) => id === '*' || accepted.has(id));
}

function actionElementMatches(statement: Statement, action: string): boolean {
  if (statement.Action !== undefined) return toArray(statement.Action).some((p) => actionMatches(p, action));
  if (statement.NotAction !== undefined) return !toArray(statement.NotAction).some((p) => actionMatches(p, action));
  return false;
}

function resourceElementMatches(statement: Statement, arn: string, ctx: Context): boolean {
  const resolve = (patterns: OneOrMany<string>): string[] =>
    toArray(patterns)
      .map((p) => substituteVariables(p, ctx))
      .filter((p): p is string => p !== undefined);
  if (statement.Resource !== undefined) return resolve(statement.Resource).some((p) => resourceMatches(p, arn));
  if (statement.NotResource !== undefined) {
    const patterns = resolve(statement.NotResource);
    return patterns.length > 0 && !patterns.some((p) => resourceMatches(p, arn));
  }
  // SCPs and identity policies always name a Resource; a statement with neither matches nothing.
  return false;
}

/** The four questions IAM asks of every statement: principal (resource policies), action, resource, conditions. */
export function statementApplies(statement: Statement, request: Request, ctx: Context, policyType: PolicyType): boolean {
  if (policyType === 'resource' && !principalMatches(statement.Principal, request.principal)) return false;
  if (!actionElementMatches(statement, request.action)) return false;
  if (!resourceElementMatches(statement, request.resource.arn, ctx)) return false;
  return conditionHolds(statement.Condition, ctx);
}

// ---------------------------------------------------------------- the evaluation

interface PolicySource {
  readonly type: PolicyType;
  readonly scpLevel?: string;
  readonly documents: readonly PolicyDocument[];
}

function label(m: MatchedStatement): string {
  const policy = m.policyType === 'scp' ? `scp:${m.scpLevel}[${m.policyIndex}]` : `${m.policyType}[${m.policyIndex}]`;
  return `${policy}.${m.sid}`;
}

function countStatements(sources: readonly PolicySource[]): { policies: number; statements: number } {
  let policies = 0;
  let statements = 0;
  for (const source of sources) {
    for (const doc of source.documents) {
      policies += 1;
      statements += doc.Statement.length;
    }
  }
  return { policies, statements };
}

/**
 * Evaluate one request against every policy that applies to it.
 *
 *  1. Deny evaluation: an explicit Deny in ANY policy type ends it. Order and policy type do not matter.
 *  2. SCPs (when the account has them) must allow at every level of the tree. They never grant; they cap.
 *  3. Permissions boundary (when the principal has one) must allow. A cap, not a grant.
 *  4. Session policy (when the session was created with one) must allow. A cap, not a grant.
 *  5. Same account: an identity-policy Allow OR a resource-policy Allow is enough.
 *     Cross account: the resource policy must name the caller AND the caller's own identity policy
 *     must allow the action. Both sides say yes, or nobody does.
 *  6. Otherwise: implicit deny. Nothing said yes.
 */
export function evaluate(request: Request): Decision {
  const ctx = buildContext(request);
  const principalAccount = accountOf(request.principal.arn);
  const sameAccount = principalAccount === request.resource.account;
  const trace: string[] = [];

  const scpLevels = request.scps ?? [];
  const sources: PolicySource[] = [
    { type: 'identity', documents: request.identityPolicies ?? [] },
    { type: 'resource', documents: request.resourcePolicy ? [request.resourcePolicy] : [] },
    { type: 'permissions-boundary', documents: request.permissionsBoundary ? [request.permissionsBoundary] : [] },
    ...scpLevels.map((level): PolicySource => ({ type: 'scp', scpLevel: level.name, documents: level.policies })),
    { type: 'session', documents: request.sessionPolicy ? [request.sessionPolicy] : [] },
  ];

  const matched: MatchedStatement[] = [];
  for (const source of sources) {
    source.documents.forEach((doc, policyIndex) => {
      doc.Statement.forEach((statement, statementIndex) => {
        if (statementApplies(statement, request, ctx, source.type)) {
          matched.push({
            policyType: source.type,
            policyIndex,
            ...(source.scpLevel === undefined ? {} : { scpLevel: source.scpLevel }),
            statementIndex,
            sid: statement.Sid ?? `statement[${statementIndex}]`,
            effect: statement.Effect,
          });
        }
      });
    });
  }
  const allowsFrom = (type: PolicyType, scpLevel?: string): MatchedStatement[] =>
    matched.filter((m) => m.policyType === type && m.effect === 'Allow' && (scpLevel === undefined || m.scpLevel === scpLevel));

  const deny = (code: DecisionCode, reason: string): Decision => {
    trace.push(`→ DENY (${code}): ${reason}`);
    return { decision: 'Deny', code, reason, matchedStatements: matched, trace };
  };
  const allow = (code: DecisionCode, reason: string): Decision => {
    trace.push(`→ ALLOW (${code}): ${reason}`);
    return { decision: 'Allow', code, reason, matchedStatements: matched, trace };
  };

  // 1. explicit deny anywhere
  const { policies, statements } = countStatements(sources);
  const denies = matched.filter((m) => m.effect === 'Deny');
  const count = (n: number, one: string, many: string): string => `${n} ${n === 1 ? one : many}`;
  trace.push(
    `1. deny evaluation: ${denies.length === 0 ? 'no explicit Deny' : `explicit Deny in ${denies.map(label).join(', ')}`} (searched ${count(policies, 'policy', 'policies')}, ${count(statements, 'statement', 'statements')})`,
  );
  if (denies.length > 0) {
    return deny('explicit-deny', `explicit deny by ${denies.map(label).join(', ')}; an explicit Deny in any policy type is final`);
  }

  // 2. SCPs: every level of the tree must contain an Allow that matches
  if (scpLevels.length === 0) {
    trace.push('2. SCPs: none (no organization, or the management account, which SCPs never restrict)');
  } else {
    const silent = scpLevels.filter((level) => allowsFrom('scp', level.name).length === 0);
    if (silent.length > 0) {
      trace.push(`2. SCPs: level ${silent.map((l) => l.name).join(', ')} has no Allow for ${request.action}`);
      return deny('scp-implicit-deny', `no SCP at level ${silent[0].name} allows ${request.action}; every level of the organization tree must allow, and SCPs cap administrators too`);
    }
    trace.push(`2. SCPs: every level allows (${allowsFrom('scp').map(label).join(', ')})`);
  }

  // 3. permissions boundary
  if (!request.permissionsBoundary) {
    trace.push('3. permissions boundary: none');
  } else if (allowsFrom('permissions-boundary').length === 0) {
    trace.push(`3. permissions boundary: does not allow ${request.action}`);
    return deny('permissions-boundary-implicit-deny', `the permissions boundary does not allow ${request.action}; a boundary is the ceiling of what identity policies can grant`);
  } else {
    trace.push(`3. permissions boundary: allows (${allowsFrom('permissions-boundary').map(label).join(', ')})`);
  }

  // 4. session policy
  if (!request.sessionPolicy) {
    trace.push('4. session policy: none');
  } else if (allowsFrom('session').length === 0) {
    trace.push(`4. session policy: does not allow ${request.action}`);
    return deny('session-policy-implicit-deny', `the session policy does not allow ${request.action}; a session policy scopes a session down, never up`);
  } else {
    trace.push(`4. session policy: allows (${allowsFrom('session').map(label).join(', ')})`);
  }

  // 5. identity policies and resource policy
  const identityAllows = allowsFrom('identity');
  const resourceAllows = allowsFrom('resource');
  trace.push(`5. identity policies: ${identityAllows.length > 0 ? `allow (${identityAllows.map(label).join(', ')})` : 'no matching Allow'}`);
  trace.push(
    `6. resource policy: ${
      request.resourcePolicy === undefined
        ? 'none'
        : resourceAllows.length > 0
          ? `allows this principal (${resourceAllows.map(label).join(', ')})`
          : 'no statement names this principal for this action'
    }`,
  );

  if (sameAccount) {
    if (identityAllows.length > 0) {
      return allow('identity-policy-allow', `allowed by ${identityAllows.map(label).join(', ')}`);
    }
    if (resourceAllows.length > 0) {
      return allow('resource-policy-allow', `allowed by ${resourceAllows.map(label).join(', ')}; same account, so the resource policy alone is enough`);
    }
    return deny('implicit-deny', `no policy allows ${request.action} on ${request.resource.arn} for ${request.principal.arn}`);
  }

  trace.push(`   cross-account request: principal in ${principalAccount}, resource in ${request.resource.account}; both sides must allow`);
  if (identityAllows.length > 0 && resourceAllows.length > 0) {
    return allow('cross-account-allow', `resource policy names the caller (${resourceAllows.map(label).join(', ')}) and the caller's identity policy allows (${identityAllows.map(label).join(', ')})`);
  }
  if (resourceAllows.length === 0) {
    return deny('cross-account-implicit-deny', `the resource policy in ${request.resource.account} does not grant ${request.action} to ${request.principal.arn}; a caller from another account needs an explicit grant on the resource side`);
  }
  return deny('cross-account-implicit-deny', `the resource policy grants access, but no identity policy in ${principalAccount} allows ${request.action}; the caller's own account must also say yes`);
}
