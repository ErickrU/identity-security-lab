import { describe, expect, it } from 'vitest';
import {
  accountOf,
  actionMatches,
  arnLike,
  buildContext,
  conditionHolds,
  evaluate,
  globToRegExp,
  literalOf,
  principalMatches,
  resourceMatches,
  roleArnOfSession,
  statementApplies,
  substituteVariables,
  type PolicyDocument,
  type Request,
} from './iam-eval';

const WORKLOAD = '111111111111';
const OTHER = '222222222222';
const alice = { arn: `arn:aws:iam::${WORKLOAD}:user/alice` };
const otherRole = { arn: `arn:aws:iam::${OTHER}:role/analytics` };
const object = { arn: 'arn:aws:s3:::lab-docs/handbook.pdf', account: WORKLOAD };

const ALLOW_READ: PolicyDocument = {
  Statement: [{ Sid: 'Read', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/*' }],
};
const ALLOW_ALL: PolicyDocument = { Statement: [{ Sid: 'All', Effect: 'Allow', Action: '*', Resource: '*' }] };
const DENY_READ: PolicyDocument = {
  Statement: [{ Sid: 'NoRead', Effect: 'Deny', Action: 's3:GetObject', Resource: '*' }],
};
const NOTHING: PolicyDocument = { Statement: [{ Sid: 'Unrelated', Effect: 'Allow', Action: 'sqs:SendMessage', Resource: '*' }] };

function request(overrides: Partial<Request> = {}): Request {
  return { principal: alice, action: 's3:GetObject', resource: object, identityPolicies: [ALLOW_READ], ...overrides };
}

const ctx = (extra: Record<string, string | boolean | number> = {}, tags: Record<string, string> = {}) =>
  buildContext({ principal: { arn: alice.arn, tags }, action: 'x:Y', resource: object, context: extra });

// ---------------------------------------------------------------- ARNs

describe('ARN helpers', () => {
  it('reads the account out of IAM and STS principal ARNs', () => {
    expect(accountOf(`arn:aws:iam::${WORKLOAD}:user/alice`)).toBe(WORKLOAD);
    expect(accountOf(`arn:aws:sts::${WORKLOAD}:assumed-role/Dev/alice`)).toBe(WORKLOAD);
    expect(accountOf(`arn:aws:iam::${WORKLOAD}:root`)).toBe(WORKLOAD);
    expect(() => accountOf('arn:aws:s3:::bucket')).toThrow(/account id/);
  });

  it('maps an assumed-role session back to its role, and nothing else', () => {
    expect(roleArnOfSession(`arn:aws:sts::${WORKLOAD}:assumed-role/Dev/alice`)).toBe(`arn:aws:iam::${WORKLOAD}:role/Dev`);
    expect(roleArnOfSession(`arn:aws:iam::${WORKLOAD}:role/Dev`)).toBeUndefined();
    expect(roleArnOfSession(`arn:aws:sts::${WORKLOAD}:federated-user/bob`)).toBeUndefined();
  });
});

// ---------------------------------------------------------------- wildcards and variables

describe('wildcards', () => {
  it('* matches any run, ? matches one character, everything else is literal', () => {
    expect(globToRegExp('s3:Get*').test('s3:GetObject')).toBe(true);
    expect(globToRegExp('s3:Get?bject').test('s3:GetObject')).toBe(true);
    expect(globToRegExp('s3:Get?').test('s3:GetObject')).toBe(false);
    expect(globToRegExp('a.b').test('axb')).toBe(false); // '.' is not a regex dot
    expect(globToRegExp('a(b)').test('a(b)')).toBe(true);
  });

  it('honours the ${*} ${?} ${$} escapes as literals', () => {
    expect(globToRegExp('bucket/${*}').test('bucket/*')).toBe(true);
    expect(globToRegExp('bucket/${*}').test('bucket/anything')).toBe(false);
    expect(globToRegExp('price${$}').test('price$')).toBe(true);
    expect(literalOf('a${*}b${?}c${$}')).toBe('a*b?c$');
  });

  it('action names are case-insensitive, resource ARNs are not', () => {
    expect(actionMatches('s3:getobject', 's3:GetObject')).toBe(true);
    expect(actionMatches('S3:Get*', 's3:GetObjectTagging')).toBe(true);
    expect(actionMatches('s3:Get*', 'sqs:GetQueueUrl')).toBe(false);
    expect(resourceMatches('arn:aws:s3:::Lab-Docs/*', 'arn:aws:s3:::lab-docs/x')).toBe(false);
  });

  it('Resource wildcards run across segments; ArnLike matches segment by segment', () => {
    expect(resourceMatches('arn:aws:s3:::lab-docs/*', 'arn:aws:s3:::lab-docs/2024/q3/report.csv')).toBe(true);
    expect(resourceMatches('*', 'anything at all')).toBe(true);
    expect(resourceMatches('arn:aws:s3:::lab-docs', 'arn:aws:s3:::lab-docs/x')).toBe(false);

    expect(arnLike('arn:aws:iam::*:role/Dev', `arn:aws:iam::${WORKLOAD}:role/Dev`)).toBe(true);
    expect(arnLike('arn:aws:iam::*:role/*', `arn:aws:iam::${WORKLOAD}:role/path/Dev`)).toBe(true);
    // a * in the account segment cannot swallow the resource segment
    expect(arnLike('arn:aws:iam::*', `arn:aws:iam::${WORKLOAD}:role/Dev`)).toBe(false);
    expect(arnLike('arn:aws:s3:::lab-docs/*', 'arn:aws:s3:::lab-docs/a/b')).toBe(true);
    expect(arnLike('not-an-arn', 'not-an-arn')).toBe(false);
  });
});

describe('policy variables', () => {
  it('substitutes from the request context, case-insensitively on the key', () => {
    expect(substituteVariables('arn:aws:s3:::lab/${aws:PrincipalTag/dept}/*', ctx({}, { dept: 'finance' }))).toBe('arn:aws:s3:::lab/finance/*');
    expect(substituteVariables('${AWS:PRINCIPALTAG/DEPT}', ctx({}, { dept: 'finance' }))).toBe('finance');
    expect(substituteVariables('${aws:PrincipalAccount}', ctx())).toBe(WORKLOAD);
  });

  it('does not let extra request context overwrite principal/resource keys derived by the simulator', () => {
    const built = buildContext({
      principal: { arn: alice.arn, tags: { dept: 'finance' } },
      action: 'x:Y',
      resource: { ...object, tags: { class: 'internal' } },
      context: {
        'aws:PrincipalArn': `arn:aws:iam::${OTHER}:user/mallory`,
        'aws:PrincipalAccount': OTHER,
        'aws:ResourceAccount': OTHER,
        'aws:PrincipalTag/dept': '*',
        'aws:ResourceTag/class': 'public',
      },
    });
    expect(built.get('aws:principalarn')).toBe(alice.arn);
    expect(built.get('aws:principalaccount')).toBe(WORKLOAD);
    expect(built.get('aws:resourceaccount')).toBe(WORKLOAD);
    expect(built.get('aws:principaltag/dept')).toBe('finance');
    expect(built.get('aws:resourcetag/class')).toBe('internal');
  });

  it('returns undefined when the variable is not in the context, so the statement does not match', () => {
    expect(substituteVariables('arn:aws:s3:::lab/${aws:PrincipalTag/dept}/*', ctx())).toBeUndefined();
    const untagged = { ...request({ principal: { arn: alice.arn } }), identityPolicies: [] };
    const abac: PolicyDocument = {
      Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/${aws:PrincipalTag/dept}/*' }],
    };
    expect(evaluate({ ...untagged, identityPolicies: [abac] }).code).toBe('implicit-deny');
  });

  it('escapes wildcard characters inside substituted values, so a tag value of * is not a wildcard', () => {
    const escaped = substituteVariables('prefix/${aws:PrincipalTag/team}/*', ctx({}, { team: '*' }));
    expect(escaped).toBe('prefix/${*}/*');
    expect(globToRegExp(escaped!).test('prefix/*/file')).toBe(true);
    expect(globToRegExp(escaped!).test('prefix/finance/file')).toBe(false);
  });
});

// ---------------------------------------------------------------- request context

describe('request context', () => {
  it('derives principal and resource facts, tags, and merges the caller-supplied context (keys lower-cased, values as strings)', () => {
    const c = buildContext({
      principal: { arn: alice.arn, tags: { Dept: 'finance' } },
      action: 's3:GetObject',
      resource: { ...object, tags: { dept: 'eng' } },
      context: { 'aws:MultiFactorAuthPresent': true, 'aws:RequestedRegion': 'eu-west-1' },
    });
    expect(c.get('aws:principalarn')).toBe(alice.arn);
    expect(c.get('aws:principalaccount')).toBe(WORKLOAD);
    expect(c.get('aws:resourceaccount')).toBe(WORKLOAD);
    expect(c.get('aws:principaltag/dept')).toBe('finance');
    expect(c.get('aws:resourcetag/dept')).toBe('eng');
    expect(c.get('aws:multifactorauthpresent')).toBe('true');
    expect(c.get('aws:requestedregion')).toBe('eu-west-1');
  });
});

// ---------------------------------------------------------------- conditions

describe('conditions', () => {
  it('an absent Condition element always holds', () => {
    expect(conditionHolds(undefined, ctx())).toBe(true);
  });

  it('StringEquals is case-sensitive and a list of values is an OR', () => {
    expect(conditionHolds({ StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } }, ctx({ 'aws:RequestedRegion': 'eu-west-1' }))).toBe(true);
    expect(conditionHolds({ StringEquals: { 'aws:RequestedRegion': 'EU-WEST-1' } }, ctx({ 'aws:RequestedRegion': 'eu-west-1' }))).toBe(false);
    expect(conditionHolds({ StringEquals: { 'aws:RequestedRegion': ['us-east-1', 'eu-west-1'] } }, ctx({ 'aws:RequestedRegion': 'eu-west-1' }))).toBe(true);
    expect(conditionHolds({ StringEqualsIgnoreCase: { 'aws:RequestedRegion': 'EU-WEST-1' } }, ctx({ 'aws:RequestedRegion': 'eu-west-1' }))).toBe(true);
  });

  it('keys inside one operator and several operators are ANDed', () => {
    const block = {
      StringEquals: { 'aws:RequestedRegion': 'eu-west-1', 'aws:PrincipalTag/dept': 'finance' },
      Bool: { 'aws:SecureTransport': 'true' },
    };
    expect(conditionHolds(block, ctx({ 'aws:RequestedRegion': 'eu-west-1', 'aws:SecureTransport': true }, { dept: 'finance' }))).toBe(true);
    expect(conditionHolds(block, ctx({ 'aws:RequestedRegion': 'eu-west-1', 'aws:SecureTransport': false }, { dept: 'finance' }))).toBe(false);
    expect(conditionHolds(block, ctx({ 'aws:RequestedRegion': 'eu-west-1', 'aws:SecureTransport': true }, { dept: 'eng' }))).toBe(false);
  });

  it('StringLike uses wildcards; ArnLike matches per segment', () => {
    const sub = 'repo:ErickrU/identity-security-lab:ref:refs/heads/main';
    expect(conditionHolds({ StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:ErickrU/identity-security-lab:*' } }, ctx({ 'token.actions.githubusercontent.com:sub': sub }))).toBe(true);
    expect(conditionHolds({ StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:ErickrU/other-repo:*' } }, ctx({ 'token.actions.githubusercontent.com:sub': sub }))).toBe(false);
    expect(conditionHolds({ ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${WORKLOAD}:user/*` } }, ctx())).toBe(true);
    expect(conditionHolds({ ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${OTHER}:user/*` } }, ctx())).toBe(false);
  });

  it('Bool compares true/false whether the context value is a boolean or a string', () => {
    expect(conditionHolds({ Bool: { 'aws:MultiFactorAuthPresent': 'true' } }, ctx({ 'aws:MultiFactorAuthPresent': true }))).toBe(true);
    expect(conditionHolds({ Bool: { 'aws:MultiFactorAuthPresent': 'true' } }, ctx({ 'aws:MultiFactorAuthPresent': 'true' }))).toBe(true);
    expect(conditionHolds({ Bool: { 'aws:MultiFactorAuthPresent': true } }, ctx({ 'aws:MultiFactorAuthPresent': 'false' }))).toBe(false);
  });

  it('a missing key makes a positive operator false, a negated operator true, and any ...IfExists operator true', () => {
    const none = ctx();
    expect(conditionHolds({ Bool: { 'aws:MultiFactorAuthPresent': 'false' } }, none)).toBe(false);
    expect(conditionHolds({ BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } }, none)).toBe(true);
    expect(conditionHolds({ StringEquals: { 'aws:RequestedRegion': 'eu-west-1' } }, none)).toBe(false);
    expect(conditionHolds({ StringEqualsIfExists: { 'aws:RequestedRegion': 'eu-west-1' } }, none)).toBe(true);
    // this is why "Deny + StringNotEquals aws:PrincipalOrgID" also stops anonymous callers
    expect(conditionHolds({ StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc' } }, none)).toBe(true);
    expect(conditionHolds({ ArnNotLike: { 'aws:SourceArn': 'arn:aws:s3:::*' } }, none)).toBe(true);
  });

  it('...IfExists still evaluates the operator when the key is present', () => {
    expect(conditionHolds({ BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } }, ctx({ 'aws:MultiFactorAuthPresent': false }))).toBe(true);
    expect(conditionHolds({ BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } }, ctx({ 'aws:MultiFactorAuthPresent': true }))).toBe(false);
  });

  it('Null tests presence, not value', () => {
    expect(conditionHolds({ Null: { 'aws:TokenIssueTime': 'true' } }, ctx())).toBe(true);
    expect(conditionHolds({ Null: { 'aws:TokenIssueTime': 'true' } }, ctx({ 'aws:TokenIssueTime': '2024-01-01T00:00:00Z' }))).toBe(false);
    expect(conditionHolds({ Null: { 'aws:TokenIssueTime': 'false' } }, ctx({ 'aws:TokenIssueTime': '2024-01-01T00:00:00Z' }))).toBe(true);
  });

  it('Numeric operators, for aws:MultiFactorAuthAge style rules', () => {
    expect(conditionHolds({ NumericLessThan: { 'aws:MultiFactorAuthAge': '900' } }, ctx({ 'aws:MultiFactorAuthAge': 300 }))).toBe(true);
    expect(conditionHolds({ NumericLessThan: { 'aws:MultiFactorAuthAge': '900' } }, ctx({ 'aws:MultiFactorAuthAge': 3600 }))).toBe(false);
    expect(conditionHolds({ NumericGreaterThanEquals: { 'aws:MultiFactorAuthAge': '900' } }, ctx({ 'aws:MultiFactorAuthAge': 900 }))).toBe(true);
    expect(conditionHolds({ NumericEquals: { 'aws:MultiFactorAuthAge': 5 } }, ctx({ 'aws:MultiFactorAuthAge': '5' }))).toBe(true);
    expect(conditionHolds({ NumericNotEquals: { 'aws:MultiFactorAuthAge': 5 } }, ctx({ 'aws:MultiFactorAuthAge': '5' }))).toBe(false);
  });

  it('accepts policy variables inside condition values (the ABAC pattern)', () => {
    const block = { StringEquals: { 'aws:ResourceTag/dept': '${aws:PrincipalTag/dept}' } };
    const same = buildContext({ principal: { arn: alice.arn, tags: { dept: 'eng' } }, action: 'x:Y', resource: { ...object, tags: { dept: 'eng' } } });
    const different = buildContext({ principal: { arn: alice.arn, tags: { dept: 'eng' } }, action: 'x:Y', resource: { ...object, tags: { dept: 'finance' } } });
    const untagged = buildContext({ principal: { arn: alice.arn }, action: 'x:Y', resource: { ...object, tags: { dept: 'eng' } } });
    expect(conditionHolds(block, same)).toBe(true);
    expect(conditionHolds(block, different)).toBe(false);
    expect(conditionHolds(block, untagged)).toBe(false);
  });

  it('refuses operators it does not model instead of treating them as true', () => {
    expect(() => conditionHolds({ IpAddress: { 'aws:SourceIp': '10.0.0.0/8' } }, ctx({ 'aws:SourceIp': '10.1.2.3' }))).toThrow(/unsupported condition operator IpAddress/);
  });
});

// ---------------------------------------------------------------- statements

describe('statement matching', () => {
  const c = ctx();
  const req = request();

  it('Action / NotAction', () => {
    expect(statementApplies({ Effect: 'Allow', Action: ['sqs:*', 's3:Get*'], Resource: '*' }, req, c, 'identity')).toBe(true);
    expect(statementApplies({ Effect: 'Allow', Action: 's3:Put*', Resource: '*' }, req, c, 'identity')).toBe(false);
    expect(statementApplies({ Effect: 'Deny', NotAction: ['iam:*', 'sts:*'], Resource: '*' }, req, c, 'identity')).toBe(true);
    expect(statementApplies({ Effect: 'Deny', NotAction: 's3:*', Resource: '*' }, req, c, 'identity')).toBe(false);
    expect(statementApplies({ Effect: 'Allow', Resource: '*' }, req, c, 'identity')).toBe(false);
  });

  it('Resource / NotResource', () => {
    expect(statementApplies({ Effect: 'Allow', Action: '*', Resource: ['arn:aws:s3:::other/*', 'arn:aws:s3:::lab-docs/*'] }, req, c, 'identity')).toBe(true);
    expect(statementApplies({ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::other/*' }, req, c, 'identity')).toBe(false);
    expect(statementApplies({ Effect: 'Deny', Action: '*', NotResource: 'arn:aws:s3:::other/*' }, req, c, 'identity')).toBe(true);
    expect(statementApplies({ Effect: 'Deny', Action: '*', NotResource: 'arn:aws:s3:::lab-docs/*' }, req, c, 'identity')).toBe(false);
    expect(statementApplies({ Effect: 'Allow', Action: '*' }, req, c, 'identity')).toBe(false);
  });

  it('Principal is checked for resource policies only', () => {
    const named = { Effect: 'Allow' as const, Principal: { AWS: alice.arn }, Action: 's3:GetObject', Resource: '*' };
    const nobody = { Effect: 'Allow' as const, Action: 's3:GetObject', Resource: '*' };
    expect(statementApplies(named, req, c, 'resource')).toBe(true);
    expect(statementApplies(nobody, req, c, 'resource')).toBe(false);
    expect(statementApplies(nobody, req, c, 'identity')).toBe(true);
  });

  it('Principal: exact ARN, the role behind a session, the account root or bare id, or *', () => {
    const session = { arn: `arn:aws:sts::${WORKLOAD}:assumed-role/Dev/alice` };
    expect(principalMatches({ AWS: alice.arn }, alice)).toBe(true);
    expect(principalMatches({ AWS: [`arn:aws:iam::${OTHER}:root`, alice.arn] }, alice)).toBe(true);
    expect(principalMatches({ AWS: `arn:aws:iam::${WORKLOAD}:role/Dev` }, session)).toBe(true);
    expect(principalMatches({ AWS: `arn:aws:iam::${WORKLOAD}:root` }, session)).toBe(true);
    expect(principalMatches({ AWS: WORKLOAD }, alice)).toBe(true);
    expect(principalMatches('*', otherRole)).toBe(true);
    expect(principalMatches({ AWS: '*' }, otherRole)).toBe(true);
    expect(principalMatches({ AWS: `arn:aws:iam::${OTHER}:root` }, alice)).toBe(false);
    expect(principalMatches({ AWS: `arn:aws:iam::${WORKLOAD}:role/Other` }, session)).toBe(false);
    expect(principalMatches(undefined, alice)).toBe(false);
  });
});

// ---------------------------------------------------------------- the algorithm

describe('evaluation: the order of the rules', () => {
  it('implicit deny is the default: no policies, no access', () => {
    const d = evaluate(request({ identityPolicies: [] }));
    expect(d.decision).toBe('Deny');
    expect(d.code).toBe('implicit-deny');
    expect(d.matchedStatements).toEqual([]);
  });

  it('an identity-based Allow that matches is enough within the account', () => {
    const d = evaluate(request());
    expect(d.decision).toBe('Allow');
    expect(d.code).toBe('identity-policy-allow');
    expect(d.matchedStatements).toEqual([{ policyType: 'identity', policyIndex: 0, statementIndex: 0, sid: 'Read', effect: 'Allow' }]);
  });

  it('a non-matching Allow (other action, other resource, false condition) grants nothing', () => {
    expect(evaluate(request({ action: 's3:PutObject' })).code).toBe('implicit-deny');
    expect(evaluate(request({ resource: { arn: 'arn:aws:s3:::other/x', account: WORKLOAD } })).code).toBe('implicit-deny');
    const conditional: PolicyDocument = {
      Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'true' } } }],
    };
    expect(evaluate(request({ identityPolicies: [conditional], context: { 'aws:SecureTransport': false } })).code).toBe('implicit-deny');
    expect(evaluate(request({ identityPolicies: [conditional], context: { 'aws:SecureTransport': true } })).code).toBe('identity-policy-allow');
  });

  it.each([
    ['identity', (r: Request): Request => ({ ...r, identityPolicies: [ALLOW_ALL, DENY_READ] })],
    ['identity, other order', (r: Request): Request => ({ ...r, identityPolicies: [DENY_READ, ALLOW_ALL] })],
    ['resource', (r: Request): Request => ({ ...r, resourcePolicy: { Statement: [{ Sid: 'NoRead', Effect: 'Deny', Principal: '*', Action: 's3:GetObject', Resource: '*' }] } })],
    ['permissions boundary', (r: Request): Request => ({ ...r, permissionsBoundary: { Statement: [...ALLOW_ALL.Statement, ...DENY_READ.Statement] } })],
    ['SCP', (r: Request): Request => ({ ...r, scps: [{ name: 'root', policies: [ALLOW_ALL, DENY_READ] }] })],
    ['session policy', (r: Request): Request => ({ ...r, sessionPolicy: { Statement: [...ALLOW_ALL.Statement, ...DENY_READ.Statement] } })],
  ])('an explicit Deny in a %s policy wins over every Allow', (_where, apply) => {
    const d = evaluate(apply(request({ identityPolicies: [ALLOW_ALL] })));
    expect(d.decision).toBe('Deny');
    expect(d.code).toBe('explicit-deny');
    expect(d.reason).toMatch(/NoRead/);
    expect(d.trace[0]).toMatch(/^1\. deny evaluation: explicit Deny/);
  });

  it('a Deny whose condition is false does not apply', () => {
    const mfaDeny: PolicyDocument = {
      Statement: [{ Effect: 'Deny', Action: '*', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } }],
    };
    expect(evaluate(request({ identityPolicies: [ALLOW_READ, mfaDeny], context: { 'aws:MultiFactorAuthPresent': true } })).decision).toBe('Allow');
    expect(evaluate(request({ identityPolicies: [ALLOW_READ, mfaDeny], context: { 'aws:MultiFactorAuthPresent': false } })).code).toBe('explicit-deny');
  });

  describe('SCPs', () => {
    it('are not consulted when the account has none (or is the management account)', () => {
      expect(evaluate(request()).trace).toContainEqual(expect.stringMatching(/^2\. SCPs: none/));
    });

    it('must allow at every level; within a level any policy may allow', () => {
      const ok = evaluate(request({ scps: [{ name: 'root', policies: [ALLOW_ALL] }, { name: 'ou', policies: [NOTHING, ALLOW_ALL] }] }));
      expect(ok.code).toBe('identity-policy-allow');
      const missingLevel = evaluate(request({ scps: [{ name: 'root', policies: [ALLOW_ALL] }, { name: 'ou', policies: [NOTHING] }] }));
      expect(missingLevel.code).toBe('scp-implicit-deny');
      expect(missingLevel.reason).toMatch(/level ou/);
    });

    it('never grant: an SCP Allow without an identity Allow is still an implicit deny', () => {
      const d = evaluate(request({ identityPolicies: [], scps: [{ name: 'root', policies: [ALLOW_ALL] }] }));
      expect(d.code).toBe('implicit-deny');
    });
  });

  describe('permissions boundary', () => {
    it('must allow when present', () => {
      expect(evaluate(request({ permissionsBoundary: ALLOW_ALL })).decision).toBe('Allow');
      const d = evaluate(request({ permissionsBoundary: NOTHING }));
      expect(d.code).toBe('permissions-boundary-implicit-deny');
    });

    it('is a cap, not a grant', () => {
      expect(evaluate(request({ identityPolicies: [NOTHING], permissionsBoundary: ALLOW_ALL })).code).toBe('implicit-deny');
    });
  });

  describe('session policy', () => {
    it('must allow when present, and grants nothing on its own', () => {
      expect(evaluate(request({ sessionPolicy: ALLOW_READ })).decision).toBe('Allow');
      expect(evaluate(request({ sessionPolicy: NOTHING })).code).toBe('session-policy-implicit-deny');
      expect(evaluate(request({ identityPolicies: [], sessionPolicy: ALLOW_ALL })).code).toBe('implicit-deny');
    });
  });

  describe('resource-based policies', () => {
    const bucketPolicy: PolicyDocument = {
      Statement: [
        { Sid: 'Alice', Effect: 'Allow', Principal: { AWS: alice.arn }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/*' },
        { Sid: 'Analytics', Effect: 'Allow', Principal: { AWS: otherRole.arn }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/*' },
      ],
    };

    it('same account: a resource-policy Allow is enough on its own', () => {
      const d = evaluate(request({ identityPolicies: [], resourcePolicy: bucketPolicy }));
      expect(d.decision).toBe('Allow');
      expect(d.code).toBe('resource-policy-allow');
    });

    it('same account: identity Allow and resource Allow both matching is reported as identity-policy-allow', () => {
      const d = evaluate(request({ resourcePolicy: bucketPolicy }));
      expect(d.code).toBe('identity-policy-allow');
      expect(d.matchedStatements.map((m) => m.sid)).toEqual(['Read', 'Alice']);
    });

    it('cross account: both the resource policy and the identity policy must allow', () => {
      const cross = request({ principal: otherRole, identityPolicies: [ALLOW_READ], resourcePolicy: bucketPolicy });
      expect(evaluate(cross).code).toBe('cross-account-allow');
      expect(evaluate({ ...cross, identityPolicies: [] }).code).toBe('cross-account-implicit-deny');
      expect(evaluate({ ...cross, identityPolicies: [] }).reason).toMatch(/own account must also say yes/);
      expect(evaluate({ ...cross, resourcePolicy: undefined }).code).toBe('cross-account-implicit-deny');
      expect(evaluate({ ...cross, resourcePolicy: undefined }).reason).toMatch(/explicit grant on the resource side/);
    });

    it('cross account: a policy naming the other account root admits any principal that account allows', () => {
      const trustAccount: PolicyDocument = {
        Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${OTHER}:root` }, Action: 's3:GetObject', Resource: '*' }],
      };
      expect(evaluate(request({ principal: otherRole, identityPolicies: [ALLOW_READ], resourcePolicy: trustAccount })).code).toBe('cross-account-allow');
      expect(evaluate(request({ principal: otherRole, identityPolicies: [], resourcePolicy: trustAccount })).code).toBe('cross-account-implicit-deny');
    });

    it('Principal "*" admits anyone, which is what makes a bucket public', () => {
      const publicRead: PolicyDocument = { Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/*' }] };
      expect(evaluate(request({ principal: otherRole, identityPolicies: [ALLOW_READ], resourcePolicy: publicRead })).decision).toBe('Allow');
    });

    it('a resource-policy statement with no Principal applies to nobody', () => {
      const broken: PolicyDocument = { Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] };
      expect(evaluate(request({ identityPolicies: [], resourcePolicy: broken })).code).toBe('implicit-deny');
    });
  });

  it('records every matched statement, Allow and Deny, from every policy type, with the SCP level', () => {
    const d = evaluate(
      request({
        identityPolicies: [ALLOW_ALL],
        permissionsBoundary: ALLOW_ALL,
        sessionPolicy: ALLOW_ALL,
        scps: [{ name: 'root', policies: [ALLOW_ALL] }, { name: 'ou:prod', policies: [NOTHING, DENY_READ] }],
      }),
    );
    expect(d.code).toBe('explicit-deny');
    expect(d.matchedStatements).toEqual([
      { policyType: 'identity', policyIndex: 0, statementIndex: 0, sid: 'All', effect: 'Allow' },
      { policyType: 'permissions-boundary', policyIndex: 0, statementIndex: 0, sid: 'All', effect: 'Allow' },
      { policyType: 'scp', policyIndex: 0, scpLevel: 'root', statementIndex: 0, sid: 'All', effect: 'Allow' },
      { policyType: 'scp', policyIndex: 1, scpLevel: 'ou:prod', statementIndex: 0, sid: 'NoRead', effect: 'Deny' },
      { policyType: 'session', policyIndex: 0, statementIndex: 0, sid: 'All', effect: 'Allow' },
    ]);
    expect(d.reason).toMatch(/scp:ou:prod\[1\]\.NoRead/);
  });

  it('names statements without a Sid by their index', () => {
    const anonymous: PolicyDocument = { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] };
    expect(evaluate(request({ identityPolicies: [anonymous] })).matchedStatements[0].sid).toBe('statement[0]');
  });

  it('the trace lists the steps in the order IAM performs them and ends with the decision', () => {
    const d = evaluate(request({ scps: [{ name: 'root', policies: [ALLOW_ALL] }], permissionsBoundary: ALLOW_ALL }));
    expect(d.trace.map((line) => line.slice(0, 2))).toEqual(['1.', '2.', '3.', '4.', '5.', '6.', '→ ']);
    expect(d.trace.at(-1)).toBe('→ ALLOW (identity-policy-allow): allowed by identity[0].Read');
  });
});
