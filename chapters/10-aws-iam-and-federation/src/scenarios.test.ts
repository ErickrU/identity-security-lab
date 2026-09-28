/**
 * The demo's claims, as assertions. If a scenario in demo.ts stops saying what the README says it
 * says, this file fails.
 */
import { describe, expect, it } from 'vitest';
import { evaluate, type Request } from './iam-eval';
import {
  ABAC_DEPARTMENT_DATA,
  ADMINISTRATOR_ACCESS,
  ANALYTICS_ROLE_POLICY,
  APP_ROLE_DYNAMODB,
  APP_ROLE_TOO_BROAD,
  BOUNDARY_APP_SERVICES,
  DENY_IAM_WITHOUT_MFA_BOOL,
  DENY_IAM_WITHOUT_MFA_BOOL_IF_EXISTS,
  DENY_S3_DELETE,
  DEV_READ_DOCS,
  IAM_READ,
  PRINCIPALS,
  RESOURCES,
  SCP_EU_ONLY,
  SCP_FULL_AWS_ACCESS,
  SESSION_READ_ONE_PREFIX,
  SHARED_BUCKET_POLICY,
  SHARED_BUCKET_POLICY_WHOLE_ACCOUNT,
} from './scenarios';

const code = (r: Request): string => evaluate(r).code;

describe('1) identity policy', () => {
  it('allows what it names and nothing else', () => {
    expect(code({ principal: PRINCIPALS.alice, action: 's3:GetObject', resource: RESOURCES.handbook, identityPolicies: [DEV_READ_DOCS] })).toBe('identity-policy-allow');
    expect(code({ principal: PRINCIPALS.alice, action: 's3:ListBucket', resource: RESOURCES.docsBucket, identityPolicies: [DEV_READ_DOCS] })).toBe('identity-policy-allow');
    expect(code({ principal: PRINCIPALS.alice, action: 's3:DeleteObject', resource: RESOURCES.handbook, identityPolicies: [DEV_READ_DOCS] })).toBe('implicit-deny');
    expect(code({ principal: PRINCIPALS.alice, action: 's3:GetObject', resource: RESOURCES.sharedReport, identityPolicies: [DEV_READ_DOCS] })).toBe('implicit-deny');
  });
});

describe('2) explicit deny', () => {
  const policies = [ADMINISTRATOR_ACCESS, DENY_S3_DELETE];
  it('beats AdministratorAccess for the denied actions only', () => {
    expect(code({ principal: PRINCIPALS.adminSession, action: 's3:DeleteObject', resource: RESOURCES.handbook, identityPolicies: policies })).toBe('explicit-deny');
    expect(code({ principal: PRINCIPALS.adminSession, action: 's3:DeleteBucket', resource: RESOURCES.docsBucket, identityPolicies: policies })).toBe('explicit-deny');
    expect(code({ principal: PRINCIPALS.adminSession, action: 's3:GetObject', resource: RESOURCES.handbook, identityPolicies: policies })).toBe('identity-policy-allow');
    expect(code({ principal: PRINCIPALS.adminSession, action: 's3:DeleteObject', resource: RESOURCES.handbook, identityPolicies: [...policies].reverse() })).toBe('explicit-deny');
  });
});

describe('3) SCPs', () => {
  const scps = [
    { name: 'root', policies: [SCP_FULL_AWS_ACCESS] },
    { name: 'ou:workloads', policies: [SCP_FULL_AWS_ACCESS, SCP_EU_ONLY] },
  ];
  const admin = (action: string, resource: Request['resource'], region: string, levels = scps): Request => ({
    principal: PRINCIPALS.adminSession,
    action,
    resource,
    context: { 'aws:RequestedRegion': region },
    identityPolicies: [ADMINISTRATOR_ACCESS],
    scps: levels,
  });

  it('deny outside the allowed regions, even for administrators', () => {
    expect(code(admin('ec2:RunInstances', RESOURCES.instancesSingapore, 'ap-southeast-1'))).toBe('explicit-deny');
    expect(code(admin('ec2:RunInstances', RESOURCES.instancesIreland, 'eu-west-1'))).toBe('identity-policy-allow');
  });

  it('global services excluded through NotAction keep working', () => {
    expect(code(admin('iam:ListUsers', RESOURCES.anyIamUser, 'us-east-1'))).toBe('identity-policy-allow');
    expect(code(admin('sts:GetCallerIdentity', RESOURCES.anyIamUser, 'us-east-1'))).toBe('identity-policy-allow');
  });

  it('a level with only Deny statements allows nothing: FullAWSAccess must stay attached', () => {
    const broken = [{ name: 'root', policies: [SCP_FULL_AWS_ACCESS] }, { name: 'ou:workloads', policies: [SCP_EU_ONLY] }];
    expect(code(admin('ec2:RunInstances', RESOURCES.instancesIreland, 'eu-west-1', broken))).toBe('scp-implicit-deny');
  });

  it('do not apply when not passed (the management account)', () => {
    expect(code({ ...admin('ec2:RunInstances', RESOURCES.instancesSingapore, 'ap-southeast-1'), scps: undefined })).toBe('identity-policy-allow');
  });
});

describe('4) permissions boundary and session policy', () => {
  const appRole = (action: string, resource: Request['resource'], identity = APP_ROLE_TOO_BROAD): Request => ({
    principal: PRINCIPALS.appRole,
    action,
    resource,
    identityPolicies: [identity],
    permissionsBoundary: BOUNDARY_APP_SERVICES,
  });

  it('caps an over-broad identity policy to the boundary', () => {
    expect(code(appRole('s3:GetObject', RESOURCES.handbook))).toBe('identity-policy-allow');
    expect(code(appRole('dynamodb:PutItem', RESOURCES.engTable))).toBe('identity-policy-allow');
    expect(code(appRole('iam:CreateUser', RESOURCES.bob))).toBe('permissions-boundary-implicit-deny');
    expect(code(appRole('ec2:RunInstances', RESOURCES.instancesIreland))).toBe('permissions-boundary-implicit-deny');
  });

  it('grants nothing by itself', () => {
    expect(code(appRole('s3:GetObject', RESOURCES.handbook, APP_ROLE_DYNAMODB))).toBe('implicit-deny');
  });

  it('a session policy narrows one session further', () => {
    const session = { ...appRole('s3:GetObject', RESOURCES.handbook), sessionPolicy: SESSION_READ_ONE_PREFIX };
    expect(code(session)).toBe('session-policy-implicit-deny');
    const publicObject = { arn: 'arn:aws:s3:::lab-docs/public/faq.md', account: RESOURCES.handbook.account };
    expect(code({ ...session, resource: publicObject })).toBe('identity-policy-allow');
  });
});

describe('5) resource policies, same account and cross account', () => {
  const read = (principal: Request['principal'], extra: Partial<Request>): Request => ({
    principal,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [],
    ...extra,
  });

  it('cross account needs both sides', () => {
    expect(code(read(PRINCIPALS.analyticsRole, { identityPolicies: [ANALYTICS_ROLE_POLICY], resourcePolicy: SHARED_BUCKET_POLICY }))).toBe('cross-account-allow');
    expect(code(read(PRINCIPALS.analyticsRole, { resourcePolicy: SHARED_BUCKET_POLICY }))).toBe('cross-account-implicit-deny');
    expect(code(read(PRINCIPALS.analyticsRole, { identityPolicies: [ANALYTICS_ROLE_POLICY] }))).toBe('cross-account-implicit-deny');
  });

  it('same account needs one side', () => {
    expect(code(read(PRINCIPALS.auditor, { resourcePolicy: SHARED_BUCKET_POLICY }))).toBe('resource-policy-allow');
    expect(code(read(PRINCIPALS.alice, { resourcePolicy: SHARED_BUCKET_POLICY }))).toBe('implicit-deny');
  });

  it('trusting an account root delegates to that account', () => {
    expect(code(read(PRINCIPALS.analyticsRole, { identityPolicies: [ANALYTICS_ROLE_POLICY], resourcePolicy: SHARED_BUCKET_POLICY_WHOLE_ACCOUNT }))).toBe('cross-account-allow');
    expect(code(read(PRINCIPALS.analyticsRole, { resourcePolicy: SHARED_BUCKET_POLICY_WHOLE_ACCOUNT }))).toBe('cross-account-implicit-deny');
  });

  it('a role named in the bucket policy admits its sessions too', () => {
    const session = { arn: PRINCIPALS.analyticsRole.arn.replace(':iam::', ':sts::').replace(':role/', ':assumed-role/') + '/etl-job' };
    expect(code(read(session, { identityPolicies: [ANALYTICS_ROLE_POLICY], resourcePolicy: SHARED_BUCKET_POLICY }))).toBe('cross-account-allow');
  });
});

describe('6) ABAC', () => {
  const abac = (principal: Request['principal'], action: string, resource: Request['resource']): Request => ({
    principal,
    action,
    resource,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });

  it('${aws:PrincipalTag/dept} in the Resource selects the department prefix', () => {
    expect(code(abac(PRINCIPALS.financeAnalyst, 's3:GetObject', RESOURCES.financeObject))).toBe('identity-policy-allow');
    expect(code(abac(PRINCIPALS.financeAnalyst, 's3:GetObject', RESOURCES.engObject))).toBe('implicit-deny');
    expect(code(abac(PRINCIPALS.engAnalyst, 's3:GetObject', RESOURCES.engObject))).toBe('identity-policy-allow');
  });

  it('aws:ResourceTag/dept == aws:PrincipalTag/dept selects the department tables', () => {
    expect(code(abac(PRINCIPALS.engAnalyst, 'dynamodb:Query', RESOURCES.engTable))).toBe('identity-policy-allow');
    expect(code(abac(PRINCIPALS.engAnalyst, 'dynamodb:Query', RESOURCES.financeTable))).toBe('implicit-deny');
    expect(code(abac(PRINCIPALS.financeAnalyst, 'dynamodb:GetItem', RESOURCES.financeTable))).toBe('identity-policy-allow');
  });

  it('missing tags mean deny: untagged principal, untagged resource', () => {
    expect(code(abac(PRINCIPALS.untaggedAnalyst, 's3:GetObject', RESOURCES.financeObject))).toBe('implicit-deny');
    expect(code(abac(PRINCIPALS.untaggedAnalyst, 'dynamodb:Query', RESOURCES.engTable))).toBe('implicit-deny');
    expect(code(abac(PRINCIPALS.engAnalyst, 'dynamodb:Query', RESOURCES.untaggedTable))).toBe('implicit-deny');
  });
});

describe('gotcha) MFA with Bool vs BoolIfExists', () => {
  const list = (principal: Request['principal'], policies: Request['identityPolicies'], context?: Request['context']): Request => ({
    principal,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    identityPolicies: policies,
    ...(context ? { context } : {}),
  });

  it('Bool: denies a session without MFA but lets long-term keys through', () => {
    const policies = [IAM_READ, DENY_IAM_WITHOUT_MFA_BOOL];
    expect(code(list(PRINCIPALS.opsSession, policies, { 'aws:MultiFactorAuthPresent': false }))).toBe('explicit-deny');
    expect(code(list(PRINCIPALS.opsSession, policies, { 'aws:MultiFactorAuthPresent': true }))).toBe('identity-policy-allow');
    expect(code(list(PRINCIPALS.opsUser, policies))).toBe('identity-policy-allow');
  });

  it('BoolIfExists: denies both', () => {
    const policies = [IAM_READ, DENY_IAM_WITHOUT_MFA_BOOL_IF_EXISTS];
    expect(code(list(PRINCIPALS.opsSession, policies, { 'aws:MultiFactorAuthPresent': false }))).toBe('explicit-deny');
    expect(code(list(PRINCIPALS.opsUser, policies))).toBe('explicit-deny');
    expect(code(list(PRINCIPALS.opsSession, policies, { 'aws:MultiFactorAuthPresent': true }))).toBe('identity-policy-allow');
  });
});
