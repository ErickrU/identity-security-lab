/**
 * Chapter 10 fixtures: two accounts, a handful of principals, and the policies the demo and the
 * tests share. Everything is data; `iam-eval.ts` does the thinking.
 *
 * Account 111111111111 ("workload") owns the buckets and tables. Account 222222222222
 * ("analytics") is the other side of the cross-account scenario.
 */
import type { PolicyDocument, Principal, Resource } from './iam-eval';

export const ACCOUNTS = {
  workload: '111111111111',
  analytics: '222222222222',
} as const;

// ---------------------------------------------------------------- principals

export const PRINCIPALS = {
  /** A developer with a user (chapter text: prefer roles; users exist, so the simulator has one). */
  alice: { arn: `arn:aws:iam::${ACCOUNTS.workload}:user/alice` },
  /** Someone who signed in through IAM Identity Center with the AdministratorAccess permission set. */
  adminSession: { arn: `arn:aws:sts::${ACCOUNTS.workload}:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/alice` },
  /** A role a developer created for an application, under a mandatory permissions boundary. */
  appRole: { arn: `arn:aws:iam::${ACCOUNTS.workload}:role/app-orders` },
  /** A same-account auditor with no identity policies at all. */
  auditor: { arn: `arn:aws:iam::${ACCOUNTS.workload}:user/auditor` },
  /** A role in the other account. */
  analyticsRole: { arn: `arn:aws:iam::${ACCOUNTS.analytics}:role/analytics` },
  /** ABAC: principals whose only difference is a tag. */
  financeAnalyst: { arn: `arn:aws:iam::${ACCOUNTS.workload}:role/analyst-finance`, tags: { dept: 'finance' } },
  engAnalyst: { arn: `arn:aws:iam::${ACCOUNTS.workload}:role/analyst-eng`, tags: { dept: 'eng' } },
  untaggedAnalyst: { arn: `arn:aws:iam::${ACCOUNTS.workload}:role/analyst-new` },
  /** MFA: the same operator, once as a role session and once with long-term access keys. */
  opsSession: { arn: `arn:aws:sts::${ACCOUNTS.workload}:assumed-role/ops/carol` },
  opsUser: { arn: `arn:aws:iam::${ACCOUNTS.workload}:user/carol` },
} as const satisfies Record<string, Principal>;

// ---------------------------------------------------------------- resources

export const RESOURCES = {
  handbook: { arn: 'arn:aws:s3:::lab-docs/handbook.pdf', account: ACCOUNTS.workload },
  docsBucket: { arn: 'arn:aws:s3:::lab-docs', account: ACCOUNTS.workload },
  sharedReport: { arn: 'arn:aws:s3:::lab-shared/2024/q3/report.csv', account: ACCOUNTS.workload },
  financeObject: { arn: 'arn:aws:s3:::lab-abac/finance/q3.csv', account: ACCOUNTS.workload },
  engObject: { arn: 'arn:aws:s3:::lab-abac/eng/design.md', account: ACCOUNTS.workload },
  financeTable: { arn: `arn:aws:dynamodb:eu-west-1:${ACCOUNTS.workload}:table/finance-ledger`, account: ACCOUNTS.workload, tags: { dept: 'finance' } },
  engTable: { arn: `arn:aws:dynamodb:eu-west-1:${ACCOUNTS.workload}:table/eng-builds`, account: ACCOUNTS.workload, tags: { dept: 'eng' } },
  untaggedTable: { arn: `arn:aws:dynamodb:eu-west-1:${ACCOUNTS.workload}:table/legacy`, account: ACCOUNTS.workload },
  instancesSingapore: { arn: `arn:aws:ec2:ap-southeast-1:${ACCOUNTS.workload}:instance/*`, account: ACCOUNTS.workload },
  instancesIreland: { arn: `arn:aws:ec2:eu-west-1:${ACCOUNTS.workload}:instance/*`, account: ACCOUNTS.workload },
  anyIamUser: { arn: `arn:aws:iam::${ACCOUNTS.workload}:user/*`, account: ACCOUNTS.workload },
  bob: { arn: `arn:aws:iam::${ACCOUNTS.workload}:user/bob`, account: ACCOUNTS.workload },
} as const satisfies Record<string, Resource>;

// ---------------------------------------------------------------- identity policies

/** What a developer typically gets: read the docs bucket, nothing else. */
export const DEV_READ_DOCS: PolicyDocument = {
  Version: '2012-10-17',
  Statement: [
    { Sid: 'ListDocsBucket', Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::lab-docs' },
    { Sid: 'ReadDocs', Effect: 'Allow', Action: ['s3:Get*'], Resource: 'arn:aws:s3:::lab-docs/*' },
  ],
};

/** A guardrail policy a security team attaches to every group: nobody deletes through the API. */
export const DENY_S3_DELETE: PolicyDocument = {
  Statement: [{ Sid: 'NoDeletes', Effect: 'Deny', Action: ['s3:DeleteObject', 's3:DeleteBucket'], Resource: '*' }],
};

/** AdministratorAccess, verbatim. */
export const ADMINISTRATOR_ACCESS: PolicyDocument = {
  Statement: [{ Sid: 'Admin', Effect: 'Allow', Action: '*', Resource: '*' }],
};

/** A developer gave their application role everything. The boundary below is what stops it. */
export const APP_ROLE_TOO_BROAD: PolicyDocument = {
  Statement: [{ Sid: 'EverythingPlease', Effect: 'Allow', Action: '*', Resource: '*' }],
};

/** A modest identity policy for the boundary scenario: DynamoDB only. */
export const APP_ROLE_DYNAMODB: PolicyDocument = {
  Statement: [{ Sid: 'Orders', Effect: 'Allow', Action: 'dynamodb:*', Resource: `arn:aws:dynamodb:eu-west-1:${ACCOUNTS.workload}:table/orders` }],
};

/** The analytics account grants its own role read access to the shared bucket. */
export const ANALYTICS_ROLE_POLICY: PolicyDocument = {
  Statement: [{ Sid: 'ReadShared', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-shared/*' }],
};

/** ABAC: one policy for every department, thanks to tags and one policy variable. */
export const ABAC_DEPARTMENT_DATA: PolicyDocument = {
  // IAM policy variables such as ${aws:PrincipalTag/dept} require this policy-language version.
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ReadOwnDepartmentPrefix',
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::lab-abac/${aws:PrincipalTag/dept}/*',
    },
    {
      Sid: 'ReadOwnDepartmentTables',
      Effect: 'Allow',
      Action: ['dynamodb:GetItem', 'dynamodb:Query'],
      Resource: `arn:aws:dynamodb:eu-west-1:${ACCOUNTS.workload}:table/*`,
      Condition: { StringEquals: { 'aws:ResourceTag/dept': '${aws:PrincipalTag/dept}' } },
    },
  ],
};

/** Read-only IAM for operators. */
export const IAM_READ: PolicyDocument = {
  Statement: [{ Sid: 'IamRead', Effect: 'Allow', Action: ['iam:Get*', 'iam:List*'], Resource: '*' }],
};

/** The MFA guardrail as people first write it. It has a hole. */
export const DENY_IAM_WITHOUT_MFA_BOOL: PolicyDocument = {
  Statement: [
    {
      Sid: 'DenyIamWithoutMfa',
      Effect: 'Deny',
      Action: 'iam:*',
      Resource: '*',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
    },
  ],
};

/** The same guardrail, written so that a missing key also denies. */
export const DENY_IAM_WITHOUT_MFA_BOOL_IF_EXISTS: PolicyDocument = {
  Statement: [
    {
      Sid: 'DenyIamWithoutMfa',
      Effect: 'Deny',
      Action: 'iam:*',
      Resource: '*',
      Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } },
    },
  ],
};

// ---------------------------------------------------------------- resource policies

/** Bucket policy on lab-shared: one cross-account role, one same-account user. */
export const SHARED_BUCKET_POLICY: PolicyDocument = {
  Statement: [
    {
      Sid: 'AnalyticsAccountRole',
      Effect: 'Allow',
      Principal: { AWS: PRINCIPALS.analyticsRole.arn },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::lab-shared/*',
    },
    {
      Sid: 'SameAccountAuditor',
      Effect: 'Allow',
      Principal: { AWS: PRINCIPALS.auditor.arn },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::lab-shared/*',
    },
  ],
};

/** The lazy version: trust the whole other account. Its administrators decide who gets in. */
export const SHARED_BUCKET_POLICY_WHOLE_ACCOUNT: PolicyDocument = {
  Statement: [
    {
      Sid: 'AnyoneInAnalyticsAccount',
      Effect: 'Allow',
      Principal: { AWS: `arn:aws:iam::${ACCOUNTS.analytics}:root` },
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::lab-shared/*',
    },
  ],
};

// ---------------------------------------------------------------- guardrails: SCPs, boundary, session policy

/** FullAWSAccess, the SCP AWS attaches by default. Without it, an OU allows nothing. */
export const SCP_FULL_AWS_ACCESS: PolicyDocument = {
  Statement: [{ Sid: 'FullAWSAccess', Effect: 'Allow', Action: '*', Resource: '*' }],
};

/**
 * The region-restriction SCP from the Organizations documentation, shortened: deny everything
 * outside the allowed regions, except the global services that only exist in us-east-1.
 * `NotAction` in a Deny reads "deny everything but these".
 */
export const SCP_EU_ONLY: PolicyDocument = {
  Statement: [
    {
      Sid: 'DenyOutsideEu',
      Effect: 'Deny',
      NotAction: ['iam:*', 'sts:*', 'organizations:*', 'support:*', 'budgets:*', 'cloudfront:*', 'route53:*', 'health:*'],
      Resource: '*',
      Condition: { StringNotEquals: { 'aws:RequestedRegion': ['eu-west-1', 'eu-central-1'] } },
    },
  ],
};

/** The boundary every developer-created role must carry (enforced with an iam:PermissionsBoundary condition on iam:CreateRole). */
export const BOUNDARY_APP_SERVICES: PolicyDocument = {
  Statement: [{ Sid: 'AppServicesOnly', Effect: 'Allow', Action: ['s3:*', 'dynamodb:*', 'sqs:*', 'logs:*'], Resource: '*' }],
};

/** A session policy a credential-vending service passes to AssumeRole: this session may only read one prefix. */
export const SESSION_READ_ONE_PREFIX: PolicyDocument = {
  Statement: [{ Sid: 'ThisSessionOnly', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::lab-docs/public/*' }],
};
