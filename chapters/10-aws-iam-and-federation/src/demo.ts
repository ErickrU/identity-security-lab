/**
 * Chapter 10 demo: IAM policy evaluation, one rule at a time.
 *
 *   npx tsx chapters/10-aws-iam-and-federation/src/demo.ts
 *
 * Six scenarios plus one gotcha, all offline. Each prints the request, then the evaluation steps
 * in the order IAM performs them, then the decision and why. Nothing here calls AWS.
 */
import { evaluate, type Decision, type Request } from './iam-eval';
import {
  ABAC_DEPARTMENT_DATA,
  ACCOUNTS,
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

// ---------------------------------------------------------------- printing

function heading(text: string): void {
  console.log(`\n${'='.repeat(78)}\n${text}\n${'='.repeat(78)}`);
}

function note(text: string): void {
  console.log(`  ${text}`);
}

function shortArn(arn: string): string {
  return arn.replace(/^arn:aws:(iam|sts)::(\d{12}):/, (_, __, account: string) => `${account}:`);
}

function run(title: string, request: Request): Decision {
  const decision = evaluate(request);
  console.log(`\n  ${title}`);
  console.log(`    who     ${shortArn(request.principal.arn)}${request.principal.tags ? `  tags ${JSON.stringify(request.principal.tags)}` : ''}`);
  console.log(`    what    ${request.action}`);
  console.log(`    on      ${request.resource.arn}${request.resource.tags ? `  tags ${JSON.stringify(request.resource.tags)}` : ''}`);
  if (request.context) console.log(`    context ${JSON.stringify(request.context)}`);
  for (const line of decision.trace) console.log(`      ${line}`);
  return decision;
}

// ---------------------------------------------------------------- scenarios

function scenario1IdentityAllow(): void {
  heading('1) Identity-based policy: the default is "no", a matching Allow turns it into "yes"');
  note('alice has one policy: list the docs bucket and read its objects. Nothing says she may delete.');
  run('alice reads the handbook', {
    principal: PRINCIPALS.alice,
    action: 's3:GetObject',
    resource: RESOURCES.handbook,
    identityPolicies: [DEV_READ_DOCS],
  });
  run('alice deletes the handbook', {
    principal: PRINCIPALS.alice,
    action: 's3:DeleteObject',
    resource: RESOURCES.handbook,
    identityPolicies: [DEV_READ_DOCS],
  });
  note('Implicit deny: not a rule that said no, the absence of a rule that said yes. Most IAM AccessDenied errors are this.');
}

function scenario2ExplicitDenyWins(): void {
  heading('2) Explicit Deny wins over any Allow, in any policy, in any order');
  note('The security team attached DENY_S3_DELETE to every group. An administrator has Allow * on *.');
  run('administrator deletes the handbook', {
    principal: PRINCIPALS.adminSession,
    action: 's3:DeleteObject',
    resource: RESOURCES.handbook,
    identityPolicies: [ADMINISTRATOR_ACCESS, DENY_S3_DELETE],
  });
  run('administrator reads the handbook (the Deny names only delete actions)', {
    principal: PRINCIPALS.adminSession,
    action: 's3:GetObject',
    resource: RESOURCES.handbook,
    identityPolicies: [ADMINISTRATOR_ACCESS, DENY_S3_DELETE],
  });
  note('Why: the deny evaluation runs first, over every policy type. A Deny cannot be out-voted; it can only be removed.');
}

function scenario3ScpBlocksRegion(): void {
  heading('3) SCPs: an organization-level ceiling that applies to administrators too');
  note('Tree: root (FullAWSAccess) → OU "workloads" (FullAWSAccess + "EU regions only": Deny + NotAction for global services) → account.');
  const scps = [
    { name: 'root', policies: [SCP_FULL_AWS_ACCESS] },
    { name: 'ou:workloads', policies: [SCP_FULL_AWS_ACCESS, SCP_EU_ONLY] },
  ];
  run('administrator launches an instance in ap-southeast-1', {
    principal: PRINCIPALS.adminSession,
    action: 'ec2:RunInstances',
    resource: RESOURCES.instancesSingapore,
    context: { 'aws:RequestedRegion': 'ap-southeast-1' },
    identityPolicies: [ADMINISTRATOR_ACCESS],
    scps,
  });
  run('administrator launches an instance in eu-west-1', {
    principal: PRINCIPALS.adminSession,
    action: 'ec2:RunInstances',
    resource: RESOURCES.instancesIreland,
    context: { 'aws:RequestedRegion': 'eu-west-1' },
    identityPolicies: [ADMINISTRATOR_ACCESS],
    scps,
  });
  run('administrator lists IAM users (a global service, excluded through NotAction)', {
    principal: PRINCIPALS.adminSession,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    context: { 'aws:RequestedRegion': 'us-east-1' },
    identityPolicies: [ADMINISTRATOR_ACCESS],
    scps,
  });
  note('SCPs never grant anything: FullAWSAccess is there so each level allows something at all. Detach it from one level:');
  run('same launch in eu-west-1, but someone removed FullAWSAccess from the OU, leaving only the Deny policy', {
    principal: PRINCIPALS.adminSession,
    action: 'ec2:RunInstances',
    resource: RESOURCES.instancesIreland,
    context: { 'aws:RequestedRegion': 'eu-west-1' },
    identityPolicies: [ADMINISTRATOR_ACCESS],
    scps: [
      { name: 'root', policies: [SCP_FULL_AWS_ACCESS] },
      { name: 'ou:workloads', policies: [SCP_EU_ONLY] },
    ],
  });
  note('Every level of the tree must allow; within a level the Allows add up. Identity policies still decide the rest.');
  note('SCPs do not apply to the management account, which is one reason nothing should run there.');
}

function scenario4BoundaryAndSession(): void {
  heading('4) Permissions boundary and session policy: caps, not grants');
  note('Developers may create roles only if they attach BOUNDARY_APP_SERVICES (s3, dynamodb, sqs, logs).');
  note('A developer gives the app role Allow * on *. The boundary decides what that is worth.');
  run('app role reads an object (identity allows, boundary allows)', {
    principal: PRINCIPALS.appRole,
    action: 's3:GetObject',
    resource: RESOURCES.handbook,
    identityPolicies: [APP_ROLE_TOO_BROAD],
    permissionsBoundary: BOUNDARY_APP_SERVICES,
  });
  run('app role creates an IAM user (identity allows, boundary does not)', {
    principal: PRINCIPALS.appRole,
    action: 'iam:CreateUser',
    resource: RESOURCES.bob,
    identityPolicies: [APP_ROLE_TOO_BROAD],
    permissionsBoundary: BOUNDARY_APP_SERVICES,
  });
  note('The other direction: a boundary that allows s3:* grants nothing by itself.');
  run('app role with a DynamoDB-only identity policy reads an object (boundary allows, identity does not)', {
    principal: PRINCIPALS.appRole,
    action: 's3:GetObject',
    resource: RESOURCES.handbook,
    identityPolicies: [APP_ROLE_DYNAMODB],
    permissionsBoundary: BOUNDARY_APP_SERVICES,
  });
  note('Session policies work the same way, per session: a vending service assumes the role with a scoped-down policy.');
  run('same role, session created with "read lab-docs/public/* only", reads the handbook', {
    principal: PRINCIPALS.appRole,
    action: 's3:GetObject',
    resource: RESOURCES.handbook,
    identityPolicies: [APP_ROLE_TOO_BROAD],
    permissionsBoundary: BOUNDARY_APP_SERVICES,
    sessionPolicy: SESSION_READ_ONE_PREFIX,
  });
  note('Effective permissions = identity policy ∩ boundary ∩ session policy ∩ SCPs, minus every explicit Deny.');
}

function scenario5ResourcePolicy(): void {
  heading('5) Resource-based policies: same account, one yes is enough; cross account, both sides must say yes');
  note(`lab-shared (account ${ACCOUNTS.workload}) has a bucket policy naming a role in ${ACCOUNTS.analytics} and a same-account auditor.`);
  run('analytics role reads the report: bucket policy names it, its own account allows s3:GetObject', {
    principal: PRINCIPALS.analyticsRole,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [ANALYTICS_ROLE_POLICY],
    resourcePolicy: SHARED_BUCKET_POLICY,
  });
  run('analytics role, same bucket policy, but nobody in its own account gave it s3:GetObject', {
    principal: PRINCIPALS.analyticsRole,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [],
    resourcePolicy: SHARED_BUCKET_POLICY,
  });
  run('auditor (same account, zero identity policies) reads the report', {
    principal: PRINCIPALS.auditor,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [],
    resourcePolicy: SHARED_BUCKET_POLICY,
  });
  run('analytics role with identity policy, but the bucket policy does not name it', {
    principal: PRINCIPALS.analyticsRole,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [ANALYTICS_ROLE_POLICY],
  });
  note('Why the asymmetry: inside one account the account owner wrote both policies, so either is a decision by the owner.');
  note('Across accounts, each administrator only controls their half; the union of two "yes" is the smallest safe rule.');
  run(`bucket policy trusts the whole account ${ACCOUNTS.analytics} (Principal arn:aws:iam::${ACCOUNTS.analytics}:root)`, {
    principal: PRINCIPALS.analyticsRole,
    action: 's3:GetObject',
    resource: RESOURCES.sharedReport,
    identityPolicies: [ANALYTICS_ROLE_POLICY],
    resourcePolicy: SHARED_BUCKET_POLICY_WHOLE_ACCOUNT,
  });
  note("Trusting an account root delegates the decision to that account's administrators: any principal they allow gets in.");
}

function scenario6Abac(): void {
  heading('6) ABAC: one policy for every department, decided by tags at request time');
  note('ReadOwnDepartmentPrefix: Resource arn:aws:s3:::lab-abac/${aws:PrincipalTag/dept}/*');
  note('ReadOwnDepartmentTables: Condition StringEquals aws:ResourceTag/dept = ${aws:PrincipalTag/dept}');
  run('finance analyst reads finance/q3.csv', {
    principal: PRINCIPALS.financeAnalyst,
    action: 's3:GetObject',
    resource: RESOURCES.financeObject,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });
  run('finance analyst reads eng/design.md', {
    principal: PRINCIPALS.financeAnalyst,
    action: 's3:GetObject',
    resource: RESOURCES.engObject,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });
  run('eng analyst queries the eng-builds table (tag dept=eng)', {
    principal: PRINCIPALS.engAnalyst,
    action: 'dynamodb:Query',
    resource: RESOURCES.engTable,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });
  run('eng analyst queries the finance-ledger table (tag dept=finance)', {
    principal: PRINCIPALS.engAnalyst,
    action: 'dynamodb:Query',
    resource: RESOURCES.financeTable,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });
  run('a new analyst with no dept tag reads finance/q3.csv (the variable cannot be resolved)', {
    principal: PRINCIPALS.untaggedAnalyst,
    action: 's3:GetObject',
    resource: RESOURCES.financeObject,
    identityPolicies: [ABAC_DEPARTMENT_DATA],
  });
  note('A missing tag makes the statement not match at all. Missing means deny, which is the safe direction.');
  note('Tags arrive from IAM (on the role) or as session tags at federation time: SAML PrincipalTag attributes, OIDC principal_tags.');
  note('Whoever can set aws:PrincipalTag/dept is now an administrator of finance data. Protect tag writes like policy writes.');
}

function gotchaMfaBoolIfExists(): void {
  heading('Gotcha) "Deny iam:* unless MFA" written with Bool does not deny long-term access keys');
  note('aws:MultiFactorAuthPresent is only in the request context for temporary credentials (sessions).');
  note('A request signed with long-term access keys has no such key at all: not true, not false, absent.');
  const withBool = [IAM_READ, DENY_IAM_WITHOUT_MFA_BOOL];
  run('carol, role session without MFA (context aws:MultiFactorAuthPresent=false), lists users', {
    principal: PRINCIPALS.opsSession,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    context: { 'aws:MultiFactorAuthPresent': false },
    identityPolicies: withBool,
  });
  run('carol, long-term access keys (no MFA key in the context), lists users: the Bool Deny does not apply', {
    principal: PRINCIPALS.opsUser,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    identityPolicies: withBool,
  });
  note('The fix: BoolIfExists. "If the key exists, it must not be false; if it does not exist, treat the condition as true."');
  const withBoolIfExists = [IAM_READ, DENY_IAM_WITHOUT_MFA_BOOL_IF_EXISTS];
  run('carol, long-term access keys, same request, Deny written with BoolIfExists', {
    principal: PRINCIPALS.opsUser,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    identityPolicies: withBoolIfExists,
  });
  run('carol, role session with MFA (context aws:MultiFactorAuthPresent=true), lists users', {
    principal: PRINCIPALS.opsSession,
    action: 'iam:ListUsers',
    resource: RESOURCES.anyIamUser,
    context: { 'aws:MultiFactorAuthPresent': true },
    identityPolicies: withBoolIfExists,
  });
  note('Better still: no long-term access keys for humans at all. Then the key is always present, and so is the answer.');
}

// ---------------------------------------------------------------- main

function main(): void {
  console.log('Chapter 10 · IAM policy evaluation, offline. Order of evaluation: explicit Deny → SCPs → boundary → session policy → identity / resource policies → implicit deny.');
  scenario1IdentityAllow();
  scenario2ExplicitDenyWins();
  scenario3ScpBlocksRegion();
  scenario4BoundaryAndSession();
  scenario5ResourcePolicy();
  scenario6Abac();
  gotchaMfaBoolIfExists();
  console.log('\nDone. Same rules, real AWS: the CDK stack in lib/ builds a role that only a GitHub Actions workflow of one repository can assume. See README.md → Run it.');
}

main();
