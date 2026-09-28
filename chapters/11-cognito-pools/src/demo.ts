import {
  authorizeS3,
  evaluateRoleTrust,
  type PolicyDecision,
} from './policy';

const ALICE_IDENTITY_ID = 'us-west-2:11111111-1111-4111-8111-111111111111';
const BOB_IDENTITY_ID = 'us-west-2:22222222-2222-4222-8222-222222222222';
const IDENTITY_POOL_ID = 'us-west-2:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NOW = 1_800_000_000;
const EXPIRES_AT = NOW + 3_600;

function renderDecision(label: string, decision: PolicyDecision, log: (line: string) => void): void {
  log(`${decision.allowed ? '✓ ALLOW' : '✗ DENY '} ${label}`);
  log(`  → ${decision.reason}`);
}

export function runDemo(log: (line: string) => void = console.log): void {
  log('Cognito pools: one authentication flow, two different services');
  log('');
  log('1. User Pool authenticates alice with a username and password.');
  log('   → It emits an ID-token JWT and access-token JWT, plus a refresh token.');
  log('   → The ID token names this public app client in aud (token not printed).');
  log('');
  log('2. Identity Pool accepts that provider ID token in Logins.');
  log(`   → GetId returns a stable identity ID: ${ALICE_IDENTITY_ID}`);
  log('   → This identifier is not a JWT and is not the User Pool sub claim.');
  log('');
  log('3. GetCredentialsForIdentity evaluates the authenticated IAM role trust.');
  renderDecision(
    'role context has this identity-pool audience and authenticated amr',
    evaluateRoleTrust({
      expectedAudience: IDENTITY_POOL_ID,
      aud: IDENTITY_POOL_ID,
      amr: ['cognito-idp.example', 'authenticated'],
    }),
    log,
  );
  log('   → Cognito Identity returns temporary accessKeyId/secret/sessionToken values.');
  log('   → They sign AWS API requests with SigV4. They are NOT another app JWT.');
  log('   → Credential values are intentionally not printed.');
  log('');
  log('4. IAM substitutes the role session identity ID into the S3 policy.');
  renderDecision(
    'alice writes alice/notes.txt',
    authorizeS3({
      action: 's3:PutObject',
      principalIdentityId: ALICE_IDENTITY_ID,
      key: `${ALICE_IDENTITY_ID}/notes.txt`,
      nowEpochSeconds: NOW,
      credentialsExpireAtEpochSeconds: EXPIRES_AT,
    }),
    log,
  );
  renderDecision(
    'bob reads alice/notes.txt',
    authorizeS3({
      action: 's3:GetObject',
      principalIdentityId: BOB_IDENTITY_ID,
      key: `${ALICE_IDENTITY_ID}/notes.txt`,
      nowEpochSeconds: NOW,
      credentialsExpireAtEpochSeconds: EXPIRES_AT,
    }),
    log,
  );
  log('');
  log('5. Fail closed at each boundary.');
  renderDecision(
    'role context carries the wrong identity-pool audience',
    evaluateRoleTrust({
      expectedAudience: IDENTITY_POOL_ID,
      aud: 'us-west-2:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      amr: ['authenticated'],
    }),
    log,
  );
  renderDecision(
    'token/session is unauthenticated',
    evaluateRoleTrust({
      expectedAudience: IDENTITY_POOL_ID,
      aud: IDENTITY_POOL_ID,
      amr: ['unauthenticated'],
    }),
    log,
  );
  renderDecision(
    'alice signs S3 after temporary credentials expire',
    authorizeS3({
      action: 's3:GetObject',
      principalIdentityId: ALICE_IDENTITY_ID,
      key: `${ALICE_IDENTITY_ID}/notes.txt`,
      nowEpochSeconds: EXPIRES_AT,
      credentialsExpireAtEpochSeconds: EXPIRES_AT,
    }),
    log,
  );
}

if (require.main === module) {
  runDemo();
}
