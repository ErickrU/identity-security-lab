import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  AdminAddUserToGroupCommand,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  CognitoIdentityClient,
  GetCredentialsForIdentityCommand,
  GetIdCommand,
} from '@aws-sdk/client-cognito-identity';
import { GetObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

interface LabOutputs {
  readonly UserPoolId: string;
  readonly UserPoolClientId: string;
  readonly IdentityPoolId: string;
  readonly BucketName: string;
  readonly Region: string;
  readonly LabOnlyWarning: string;
}

interface IdentitySession {
  readonly identityId: string;
  readonly credentials: {
    readonly accessKeyId: string;
    readonly secretAccessKey: string;
    readonly sessionToken: string;
    readonly expiration: Date;
  };
}

const USERS = [
  { username: 'alice', password: 'Lab-only-Alice-42!' },
  { username: 'bob', password: 'Lab-only-Bob-42!' },
] as const;

function printMutationWarning(): void {
  console.warn(`
WARNING: this script mutates a deployed LAB stack.
It creates or resets alice and bob, adds alice to the application-level admins
user-pool group, and writes one S3 object per identity. It does not clean up.
Inspect your AWS account and Region before continuing.

  Deploy:  npx cdk deploy --outputs-file cdk-outputs.json
  Demo:    npx tsx scripts/live-demo.ts --confirm-lab
  Destroy: npx cdk destroy
`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`cdk-outputs.json is missing string output ${key}`);
  }
  return value;
}

async function readOutputs(): Promise<LabOutputs> {
  const outputsPath = resolve(process.cwd(), 'cdk-outputs.json');
  const parsed: unknown = JSON.parse(await readFile(outputsPath, 'utf8'));
  if (!isRecord(parsed)) {
    throw new Error('cdk-outputs.json must contain a stack output object');
  }

  const rawStack = parsed.LabCognitoPools;
  if (!isRecord(rawStack)) {
    throw new Error(
      'cdk-outputs.json has no LabCognitoPools entry; deploy this chapter stack first',
    );
  }

  const outputs: LabOutputs = {
    UserPoolId: requiredString(rawStack, 'UserPoolId'),
    UserPoolClientId: requiredString(rawStack, 'UserPoolClientId'),
    IdentityPoolId: requiredString(rawStack, 'IdentityPoolId'),
    BucketName: requiredString(rawStack, 'BucketName'),
    Region: requiredString(rawStack, 'Region'),
    LabOnlyWarning: requiredString(rawStack, 'LabOnlyWarning'),
  };

  if (!outputs.LabOnlyWarning.startsWith('LAB ONLY')) {
    throw new Error('refusing to mutate a stack whose output is not labeled LAB ONLY');
  }

  return outputs;
}

function isNamedError(error: unknown, name: string): boolean {
  return isRecord(error) && error.name === name;
}

async function createOrResetUser(
  client: CognitoIdentityProviderClient,
  userPoolId: string,
  username: string,
  password: string,
): Promise<void> {
  try {
    await client.send(
      new AdminCreateUserCommand({
        UserPoolId: userPoolId,
        Username: username,
        MessageAction: 'SUPPRESS',
      }),
    );
    console.log(`Created User Pool user ${username}.`);
  } catch (error: unknown) {
    if (!isNamedError(error, 'UsernameExistsException')) {
      throw error;
    }
    console.log(`User Pool user ${username} already exists; resetting its lab password.`);
  }

  await client.send(
    new AdminSetUserPasswordCommand({
      UserPoolId: userPoolId,
      Username: username,
      Password: password,
      Permanent: true,
    }),
  );
}

async function getIdToken(
  client: CognitoIdentityProviderClient,
  clientId: string,
  username: string,
  password: string,
): Promise<string> {
  const response = await client.send(
    new InitiateAuthCommand({
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: clientId,
      AuthParameters: {
        USERNAME: username,
        PASSWORD: password,
      },
    }),
  );

  const idToken = response.AuthenticationResult?.IdToken;
  if (idToken === undefined) {
    throw new Error(`Cognito did not return an ID token for ${username}`);
  }

  console.log(`Authenticated ${username}; received an ID-token JWT (not printed).`);
  return idToken;
}

async function getIdentitySession(
  client: CognitoIdentityClient,
  identityPoolId: string,
  providerName: string,
  idToken: string,
): Promise<IdentitySession> {
  const idResponse = await client.send(
    new GetIdCommand({
      IdentityPoolId: identityPoolId,
      Logins: { [providerName]: idToken },
    }),
  );
  if (idResponse.IdentityId === undefined) {
    throw new Error('GetId did not return an identity ID');
  }

  const credentialResponse = await client.send(
    new GetCredentialsForIdentityCommand({
      IdentityId: idResponse.IdentityId,
      Logins: { [providerName]: idToken },
    }),
  );
  const credentials = credentialResponse.Credentials;
  if (
    credentials?.AccessKeyId === undefined ||
    credentials.SecretKey === undefined ||
    credentials.SessionToken === undefined ||
    credentials.Expiration === undefined
  ) {
    throw new Error('GetCredentialsForIdentity returned incomplete AWS credentials');
  }

  console.log(`GetId returned ${idResponse.IdentityId}.`);
  console.log(
    `GetCredentialsForIdentity returned temporary SigV4 credentials expiring ${credentials.Expiration.toISOString()} (values not printed).`,
  );

  return {
    identityId: idResponse.IdentityId,
    credentials: {
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretKey,
      sessionToken: credentials.SessionToken,
      expiration: credentials.Expiration,
    },
  };
}

async function putAndGetOwnObject(
  region: string,
  bucket: string,
  username: string,
  session: IdentitySession,
): Promise<void> {
  const client = new S3Client({ region, credentials: session.credentials });
  const key = `${session.identityId}/hello.txt`;
  const expectedBody = `hello from ${username}\n`;

  await client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: expectedBody,
      ContentType: 'text/plain',
    }),
  );
  const result = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  const actualBody = await result.Body?.transformToString();
  if (actualBody !== expectedBody) {
    throw new Error(`${username} read an unexpected S3 object body`);
  }

  console.log(`S3 allowed ${username} to PutObject/GetObject at ${key}.`);
}

async function proveCrossPrefixDenied(
  region: string,
  bucket: string,
  alice: IdentitySession,
  bob: IdentitySession,
): Promise<void> {
  const bobClient = new S3Client({ region, credentials: bob.credentials });
  const aliceKey = `${alice.identityId}/hello.txt`;

  try {
    await bobClient.send(new GetObjectCommand({ Bucket: bucket, Key: aliceKey }));
  } catch (error: unknown) {
    const denied =
      isNamedError(error, 'AccessDenied') ||
      (isRecord(error) &&
        isRecord(error.$metadata) &&
        error.$metadata.httpStatusCode === 403);
    if (denied) {
      console.log('S3 returned AccessDenied when bob tried to read alice prefix: expected.');
      return;
    }
    throw error;
  }

  throw new Error('SECURITY CHECK FAILED: bob read alice object');
}

async function main(): Promise<void> {
  printMutationWarning();
  if (!process.argv.includes('--confirm-lab')) {
    throw new Error('refusing to mutate AWS without the explicit --confirm-lab flag');
  }

  const outputs = await readOutputs();
  console.log(`Using LAB outputs in Region ${outputs.Region}.`);

  const userPools = new CognitoIdentityProviderClient({ region: outputs.Region });
  for (const user of USERS) {
    await createOrResetUser(
      userPools,
      outputs.UserPoolId,
      user.username,
      user.password,
    );
  }
  await userPools.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: outputs.UserPoolId,
      Username: 'alice',
      GroupName: 'admins',
    }),
  );
  console.log('Added alice to admins; this application group has no IAM role mapping.');

  const providerName = `cognito-idp.${outputs.Region}.amazonaws.com/${outputs.UserPoolId}`;
  const identityPools = new CognitoIdentityClient({ region: outputs.Region });
  const sessions = new Map<string, IdentitySession>();

  for (const user of USERS) {
    const idToken = await getIdToken(
      userPools,
      outputs.UserPoolClientId,
      user.username,
      user.password,
    );
    const session = await getIdentitySession(
      identityPools,
      outputs.IdentityPoolId,
      providerName,
      idToken,
    );
    sessions.set(user.username, session);
    await putAndGetOwnObject(
      outputs.Region,
      outputs.BucketName,
      user.username,
      session,
    );
  }

  const alice = sessions.get('alice');
  const bob = sessions.get('bob');
  if (alice === undefined || bob === undefined || alice.identityId === bob.identityId) {
    throw new Error('expected alice and bob to receive distinct Cognito identity IDs');
  }

  await proveCrossPrefixDenied(outputs.Region, outputs.BucketName, alice, bob);
  console.log('Live lab complete. Run `npx cdk destroy` to remove its resources and data.');
}

void main().catch((error: unknown) => {
  console.error(`Live demo failed: ${error instanceof Error ? error.message : 'unknown error'}`);
  process.exitCode = 1;
});
