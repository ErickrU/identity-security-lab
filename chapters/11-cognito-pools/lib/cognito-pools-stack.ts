import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import type { Construct } from 'constructs';

/**
 * Lab-only composition:
 *
 *   User Pool -> ID token -> Identity Pool -> temporary AWS credentials -> S3
 *
 * The `admins` user-pool group is deliberately NOT mapped to an IAM role. The
 * central authorization boundary is one authenticated role whose policy uses
 * Cognito Identity's `sub` context key to isolate every identity's S3 prefix.
 */
export class CognitoPoolsStack extends Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly identityPool: cognito.CfnIdentityPool;
  public readonly authenticatedRole: iam.Role;
  public readonly bucket: s3.Bucket;

  public constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false,
      signInAliases: { username: true },
      signInCaseSensitive: false,
      accountRecovery: cognito.AccountRecovery.NONE,
      deletionProtection: false,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.userPoolClient = this.userPool.addClient('PublicCliClient', {
      authFlows: { userPassword: true },
      disableOAuth: true,
      generateSecret: false,
      accessTokenValidity: Duration.minutes(15),
      idTokenValidity: Duration.minutes(15),
      refreshTokenValidity: Duration.days(1),
      preventUserExistenceErrors: true,
    });

    new cognito.CfnUserPoolGroup(this, 'AdminsGroup', {
      userPoolId: this.userPool.userPoolId,
      groupName: 'admins',
      description:
        'Application group only; this lab does not map cognito:groups to AWS permissions',
    });

    this.identityPool = new cognito.CfnIdentityPool(this, 'IdentityPool', {
      allowClassicFlow: false,
      allowUnauthenticatedIdentities: false,
      cognitoIdentityProviders: [
        {
          clientId: this.userPoolClient.userPoolClientId,
          providerName: this.userPool.userPoolProviderName,
          serverSideTokenCheck: true,
        },
      ],
      identityPoolName: 'identity_security_lab',
    });

    this.bucket = new s3.Bucket(this, 'IdentityDataBucket', {
      autoDeleteObjects: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    this.authenticatedRole = new iam.Role(this, 'AuthenticatedRole', {
      description:
        'Cognito Identity authenticated role, isolated to each identity ID in S3',
      assumedBy: new iam.FederatedPrincipal(
        'cognito-identity.amazonaws.com',
        {
          StringEquals: {
            'cognito-identity.amazonaws.com:aud': this.identityPool.ref,
          },
          'ForAnyValue:StringLike': {
            'cognito-identity.amazonaws.com:amr': 'authenticated',
          },
        },
        'sts:AssumeRoleWithWebIdentity',
      ),
      maxSessionDuration: Duration.hours(1),
    });

    // Keep this as a plain string. CloudFormation must preserve the IAM policy
    // variable literally; it is substituted from the Cognito Identity session
    // at authorization time, not by TypeScript or Fn::Sub during deployment.
    const identityIdVariable = '${cognito-identity.amazonaws.com:sub}';

    this.authenticatedRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ListOnlyOwnIdentityPrefix',
        actions: ['s3:ListBucket'],
        resources: [this.bucket.bucketArn],
        conditions: {
          StringLike: {
            's3:prefix': [`${identityIdVariable}/*`],
          },
        },
      }),
    );

    this.authenticatedRole.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadWriteOnlyOwnIdentityObjects',
        actions: ['s3:GetObject', 's3:PutObject'],
        resources: [this.bucket.arnForObjects(`${identityIdVariable}/*`)],
      }),
    );

    new cognito.CfnIdentityPoolRoleAttachment(this, 'IdentityPoolRoles', {
      identityPoolId: this.identityPool.ref,
      roles: {
        authenticated: this.authenticatedRole.roleArn,
      },
    });

    new CfnOutput(this, 'UserPoolId', {
      value: this.userPool.userPoolId,
      description: 'Cognito User Pool ID',
    });
    new CfnOutput(this, 'UserPoolClientId', {
      value: this.userPoolClient.userPoolClientId,
      description: 'Public app client ID (no client secret)',
    });
    new CfnOutput(this, 'IdentityPoolId', {
      value: this.identityPool.ref,
      description: 'Cognito Identity Pool ID',
    });
    new CfnOutput(this, 'BucketName', {
      value: this.bucket.bucketName,
      description: 'Lab bucket with per-identity prefixes',
    });
    new CfnOutput(this, 'Region', {
      value: this.region,
      description: 'Deployment Region',
    });
    new CfnOutput(this, 'LabOnlyWarning', {
      value: 'LAB ONLY - deploys mutable resources and DESTROY removal policies',
      description: 'Do not deploy this teaching stack as production infrastructure',
    });
  }
}
