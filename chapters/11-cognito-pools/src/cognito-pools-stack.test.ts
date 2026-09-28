import { App, Token } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import { CognitoPoolsStack } from '../lib/cognito-pools-stack';

interface Synthesized {
  readonly stack: CognitoPoolsStack;
  readonly template: Template;
}

function synthesize(): Synthesized {
  const app = new App();
  const stack = new CognitoPoolsStack(app, 'TestLabCognitoPools');
  return { stack, template: Template.fromStack(stack) };
}

function onlyResource(template: Template, type: string): [string, any] {
  const resources = template.findResources(type);
  expect(Object.keys(resources)).toHaveLength(1);
  return Object.entries(resources)[0] as [string, any];
}

function asArray(value: string | string[]): string[] {
  return Array.isArray(value) ? value : [value];
}

describe('LabCognitoPools infrastructure', () => {
  it('is environment-agnostic and creates both Cognito pool types', () => {
    const { stack, template } = synthesize();

    expect(Token.isUnresolved(stack.account)).toBe(true);
    expect(Token.isUnresolved(stack.region)).toBe(true);
    template.resourceCountIs('AWS::Cognito::UserPool', 1);
    template.resourceCountIs('AWS::Cognito::IdentityPool', 1);
    template.resourceCountIs('AWS::Cognito::IdentityPoolRoleAttachment', 1);
  });

  it('keeps self sign-up and deletion protection off and destroys the lab user pool', () => {
    const { template } = synthesize();
    const [, userPool] = onlyResource(template, 'AWS::Cognito::UserPool');

    expect(userPool.Properties.AdminCreateUserConfig.AllowAdminCreateUserOnly).toBe(true);
    expect(userPool.Properties.DeletionProtection).toBe('INACTIVE');
    expect(userPool.Properties.UsernameConfiguration.CaseSensitive).toBe(false);
    expect(userPool.DeletionPolicy).toBe('Delete');
    expect(userPool.UpdateReplacePolicy).toBe('Delete');
  });

  it('uses a public short-lived USER_PASSWORD_AUTH client', () => {
    const { template } = synthesize();
    const [, client] = onlyResource(template, 'AWS::Cognito::UserPoolClient');

    expect(client.Properties.GenerateSecret).toBe(false);
    expect(client.Properties.ExplicitAuthFlows).toEqual(
      expect.arrayContaining(['ALLOW_USER_PASSWORD_AUTH', 'ALLOW_REFRESH_TOKEN_AUTH']),
    );
    expect(client.Properties.AccessTokenValidity).toBe(15);
    expect(client.Properties.IdTokenValidity).toBe(15);
    expect(client.Properties.RefreshTokenValidity).toBe(1_440);
    expect(client.Properties.TokenValidityUnits).toEqual({
      AccessToken: 'minutes',
      IdToken: 'minutes',
      RefreshToken: 'minutes',
    });
    expect(client.Properties.AllowedOAuthFlowsUserPoolClient).not.toBe(true);
  });

  it('creates admins only as an application group', () => {
    const { template } = synthesize();
    const [, group] = onlyResource(template, 'AWS::Cognito::UserPoolGroup');

    expect(group.Properties.GroupName).toBe('admins');
    expect(group.Properties.Description).toContain('does not map cognito:groups');
    expect(group.Properties.RoleArn).toBeUndefined();
  });

  it('accepts only authenticated identities from the configured user-pool client', () => {
    const { template } = synthesize();
    const [userPoolId] = onlyResource(template, 'AWS::Cognito::UserPool');
    const [clientId] = onlyResource(template, 'AWS::Cognito::UserPoolClient');
    const [, identityPool] = onlyResource(template, 'AWS::Cognito::IdentityPool');

    expect(identityPool.Properties.AllowUnauthenticatedIdentities).toBe(false);
    expect(identityPool.Properties.AllowClassicFlow).toBe(false);
    expect(identityPool.Properties.CognitoIdentityProviders).toEqual([
      {
        ClientId: { Ref: clientId },
        ProviderName: { 'Fn::GetAtt': [userPoolId, 'ProviderName'] },
        ServerSideTokenCheck: true,
      },
    ]);
  });

  it('pins role trust to the identity pool audience and authenticated amr', () => {
    const { template } = synthesize();
    const [identityPoolId] = onlyResource(template, 'AWS::Cognito::IdentityPool');
    const roles = template.findResources('AWS::IAM::Role');
    const authenticated = Object.entries(roles).find(([, role]) =>
      JSON.stringify(role).includes('cognito-identity.amazonaws.com'),
    );

    expect(authenticated).toBeDefined();
    const [, role] = authenticated as [string, any];
    const statement = role.Properties.AssumeRolePolicyDocument.Statement[0];
    expect(statement).toEqual({
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        'ForAnyValue:StringLike': {
          'cognito-identity.amazonaws.com:amr': 'authenticated',
        },
        StringEquals: {
          'cognito-identity.amazonaws.com:aud': { Ref: identityPoolId },
        },
      },
      Effect: 'Allow',
      Principal: { Federated: 'cognito-identity.amazonaws.com' },
    });
  });

  it('limits the authenticated role to ListBucket and per-identity Get/Put', () => {
    const { template } = synthesize();
    const roles = template.findResources('AWS::IAM::Role');
    const authenticated = Object.entries(roles).find(([, role]) =>
      JSON.stringify(role).includes('cognito-identity.amazonaws.com'),
    ) as [string, any];
    const [authenticatedRoleId] = authenticated;
    const policies = template.findResources('AWS::IAM::Policy');
    const rolePolicy = Object.values(policies).find((policy: any) =>
      policy.Properties.Roles?.some(
        (role: unknown) => JSON.stringify(role) === JSON.stringify({ Ref: authenticatedRoleId }),
      ),
    ) as any;

    expect(rolePolicy).toBeDefined();
    const statements = rolePolicy.Properties.PolicyDocument.Statement as any[];
    const list = statements.find((statement) => statement.Sid === 'ListOnlyOwnIdentityPrefix');
    const objects = statements.find(
      (statement) => statement.Sid === 'ReadWriteOnlyOwnIdentityObjects',
    );

    expect(asArray(list.Action)).toEqual(['s3:ListBucket']);
    expect(list.Condition.StringLike['s3:prefix']).toEqual([
      '${cognito-identity.amazonaws.com:sub}/*',
    ]);
    expect(asArray(objects.Action)).toEqual(
      expect.arrayContaining(['s3:GetObject', 's3:PutObject']),
    );
    expect(asArray(objects.Action)).toHaveLength(2);
    expect(JSON.stringify(objects.Resource)).toContain(
      '${cognito-identity.amazonaws.com:sub}/*',
    );
    expect(JSON.stringify(rolePolicy)).not.toContain('s3:DeleteObject');
    expect(JSON.stringify(rolePolicy)).not.toContain('s3:*');
  });

  it('attaches only the authenticated role and defines no role mapping', () => {
    const { template } = synthesize();
    const [identityPoolId] = onlyResource(template, 'AWS::Cognito::IdentityPool');
    const roles = template.findResources('AWS::IAM::Role');
    const authenticated = Object.entries(roles).find(([, role]) =>
      JSON.stringify(role).includes('cognito-identity.amazonaws.com'),
    ) as [string, any];
    const [authenticatedRoleId] = authenticated;
    const [, attachment] = onlyResource(
      template,
      'AWS::Cognito::IdentityPoolRoleAttachment',
    );

    expect(attachment.Properties.IdentityPoolId).toEqual({ Ref: identityPoolId });
    expect(attachment.Properties.Roles).toEqual({
      authenticated: { 'Fn::GetAtt': [authenticatedRoleId, 'Arn'] },
    });
    expect(attachment.Properties.RoleMappings).toBeUndefined();
  });

  it('encrypts the lab bucket, blocks public access, and deletes it on cleanup', () => {
    const { template } = synthesize();
    const [, bucket] = onlyResource(template, 'AWS::S3::Bucket');

    expect(bucket.Properties.PublicAccessBlockConfiguration).toEqual({
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    });
    expect(bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration).toEqual([
      { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
    ]);
    expect(bucket.DeletionPolicy).toBe('Delete');
    expect(bucket.UpdateReplacePolicy).toBe('Delete');
    template.resourceCountIs('Custom::S3AutoDeleteObjects', 1);
  });

  it('outputs every value consumed by the live demo plus a lab warning', () => {
    const { template } = synthesize();
    const outputs = template.toJSON().Outputs;

    expect(Object.keys(outputs)).toEqual(
      expect.arrayContaining([
        'UserPoolId',
        'UserPoolClientId',
        'IdentityPoolId',
        'BucketName',
        'Region',
        'LabOnlyWarning',
      ]),
    );
    expect(outputs.LabOnlyWarning.Value).toContain('LAB ONLY');
  });
});
