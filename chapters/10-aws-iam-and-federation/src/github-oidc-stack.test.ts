/**
 * The CDK stack, checked offline: `Template.fromStack` synthesizes in memory, no credentials, no
 * network. What we assert is exactly what the README promises about the trust policy.
 */
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_GITHUB_REF,
  DEFAULT_GITHUB_REPO,
  GITHUB_OIDC_AUDIENCE,
  GITHUB_OIDC_ISSUER,
  GithubOidcStack,
  ROLE_NAME,
  trustedSubject,
  type GithubOidcStackProps,
} from '../lib/github-oidc-stack';

function synth(props: GithubOidcStackProps = {}): Template {
  const app = new App({ context: { '@aws-cdk/core:enablePartitionLiterals': true } });
  return Template.fromStack(new GithubOidcStack(app, 'LabGithubOidcFederation', props));
}

describe('trustedSubject', () => {
  it('builds repository-wide trust only when the helper is deliberately called without a ref', () => {
    expect(trustedSubject('ErickrU/identity-security-lab')).toBe('repo:ErickrU/identity-security-lab:*');
  });

  it('narrows to one ref when asked', () => {
    expect(trustedSubject('o/r', 'refs/heads/main')).toBe('repo:o/r:ref:refs/heads/main');
    expect(trustedSubject('o/r', 'refs/tags/v1.0.0')).toBe('repo:o/r:ref:refs/tags/v1.0.0');
  });

  it('refuses wildcards and malformed input, because repo:org/* is the classic over-broad trust', () => {
    expect(() => trustedSubject('ErickrU/*')).toThrow(/owner\/repo with no wildcards/);
    expect(() => trustedSubject('*')).toThrow(/owner\/repo/);
    expect(() => trustedSubject('just-a-name')).toThrow(/owner\/repo/);
    expect(() => trustedSubject('o/r', 'main')).toThrow(/full git ref/);
    expect(() => trustedSubject('o/r', 'refs/heads/*')).toThrow(/no wildcards/);
    expect(() => trustedSubject('o/r', 'refs/heads/?')).toThrow(/no wildcards/);
  });
});

describe('LabGithubOidcFederation stack', () => {
  const template = synth();

  it('creates one native OIDC provider for GitHub with sts.amazonaws.com as the only audience', () => {
    template.resourceCountIs('AWS::IAM::OIDCProvider', 1);
    template.hasResourceProperties('AWS::IAM::OIDCProvider', {
      Url: GITHUB_OIDC_ISSUER,
      ClientIdList: [GITHUB_OIDC_AUDIENCE],
    });
    // no thumbprint pinned: IAM validates GitHub's issuer against its trusted CAs (see the stack comment)
    template.hasResourceProperties('AWS::IAM::OIDCProvider', { ThumbprintList: Match.absent() });
  });

  it('creates the role with a one hour maximum session', () => {
    template.resourceCountIs('AWS::IAM::Role', 1);
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: ROLE_NAME,
      MaxSessionDuration: 3600,
    });
  });

  it('trust policy: AssumeRoleWithWebIdentity from the provider only, aud must equal, sub must match the repository', () => {
    const [providerId] = Object.keys(template.findResources('AWS::IAM::OIDCProvider'));
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'sts:AssumeRoleWithWebIdentity',
            Principal: { Federated: { Ref: providerId } },
            Condition: {
              StringEquals: { 'token.actions.githubusercontent.com:aud': GITHUB_OIDC_AUDIENCE },
              StringLike: { 'token.actions.githubusercontent.com:sub': `repo:${DEFAULT_GITHUB_REPO}:ref:${DEFAULT_GITHUB_REF}` },
            },
          },
        ],
      },
    });
  });

  it('trust policy has exactly one statement and no other principal', () => {
    const roles = template.findResources('AWS::IAM::Role');
    const [role] = Object.values(roles);
    const statements = role.Properties.AssumeRolePolicyDocument.Statement as unknown[];
    expect(statements).toHaveLength(1);
    expect(JSON.stringify(role.Properties.AssumeRolePolicyDocument)).not.toMatch(/"AWS"|"Service"|sts:AssumeRole"/);
  });

  it('grants next to nothing: no managed policies, one inline statement, iam:GetRole on itself', () => {
    const [role] = Object.values(template.findResources('AWS::IAM::Role'));
    expect(role.Properties.ManagedPolicyArns).toBeUndefined();
    expect(role.Properties.Policies).toBeUndefined();

    template.resourceCountIs('AWS::IAM::Policy', 1);
    const [roleId] = Object.keys(template.findResources('AWS::IAM::Role'));
    template.hasResourceProperties('AWS::IAM::Policy', {
      Roles: [{ Ref: roleId }],
      PolicyDocument: {
        Statement: [
          {
            Sid: 'ReadOwnTrustPolicy',
            Effect: 'Allow',
            Action: 'iam:GetRole',
            Resource: { 'Fn::GetAtt': [roleId, 'Arn'] },
          },
        ],
      },
    });
    // nothing else: no Lambda, no custom resource, no bucket
    const types = Object.values(template.toJSON().Resources as Record<string, { Type: string }>)
      .map((r) => r.Type)
      .filter((t) => t !== 'AWS::CDK::Metadata') // the CLI adds this one at synth time, tests do not
      .sort();
    expect(types).toEqual(['AWS::IAM::OIDCProvider', 'AWS::IAM::Policy', 'AWS::IAM::Role']);
  });

  it('outputs the role ARN, the provider ARN and the exact trusted sub pattern', () => {
    const [roleId] = Object.keys(template.findResources('AWS::IAM::Role'));
    const [providerId] = Object.keys(template.findResources('AWS::IAM::OIDCProvider'));
    template.hasOutput('RoleArn', { Value: { 'Fn::GetAtt': [roleId, 'Arn'] } });
    template.hasOutput('ProviderArn', { Value: { Ref: providerId } });
    template.hasOutput('TrustedSubject', { Value: `repo:${DEFAULT_GITHUB_REPO}:ref:${DEFAULT_GITHUB_REF}` });
    template.hasOutput('TrustedAudience', { Value: GITHUB_OIDC_AUDIENCE });
  });

  it('is environment-agnostic: no account or region baked into the template', () => {
    const json = JSON.stringify(template.toJSON());
    expect(json).not.toMatch(/\d{12}/);
    expect(json).not.toMatch(/arn:aws:iam::\d/);
  });
});

describe('context variations', () => {
  it('githubRepo and githubRef narrow the sub condition', () => {
    const template = synth({ githubRepo: 'octo-org/octo-repo', githubRef: 'refs/heads/main' });
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: {
        Statement: [
          Match.objectLike({
            Condition: Match.objectLike({
              StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:octo-org/octo-repo:ref:refs/heads/main' },
            }),
          }),
        ],
      },
    });
    template.hasOutput('TrustedSubject', { Value: 'repo:octo-org/octo-repo:ref:refs/heads/main' });
  });

  it('requires explicit opt-in before trusting every subject in a repository', () => {
    const template = synth({ githubRepo: 'octo-org/octo-repo', trustAllRepositorySubjects: true });
    template.hasOutput('TrustedSubject', { Value: 'repo:octo-org/octo-repo:*' });
    expect(() => synth({ githubRef: 'refs/heads/main', trustAllRepositorySubjects: true })).toThrow(/either/);
  });

  it('existingProviderArn reuses the account provider instead of creating one', () => {
    const arn = 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com';
    const template = synth({ githubRepo: 'o/r', existingProviderArn: arn });
    template.resourceCountIs('AWS::IAM::OIDCProvider', 0);
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: {
        Statement: [Match.objectLike({ Principal: { Federated: arn } })],
      },
    });
    template.hasOutput('ProviderArn', { Value: arn });
  });

  it('refuses a wildcard repository at synth time', () => {
    expect(() => synth({ githubRepo: 'ErickrU/*' })).toThrow(/no wildcards/);
  });
});
