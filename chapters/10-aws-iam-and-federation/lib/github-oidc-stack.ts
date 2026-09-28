/**
 * Chapter 10: federation into AWS with OpenID Connect, GitHub Actions as the worked example.
 *
 * What gets created:
 *   - one IAM OIDC identity provider for https://token.actions.githubusercontent.com, audience
 *     sts.amazonaws.com (an account has at most one provider per issuer URL);
 *   - one role, lab-github-actions-readonly, whose trust policy accepts
 *     sts:AssumeRoleWithWebIdentity only from that provider, only when the token's `aud` is
 *     sts.amazonaws.com and its `sub` names one repository (optionally one ref);
 *   - almost no permissions: the role may describe itself, nothing else. The point is to prove
 *     identity without storing an AWS secret anywhere.
 *
 * Deploy it yourself (the lab never deploys): see README.md → Run it.
 */
import { CfnOutput, Duration, Stack, type StackProps } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import type { Construct } from 'constructs';

export const GITHUB_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
/** The host part of the issuer is the prefix of the condition keys: `<host>:aud`, `<host>:sub`. */
export const GITHUB_OIDC_CLAIM_PREFIX = 'token.actions.githubusercontent.com';
/** What the workflow asks GitHub to put in `aud`, and the only client id the provider accepts. */
export const GITHUB_OIDC_AUDIENCE = 'sts.amazonaws.com';
export const DEFAULT_GITHUB_REPO = 'ErickrU/identity-security-lab';
export const DEFAULT_GITHUB_REF = 'refs/heads/main';
export const ROLE_NAME = 'lab-github-actions-readonly';

export interface GithubOidcStackProps extends StackProps {
  /** `owner/repo`. No wildcards: the whole point is to trust exactly one repository. */
  readonly githubRepo?: string;
  /** Optional full git ref. The stack defaults to refs/heads/main. */
  readonly githubRef?: string;
  /** Deliberate opt-in to every branch, tag, PR and environment in this repository. */
  readonly trustAllRepositorySubjects?: boolean;
  /** Reuse a provider that already exists in the account (there can be only one per issuer URL). */
  readonly existingProviderArn?: string;
}

const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/**
 * The exact value the trust policy will compare `token.actions.githubusercontent.com:sub` against.
 *
 *   repo:<owner>/<repo>:*                         any branch, tag, pull request or environment of the repo
 *   repo:<owner>/<repo>:ref:refs/heads/main       pushes to main only (workflow_dispatch on main counts)
 *
 * Other shapes GitHub emits: `repo:o/r:ref:refs/tags/v1`, `repo:o/r:pull_request`,
 * `repo:o/r:environment:prod`. Narrow to what the workflow really needs.
 */
export function trustedSubject(githubRepo: string, githubRef?: string): string {
  if (!REPO_PATTERN.test(githubRepo)) {
    throw new Error(`githubRepo must look like owner/repo with no wildcards, got "${githubRepo}"`);
  }
  if (githubRef !== undefined) {
    // IAM StringLike treats both * and ? as wildcards. A ref is intended to be exact.
    if (!githubRef.startsWith('refs/') || /[*?]/.test(githubRef)) {
      throw new Error(`githubRef must be a full git ref with no wildcards, such as refs/heads/main, got "${githubRef}"`);
    }
    return `repo:${githubRepo}:ref:${githubRef}`;
  }
  return `repo:${githubRepo}:*`;
}

export class GithubOidcStack extends Stack {
  public readonly role: iam.Role;
  public readonly provider: iam.IOidcProvider;
  public readonly subject: string;

  constructor(scope: Construct, id: string, props: GithubOidcStackProps = {}) {
    super(scope, id, props);

    const githubRepo = props.githubRepo ?? DEFAULT_GITHUB_REPO;
    if (props.trustAllRepositorySubjects && props.githubRef) {
      throw new Error('choose either githubRef or trustAllRepositorySubjects, not both');
    }
    const ref = props.trustAllRepositorySubjects ? undefined : (props.githubRef ?? DEFAULT_GITHUB_REF);
    this.subject = trustedSubject(githubRepo, ref);

    // The identity provider: "this account trusts tokens whose `iss` is GitHub's issuer, when
    // their `aud` is sts.amazonaws.com". STS fetches the issuer's signing keys from
    // <issuer>/.well-known/openid-configuration → jwks_uri and verifies the token signature itself.
    //
    // No thumbprint on purpose. A thumbprint pins the CA of the issuer's TLS certificate. Since
    // 2023 IAM validates token.actions.githubusercontent.com (and other well-known issuers)
    // against its own library of trusted root CAs, so the thumbprint list is ignored for it.
    // If the API still wants one, IAM computes it from the live certificate when the provider
    // is created, which is what happens here.
    //
    // OidcProviderNative is the AWS::IAM::OIDCProvider resource; the older OpenIdConnectProvider
    // construct is a Lambda-backed custom resource from before CloudFormation supported it.
    this.provider = props.existingProviderArn
      ? iam.OidcProviderNative.fromOidcProviderArn(this, 'GithubProvider', props.existingProviderArn)
      : new iam.OidcProviderNative(this, 'GithubProvider', {
          url: GITHUB_OIDC_ISSUER,
          clientIds: [GITHUB_OIDC_AUDIENCE],
        });

    // The trust policy. Every one of these conditions closes a door:
    //   Federated principal = this provider   → only tokens signed by GitHub's issuer
    //   aud == sts.amazonaws.com               → only tokens minted for AWS (not for another relying party)
    //   sub like repo:<owner>/<repo>:*         → only workflows of this repository
    // A trust policy without the `sub` condition trusts every GitHub repository in the world.
    this.role = new iam.Role(this, 'ReadOnlyRole', {
      roleName: ROLE_NAME,
      description: `Assumable only by GitHub Actions workflows of ${githubRepo} through OIDC. Grants next to nothing.`,
      maxSessionDuration: Duration.hours(1),
      assumedBy: new iam.OpenIdConnectPrincipal(this.provider, {
        StringEquals: { [`${GITHUB_OIDC_CLAIM_PREFIX}:aud`]: GITHUB_OIDC_AUDIENCE },
        StringLike: { [`${GITHUB_OIDC_CLAIM_PREFIX}:sub`]: this.subject },
      }),
    });

    // Permissions: the demo proves *who* the workflow is, not what it may do. sts:GetCallerIdentity
    // needs no permission at all. The single grant below lets the workflow read the trust policy
    // that let it in, and nothing else in the account.
    this.role.addToPolicy(
      new iam.PolicyStatement({
        sid: 'ReadOwnTrustPolicy',
        actions: ['iam:GetRole'],
        resources: [this.role.roleArn],
      }),
    );

    new CfnOutput(this, 'RoleArn', {
      value: this.role.roleArn,
      description: 'Paste this into the GitHub repository variable AWS_OIDC_ROLE_ARN',
    });
    new CfnOutput(this, 'ProviderArn', {
      value: this.provider.oidcProviderArn,
      description: 'The IAM OIDC identity provider for GitHub Actions (one per account per issuer)',
    });
    new CfnOutput(this, 'TrustedSubject', {
      value: this.subject,
      description: `${GITHUB_OIDC_CLAIM_PREFIX}:sub must match this pattern (StringLike)`,
    });
    new CfnOutput(this, 'TrustedAudience', {
      value: GITHUB_OIDC_AUDIENCE,
      description: `${GITHUB_OIDC_CLAIM_PREFIX}:aud must equal this (StringEquals)`,
    });
  }
}
