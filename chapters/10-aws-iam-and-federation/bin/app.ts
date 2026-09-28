/**
 * CDK entry point for chapter 10. Run from inside chapters/10-aws-iam-and-federation:
 *
 *   npx cdk synth                                          # template only, no credentials needed
 *   npx cdk deploy -c githubRepo=<owner>/<repo>            # defaults to refs/heads/main
 *   npx cdk deploy -c githubRepo=o/r -c githubRef=refs/heads/main
 *   npx cdk deploy -c githubProviderArn=arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
 *
 * The stack is environment-agnostic: it has no account or region baked in, so `synth` works
 * offline and `deploy` goes wherever your credentials point.
 */
import { App } from 'aws-cdk-lib';
import { DEFAULT_GITHUB_REPO, GithubOidcStack } from '../lib/github-oidc-stack';

function main(): void {
  const app = new App();
  const githubRepo: string = app.node.tryGetContext('githubRepo') ?? DEFAULT_GITHUB_REPO;
  const githubRef: string | undefined = app.node.tryGetContext('githubRef');
  const trustAllRaw: unknown = app.node.tryGetContext('trustAllRepoSubjects');
  const trustAllRepositorySubjects = trustAllRaw === true || trustAllRaw === 'true';
  const existingProviderArn: string | undefined = app.node.tryGetContext('githubProviderArn');

  new GithubOidcStack(app, 'LabGithubOidcFederation', {
    githubRepo,
    githubRef,
    trustAllRepositorySubjects,
    existingProviderArn,
    description: `identity-security-lab chapter 10: GitHub Actions OIDC federation into AWS for ${githubRepo}`,
  });

  app.synth();
}

main();
