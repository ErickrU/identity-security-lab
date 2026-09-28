# Contributing

Thank you for improving the lab. Keep it readable, runnable and safe.

## Before changing a chapter

1. Read [`docs/CHAPTER_TEMPLATE.md`](docs/CHAPTER_TEMPLATE.md).
2. State the learner's question and the failure the concept was invented to fix.
3. Prefer a small executable mechanism over framework magic.
4. Include at least one attack/failure and prove the implementation rejects it.
5. Cite the primary RFC/standard and current service documentation.

## Content rules

- TL;DR first: complete enough to choose/use/not-use the technology.
- Keep concepts at the right layer. Token is not JWT; SSO is not federation; OAuth is not login;
  authentication is not authorization; IAM Identity Center is not IAM or Cognito.
- Explain who issues, who verifies, which key/proof, audience/recipient, freshness/replay, resulting
  authority and revocation path.
- Use compact tables and diagrams rather than repeating prose.
- Include why invented, mechanism, run steps, scenarios, pros/cons, alternatives, pitfalls and
  primary reading.
- Use inclusive terms: primary/replica, allowlist/denylist, leader/follower.
- Do not present Amazon/AWS product behavior as current without primary documentation. Do not add
  private corporate implementation details.

## Code rules

- TypeScript strict mode; Node built-ins first. Explain every dependency.
- Pin dependency versions exactly.
- Tests must be offline and deterministic; loopback port `0`, injected clocks, no sleeps.
- Never log passwords, private keys, bearer/refresh/session tokens or AWS credential values.
- Security demos may contain deliberately vulnerable code only when the filename/comment/output says
  so and tests contrast it with the correct path.
- Do not implement production cryptography/protocol parsers for reuse. Teaching implementations must
  say what they omit and point to maintained libraries/services.
- AWS CDK tests/synthesis must not deploy. Live scripts need a visible mutation warning, explicit
  confirmation flag, lab/sandbox label and cleanup command.
- No production resource mutation/deletion or protection disablement.

## Validate

```bash
npm install
npm run typecheck
npm test

# Run the chapter demo you changed. Examples:
npm run 03
npm run 06
npm run 13

# AWS chapter template-only checks:
npm run 10:synth
npm run 11:synth
```

For chapter 02, generate the temporary PKI and run server/client. For chapter 08, OpenSSL must be
available. Ensure generated certificates, CDK output and credentials remain ignored.

## Pull request

Explain:

- concept/failure clarified;
- code/demo behavior added;
- negative tests added;
- production omissions/security boundaries;
- commands run and results.
