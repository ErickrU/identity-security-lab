# Chapter conventions

Every chapter lives in `chapters/NN-name/` and follows the same shape so you can
read any of them in the same way.

```
chapters/NN-name/
  README.md        the chapter text (structure below)
  src/             runnable code, TypeScript, run with `npx tsx`
  src/*.test.ts    offline, deterministic tests (vitest)
```

## README structure

```markdown
# NN · Title

> **TL;DR** — 3 to 6 lines. What it is, the problem it solves, when to use it,
> when not to. A reader in a hurry stops here and still leaves with the essentials.

## Why it was invented
The world before it, the specific pain, and the year/standard that fixed it.

## How it works
The mechanism, step by step. One diagram (mermaid) if it helps. Name the
messages, the keys, the claims. Say what is verified and by whom.

## Run it
Exact commands, what you will see, and what to look at in the output.

## Scenarios
Where you meet it in real life. Always include the AWS mapping (Cognito, IAM,
Identity Center, ACM, API Gateway, EKS...) and, when relevant, the Amazon
corporate one (Federate, Midway) at the level of public knowledge.

## Pros and cons
Two short lists. Be honest; every technology here has real downsides.

## Alternatives
What else solves the same problem and when you would pick it instead.

## Pitfalls
The mistakes people actually make with it, and the attack each one enables.

## Further reading
RFCs and primary sources first.
```

## Code conventions

- TypeScript, strict. Prefer Node built-ins (`node:crypto`, `node:http`,
  `node:https`) over dependencies. The whole lab has very few dependencies on
  purpose; do not add one without a reason in the README.
- Demos teach when run: `console.log` the steps, the messages, the decisions
  ("→ rejecting: signature does not match"). Never log secrets you would not
  print in production (passwords, private keys, full refresh tokens).
- Tests are offline and deterministic. Servers bind to port `0` in tests.
- Ports for interactive demos, so chapters can run side by side:
  `01` 4010 · `02` 4443 · small IdP 4000 · resource server 4100 ·
  relying party A 4001 · relying party B 4002.
- Inclusive language: allowlist/denylist, primary/replica.
- Style: short sentences, plain words, tables for comparisons. TL;DR first,
  deep dive after. No marketing adjectives.
