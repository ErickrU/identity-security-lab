/**
 * Chapter 12 demo: one question, "may bob edit alice's document?", answered by RBAC, ABAC
 * and ReBAC, then the same question asked the way production asks it: a token arrives.
 *
 *   npm run 12
 *
 * Everything is offline and deterministic (fixed clock, fixed users). Read the output top to
 * bottom; every decision prints the reason it was taken.
 */
import { decisionFromClaims, type ChainDecision, type VerifiedClaims } from './claims';
import {
  ACTIONS,
  ACTION_RELATION,
  POLICY,
  abacAllows,
  permissionsOf,
  rbacAllows,
  rebacAllows,
  whoCan,
  type Action,
  type Document,
  type Role,
  type User,
} from './models';
import { DOCUMENTS, MINUTE, NOW, SHARE_ROADMAPS_WITH_ENG, USERS, baseTuples, lookupUser } from './scenario';

// ---------------------------------------------------------------- helpers

const ROLES: readonly Role[] = ['viewer', 'editor', 'admin'];

function heading(text: string): void {
  console.log(`\n${text}`);
}

function verdict(allowed: boolean, reason: string): string {
  return `→ ${allowed ? 'ALLOWED' : 'denied '}  ${reason}`;
}

function describe(user: User): string {
  return `${user.id} (${user.roles.join('+')}, ${user.department}, ${user.clearance} clearance)`;
}

function describeDoc(doc: Document): string {
  return `doc:${doc.id} (owner ${doc.owner}, ${doc.department}, ${doc.classification})`;
}

function utc(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** The claims an authorizer would hand over for `user` after a login `minutesAgo` minutes ago. */
function tokenFor(user: User, overrides: Partial<VerifiedClaims> = {}, minutesAgo = 5): VerifiedClaims {
  const groups = user.roles.map((role) => `docs-${role}s`); // docs-viewers, docs-editors, docs-admins
  return {
    sub: user.id,
    username: user.id,
    groups,
    scope: 'openid docs:read docs:write',
    amr: ['pwd'],
    auth_time: Math.floor((NOW - minutesAgo * MINUTE) / 1000),
    ...overrides,
  };
}

function printChain(title: string, decision: ChainDecision): void {
  console.log(`  ${title}`);
  for (const step of decision.steps) {
    console.log(`    [${step.layer.padEnd(8)}] ${step.ok ? 'pass' : 'STOP'}  ${step.check}`);
    console.log(`               ${step.detail}`);
  }
  console.log(`    → HTTP ${decision.status}, decided at the ${decision.decidedAt} layer: ${decision.reason}`);
}

// ---------------------------------------------------------------- the walkthrough

function main(): void {
  const { alice, bob, carol, dave } = USERS;
  const { roadmap, incident } = DOCUMENTS;
  const env = (mfaMinutesAgo: number | null) => ({ now: NOW, mfaAt: mfaMinutesAgo === null ? null : NOW - mfaMinutesAgo * MINUTE });

  console.log('Chapter 12 · Authorization: authentication said who; this decides what they may do.');
  console.log(`\nThe question all the way through: may ${describe(bob)} EDIT ${describeDoc(roadmap)}?`);
  console.log(`Cast: ${Object.values(USERS).map(describe).join('; ')}.`);
  console.log(`Clock fixed at ${utc(NOW)}.`);

  // 1) RBAC ------------------------------------------------------------------------------
  heading('1) RBAC: roles → permissions. The question it answers is "what can editors do?"');
  console.log('  role     permissions (own + inherited: admin ⊇ editor ⊇ viewer)');
  for (const role of ROLES) console.log(`  ${role.padEnd(8)} ${[...permissionsOf(role)].join(', ')}`);
  console.log();
  const rbacBob = rbacAllows(bob, 'edit');
  console.log(`  bob edit    ${verdict(rbacBob.allowed, rbacBob.reason)}`);
  const rbacCarol = rbacAllows(carol, 'edit');
  console.log(`  carol edit  ${verdict(rbacCarol.allowed, rbacCarol.reason)}`);
  const rbacBobDelete = rbacAllows(bob, 'delete');
  console.log(`  bob delete  ${verdict(rbacBobDelete.allowed, rbacBobDelete.reason)}`);
  console.log(`
  Look at what rbacAllows() received: a user and an action. No document. Bob may edit alice's
  roadmap, the restricted incident report, carol's budget, everything: the model has no words for
  "only your own" or "only your department". Cheap, easy to reason about, and too coarse for
  anything owned by someone.`);

  // 2) ABAC ------------------------------------------------------------------------------
  heading('2) ABAC: rules over attributes of subject, action, resource and environment.');
  console.log('  policy (evaluated in full, every time; explicit deny > explicit allow > implicit deny):');
  for (const rule of POLICY) console.log(`    ${rule.effect.padEnd(5)} ${rule.id.padEnd(28)} ${rule.description}`);
  console.log();
  const abacCases: Array<[User, Action, Document, string]> = [
    [bob, 'edit', roadmap, 'bob edit roadmap    '],
    [bob, 'view', roadmap, 'bob view roadmap    '],
    [alice, 'edit', roadmap, 'alice edit roadmap  '],
    [bob, 'view', incident, 'bob view incident   '],
    [alice, 'view', incident, 'alice view incident '],
    [carol, 'view', roadmap, 'carol view roadmap  '],
  ];
  for (const [user, action, doc, label] of abacCases) {
    const d = abacAllows({ subject: user, action, resource: doc, environment: env(null) });
    console.log(`  ${label}${verdict(d.allowed, `${d.effect}. ${d.reason}`)}`);
  }
  console.log(`
  Same bob, same roadmap: denied to edit (no rule says so, and silence is a no), allowed to view
  (same department). The incident report is restricted and bob's clearance is low, so the deny rule
  fires even though the department rule matched: an explicit deny wins over an explicit allow. The
  policy reads like the requirements document. The price: every attribute must be correct and
  available at decision time, and "who can see this document?" means evaluating every user.`);

  // 3) ReBAC -----------------------------------------------------------------------------
  heading('3) ReBAC: a graph of relationships. Access is a path from the object to the user.');
  const graph = baseTuples();
  console.log('  tuples (object#relation@subject):');
  for (const t of graph.list()) console.log(`    ${t}`);
  console.log('  schema: owner ⊆ editor ⊆ viewer on docs and folders; editor/viewer of a doc inherit from its parent folder.');
  console.log();
  const before = rebacAllows(graph, 'user:bob', ACTION_RELATION.edit, 'doc:42');
  console.log(`  bob editor doc:42   ${verdict(before.allowed, before.reason)}`);
  const aliceEdit = rebacAllows(graph, 'user:alice', ACTION_RELATION.edit, 'doc:42');
  console.log(`  alice editor doc:42 ${verdict(aliceEdit.allowed, aliceEdit.reason)}`);
  console.log(`\n  alice shares the folder with her team. That is one new tuple: ${SHARE_ROADMAPS_WITH_ENG}`);
  graph.add(SHARE_ROADMAPS_WITH_ENG);
  const after = rebacAllows(graph, 'user:bob', ACTION_RELATION.edit, 'doc:42');
  console.log(`  bob editor doc:42   ${verdict(after.allowed, '')}`);
  console.log(`      path: ${after.path.join('\n            → ')}`);
  const carolAfter = rebacAllows(graph, 'user:carol', ACTION_RELATION.edit, 'doc:42');
  console.log(`  carol editor doc:42 ${verdict(carolAfter.allowed, carolAfter.reason)}`);
  console.log(`
  Nothing about bob changed. Nothing about the document changed. A relationship appeared between the
  folder and a group he is in, and the check found the path: doc → parent folder → shared with
  group → bob is a member. Remove the tuple and the path is gone, immediately. This is how Google
  Drive (Zanzibar's first users) and every "share with..." button work.`);

  // 4) A token arrives -------------------------------------------------------------------
  heading('4) Production: a token arrives. Scope at the edge, roles in the service, the resource last.');
  const bobToken = tokenFor(bob, { groups: ['docs-editors', 'superuser'] });
  console.log(`  bob's verified claims: ${JSON.stringify(bobToken)}`);
  console.log(`  ("superuser" is a group the IdP administrator created; this application has never heard of it.)\n`);
  printChain('bob edits doc:42, folder not shared:', decisionFromClaims(bobToken, 'edit', roadmap, { lookupUser, tuples: baseTuples(), now: NOW }));
  console.log();
  printChain('bob edits doc:42 after alice shared the folder:', decisionFromClaims(bobToken, 'edit', roadmap, { lookupUser, tuples: graph, now: NOW }));
  console.log();
  const readOnlyClient = tokenFor(bob, { scope: 'openid docs:read' });
  printChain('bob, through a client that only asked for docs:read, edits doc:42:', decisionFromClaims(readOnlyClient, 'edit', roadmap, { lookupUser, tuples: graph, now: NOW }));
  console.log();
  const partnerToken = tokenFor(bob, { groups: ['admin', 'Admin', 'docs-admin'] });
  printChain('a token whose groups say "admin" but not in our allowlist:', decisionFromClaims(partnerToken, 'view', roadmap, { lookupUser, now: NOW }));
  console.log(`
  Three layers, three vocabularies. The scope stopped a client, not a user: bob is allowed to edit,
  that app was not allowed to ask. The group→role step turned the IdP's strings into our roles and
  dropped the rest: "admin" from a directory we do not administer is just a word. Only the last
  layer looked at doc:42, because only the last layer had loaded it.`);

  // 5) Deny overrides allow --------------------------------------------------------------
  heading('5) Explicit deny beats explicit allow: delete needs MFA in the last 15 minutes.');
  const noMfa = tokenFor(dave, { amr: ['pwd'] }, 2);
  printChain('dave (admin) deletes doc:42, password only:', decisionFromClaims(noMfa, 'delete', roadmap, { lookupUser, now: NOW }));
  console.log();
  const staleMfa = tokenFor(dave, { amr: ['pwd', 'mfa'] }, 40);
  printChain('dave deletes doc:42, MFA done 40 minutes ago:', decisionFromClaims(staleMfa, 'delete', roadmap, { lookupUser, now: NOW }));
  console.log();
  const freshMfa = tokenFor(dave, { amr: ['pwd', 'mfa'] }, 2);
  printChain('dave deletes doc:42, MFA done 2 minutes ago:', decisionFromClaims(freshMfa, 'delete', roadmap, { lookupUser, now: NOW }));
  console.log();
  const shared = baseTuples().add('doc:7#viewer@user:bob');
  printChain('bob views the restricted incident report that alice shared with him directly:', decisionFromClaims(tokenFor(bob), 'view', incident, { lookupUser, tuples: shared, now: NOW }));
  console.log(`
  The admin rule allowed. The MFA rule denied. Deny won, and the audit line says both. Step-up
  authentication is one rule, not a special case. And the last case shows the guardrail holding
  against the sharing graph: alice can share the incident report with bob, the relationship exists,
  and bob still cannot read it, because clearance is not something a share button hands out.`);

  // 6) The reverse query -----------------------------------------------------------------
  heading('6) The reverse question: who can VIEW doc:42?');
  const everyone = Object.values(USERS) as readonly User[];
  const rbacViewers = everyone.filter((u) => rbacAllows(u, 'view').allowed).map((u) => u.id);
  console.log(`  RBAC   ${rbacViewers.join(', ')}   (every role grants view; the model does not know doc:42 exists)`);
  const abacViewers = everyone
    .filter((u) => abacAllows({ subject: u, action: 'view', resource: roadmap, environment: env(null) }).allowed)
    .map((u) => u.id);
  console.log(`  ABAC   ${abacViewers.join(', ')}   (correct, but it took ${everyone.length} policy evaluations, one per user in the company)`);
  const rebacViewers = whoCan(graph, 'viewer', 'doc:42');
  console.log(`  ReBAC  ${rebacViewers.join(', ')}   (one graph expansion from doc:42#viewer)`);
  for (const user of rebacViewers) {
    console.log(`         ${user.padEnd(11)} ${rebacAllows(graph, user, 'viewer', 'doc:42').path.join(' → ')}`);
  }
  console.log(`
  "What can bob do?" is RBAC's home turf. "Who can see this?" is ReBAC's: the answer is a walk from
  the object. ABAC can answer both, by brute force. Pick the model by the questions you will ask.

  What each model needs at decision time, for the same request:`);
  console.log('  model   inputs                                              blind spot');
  console.log('  RBAC    user roles                                          the resource');
  console.log('  ABAC    user + resource attributes + environment            listing (who can?)');
  console.log('  ReBAC   the relationship graph                              conditions (time, MFA, clearance)');
  console.log(`\n  Actions in this domain: ${ACTIONS.join(', ')}. Done.`);
}

main();
