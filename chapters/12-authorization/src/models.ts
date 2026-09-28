/**
 * Three authorization models over one small domain, side by side.
 *
 * The domain is a document service: documents have an owner, a department and a
 * classification; users have roles, a department and a clearance; the actions are
 * view, edit, share and delete. Authentication already happened somewhere else
 * (chapters 03 to 11). Here we only decide, given a verified identity, what it may do.
 *
 *   RBAC   roles → permissions            "what can editors do?"
 *   ABAC   rules over attributes          "may this user do this to this document, now?"
 *   ReBAC  a graph of relationships       "who can see this document?"
 *
 * Every engine returns a `Decision` with a one-line `reason`: an authorization decision
 * you cannot explain is one you cannot audit or debug.
 */

// ---------------------------------------------------------------- domain

export type Action = 'view' | 'edit' | 'share' | 'delete';
export const ACTIONS: readonly Action[] = ['view', 'edit', 'share', 'delete'];

export type Classification = 'public' | 'internal' | 'restricted';
export type Clearance = 'low' | 'high';
export type Role = 'viewer' | 'editor' | 'admin';

export interface User {
  /** Stable identifier: the `sub` claim of a token, never the display name. */
  id: string;
  roles: readonly Role[];
  department: string;
  clearance: Clearance;
}

export interface Document {
  /** Just the id ("42"); the ReBAC engine writes it as `doc:42`. */
  id: string;
  /** User id of the owner. */
  owner: string;
  department: string;
  classification: Classification;
}

export interface Decision {
  allowed: boolean;
  /** One line for the audit log: which role, rule or relationship decided, and why. */
  reason: string;
}

// ---------------------------------------------------------------- RBAC

/**
 * Hierarchical RBAC (NIST RBAC, ANSI INCITS 359-2004, "hierarchical" level): a role
 * inherits every permission of the roles below it, so admin ⊇ editor ⊇ viewer.
 * Two tables instead of one so the hierarchy is data, not four copy-pasted lists.
 */
export const ROLE_INHERITS: Readonly<Record<Role, readonly Role[]>> = {
  viewer: [],
  editor: ['viewer'],
  admin: ['editor'],
};

/** What each role adds on top of what it inherits. Delete is destructive: admins only. */
export const ROLE_GRANTS: Readonly<Record<Role, readonly Action[]>> = {
  viewer: ['view'],
  editor: ['edit', 'share'],
  admin: ['delete'],
};

/** The full permission set of a role, own grants plus everything inherited. */
export function permissionsOf(role: Role): Set<Action> {
  const out = new Set<Action>();
  const visit = (r: Role): void => {
    for (const action of ROLE_GRANTS[r]) out.add(action);
    for (const parent of ROLE_INHERITS[r]) visit(parent);
  };
  visit(role);
  return out;
}

export interface RbacDecision extends Decision {
  /** The role that granted the permission, or null when denied. */
  role: Role | null;
}

/**
 * RBAC: allowed if any of the user's roles grants the action.
 *
 * Look at the signature: there is no resource parameter. That is the blind spot, not a
 * shortcut in this lab. RBAC answers "can editors edit?" and has no words for "only your
 * own documents" or "only documents of your department". To express those you either
 * explode roles (editor-eng, editor-finance, editor-of-doc-42...) or add a second check
 * after RBAC, which is where ABAC and ReBAC come in.
 */
export function rbacAllows(user: Pick<User, 'id' | 'roles'>, action: Action): RbacDecision {
  for (const role of user.roles) {
    if (permissionsOf(role).has(action)) {
      return { allowed: true, role, reason: `role ${role} grants ${action}` };
    }
  }
  const roles = user.roles.length ? user.roles.join(', ') : 'none';
  return { allowed: false, role: null, reason: `no role of ${user.id} grants ${action} (roles: ${roles})` };
}

// ---------------------------------------------------------------- ABAC

export interface Environment {
  /** Current time, ms since the Unix epoch. Injected, so tests and demos are deterministic. */
  now: number;
  /** When the subject last completed MFA, ms since the epoch; null when never or unknown. */
  mfaAt: number | null;
}

/** Everything a rule may look at: subject, action, resource, environment (NIST SP 800-162). */
export interface AbacContext {
  subject: User;
  action: Action;
  resource: Document;
  environment: Environment;
}

export type Effect = 'allow' | 'deny';

export interface Rule {
  id: string;
  effect: Effect;
  /** Plain words, printed in every decision that involves the rule. */
  description: string;
  /** The predicate. True means "this rule applies to this request". */
  when: (ctx: AbacContext) => boolean;
}

/** "Recent" MFA for step-up: 15 minutes, the same order of magnitude as `aws:MultiFactorAuthAge` checks. */
export const MFA_FRESHNESS_MS = 15 * 60 * 1000;
/** Maximum tolerated IdP/service clock difference for a future authentication timestamp. */
export const MAX_MFA_CLOCK_SKEW_MS = 60 * 1000;

export function mfaIsFresh({ now, mfaAt }: Environment): boolean {
  if (mfaAt === null || !Number.isFinite(now) || !Number.isFinite(mfaAt)) return false;
  const age = now - mfaAt;
  return age >= -MAX_MFA_CLOCK_SKEW_MS && age <= MFA_FRESHNESS_MS;
}

/**
 * The policy. Allow rules say what is possible; deny rules are guardrails that hold
 * whatever else matched. Order does not matter: every rule is evaluated and an explicit
 * deny always wins (`abacAllows` below), exactly like an IAM policy.
 */
export const POLICY: readonly Rule[] = [
  {
    id: 'owner-controls-own-documents',
    effect: 'allow',
    description: 'the owner may view, edit and share their own documents (delete is an admin operation)',
    when: ({ subject, resource, action }) => subject.id === resource.owner && action !== 'delete',
  },
  {
    id: 'department-may-view',
    effect: 'allow',
    description: 'anyone may view the documents of their own department',
    when: ({ subject, resource, action }) => action === 'view' && subject.department === resource.department,
  },
  {
    id: 'admins-manage-all-documents',
    effect: 'allow',
    description: 'admins may do anything to any document',
    when: ({ subject }) => subject.roles.includes('admin'),
  },
  {
    id: 'restricted-needs-clearance',
    effect: 'deny',
    description: 'restricted documents need high clearance, whoever you are (owner and admin included)',
    when: ({ subject, resource }) => resource.classification === 'restricted' && subject.clearance === 'low',
  },
  {
    id: 'delete-needs-fresh-mfa',
    effect: 'deny',
    description: 'delete needs MFA within the last 15 minutes',
    when: ({ action, environment }) => action === 'delete' && !mfaIsFresh(environment),
  },
];

export type AbacEffect = 'allow' | 'explicit-deny' | 'implicit-deny';

export interface AbacDecision extends Decision {
  effect: AbacEffect;
  /** Ids of the rules that matched, for the audit log. */
  matchedAllow: string[];
  matchedDeny: string[];
}

/**
 * ABAC evaluation with IAM's logic: explicit deny > explicit allow > implicit deny.
 *
 * Every rule is evaluated, no early exit, so the decision lists everything that matched
 * and does not depend on the order of the rules. Silence is a denial: if nothing allows,
 * the answer is no. This is what makes a policy safe to extend: adding an allow rule can
 * never weaken a deny rule, and forgetting a rule fails closed.
 */
export function abacAllows(ctx: AbacContext, policy: readonly Rule[] = POLICY): AbacDecision {
  const matched = policy.filter((rule) => rule.when(ctx));
  const denies = matched.filter((rule) => rule.effect === 'deny');
  const allows = matched.filter((rule) => rule.effect === 'allow');
  const matchedAllow = allows.map((rule) => rule.id);
  const matchedDeny = denies.map((rule) => rule.id);
  const what = `${ctx.action} on doc:${ctx.resource.id} by ${ctx.subject.id}`;

  if (denies.length > 0) {
    const overridden = allows.length ? `; overrides allow from ${matchedAllow.join(', ')}` : '';
    return {
      allowed: false,
      effect: 'explicit-deny',
      matchedAllow,
      matchedDeny,
      reason: `explicit deny by ${matchedDeny.join(', ')}: ${denies.map((r) => r.description).join('; ')}${overridden}`,
    };
  }
  if (allows.length > 0) {
    return {
      allowed: true,
      effect: 'allow',
      matchedAllow,
      matchedDeny,
      reason: `allowed by ${matchedAllow.join(', ')}: ${allows.map((r) => r.description).join('; ')}`,
    };
  }
  return { allowed: false, effect: 'implicit-deny', matchedAllow, matchedDeny, reason: `implicit deny: no rule allows ${what}` };
}

// ---------------------------------------------------------------- ReBAC

/**
 * Relationship-based access control, Zanzibar style (Google, 2019).
 *
 * Everything is a tuple `object#relation@subject`:
 *
 *   doc:42#owner@user:alice                alice owns document 42
 *   doc:42#parent@folder:roadmaps          document 42 lives in folder "roadmaps"
 *   group:eng#member@user:bob              bob is a member of group eng
 *   folder:roadmaps#editor@group:eng#member every member of eng is an editor of the folder
 *
 * The last subject is a *userset* (`group:eng#member`): not one user but "whoever has
 * relation member on group:eng", resolved recursively at check time. Groups, nested
 * groups and sharing are all the same mechanism.
 *
 * The schema below is the Zanzibar "namespace configuration": which relations exist and
 * how they derive from each other. Two kinds of derivation are enough for this lab:
 *
 *   includes   a computed userset on the same object: every owner is an editor, every
 *              editor is a viewer (the role hierarchy, expressed per object)
 *   viaParent  a tuple-to-userset: viewers of the parent folder are viewers of the doc
 */
interface RelationDef {
  includes?: readonly string[];
  viaParent?: string;
  /** Structural relations such as `parent`: the subject is an object of this namespace, not a user. */
  objectSubject?: string;
}

export const SCHEMA: Readonly<Record<string, Readonly<Record<string, RelationDef>>>> = {
  doc: {
    owner: {},
    editor: { includes: ['owner'], viaParent: 'editor' },
    viewer: { includes: ['editor'], viaParent: 'viewer' },
    parent: { objectSubject: 'folder' },
  },
  folder: {
    owner: {},
    editor: { includes: ['owner'], viaParent: 'editor' },
    viewer: { includes: ['editor'], viaParent: 'viewer' },
    parent: { objectSubject: 'folder' },
  },
  group: {
    member: {},
  },
};

/** Which relation each action needs. Sharing and deleting are for owners. */
export const ACTION_RELATION: Readonly<Record<Action, string>> = {
  view: 'viewer',
  edit: 'editor',
  share: 'owner',
  delete: 'owner',
};

export interface Tuple {
  object: string;
  relation: string;
  /** `user:alice`, or an object such as `group:eng` when `subjectRelation` is set. */
  subject: string;
  /** Set for usersets: `group:eng#member` → subject `group:eng`, subjectRelation `member`. */
  subjectRelation?: string;
}

function namespaceOf(ref: string): string {
  const i = ref.indexOf(':');
  if (i <= 0 || i === ref.length - 1) throw new Error(`rebac: "${ref}" is not a namespace:id reference`);
  return ref.slice(0, i);
}

function relationDef(object: string, relation: string): RelationDef {
  const ns = namespaceOf(object);
  if (!Object.hasOwn(SCHEMA, ns)) throw new Error(`rebac: unknown namespace "${ns}" in "${object}"`);
  if (!Object.hasOwn(SCHEMA[ns], relation)) throw new Error(`rebac: "${ns}" has no relation "${relation}"`);
  return SCHEMA[ns][relation];
}

/**
 * Parse `object#relation@user:x`, `object#relation@object#relation` (a userset) or, for
 * structural relations, `object#parent@folder:f`. Anything else throws: a store that accepts
 * typos silently is a store whose checks silently fail closed for the wrong people.
 */
export function parseTuple(spec: string): Tuple {
  const at = spec.indexOf('@');
  if (at < 0) throw new Error(`rebac: "${spec}" is missing "@subject"`);
  const [object, relation, ...restLeft] = spec.slice(0, at).split('#');
  if (!object || !relation || restLeft.length) throw new Error(`rebac: "${spec}" must start with object#relation`);
  const def = relationDef(object, relation);

  const [subject, subjectRelation, ...restRight] = spec.slice(at + 1).split('#');
  if (!subject || restRight.length) throw new Error(`rebac: "${spec}" has a malformed subject`);

  if (def.objectSubject) {
    if (subjectRelation !== undefined || namespaceOf(subject) !== def.objectSubject) {
      throw new Error(`rebac: the subject of ${object}#${relation} must be a ${def.objectSubject}`);
    }
    return { object, relation, subject };
  }
  if (subjectRelation !== undefined) {
    relationDef(subject, subjectRelation);
    return { object, relation, subject, subjectRelation };
  }
  if (namespaceOf(subject) !== 'user') {
    throw new Error(`rebac: subject "${subject}" must be a user or an object#relation userset`);
  }
  return { object, relation, subject };
}

export function formatTuple({ object, relation, subject, subjectRelation }: Tuple): string {
  return `${object}#${relation}@${subject}${subjectRelation ? `#${subjectRelation}` : ''}`;
}

/** The relationship store. In production this is a database (or a Zanzibar service); here, an array. */
export class TupleStore {
  private readonly tuples: Tuple[] = [];

  add(...specs: string[]): this {
    for (const spec of specs) {
      const t = parseTuple(spec);
      if (!this.tuples.some((x) => formatTuple(x) === formatTuple(t))) this.tuples.push(t);
    }
    return this;
  }

  /** Revocation is deleting a tuple: the next check sees it immediately. */
  remove(spec: string): boolean {
    const key = formatTuple(parseTuple(spec));
    const i = this.tuples.findIndex((t) => formatTuple(t) === key);
    if (i < 0) return false;
    this.tuples.splice(i, 1);
    return true;
  }

  find(object: string, relation: string): Tuple[] {
    return this.tuples.filter((t) => t.object === object && t.relation === relation);
  }

  list(): string[] {
    return this.tuples.map(formatTuple);
  }
}

export interface RebacDecision extends Decision {
  /** The chain of tuples and schema steps that connects the object to the user; empty when denied. */
  path: string[];
}

/**
 * ReBAC check: is `user` reachable from `object#relation` through the graph?
 *
 * A depth-first search over four kinds of edges: direct tuples, usersets (recurse into the
 * group), `includes` (recurse into the stronger relation on the same object) and
 * `viaParent` (recurse into the parent folder). `visited` stops cycles (a folder that is its
 * own ancestor) and avoids re-walking a node. The path is returned so the decision can be
 * explained: "bob can edit doc 42 because it is in a folder shared with a group he is in".
 */
export function rebacAllows(store: TupleStore, user: string, relation: string, object: string): RebacDecision {
  if (namespaceOf(user) !== 'user') throw new Error(`rebac: "${user}" is not a user reference`);
  relationDef(object, relation);
  const path = walk(store, object, relation, user, new Set());
  if (path) return { allowed: true, path, reason: `allowed: ${path.join(' → ')}` };
  return { allowed: false, path: [], reason: `denied: no relationship path from ${object}#${relation} to ${user}` };
}

function walk(store: TupleStore, object: string, relation: string, user: string, visited: Set<string>): string[] | null {
  const node = `${object}#${relation}`;
  if (visited.has(node)) return null;
  visited.add(node);

  for (const t of store.find(object, relation)) {
    if (t.subjectRelation === undefined) {
      if (t.subject === user) return [formatTuple(t)];
    } else {
      const inner = walk(store, t.subject, t.subjectRelation, user, visited);
      if (inner) return [formatTuple(t), ...inner];
    }
  }

  const def = relationDef(object, relation);
  for (const stronger of def.includes ?? []) {
    const inner = walk(store, object, stronger, user, visited);
    if (inner) return [`${node} includes ${object}#${stronger}`, ...inner];
  }
  if (def.viaParent) {
    for (const parentTuple of store.find(object, 'parent')) {
      const inner = walk(store, parentTuple.subject, def.viaParent, user, visited);
      if (inner) return [formatTuple(parentTuple), ...inner];
    }
  }
  return null;
}

/**
 * The reverse question, "who has `relation` on `object`?", as a set of users.
 *
 * Same graph, walked the other way: expand every userset, every included relation and
 * every parent. This is Zanzibar's `Expand`. It is natural here and awkward in RBAC (the
 * model does not know the object exists) and expensive in ABAC (evaluate every user).
 */
export function whoCan(store: TupleStore, relation: string, object: string): string[] {
  relationDef(object, relation);
  const users = new Set<string>();
  expand(store, object, relation, users, new Set());
  return [...users].sort();
}

function expand(store: TupleStore, object: string, relation: string, users: Set<string>, visited: Set<string>): void {
  const node = `${object}#${relation}`;
  if (visited.has(node)) return;
  visited.add(node);

  const def = relationDef(object, relation);
  if (def.objectSubject) return; // structural relation (parent): its subjects are folders, not users

  for (const t of store.find(object, relation)) {
    if (t.subjectRelation === undefined) users.add(t.subject);
    else expand(store, t.subject, t.subjectRelation, users, visited);
  }
  for (const stronger of def.includes ?? []) expand(store, object, stronger, users, visited);
  if (def.viaParent) {
    for (const parentTuple of store.find(object, 'parent')) expand(store, parentTuple.subject, def.viaParent, users, visited);
  }
}
