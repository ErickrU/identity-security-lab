/**
 * From verified token claims to a decision, in three layers.
 *
 * The authorizer (an API Gateway JWT authorizer, a Lambda authorizer, an OIDC relying party,
 * a Kerberos service) has done its job: signature, issuer, audience, expiry are checked and
 * the application receives claims it can trust. Trusting that they are genuine is not the
 * same as trusting what they mean. Each kind of claim answers a different question and is
 * checked in a different place:
 *
 *   scope            what the CLIENT application was allowed to ask for (OAuth delegation).
 *                    Checked at the EDGE (gateway, per route) before the service runs.
 *                    "docs:write" means "this app may edit documents on the user's behalf",
 *                    not "this user may edit this document".
 *   groups           who the USER is in the organisation, as the IdP sees it.
 *                    Mapped to this application's roles through an allowlist, in the SERVICE.
 *                    A group name is a string chosen by whoever administers the IdP; the
 *                    application decides what it means here, never the other way round.
 *   amr, auth_time   how and when the user authenticated. Fed to the policy as environment.
 *   (resource data)  who owns THIS document, which department, which classification, who it
 *                    was shared with. Not in the token at all: the token was minted before the
 *                    request existed. Checked in the DATA LAYER, once the resource is loaded.
 *
 * Every layer narrows. Passing one buys the right to be evaluated by the next, nothing more.
 */
import {
  ACTION_RELATION,
  abacAllows,
  rbacAllows,
  rebacAllows,
  type Action,
  type Document,
  type Role,
  type TupleStore,
  type User,
} from './models';

/** The claims an authorizer hands over. `sub` is the identity; everything else is context. */
export interface VerifiedClaims {
  sub: string;
  /** For logs and greetings only. Usernames get renamed and reassigned; `sub` does not. */
  username?: string;
  /** Group names from the IdP. Cognito puts them in `cognito:groups`, most others in `groups`. */
  groups?: readonly string[];
  'cognito:groups'?: readonly string[];
  /** RFC 6749 section 3.3: space-delimited, case-sensitive. */
  scope?: string;
  /** RFC 8176 authentication methods references: ["pwd"], ["pwd", "mfa"], ["pwd", "otp"]... */
  amr?: readonly string[];
  /** OIDC Core section 2: when the user authenticated, seconds since the epoch. */
  auth_time?: number;
  [claim: string]: unknown;
}

// ---------------------------------------------------------------- layer 1: scopes (edge)

/**
 * Which scope a route needs. Coarse on purpose: three scopes for a whole API. Scopes are
 * for limiting what a third-party client may attempt, not for expressing business rules.
 */
export const SCOPE_FOR_ACTION: Readonly<Record<Action, string>> = {
  view: 'docs:read',
  edit: 'docs:write',
  share: 'docs:write',
  delete: 'docs:write',
};

export function scopesOf(claims: VerifiedClaims): Set<string> {
  return new Set((claims.scope ?? '').split(' ').filter(Boolean));
}

// ---------------------------------------------------------------- layer 2: groups → roles (service)

/**
 * The allowlist. Only these exact strings become roles; anything else is ignored and
 * reported. A `Map`, not an object literal, so a group called "constructor" or "__proto__"
 * cannot accidentally resolve to something. Case-sensitive: "Admin" is not "docs-admins".
 *
 * Why an allowlist and not `role = group as Role`: the IdP may be a partner's, a merged
 * company's, or a SaaS directory with self-service groups. A string in a token proves the
 * IdP said it, not that it means anything in this application.
 */
export const GROUP_TO_ROLE: ReadonlyMap<string, Role> = new Map<string, Role>([
  ['docs-viewers', 'viewer'],
  ['docs-editors', 'editor'],
  ['docs-admins', 'admin'],
]);

export interface RoleMapping {
  roles: Role[];
  /** Groups the token carried that mean nothing here. Log them; do not act on them. */
  ignored: string[];
}

export function rolesFromGroups(groups: readonly string[]): RoleMapping {
  const roles = new Set<Role>();
  const ignored: string[] = [];
  for (const group of groups) {
    const role = GROUP_TO_ROLE.get(group);
    if (role) roles.add(role);
    else ignored.push(group);
  }
  return { roles: [...roles], ignored };
}

export function groupsOf(claims: VerifiedClaims): readonly string[] {
  return claims.groups ?? claims['cognito:groups'] ?? [];
}

// ---------------------------------------------------------------- environment: MFA freshness

/** RFC 8176 values that mean a second factor was used next to the password. */
const SECOND_FACTORS: ReadonlySet<string> = new Set(['otp', 'hwk', 'swk', 'fpt', 'face', 'sc']);

/**
 * When did this user last do MFA, according to the token? `null` when the token cannot say.
 *
 * `amr` lists how the user authenticated; "mfa" is RFC 8176's explicit marker, and some IdPs
 * list the methods instead ("pwd" plus "otp"). `auth_time` says when. Without both we cannot
 * judge freshness, and "cannot judge" must read as "no": an absent claim is not a weak yes.
 * (Same lesson as IAM's `aws:MultiFactorAuthPresent`, which is absent, not false, for
 * long-term keys; chapter 09.)
 */
export function mfaTimeFromClaims(claims: VerifiedClaims): number | null {
  const amr = claims.amr ?? [];
  const usedMfa = amr.includes('mfa') || (amr.includes('pwd') && amr.some((m) => SECOND_FACTORS.has(m)));
  if (!usedMfa || typeof claims.auth_time !== 'number') return null;
  return claims.auth_time * 1000;
}

// ---------------------------------------------------------------- the chain

export type Layer = 'edge' | 'service' | 'resource';

export interface Step {
  layer: Layer;
  /** What was checked, in plain words. */
  check: string;
  ok: boolean;
  detail: string;
}

export interface ChainDecision {
  allowed: boolean;
  /**
   * 200 when allowed, 403 when a layer said no. Never 401: the claims are already verified,
   * so "who are you?" was answered. 403 says "I know who you are, and no". (Whether to say
   * 404 instead, to hide that the document exists, is the caller's call; see the README.)
   */
  status: 200 | 403;
  /** The layer whose answer was final. */
  decidedAt: Layer;
  /** Every check that ran, in order, for the audit log and for the demo. */
  steps: Step[];
  reason: string;
}

export interface ChainOptions {
  /** Policy Information Point: attributes the token does not carry, looked up by `sub`. */
  lookupUser: (sub: string) => Pick<User, 'department' | 'clearance'> | undefined;
  /** Relationship tuples, when the service supports sharing. Optional: the policy alone is a complete answer. */
  tuples?: TupleStore;
  /** Current time, ms since the epoch. Default `Date.now()`. */
  now?: number;
}

/**
 * The whole chain for one request: `action` on `resource` by whoever the claims describe.
 *
 *   edge      is the needed scope in the token?                        gateway, before the service
 *   service   do the groups map to a role, and may that role even try? before loading the resource
 *   resource  what does the policy (and the sharing graph) say for THIS document, now?
 *
 * A deny rule of the policy is a guardrail: it holds even when a relationship would grant
 * access. Sharing a restricted document with someone of low clearance does not make them
 * cleared. That is the same idea as an SCP or a permissions boundary in IAM: grants come
 * from one place, limits from another, and limits win.
 */
export function decisionFromClaims(
  claims: VerifiedClaims,
  action: Action,
  resource: Document,
  options: ChainOptions,
): ChainDecision {
  const now = options.now ?? Date.now();
  const steps: Step[] = [];
  const deny = (decidedAt: Layer, reason: string): ChainDecision => ({ allowed: false, status: 403, decidedAt, steps, reason });
  const allow = (reason: string): ChainDecision => ({ allowed: true, status: 200, decidedAt: 'resource', steps, reason });

  // Layer 1, the edge. A gateway does this per route with no idea what a document is. When it
  // fails, RFC 6750 section 3.1 says: 403 with `WWW-Authenticate: Bearer error="insufficient_scope"`.
  const needed = SCOPE_FOR_ACTION[action];
  const scopes = scopesOf(claims);
  const hasScope = scopes.has(needed);
  steps.push({
    layer: 'edge',
    check: `route needs scope ${needed}`,
    ok: hasScope,
    detail: `token scope is "${claims.scope ?? ''}"${hasScope ? '' : `: ${needed} missing`}`,
  });
  if (!hasScope) return deny('edge', `insufficient_scope: ${action} needs ${needed}, the client was not granted it`);

  // Layer 2, the service. Groups are the IdP's words; roles are ours. Then the coarse RBAC
  // gate: "may editors delete at all?" is answerable without touching the database.
  const { roles, ignored } = rolesFromGroups(groupsOf(claims));
  steps.push({
    layer: 'service',
    check: 'groups → roles through the allowlist',
    ok: roles.length > 0,
    detail: `groups [${groupsOf(claims).join(', ')}] → roles [${roles.join(', ')}]${ignored.length ? `, ignored [${ignored.join(', ')}]` : ''}`,
  });
  if (roles.length === 0) return deny('service', `no group in the token maps to a role of this application (ignored: ${ignored.join(', ') || 'none'})`);

  const gate = rbacAllows({ id: claims.sub, roles }, action);
  steps.push({ layer: 'service', check: `RBAC gate: may [${roles.join(', ')}] ${action} at all?`, ok: gate.allowed, detail: gate.reason });
  if (!gate.allowed) return deny('service', gate.reason);

  const attributes = options.lookupUser(claims.sub);
  steps.push({
    layer: 'service',
    check: 'directory lookup (the PIP): department and clearance',
    ok: attributes !== undefined,
    detail: attributes ? `department ${attributes.department}, clearance ${attributes.clearance}` : `no directory entry for sub ${claims.sub}`,
  });
  if (!attributes) return deny('service', `sub ${claims.sub} authenticated at the IdP but is not a user of this application`);

  // Layer 3, the resource. Now, and only now, the document is loaded and the policy can run.
  const subject: User = { id: claims.sub, roles, ...attributes };
  const environment = { now, mfaAt: mfaTimeFromClaims(claims) };
  const mfaAge = environment.mfaAt === null ? 'never' : `${Math.round((now - environment.mfaAt) / 60_000)} min ago`;
  const abac = abacAllows({ subject, action, resource, environment });
  steps.push({
    layer: 'resource',
    check: `policy over subject, action, resource, environment (amr [${(claims.amr ?? []).join(', ')}] → MFA ${mfaAge})`,
    ok: abac.allowed,
    detail: abac.reason,
  });
  if (abac.effect === 'explicit-deny') return deny('resource', abac.reason);
  if (abac.allowed) return allow(abac.reason);

  if (options.tuples) {
    const relation = ACTION_RELATION[action];
    const rebac = rebacAllows(options.tuples, `user:${claims.sub}`, relation, `doc:${resource.id}`);
    steps.push({ layer: 'resource', check: `relationship ${relation} on doc:${resource.id}`, ok: rebac.allowed, detail: rebac.reason });
    if (rebac.allowed) return allow(rebac.reason);
  }
  return deny('resource', abac.reason);
}
