import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  GROUP_TO_ROLE,
  SCOPE_FOR_ACTION,
  decisionFromClaims,
  groupsOf,
  mfaTimeFromClaims,
  rolesFromGroups,
  scopesOf,
  type ChainOptions,
  type VerifiedClaims,
} from './claims';
import { DOCUMENTS, MINUTE, NOW, SHARE_ROADMAPS_WITH_ENG, baseTuples, lookupUser } from './scenario';

const { roadmap, incident } = DOCUMENTS;
const seconds = (ms: number): number => Math.floor(ms / 1000);

/** A token as the authorizer would hand it over: bob, editor, password login 5 minutes ago. */
function token(overrides: Partial<VerifiedClaims> = {}): VerifiedClaims {
  return {
    sub: 'bob',
    username: 'bob',
    groups: ['docs-editors'],
    scope: 'openid docs:read docs:write',
    amr: ['pwd'],
    auth_time: seconds(NOW - 5 * MINUTE),
    ...overrides,
  };
}

const options: ChainOptions = { lookupUser, now: NOW };
const layersRun = (steps: { layer: string }[]): string[] => [...new Set(steps.map((s) => s.layer))];

// ---------------------------------------------------------------- the pieces

describe('scopes', () => {
  it('parses the space-delimited, case-sensitive scope claim (RFC 6749 section 3.3)', () => {
    expect(scopesOf({ sub: 'x', scope: 'openid  docs:read docs:write ' })).toEqual(new Set(['openid', 'docs:read', 'docs:write']));
    expect(scopesOf({ sub: 'x' })).toEqual(new Set());
    expect(scopesOf({ sub: 'x', scope: 'Docs:Read' }).has('docs:read')).toBe(false);
  });

  it('view needs docs:read; everything that changes state needs docs:write', () => {
    expect(SCOPE_FOR_ACTION).toEqual({ view: 'docs:read', edit: 'docs:write', share: 'docs:write', delete: 'docs:write' });
  });
});

describe('groups → roles', () => {
  it('maps only allowlisted group names and reports the rest', () => {
    expect(rolesFromGroups(['docs-editors', 'superuser'])).toEqual({ roles: ['editor'], ignored: ['superuser'] });
    expect(rolesFromGroups(['docs-viewers', 'docs-admins'])).toEqual({ roles: ['viewer', 'admin'], ignored: [] });
    expect(rolesFromGroups([])).toEqual({ roles: [], ignored: [] });
  });

  it('never turns a raw role string into a role: "admin", "Admin", "docs-admin" are all ignored', () => {
    const mapping = rolesFromGroups(['admin', 'Admin', 'ADMIN', 'docs-admin', 'docs-Admins', 'editor']);
    expect(mapping.roles).toEqual([]);
    expect(mapping.ignored).toHaveLength(6);
  });

  it('is not fooled by object prototype names', () => {
    expect(rolesFromGroups(['constructor', '__proto__', 'toString', 'hasOwnProperty']).roles).toEqual([]);
  });

  it('deduplicates roles when two groups map to the same one', () => {
    const mapping = rolesFromGroups(['docs-editors', 'docs-editors']);
    expect(mapping.roles).toEqual(['editor']);
  });

  it('the allowlist is small and explicit', () => {
    expect([...GROUP_TO_ROLE.entries()]).toEqual([
      ['docs-viewers', 'viewer'],
      ['docs-editors', 'editor'],
      ['docs-admins', 'admin'],
    ]);
  });

  it('reads groups from `groups`, then `cognito:groups`, else none', () => {
    expect(groupsOf({ sub: 'x', groups: ['a'], 'cognito:groups': ['b'] })).toEqual(['a']);
    expect(groupsOf({ sub: 'x', 'cognito:groups': ['b'] })).toEqual(['b']);
    expect(groupsOf({ sub: 'x' })).toEqual([]);
  });
});

describe('MFA from amr and auth_time', () => {
  const at = seconds(NOW - 3 * MINUTE);

  it('password only is not MFA', () => {
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['pwd'], auth_time: at })).toBeNull();
    expect(mfaTimeFromClaims({ sub: 'x', auth_time: at })).toBeNull();
  });

  it('the explicit "mfa" marker, or a password plus a second factor, counts', () => {
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['pwd', 'mfa'], auth_time: at })).toBe(at * 1000);
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['mfa'], auth_time: at })).toBe(at * 1000);
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['pwd', 'otp'], auth_time: at })).toBe(at * 1000);
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['pwd', 'hwk'], auth_time: at })).toBe(at * 1000);
  });

  it('a lone second factor is not two factors', () => {
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['otp'], auth_time: at })).toBeNull();
  });

  it('without auth_time the freshness cannot be judged, so it is not MFA', () => {
    expect(mfaTimeFromClaims({ sub: 'x', amr: ['pwd', 'mfa'] })).toBeNull();
  });
});

// ---------------------------------------------------------------- the chain

describe('decisionFromClaims: layer 1, the edge (scopes)', () => {
  it('stops at the edge when the client was not granted the scope; the service never runs', () => {
    const d = decisionFromClaims(token({ scope: 'openid docs:read' }), 'edit', roadmap, options);
    expect(d.allowed).toBe(false);
    expect(d.status).toBe(403);
    expect(d.decidedAt).toBe('edge');
    expect(d.reason).toContain('insufficient_scope');
    expect(layersRun(d.steps)).toEqual(['edge']);
  });

  it('a token with no scope at all is stopped too', () => {
    const d = decisionFromClaims(token({ scope: undefined }), 'view', roadmap, options);
    expect(d.decidedAt).toBe('edge');
  });

  it('docs:read is enough to view, not to edit, share or delete', () => {
    const readOnly = token({ scope: 'docs:read' });
    expect(decisionFromClaims(readOnly, 'view', roadmap, options).decidedAt).not.toBe('edge');
    for (const action of ['edit', 'share', 'delete'] as const) {
      expect(decisionFromClaims(readOnly, action, roadmap, options).decidedAt).toBe('edge');
    }
  });
});

describe('decisionFromClaims: layer 2, the service (groups → roles, RBAC gate, directory)', () => {
  it('rejects a token whose groups are not in the allowlist, even if they say "admin"', () => {
    const d = decisionFromClaims(token({ groups: ['admin', 'Admin'] }), 'view', roadmap, options);
    expect(d.allowed).toBe(false);
    expect(d.decidedAt).toBe('service');
    expect(d.reason).toContain('no group in the token maps to a role');
    expect(d.reason).toContain('admin, Admin');
    expect(layersRun(d.steps)).toEqual(['edge', 'service']);
  });

  it('ignores role-like claims that are not groups: a partner IdP cannot mint roles', () => {
    const d = decisionFromClaims(token({ groups: [], role: 'admin', roles: ['admin'], 'custom:role': 'admin' }), 'view', roadmap, options);
    expect(d.decidedAt).toBe('service');
    expect(d.allowed).toBe(false);
  });

  it('a group name only counts as an exact match', () => {
    expect(decisionFromClaims(token({ groups: ['docs-Editors'] }), 'view', roadmap, options).decidedAt).toBe('service');
    expect(decisionFromClaims(token({ groups: ['docs-editors'] }), 'view', roadmap, options).decidedAt).toBe('resource');
  });

  it('the RBAC gate stops a viewer from editing before the document is loaded', () => {
    const d = decisionFromClaims(token({ sub: 'carol', groups: ['docs-viewers'] }), 'edit', DOCUMENTS.budget, options);
    expect(d.allowed).toBe(false); // even though carol owns the budget: the gate runs first
    expect(d.decidedAt).toBe('service');
    expect(d.reason).toBe('no role of carol grants edit (roles: viewer)');
    expect(d.steps.some((s) => s.layer === 'resource')).toBe(false);
  });

  it('the RBAC gate stops an editor from deleting', () => {
    const d = decisionFromClaims(token({ sub: 'alice', amr: ['pwd', 'mfa'] }), 'delete', roadmap, options);
    expect(d.decidedAt).toBe('service');
    expect(d.reason).toContain('grants delete');
  });

  it('rejects a subject the IdP knows but the application does not', () => {
    const d = decisionFromClaims(token({ sub: 'mallory' }), 'view', roadmap, options);
    expect(d.decidedAt).toBe('service');
    expect(d.reason).toContain('mallory');
    expect(d.reason).toContain('not a user of this application');
  });

  it('accepts Cognito-style `cognito:groups`', () => {
    const d = decisionFromClaims(token({ groups: undefined, 'cognito:groups': ['docs-editors'] }), 'view', roadmap, options);
    expect(d.allowed).toBe(true);
  });
});

describe('decisionFromClaims: layer 3, the resource (policy and relationships)', () => {
  it('bob may view but not edit alice roadmap: implicit deny at the resource layer', () => {
    expect(decisionFromClaims(token(), 'view', roadmap, options)).toMatchObject({ allowed: true, status: 200, decidedAt: 'resource' });
    const edit = decisionFromClaims(token(), 'edit', roadmap, options);
    expect(edit).toMatchObject({ allowed: false, status: 403, decidedAt: 'resource' });
    expect(edit.reason).toContain('implicit deny');
    expect(layersRun(edit.steps)).toEqual(['edge', 'service', 'resource']);
  });

  it('alice may edit her own roadmap', () => {
    const d = decisionFromClaims(token({ sub: 'alice' }), 'edit', roadmap, options);
    expect(d.allowed).toBe(true);
    expect(d.reason).toContain('owner-controls-own-documents');
  });

  it('without a tuple store the policy is the whole answer (no relationship step)', () => {
    const d = decisionFromClaims(token(), 'edit', roadmap, options);
    expect(d.steps.filter((s) => s.layer === 'resource')).toHaveLength(1);
  });

  it('with a tuple store, a relationship grants what the policy left implicit', () => {
    const unshared = decisionFromClaims(token(), 'edit', roadmap, { ...options, tuples: baseTuples() });
    expect(unshared.allowed).toBe(false);
    expect(unshared.steps.filter((s) => s.layer === 'resource')).toHaveLength(2);

    const shared = decisionFromClaims(token(), 'edit', roadmap, { ...options, tuples: baseTuples().add(SHARE_ROADMAPS_WITH_ENG) });
    expect(shared.allowed).toBe(true);
    expect(shared.status).toBe(200);
    expect(shared.reason).toBe('allowed: doc:42#parent@folder:roadmaps → folder:roadmaps#editor@group:eng#member → group:eng#member@user:bob');
  });

  it('a relationship does not bypass an explicit deny: sharing a restricted doc with low clearance', () => {
    const tuples = baseTuples().add('doc:7#viewer@user:bob');
    const d = decisionFromClaims(token(), 'view', incident, { ...options, tuples });
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('explicit deny by restricted-needs-clearance');
    // the relationship check never ran: a deny is final
    expect(d.steps.filter((s) => s.layer === 'resource')).toHaveLength(1);
  });

  it('a relationship does not bypass the scope or the RBAC gate either', () => {
    const tuples = baseTuples().add(SHARE_ROADMAPS_WITH_ENG);
    expect(decisionFromClaims(token({ scope: 'docs:read' }), 'edit', roadmap, { ...options, tuples }).decidedAt).toBe('edge');
    expect(decisionFromClaims(token({ groups: ['docs-viewers'] }), 'edit', roadmap, { ...options, tuples }).decidedAt).toBe('service');
  });
});

describe('decisionFromClaims: explicit deny overrides allow, with MFA freshness from the token', () => {
  const dave = (amr: string[], minutesAgo: number): VerifiedClaims =>
    token({ sub: 'dave', groups: ['docs-admins'], amr, auth_time: seconds(NOW - minutesAgo * MINUTE) });

  it('admin delete with password only: the admin allow is overridden', () => {
    const d = decisionFromClaims(dave(['pwd'], 1), 'delete', roadmap, options);
    expect(d.allowed).toBe(false);
    expect(d.decidedAt).toBe('resource');
    expect(d.reason).toContain('explicit deny by delete-needs-fresh-mfa');
    expect(d.reason).toContain('overrides allow from admins-manage-all-documents');
  });

  it('admin delete with MFA 2 minutes ago: allowed', () => {
    expect(decisionFromClaims(dave(['pwd', 'mfa'], 2), 'delete', roadmap, options)).toMatchObject({ allowed: true, status: 200 });
  });

  it('admin delete with MFA 15 minutes ago is still fresh; 16 is not', () => {
    expect(decisionFromClaims(dave(['pwd', 'mfa'], 15), 'delete', roadmap, options).allowed).toBe(true);
    expect(decisionFromClaims(dave(['pwd', 'mfa'], 16), 'delete', roadmap, options).allowed).toBe(false);
  });

  it('the same token expires as the injected clock advances', () => {
    const claims = dave(['pwd', 'mfa'], 10);
    expect(decisionFromClaims(claims, 'delete', roadmap, { lookupUser, now: NOW }).allowed).toBe(true);
    expect(decisionFromClaims(claims, 'delete', roadmap, { lookupUser, now: NOW + 5 * MINUTE }).allowed).toBe(true);
    expect(decisionFromClaims(claims, 'delete', roadmap, { lookupUser, now: NOW + 6 * MINUTE }).allowed).toBe(false);
  });

  it('MFA is not needed to view, edit or share', () => {
    for (const action of ['view', 'edit', 'share'] as const) {
      expect(decisionFromClaims(dave(['pwd'], 200), action, roadmap, options).allowed).toBe(true);
    }
  });

  it('the resource step tells the auditor what the environment looked like', () => {
    const d = decisionFromClaims(dave(['pwd', 'mfa'], 40), 'delete', roadmap, options);
    const policyStep = d.steps.find((s) => s.layer === 'resource');
    expect(policyStep?.check).toContain('amr [pwd, mfa] → MFA 40 min ago');
    expect(decisionFromClaims(dave(['pwd'], 1), 'delete', roadmap, options).steps.at(-1)?.check).toContain('MFA never');
  });
});

describe('decisionFromClaims: clock', () => {
  afterEach(() => vi.useRealTimers());

  it('uses the wall clock when `now` is not injected', () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const claims = token({ sub: 'dave', groups: ['docs-admins'], amr: ['pwd', 'mfa'], auth_time: seconds(NOW - 14 * MINUTE) });
    expect(decisionFromClaims(claims, 'delete', roadmap, { lookupUser }).allowed).toBe(true);
    vi.setSystemTime(NOW + 2 * MINUTE);
    expect(decisionFromClaims(claims, 'delete', roadmap, { lookupUser }).allowed).toBe(false);
  });
});
