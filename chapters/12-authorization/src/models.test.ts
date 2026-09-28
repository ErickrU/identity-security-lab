import { describe, expect, it } from 'vitest';
import {
  ACTIONS,
  ACTION_RELATION,
  MAX_MFA_CLOCK_SKEW_MS,
  MFA_FRESHNESS_MS,
  POLICY,
  TupleStore,
  abacAllows,
  formatTuple,
  mfaIsFresh,
  parseTuple,
  permissionsOf,
  rbacAllows,
  rebacAllows,
  whoCan,
  type AbacContext,
  type Action,
  type Document,
  type Role,
  type User,
} from './models';
import { DOCUMENTS, MINUTE, NOW, SHARE_ROADMAPS_WITH_ENG, USERS, baseTuples } from './scenario';

const { alice, bob, carol, dave } = USERS;
const { roadmap, incident, budget } = DOCUMENTS;
const ROLES: readonly Role[] = ['viewer', 'editor', 'admin'];

/** Build an ABAC context with a fixed clock; `mfaMinutesAgo: null` means never. */
function ctx(subject: User, action: Action, resource: Document, mfaMinutesAgo: number | null = null): AbacContext {
  return {
    subject,
    action,
    resource,
    environment: { now: NOW, mfaAt: mfaMinutesAgo === null ? null : NOW - mfaMinutesAgo * MINUTE },
  };
}

// ---------------------------------------------------------------- RBAC

describe('RBAC: roles → permissions', () => {
  it('has the expected permission table', () => {
    expect([...permissionsOf('viewer')].sort()).toEqual(['view']);
    expect([...permissionsOf('editor')].sort()).toEqual(['edit', 'share', 'view']);
    expect([...permissionsOf('admin')].sort()).toEqual(['delete', 'edit', 'share', 'view']);
  });

  it('is hierarchical: admin ⊇ editor ⊇ viewer', () => {
    const viewer = permissionsOf('viewer');
    const editor = permissionsOf('editor');
    const admin = permissionsOf('admin');
    for (const p of viewer) expect(editor.has(p)).toBe(true);
    for (const p of editor) expect(admin.has(p)).toBe(true);
    expect(admin.size).toBeGreaterThan(editor.size);
    expect(editor.size).toBeGreaterThan(viewer.size);
  });

  it.each([
    ['viewer', 'view', true],
    ['viewer', 'edit', false],
    ['viewer', 'share', false],
    ['viewer', 'delete', false],
    ['editor', 'view', true],
    ['editor', 'edit', true],
    ['editor', 'share', true],
    ['editor', 'delete', false],
    ['admin', 'view', true],
    ['admin', 'edit', true],
    ['admin', 'share', true],
    ['admin', 'delete', true],
  ] as Array<[Role, Action, boolean]>)('%s may %s: %s', (role, action, allowed) => {
    const decision = rbacAllows({ id: 'x', roles: [role] }, action);
    expect(decision.allowed).toBe(allowed);
    expect(decision.role).toBe(allowed ? role : null);
    expect(decision.reason).toContain(allowed ? `role ${role} grants ${action}` : `grants ${action}`);
  });

  it('takes the union of several roles and names the role that granted', () => {
    const decision = rbacAllows({ id: 'x', roles: ['viewer', 'admin'] }, 'delete');
    expect(decision).toEqual({ allowed: true, role: 'admin', reason: 'role admin grants delete' });
  });

  it('denies a user with no roles, and says so', () => {
    const decision = rbacAllows({ id: 'nobody', roles: [] }, 'view');
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('no role of nobody grants view (roles: none)');
  });

  it('blind spot: the answer does not depend on the document (ABAC differs per document)', () => {
    // RBAC has no resource parameter: bob's answer is the same for his colleague's roadmap,
    // the restricted report and another department's budget.
    expect(rbacAllows(bob, 'edit').allowed).toBe(true);
    const abac = [roadmap, incident, budget].map((doc) => abacAllows(ctx(alice, 'edit', doc)).allowed);
    expect(abac).toEqual([true, true, false]); // alice owns two of them, not the budget
  });
});

// ---------------------------------------------------------------- ABAC

describe('ABAC: allow rules', () => {
  it('owner may view, edit and share their own documents', () => {
    for (const action of ['view', 'edit', 'share'] as const) {
      const d = abacAllows(ctx(alice, action, roadmap));
      expect(d.allowed).toBe(true);
      expect(d.effect).toBe('allow');
      expect(d.matchedAllow).toContain('owner-controls-own-documents');
    }
  });

  it('owner may not delete: delete is an admin operation (implicit deny)', () => {
    const d = abacAllows(ctx(alice, 'delete', roadmap, 1));
    expect(d.allowed).toBe(false);
    expect(d.effect).toBe('implicit-deny');
    expect(d.matchedAllow).toEqual([]);
  });

  it('same department may view, but not edit, share or delete', () => {
    expect(abacAllows(ctx(bob, 'view', roadmap))).toMatchObject({ allowed: true, effect: 'allow', matchedAllow: ['department-may-view'] });
    for (const action of ['edit', 'share', 'delete'] as const) {
      expect(abacAllows(ctx(bob, action, roadmap, 1)).effect).toBe('implicit-deny');
    }
  });

  it('another department may not even view', () => {
    const d = abacAllows(ctx(carol, 'view', roadmap));
    expect(d).toMatchObject({ allowed: false, effect: 'implicit-deny', matchedAllow: [], matchedDeny: [] });
    expect(d.reason).toBe('implicit deny: no rule allows view on doc:42 by carol');
  });

  it('admins may view, edit and share any document, whatever the department', () => {
    for (const doc of [roadmap, incident, budget]) {
      for (const action of ['view', 'edit', 'share'] as const) {
        expect(abacAllows(ctx(dave, action, doc)).matchedAllow).toEqual(['admins-manage-all-documents']);
      }
    }
  });

  it('lists every allow rule that matched, not only the first', () => {
    // alice owns the incident report and is in its department: two allow rules apply.
    const d = abacAllows(ctx(alice, 'view', incident));
    expect(d.matchedAllow).toEqual(['owner-controls-own-documents', 'department-may-view']);
  });
});

describe('ABAC: explicit deny overrides explicit allow', () => {
  it('restricted + low clearance: the department allow matches and the deny still wins', () => {
    const d = abacAllows(ctx(bob, 'view', incident));
    expect(d.allowed).toBe(false);
    expect(d.effect).toBe('explicit-deny');
    expect(d.matchedAllow).toEqual(['department-may-view']);
    expect(d.matchedDeny).toEqual(['restricted-needs-clearance']);
    expect(d.reason).toContain('overrides allow from department-may-view');
  });

  it('restricted + high clearance in the same department: allowed', () => {
    const erin: User = { id: 'erin', roles: ['viewer'], department: 'eng', clearance: 'high' };
    expect(abacAllows(ctx(erin, 'view', incident)).effect).toBe('allow');
  });

  it('mandatory beats discretionary: even the owner is denied without clearance', () => {
    const lowOwner: User = { id: 'frank', roles: ['editor'], department: 'eng', clearance: 'low' };
    const secret: Document = { id: '8', owner: 'frank', department: 'eng', classification: 'restricted' };
    const d = abacAllows(ctx(lowOwner, 'edit', secret));
    expect(d.effect).toBe('explicit-deny');
    expect(d.matchedAllow).toEqual(['owner-controls-own-documents']);
    expect(d.matchedDeny).toEqual(['restricted-needs-clearance']);
  });

  it('even an admin is denied on a restricted document without clearance', () => {
    const lowAdmin: User = { id: 'grace', roles: ['admin'], department: 'it', clearance: 'low' };
    const d = abacAllows(ctx(lowAdmin, 'view', incident));
    expect(d.effect).toBe('explicit-deny');
    expect(d.matchedAllow).toEqual(['admins-manage-all-documents']);
  });

  it('delete without MFA: admin allow matches, MFA deny wins', () => {
    const d = abacAllows(ctx(dave, 'delete', roadmap, null));
    expect(d.effect).toBe('explicit-deny');
    expect(d.matchedAllow).toEqual(['admins-manage-all-documents']);
    expect(d.matchedDeny).toEqual(['delete-needs-fresh-mfa']);
  });

  it('two deny rules can match at once and both are reported', () => {
    const lowAdmin: User = { id: 'grace', roles: ['admin'], department: 'it', clearance: 'low' };
    const d = abacAllows(ctx(lowAdmin, 'delete', incident, null));
    expect(d.matchedDeny).toEqual(['restricted-needs-clearance', 'delete-needs-fresh-mfa']);
  });

  it('the decision does not depend on rule order', () => {
    const reversed = [...POLICY].reverse();
    const users = [alice, bob, carol, dave];
    for (const user of users) {
      for (const doc of [roadmap, incident, budget]) {
        for (const action of ACTIONS) {
          for (const mfa of [null, 1, 60]) {
            const a = abacAllows(ctx(user, action, doc, mfa));
            const b = abacAllows(ctx(user, action, doc, mfa), reversed);
            expect(b.allowed).toBe(a.allowed);
            expect(b.effect).toBe(a.effect);
            expect([...b.matchedAllow].sort()).toEqual([...a.matchedAllow].sort());
            expect([...b.matchedDeny].sort()).toEqual([...a.matchedDeny].sort());
          }
        }
      }
    }
  });

  it('an empty policy denies everything (fail closed)', () => {
    expect(abacAllows(ctx(dave, 'view', roadmap, 1), []).effect).toBe('implicit-deny');
  });
});

describe('ABAC: MFA freshness (injected clock)', () => {
  it('mfaIsFresh: never, fresh, boundary, stale, and clock skew', () => {
    expect(mfaIsFresh({ now: NOW, mfaAt: null })).toBe(false);
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW - 2 * MINUTE })).toBe(true);
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW - MFA_FRESHNESS_MS })).toBe(true); // exactly 15 min: still fresh
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW - MFA_FRESHNESS_MS - 1 })).toBe(false); // one ms later: stale
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW + 30_000 })).toBe(true); // bounded clock skew
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW + MAX_MFA_CLOCK_SKEW_MS })).toBe(true);
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW + MAX_MFA_CLOCK_SKEW_MS + 1 })).toBe(false);
    expect(mfaIsFresh({ now: NOW, mfaAt: NOW + 24 * 60 * MINUTE })).toBe(false); // future timestamp cannot stay fresh forever
    expect(mfaIsFresh({ now: NOW, mfaAt: Number.NaN })).toBe(false);
  });

  it('admin delete: allowed with MFA 14 minutes ago, denied at 16, denied when never', () => {
    expect(abacAllows(ctx(dave, 'delete', roadmap, 14)).effect).toBe('allow');
    expect(abacAllows(ctx(dave, 'delete', roadmap, 16)).effect).toBe('explicit-deny');
    expect(abacAllows(ctx(dave, 'delete', roadmap, null)).effect).toBe('explicit-deny');
  });

  it('the same MFA timestamp expires as the clock advances', () => {
    const mfaAt = NOW - 10 * MINUTE;
    const at = (now: number): AbacContext => ({ subject: dave, action: 'delete', resource: roadmap, environment: { now, mfaAt } });
    expect(abacAllows(at(NOW)).allowed).toBe(true);
    expect(abacAllows(at(NOW + 5 * MINUTE)).allowed).toBe(true);
    expect(abacAllows(at(NOW + 5 * MINUTE + 1)).allowed).toBe(false);
  });

  it('MFA is only required for delete', () => {
    for (const action of ['view', 'edit', 'share'] as const) {
      expect(abacAllows(ctx(dave, action, roadmap, null)).matchedDeny).toEqual([]);
    }
  });
});

// ---------------------------------------------------------------- ReBAC

describe('ReBAC: tuples', () => {
  it('parses user, userset and parent tuples and formats them back', () => {
    expect(parseTuple('doc:42#owner@user:alice')).toEqual({ object: 'doc:42', relation: 'owner', subject: 'user:alice' });
    expect(parseTuple('folder:f#viewer@group:eng#member')).toEqual({
      object: 'folder:f',
      relation: 'viewer',
      subject: 'group:eng',
      subjectRelation: 'member',
    });
    expect(parseTuple('doc:42#parent@folder:roadmaps')).toEqual({ object: 'doc:42', relation: 'parent', subject: 'folder:roadmaps' });
    for (const spec of ['doc:42#owner@user:alice', 'folder:f#viewer@group:eng#member', 'doc:42#parent@folder:roadmaps']) {
      expect(formatTuple(parseTuple(spec))).toBe(spec);
    }
  });

  it.each([
    ['doc:42#owner', 'missing "@subject"'],
    ['doc:42@user:alice', 'must start with object#relation'],
    ['doc:42#owner#x@user:alice', 'must start with object#relation'],
    ['spreadsheet:1#owner@user:alice', 'unknown namespace "spreadsheet"'],
    ['doc:42#admin@user:alice', '"doc" has no relation "admin"'],
    ['doc:42#owner@folder:f', 'must be a user or an object#relation userset'],
    ['doc:42#owner@group:eng#owner', '"group" has no relation "owner"'],
    ['doc:42#parent@user:alice', 'the subject of doc:42#parent must be a folder'],
    ['doc:42#parent@folder:f#viewer', 'the subject of doc:42#parent must be a folder'],
    ['doc:42#owner@user:alice#member#x', 'has a malformed subject'],
    ['doc#owner@user:alice', 'is not a namespace:id reference'],
  ])('rejects %s', (spec, message) => {
    expect(() => parseTuple(spec)).toThrow(message);
  });

  it('the store deduplicates, removes and lists', () => {
    const store = new TupleStore().add('doc:42#owner@user:alice', 'doc:42#owner@user:alice');
    expect(store.list()).toEqual(['doc:42#owner@user:alice']);
    expect(store.remove('doc:42#owner@user:alice')).toBe(true);
    expect(store.remove('doc:42#owner@user:alice')).toBe(false);
    expect(store.list()).toEqual([]);
  });

  it('maps actions to relations: sharing and deleting are for owners', () => {
    expect(ACTION_RELATION).toEqual({ view: 'viewer', edit: 'editor', share: 'owner', delete: 'owner' });
  });
});

describe('ReBAC: checks', () => {
  it('a direct tuple grants the relation, and the stronger relations imply the weaker ones', () => {
    const store = baseTuples();
    expect(rebacAllows(store, 'user:alice', 'owner', 'doc:42').path).toEqual(['doc:42#owner@user:alice']);
    expect(rebacAllows(store, 'user:alice', 'editor', 'doc:42').path).toEqual(['doc:42#editor includes doc:42#owner', 'doc:42#owner@user:alice']);
    expect(rebacAllows(store, 'user:alice', 'viewer', 'doc:42').allowed).toBe(true);
  });

  it('a weaker relation does not imply a stronger one', () => {
    const store = new TupleStore().add('doc:1#viewer@user:bob');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:1').allowed).toBe(true);
    expect(rebacAllows(store, 'user:bob', 'editor', 'doc:1').allowed).toBe(false);
    expect(rebacAllows(store, 'user:bob', 'owner', 'doc:1').allowed).toBe(false);
  });

  it('denies when there is no path, with an empty path and a reason', () => {
    const d = rebacAllows(baseTuples(), 'user:bob', 'editor', 'doc:42');
    expect(d).toEqual({ allowed: false, path: [], reason: 'denied: no relationship path from doc:42#editor to user:bob' });
  });

  it('resolves group membership (usersets)', () => {
    const store = baseTuples().add('doc:99#viewer@group:eng#member');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:99').path).toEqual(['doc:99#viewer@group:eng#member', 'group:eng#member@user:bob']);
    expect(rebacAllows(store, 'user:carol', 'viewer', 'doc:99').allowed).toBe(true); // she owns it
    expect(rebacAllows(store, 'user:dave', 'viewer', 'doc:99').allowed).toBe(false); // not in eng
  });

  it('resolves nested groups', () => {
    const store = baseTuples().add('group:eng-leads#member@user:frank', 'group:eng#member@group:eng-leads#member', 'doc:99#viewer@group:eng#member');
    expect(rebacAllows(store, 'user:frank', 'viewer', 'doc:99').path).toEqual([
      'doc:99#viewer@group:eng#member',
      'group:eng#member@group:eng-leads#member',
      'group:eng-leads#member@user:frank',
    ]);
  });

  it('the demo scenario: sharing the parent folder with a group grants the document', () => {
    const store = baseTuples();
    expect(rebacAllows(store, 'user:bob', 'editor', 'doc:42').allowed).toBe(false);
    store.add(SHARE_ROADMAPS_WITH_ENG);
    const d = rebacAllows(store, 'user:bob', 'editor', 'doc:42');
    expect(d.allowed).toBe(true);
    expect(d.path).toEqual(['doc:42#parent@folder:roadmaps', 'folder:roadmaps#editor@group:eng#member', 'group:eng#member@user:bob']);
    // editor of the folder → viewer of the doc too, but not owner (no sharing or deleting)
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:42').allowed).toBe(true);
    expect(rebacAllows(store, 'user:bob', 'owner', 'doc:42').allowed).toBe(false);
    // carol is not in the group
    expect(rebacAllows(store, 'user:carol', 'viewer', 'doc:42').allowed).toBe(false);
  });

  it('sharing a folder as viewer does not make the group editors of its documents', () => {
    const store = baseTuples().add('folder:roadmaps#viewer@group:eng#member');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:42').allowed).toBe(true);
    expect(rebacAllows(store, 'user:bob', 'editor', 'doc:42').allowed).toBe(false);
  });

  it('inherits through several folder levels', () => {
    const store = baseTuples().add('folder:roadmaps#parent@folder:eng-root', 'folder:eng-root#viewer@user:carol');
    const d = rebacAllows(store, 'user:carol', 'viewer', 'doc:42');
    expect(d.path).toEqual(['doc:42#parent@folder:roadmaps', 'folder:roadmaps#parent@folder:eng-root', 'folder:eng-root#viewer@user:carol']);
  });

  it('revocation is immediate: remove the tuple, lose the path', () => {
    const store = baseTuples().add(SHARE_ROADMAPS_WITH_ENG);
    expect(rebacAllows(store, 'user:bob', 'editor', 'doc:42').allowed).toBe(true);
    store.remove(SHARE_ROADMAPS_WITH_ENG);
    expect(rebacAllows(store, 'user:bob', 'editor', 'doc:42').allowed).toBe(false);
  });

  it('terminates on cycles in the folder graph', () => {
    const store = new TupleStore().add('folder:a#parent@folder:b', 'folder:b#parent@folder:a', 'doc:x#parent@folder:a');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:x').allowed).toBe(false);
    store.add('folder:b#viewer@user:bob');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:x').allowed).toBe(true);
  });

  it('terminates on cyclic group membership', () => {
    const store = new TupleStore().add('group:a#member@group:b#member', 'group:b#member@group:a#member', 'doc:x#viewer@group:a#member');
    expect(rebacAllows(store, 'user:bob', 'viewer', 'doc:x').allowed).toBe(false);
  });

  it('refuses malformed questions instead of answering no', () => {
    const store = baseTuples();
    expect(() => rebacAllows(store, 'group:eng', 'viewer', 'doc:42')).toThrow('is not a user reference');
    expect(() => rebacAllows(store, 'user:bob', 'admin', 'doc:42')).toThrow('has no relation "admin"');
    expect(() => rebacAllows(store, 'user:bob', 'viewer', 'nope:1')).toThrow('unknown namespace');
  });
});

describe('ReBAC: the reverse query (who can?)', () => {
  it('lists the owner before sharing, and the group members after', () => {
    const store = baseTuples();
    expect(whoCan(store, 'viewer', 'doc:42')).toEqual(['user:alice']);
    store.add(SHARE_ROADMAPS_WITH_ENG);
    expect(whoCan(store, 'viewer', 'doc:42')).toEqual(['user:alice', 'user:bob']);
    expect(whoCan(store, 'editor', 'doc:42')).toEqual(['user:alice', 'user:bob']);
    expect(whoCan(store, 'owner', 'doc:42')).toEqual(['user:alice']);
  });

  it('deduplicates users reachable through several paths', () => {
    const store = baseTuples().add(SHARE_ROADMAPS_WITH_ENG, 'doc:42#viewer@user:alice', 'doc:42#viewer@group:eng#member');
    expect(whoCan(store, 'viewer', 'doc:42')).toEqual(['user:alice', 'user:bob']);
  });

  it('follows nested groups and several folder levels', () => {
    const store = baseTuples().add(
      'folder:roadmaps#parent@folder:eng-root',
      'folder:eng-root#viewer@group:leads#member',
      'group:leads#member@group:execs#member',
      'group:execs#member@user:zoe',
    );
    expect(whoCan(store, 'viewer', 'doc:42')).toEqual(['user:alice', 'user:zoe']);
  });

  it('never lists folders or groups as users, and survives cycles', () => {
    const store = new TupleStore().add('folder:a#parent@folder:b', 'folder:b#parent@folder:a', 'doc:x#parent@folder:a', 'folder:b#viewer@user:bob');
    expect(whoCan(store, 'viewer', 'doc:x')).toEqual(['user:bob']);
    expect(whoCan(store, 'parent', 'doc:x')).toEqual([]);
  });
});
