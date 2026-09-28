/**
 * The cast and the documents used by the demo and the tests, so both tell the same story.
 *
 *   alice   editor, eng, high clearance. Owns doc 42 (roadmap) and doc 7 (restricted incident report).
 *   bob     editor, eng, low clearance. Wants to edit alice's roadmap.
 *   carol   viewer, finance, high clearance. Owns doc 99 (budget).
 *   dave    admin, it, high clearance. Deletes things.
 */
import { TupleStore, type Document, type User } from './models';

/** A fixed clock: 2024-02-01T09:00:00Z. Every "now" in the chapter is relative to it. */
export const NOW = Date.UTC(2024, 1, 1, 9, 0, 0);
export const MINUTE = 60_000;

export const USERS = {
  alice: { id: 'alice', roles: ['editor'], department: 'eng', clearance: 'high' },
  bob: { id: 'bob', roles: ['editor'], department: 'eng', clearance: 'low' },
  carol: { id: 'carol', roles: ['viewer'], department: 'finance', clearance: 'high' },
  dave: { id: 'dave', roles: ['admin'], department: 'it', clearance: 'high' },
} as const satisfies Record<string, User>;

export const DOCUMENTS = {
  roadmap: { id: '42', owner: 'alice', department: 'eng', classification: 'internal' },
  incident: { id: '7', owner: 'alice', department: 'eng', classification: 'restricted' },
  budget: { id: '99', owner: 'carol', department: 'finance', classification: 'internal' },
} as const satisfies Record<string, Document>;

/**
 * The Policy Information Point of the chapter: attributes the token does not carry.
 * Department and clearance are HR data. They belong in your directory, looked up by `sub`,
 * not in a token minted by an IdP you may not control.
 */
export function lookupUser(sub: string): Pick<User, 'department' | 'clearance'> | undefined {
  const user = Object.values(USERS).find((u) => u.id === sub);
  return user ? { department: user.department, clearance: user.clearance } : undefined;
}

/** The relationship graph before anyone shares anything. */
export function baseTuples(): TupleStore {
  return new TupleStore().add(
    'group:eng#member@user:alice',
    'group:eng#member@user:bob',
    'group:finance#member@user:carol',
    'folder:roadmaps#owner@user:alice',
    'doc:42#owner@user:alice',
    'doc:42#parent@folder:roadmaps',
    'doc:7#owner@user:alice',
    'doc:99#owner@user:carol',
  );
}

/** What alice does when she clicks "share with eng" on the folder. One tuple. */
export const SHARE_ROADMAPS_WITH_ENG = 'folder:roadmaps#editor@group:eng#member';
