import { describe, expect, it } from 'vitest';
import {
  authorizeS3,
  evaluateRoleTrust,
  prefixForIdentity,
  type S3AuthorizationRequest,
} from './policy';

const POOL = 'us-west-2:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ALICE = 'us-west-2:11111111-1111-4111-8111-111111111111';
const BOB = 'us-west-2:22222222-2222-4222-8222-222222222222';
const NOW = 1_800_000_000;

const request = (
  overrides: Partial<S3AuthorizationRequest> = {},
): S3AuthorizationRequest => ({
  action: 's3:GetObject',
  principalIdentityId: ALICE,
  key: `${ALICE}/notes.txt`,
  nowEpochSeconds: NOW,
  credentialsExpireAtEpochSeconds: NOW + 3_600,
  ...overrides,
});

describe('Cognito Identity role trust', () => {
  it('accepts the exact identity-pool audience and authenticated amr', () => {
    const result = evaluateRoleTrust({
      expectedAudience: POOL,
      aud: POOL,
      amr: ['authenticated'],
    });

    expect(result.allowed).toBe(true);
  });

  it('accepts authenticated among several amr values', () => {
    const result = evaluateRoleTrust({
      expectedAudience: POOL,
      aud: POOL,
      amr: ['cognito-idp.us-west-2.amazonaws.com/example', 'authenticated'],
    });

    expect(result.allowed).toBe(true);
  });

  it('rejects a role attempt from another identity pool', () => {
    const result = evaluateRoleTrust({
      expectedAudience: POOL,
      aud: 'us-west-2:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      amr: ['authenticated'],
    });

    expect(result).toMatchObject({ allowed: false });
    expect(result.reason).toContain('aud');
  });

  it('rejects unauthenticated amr', () => {
    const result = evaluateRoleTrust({
      expectedAudience: POOL,
      aud: POOL,
      amr: ['unauthenticated'],
    });

    expect(result).toMatchObject({ allowed: false });
    expect(result.reason).toContain('amr');
  });

  it('rejects a missing authenticated amr', () => {
    expect(evaluateRoleTrust({ expectedAudience: POOL, aud: POOL, amr: [] }).allowed).toBe(
      false,
    );
  });

  it('matches authenticated case-sensitively', () => {
    expect(
      evaluateRoleTrust({ expectedAudience: POOL, aud: POOL, amr: ['Authenticated'] })
        .allowed,
    ).toBe(false);
  });
});

describe('per-identity S3 authorization', () => {
  it('constructs an identity prefix with a boundary slash', () => {
    expect(prefixForIdentity(ALICE)).toBe(`${ALICE}/`);
  });

  it('rejects an empty identity ID', () => {
    expect(() => prefixForIdentity('  ')).toThrow('identity ID');
  });

  it('allows listing under the caller identity prefix', () => {
    const result = authorizeS3(
      request({ action: 's3:ListBucket', key: undefined, prefix: `${ALICE}/photos/` }),
    );

    expect(result.allowed).toBe(true);
  });

  it('allows listing the root of the caller identity prefix', () => {
    expect(
      authorizeS3(request({ action: 's3:ListBucket', key: undefined, prefix: `${ALICE}/` }))
        .allowed,
    ).toBe(true);
  });

  it('rejects ListBucket without an s3:prefix', () => {
    expect(
      authorizeS3(request({ action: 's3:ListBucket', key: undefined, prefix: undefined }))
        .allowed,
    ).toBe(false);
  });

  it('rejects bob listing alice prefix', () => {
    expect(
      authorizeS3(
        request({
          action: 's3:ListBucket',
          principalIdentityId: BOB,
          key: undefined,
          prefix: `${ALICE}/`,
        }),
      ).allowed,
    ).toBe(false);
  });

  it('allows GetObject in the caller identity prefix', () => {
    expect(authorizeS3(request({ action: 's3:GetObject' })).allowed).toBe(true);
  });

  it('allows PutObject in the caller identity prefix', () => {
    expect(authorizeS3(request({ action: 's3:PutObject' })).allowed).toBe(true);
  });

  it('rejects bob reading alice object', () => {
    expect(
      authorizeS3(
        request({
          principalIdentityId: BOB,
          key: `${ALICE}/notes.txt`,
        }),
      ).allowed,
    ).toBe(false);
  });

  it('rejects bob overwriting alice object', () => {
    expect(
      authorizeS3(
        request({
          action: 's3:PutObject',
          principalIdentityId: BOB,
          key: `${ALICE}/notes.txt`,
        }),
      ).allowed,
    ).toBe(false);
  });

  it('does not confuse a similar identity string with the caller prefix', () => {
    expect(
      authorizeS3(request({ key: `${ALICE}-attacker/notes.txt` })).allowed,
    ).toBe(false);
  });

  it('rejects an object action with no key', () => {
    expect(authorizeS3(request({ key: undefined })).allowed).toBe(false);
  });

  it('rejects credentials after expiration', () => {
    const result = authorizeS3(
      request({ nowEpochSeconds: NOW + 3_601, credentialsExpireAtEpochSeconds: NOW + 3_600 }),
    );

    expect(result).toMatchObject({ allowed: false });
    expect(result.reason).toContain('expired');
  });

  it('treats the exact expiration instant as expired', () => {
    expect(
      authorizeS3(
        request({ nowEpochSeconds: NOW + 3_600, credentialsExpireAtEpochSeconds: NOW + 3_600 }),
      ).allowed,
    ).toBe(false);
  });

  it('rejects a malformed credential expiration', () => {
    expect(
      authorizeS3(request({ credentialsExpireAtEpochSeconds: Number.NaN })).allowed,
    ).toBe(false);
  });
});
