import { randomBytes } from 'node:crypto';

export interface OpaqueTokenRecord {
  sub: string;
  scope: string;
  exp: number;
}

/**
 * A reference-token server in miniature (RFC 7662 introspection + RFC 7009 revocation).
 * The client gets random bytes. All meaning stays in this store.
 */
export class OpaqueTokenStore {
  private readonly records = new Map<string, OpaqueTokenRecord>();

  constructor(private readonly now: () => number = Date.now) {}

  issue(input: { sub: string; scope: string; lifetimeSec?: number }): string {
    const token = randomBytes(32).toString('base64url');
    this.records.set(token, {
      sub: input.sub,
      scope: input.scope,
      exp: Math.floor(this.now() / 1000) + (input.lifetimeSec ?? 900),
    });
    return token;
  }

  /** A resource server must ask the issuer: "is this random string active?" */
  introspect(token: string): ({ active: true } & OpaqueTokenRecord) | { active: false } {
    const record = this.records.get(token);
    if (!record) return { active: false };
    if (record.exp <= Math.floor(this.now() / 1000)) {
      this.records.delete(token);
      return { active: false };
    }
    return { active: true, ...record };
  }

  /** Instant revocation: delete one row. The next introspection sees inactive. */
  revoke(token: string): boolean {
    return this.records.delete(token);
  }

  get size(): number {
    return this.records.size;
  }
}
