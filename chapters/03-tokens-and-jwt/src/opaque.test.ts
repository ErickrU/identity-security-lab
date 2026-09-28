import { describe, expect, it } from 'vitest';
import { OpaqueTokenStore } from './opaque';

describe('opaque/reference tokens', () => {
  it('issues 256-bit random handles and resolves them only through introspection', () => {
    let now = 1_700_000_000_000;
    const store = new OpaqueTokenStore(() => now);
    const a = store.issue({ sub: 'alice', scope: 'orders:read', lifetimeSec: 60 });
    const b = store.issue({ sub: 'alice', scope: 'orders:read', lifetimeSec: 60 });
    expect(a).toHaveLength(43);
    expect(a).not.toBe(b);
    expect(store.introspect(a)).toEqual({ active: true, sub: 'alice', scope: 'orders:read', exp: 1_700_000_060 });
    expect(store.introspect('unknown')).toEqual({ active: false });
    expect(store.size).toBe(2);
    now += 1; // keep TypeScript aware this is an injected clock
  });

  it('revokes instantly by deleting server-side state', () => {
    const store = new OpaqueTokenStore(() => 1_700_000_000_000);
    const token = store.issue({ sub: 'alice', scope: 'read' });
    expect(store.revoke(token)).toBe(true);
    expect(store.introspect(token)).toEqual({ active: false });
    expect(store.revoke(token)).toBe(false);
  });

  it('expires and removes a token on the first lookup after exp', () => {
    let now = 1_700_000_000_000;
    const store = new OpaqueTokenStore(() => now);
    const token = store.issue({ sub: 'alice', scope: 'read', lifetimeSec: 2 });
    now += 2_000;
    expect(store.introspect(token)).toEqual({ active: false });
    expect(store.size).toBe(0);
  });
});
