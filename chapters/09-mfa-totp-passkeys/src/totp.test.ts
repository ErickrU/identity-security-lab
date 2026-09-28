import { describe, expect, it } from 'vitest';
import { base32Decode } from './base32';
import type { HmacAlgorithm } from './hotp';
import { TOTP_SECRETS, TOTP_VECTORS } from './rfc-vectors';
import { generateSecret, otpauthUrl, totp, totpCounter, verifyTotp } from './totp';

// The RFC 4226 test key ("12345678901234567890") and a fixed clock: 2024-01-01T00:00:00Z.
const KEY = base32Decode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
const T = Date.UTC(2024, 0, 1, 0, 0, 0);
const at = (seconds: number): number => T + seconds * 1000;
const CURRENT = totpCounter({ time: T }); // 56802240
const codeFor = (counter: number): string => totp(KEY, { time: counter * 30_000 });

describe('TOTP (RFC 6238) Appendix B vectors, 8 digits, step 30 s', () => {
  const cases = TOTP_VECTORS.flatMap((v) =>
    (Object.keys(v.expected) as HmacAlgorithm[]).map((algorithm) => ({
      time: v.time,
      algorithm,
      expected: v.expected[algorithm],
      counterHex: v.counterHex,
    })),
  );

  it.each(cases)('T=$time $algorithm → $expected', ({ time, algorithm, expected, counterHex }) => {
    expect(totpCounter({ time: time * 1000 }).toString(16).toUpperCase().padStart(16, '0')).toBe(counterHex);
    expect(totp(TOTP_SECRETS[algorithm], { time: time * 1000, digits: 8, algorithm })).toBe(expected);
  });
});

describe('totpCounter', () => {
  it('is floor((unixTime - T0) / X) with X = 30 and T0 = 0 by default', () => {
    expect(totpCounter({ time: 0 })).toBe(0);
    expect(totpCounter({ time: 29_999 })).toBe(0);
    expect(totpCounter({ time: 30_000 })).toBe(1);
    expect(totpCounter({ time: 59_000 })).toBe(1);
    expect(totpCounter({ time: 1_111_111_109_000 })).toBe(0x23523ec);
    expect(CURRENT).toBe(56_802_240);
  });

  it('honours a custom step and T0', () => {
    expect(totpCounter({ time: 120_000, step: 60 })).toBe(2);
    expect(totpCounter({ time: 120_000, step: 60, t0: 60 })).toBe(1);
    expect(() => totpCounter({ time: 0, step: 0 })).toThrow(RangeError);
  });

  it('gives the same code for the whole step and a new one at the boundary', () => {
    expect(totp(KEY, { time: at(0) })).toBe(totp(KEY, { time: at(29) }));
    expect(totp(KEY, { time: at(0) })).not.toBe(totp(KEY, { time: at(30) }));
  });
});

describe('verifyTotp window', () => {
  it('accepts the previous, current and next code with window 1', () => {
    for (const delta of [-1, 0, 1]) {
      const result = verifyTotp(KEY, codeFor(CURRENT + delta), { time: T, window: 1 });
      expect(result).toEqual({ ok: true, counter: CURRENT + delta });
    }
  });

  it('rejects codes two steps away with window 1', () => {
    for (const delta of [-2, 2]) {
      const result = verifyTotp(KEY, codeFor(CURRENT + delta), { time: T, window: 1 });
      expect(result).toEqual({ ok: false, counter: null, reason: 'no-match' });
    }
  });

  it('with window 0 only the current code works', () => {
    expect(verifyTotp(KEY, codeFor(CURRENT), { time: T, window: 0 }).ok).toBe(true);
    expect(verifyTotp(KEY, codeFor(CURRENT - 1), { time: T, window: 0 }).ok).toBe(false);
    expect(verifyTotp(KEY, codeFor(CURRENT + 1), { time: T, window: 0 }).ok).toBe(false);
  });

  it('a wider window accepts more steps', () => {
    expect(verifyTotp(KEY, codeFor(CURRENT - 2), { time: T, window: 2 })).toEqual({ ok: true, counter: CURRENT - 2 });
  });

  it('reports the counter that matched, not the current one', () => {
    // A code generated 33 s ago (previous step) is accepted and attributed to that step.
    const previous = totp(KEY, { time: at(0) });
    expect(verifyTotp(KEY, previous, { time: at(33) })).toEqual({ ok: true, counter: CURRENT });
    expect(totpCounter({ time: at(33) })).toBe(CURRENT + 1);
  });

  it('never accepts a counter below zero', () => {
    expect(verifyTotp(KEY, totp(KEY, { time: 0 }), { time: 0, window: 5 })).toEqual({ ok: true, counter: 0 });
    expect(() => verifyTotp(KEY, '000000', { time: 0, window: 5 })).not.toThrow();
  });
});

describe('verifyTotp replay prevention', () => {
  it('refuses a code whose counter is at or below lastUsedCounter', () => {
    const previous = totp(KEY, { time: at(0) });

    const first = verifyTotp(KEY, previous, { time: at(33), lastUsedCounter: null });
    expect(first).toEqual({ ok: true, counter: CURRENT });

    // Same code, still inside the window, but already spent.
    const again = verifyTotp(KEY, previous, { time: at(40), lastUsedCounter: first.ok ? first.counter : null });
    expect(again).toEqual({ ok: false, counter: null, reason: 'replay' });
  });

  it('still accepts newer codes after a login, and moves forward', () => {
    let lastUsed: number | null = CURRENT;
    const next = verifyTotp(KEY, codeFor(CURRENT + 1), { time: at(40), lastUsedCounter: lastUsed });
    expect(next).toEqual({ ok: true, counter: CURRENT + 1 });
    lastUsed = next.ok ? next.counter : lastUsed;
    // The code for CURRENT is now "older than the last one used" as well.
    expect(verifyTotp(KEY, codeFor(CURRENT), { time: at(40), lastUsedCounter: lastUsed }).ok).toBe(false);
    // And CURRENT + 1 cannot be used twice either.
    expect(verifyTotp(KEY, codeFor(CURRENT + 1), { time: at(40), lastUsedCounter: lastUsed })).toEqual({
      ok: false,
      counter: null,
      reason: 'replay',
    });
  });

  it('a code from two steps ago is refused by the window before replay state is even needed', () => {
    const old = totp(KEY, { time: at(0) });
    expect(verifyTotp(KEY, old, { time: at(65), lastUsedCounter: null })).toEqual({
      ok: false,
      counter: null,
      reason: 'no-match',
    });
  });
});

describe('verifyTotp input handling', () => {
  it('rejects malformed codes before doing any crypto', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '12345a', '١٢٣٤٥٦']) {
      expect(verifyTotp(KEY, bad, { time: T })).toEqual({ ok: false, counter: null, reason: 'malformed' });
    }
  });

  it('ignores the spaces people type between groups of digits', () => {
    const code = codeFor(CURRENT);
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    expect(verifyTotp(KEY, spaced, { time: T })).toEqual({ ok: true, counter: CURRENT });
  });

  it('follows digits and algorithm options', () => {
    const opts = { time: T, digits: 8, algorithm: 'sha256' } as const;
    const code = totp(KEY, opts);
    expect(code).toMatch(/^[0-9]{8}$/);
    expect(verifyTotp(KEY, code, opts)).toEqual({ ok: true, counter: CURRENT });
    // The 6-digit SHA-1 code for the same moment is malformed for an 8-digit verifier.
    expect(verifyTotp(KEY, codeFor(CURRENT), opts).ok).toBe(false);
  });

  it('refuses a negative or fractional window', () => {
    expect(() => verifyTotp(KEY, '000000', { time: T, window: -1 })).toThrow(RangeError);
    expect(() => verifyTotp(KEY, '000000', { time: T, window: 1.5 })).toThrow(RangeError);
  });
});

describe('otpauthUrl (Key Uri Format)', () => {
  it('builds the URL authenticator apps expect, with label and issuer URL-encoded', () => {
    const url = otpauthUrl({ issuer: 'Identity Lab', account: 'alice@example.com', secret: 'JBSWY3DPEHPK3PXP' });
    expect(url).toBe(
      'otpauth://totp/Identity%20Lab:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Identity%20Lab&algorithm=SHA1&digits=6&period=30',
    );
    const parsed = new URL(url);
    expect(parsed.protocol).toBe('otpauth:');
    expect(parsed.host).toBe('totp');
    expect(decodeURIComponent(parsed.pathname.slice(1))).toBe('Identity Lab:alice@example.com');
    expect(parsed.searchParams.get('secret')).toBe('JBSWY3DPEHPK3PXP');
    expect(parsed.searchParams.get('issuer')).toBe('Identity Lab');
  });

  it('normalises the secret: upper case, no spaces, no padding', () => {
    const url = otpauthUrl({ issuer: 'Lab', account: 'bob', secret: 'jbsw y3dp ee======' });
    expect(new URL(url).searchParams.get('secret')).toBe('JBSWY3DPEE');
  });

  it('writes non-default digits, period and algorithm', () => {
    const url = otpauthUrl({
      issuer: 'Lab',
      account: 'bob',
      secret: 'JBSWY3DPEHPK3PXP',
      digits: 8,
      period: 60,
      algorithm: 'sha256',
    });
    expect(url.endsWith('&algorithm=SHA256&digits=8&period=60')).toBe(true);
  });

  it('refuses an issuer with a colon, missing fields and a secret that is not base32', () => {
    expect(() => otpauthUrl({ issuer: 'a:b', account: 'bob', secret: 'JBSWY3DPEHPK3PXP' })).toThrow(/issuer/);
    expect(() => otpauthUrl({ issuer: '', account: 'bob', secret: 'JBSWY3DPEHPK3PXP' })).toThrow(/issuer/);
    expect(() => otpauthUrl({ issuer: 'Lab', account: '', secret: 'JBSWY3DPEHPK3PXP' })).toThrow(/account/);
    expect(() => otpauthUrl({ issuer: 'Lab', account: 'bob', secret: 'not-base32!' })).toThrow(/base32/);
  });
});

describe('generateSecret', () => {
  it('produces 160 bits as 32 unpadded base32 characters by default', () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(base32Decode(secret)).toHaveLength(20);
  });

  it('is random and accepts a custom length', () => {
    expect(generateSecret()).not.toBe(generateSecret());
    expect(base32Decode(generateSecret(32))).toHaveLength(32);
  });

  it('refuses secrets shorter than 128 bits (RFC 4226 section 4)', () => {
    expect(() => generateSecret(15)).toThrow(RangeError);
  });
});
