/**
 * `lazyZxcvbn`'s caching contract.
 *
 * This module is four lines long and it caused a whole class of order-dependent
 * test failures: seven test files scored passwords against whichever zxcvbn won a
 * race for its module-level cache slot. Those files now mock the loader, which is
 * the right fix for them — and which means the real module needs its own test, or
 * the one piece of logic at the centre of that class would be exercised by nothing.
 *
 * What each case would catch:
 *   • dropping `if (cachedZxcvbn) return cachedZxcvbn` — every call re-imports, and
 *     the ~400 kB chunk is fetched again on a form the user is already typing into.
 *   • caching the module namespace instead of `mod.default` — callers get an object
 *     rather than a function, and every strength meter throws.
 */
import { describe, expect, it, vi } from 'vitest';

/**
 * A fresh module registry per case, because the thing under test IS a
 * module-level cache: importing once at the top would make the second case
 * observe the first one's state.
 */
async function freshLoader(): Promise<typeof import('../src/lib/lazyZxcvbn')> {
  vi.resetModules();
  return import('../src/lib/lazyZxcvbn');
}

describe('lazyZxcvbn', () => {
  it('resolves the library itself, not the module namespace', async () => {
    const { getZxcvbn } = await freshLoader();

    const zxcvbn = await getZxcvbn();

    expect(typeof zxcvbn).toBe('function');
    const result = zxcvbn('correct horse battery staple');
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(4);
    // A namespace object would have `default` on it and would not be callable.
    expect((zxcvbn as unknown as { default?: unknown }).default).toBeUndefined();
  });

  it('returns the cached instance on every later call', async () => {
    const { getZxcvbn } = await freshLoader();

    const first = await getZxcvbn();
    const second = await getZxcvbn();
    const third = await getZxcvbn();

    // Identity, not equality: a second `import('zxcvbn')` would resolve to the same
    // module, so only reference-sharing across calls proves the cache branch ran.
    expect(second).toBe(first);
    expect(third).toBe(first);
  });

  it('serves concurrent cold callers, which is the shape every consumer uses', async () => {
    const { getZxcvbn } = await freshLoader();

    // `RegisterPage`, `ResetPasswordPage` and `SettingsPage` each call this from a
    // mount effect AND a submit handler, with no checkpoint between them, so two
    // cold calls in flight at once is the real-world case rather than a contrived
    // one. Both must resolve to the same usable function.
    const [a, b] = await Promise.all([getZxcvbn(), getZxcvbn()]);

    expect(typeof a).toBe('function');
    expect(b).toBe(a);
  });
});
