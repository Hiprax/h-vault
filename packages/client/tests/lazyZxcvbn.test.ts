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
 *   • dropping the IN-FLIGHT memo (`inFlight ??= …`) — a caller that arrives while
 *     the first load is still running re-enters the load path instead of joining
 *     it, which is the shape all three consumers produce when a user submits
 *     before the mount effect's load has landed.
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

  it('performs ONE load for two cold callers, not one per caller', async () => {
    const { getZxcvbn } = await freshLoader();

    // Both calls are made before either can resolve — the submit-before-mount-
    // effect-lands race the three consumers above can all produce.
    const first = getZxcvbn();
    const second = getZxcvbn();

    // Promise IDENTITY is what "one load" means here, and it is the only form of
    // it that can fail. Counting `import('zxcvbn')` evaluations cannot: the ES
    // module map keys on the specifier and holds an entry for a graph that is
    // still loading, so a duplicate import attaches to the in-flight load instead
    // of starting a second one, and the count is 1 whether or not this module
    // memoizes anything. What the memoization decides is whether the SECOND
    // caller re-enters the load path at all — a fresh `import()` expression, a
    // fresh `__vitePreload` walk over the chunk's dependency list, a fresh `.then`
    // chain — and that is visible precisely as whether it is handed the first
    // caller's promise.
    //
    // This is why `getZxcvbn` is not declared `async`: an async function returns
    // a NEW promise on every call by construction, which would make this
    // assertion unwritable and the in-flight cache unobservable.
    expect(second).toBe(first);

    const [a, b] = await Promise.all([first, second]);
    expect(typeof a).toBe('function');
    expect(b).toBe(a);
  });

  it('lets a failed load be retried instead of caching the rejection forever', async () => {
    vi.resetModules();
    let failNextRead = true;
    // The failure is raised from the namespace's `default` GETTER rather than
    // from the factory body. A factory that throws is reported as vitest's own
    // "there was an error when mocking a module", which would leave this case
    // asserting on the harness's wording instead of on the error a failed chunk
    // load actually produces.
    vi.doMock('zxcvbn', () => ({
      get default() {
        if (failNextRead) {
          failNextRead = false;
          throw new Error('chunk load failed');
        }
        return () => ({ score: 4 });
      },
    }));
    const { getZxcvbn } = await import('../src/lib/lazyZxcvbn');

    await expect(getZxcvbn()).rejects.toThrow(/chunk load failed/);
    // The retry succeeds, which it cannot do if the rejected promise stayed in
    // the cache slot: a user whose network blipped on the register screen would
    // otherwise never get a strength meter again without a full reload.
    // The discriminating assertion: with `inFlight` left holding the rejected
    // promise, this second call would reject with the SAME error rather than
    // resolve.
    await expect(getZxcvbn()).resolves.toBeTypeOf('function');
    expect(failNextRead).toBe(false);

    vi.doUnmock('zxcvbn');
    vi.resetModules();
  });
});
