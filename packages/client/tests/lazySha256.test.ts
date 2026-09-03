/**
 * `lazySha256`'s caching contract.
 *
 * The module is a dozen lines and every one of them is load-bearing for something
 * that is invisible when it breaks. It exists because two things are true at once:
 * a document's whole-file digest has to be fed incrementally, which Web Crypto
 * cannot do, and the module that needs it is reachable STATICALLY from `authStore`
 * — so a static `import` of `hash-wasm` would put the hasher in the initial
 * download for every user, including everyone who never opens a document.
 *
 * What each case would catch:
 *   • dropping `if (cachedFactory) return …` — every transfer re-enters the load
 *     path for a module it already holds.
 *   • caching a HASHER instead of the factory — one `IHasher` carries mutable
 *     state, so two documents digested at once would interleave their bytes into
 *     one wrong digest, and every later download would report both files corrupt.
 *   • dropping the IN-FLIGHT memo — a second caller arriving mid-load starts the
 *     path over rather than joining it.
 *   • dropping `inFlight = null` on rejection — one failed chunk load would leave
 *     every later transfer attached to the same rejected promise for the tab's
 *     whole life.
 */
import { describe, expect, it, vi } from 'vitest';

/**
 * A fresh module registry per case, because the thing under test IS a
 * module-level cache: importing once at the top would make the second case
 * observe the first one's state.
 */
async function freshLoader(): Promise<typeof import('../src/lib/lazySha256')> {
  vi.resetModules();
  return import('../src/lib/lazySha256');
}

describe('lazySha256', () => {
  it('resolves the FACTORY, and each call to it builds a separate hasher', async () => {
    const { getSha256Factory } = await freshLoader();

    const createSHA256 = await getSha256Factory();
    const first = await createSHA256();
    const second = await createSHA256();

    expect(typeof createSHA256).toBe('function');
    // Two hashers, not one shared instance. The negative is the whole point:
    // feeding them different bytes must produce different digests, which a cached
    // singleton could not do.
    expect(second).not.toBe(first);
    first.init();
    first.update('hvault');
    second.init();
    second.update('other');
    expect(first.digest('hex')).not.toBe(second.digest('hex'));
  });

  it('produces the same digest Web Crypto does for the same bytes', async () => {
    // The reason this dependency is here at all is that it can be fed in pieces;
    // it is only worth having if the answer agrees with the one-shot primitive
    // this codebase uses everywhere else.
    const { getSha256Factory } = await freshLoader();
    const bytes = new Uint8Array([104, 118, 97, 117, 108, 116]);

    const hasher = await (await getSha256Factory())();
    hasher.init();
    hasher.update(bytes.subarray(0, 3));
    hasher.update(bytes.subarray(3));
    const incremental = hasher.digest('hex');

    const oneShot = Array.from(
      new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)),
      (byte) => byte.toString(16).padStart(2, '0'),
    ).join('');
    expect(incremental).toBe(oneShot);
  });

  it('returns the cached factory on every later call', async () => {
    const { getSha256Factory } = await freshLoader();

    const first = await getSha256Factory();
    const second = await getSha256Factory();

    // Identity, not equality: a second `import('hash-wasm')` resolves to the same
    // module either way, so only reference-sharing across calls proves the cache
    // branch ran.
    expect(second).toBe(first);
  });

  it('performs ONE load for two cold callers, not one per caller', async () => {
    const { getSha256Factory } = await freshLoader();

    const first = getSha256Factory();
    const second = getSha256Factory();

    // Promise IDENTITY is what "one load" means, and it is the only form of it
    // that can fail: the ES module map already deduplicates the fetch, so counting
    // imports would read 1 whether or not this module memoizes anything. What the
    // memo decides is whether the SECOND caller re-enters the load path — a fresh
    // `import()` expression and a fresh `.then` chain — and that is visible
    // precisely as whether it is handed the first caller's promise. It is also why
    // `getSha256Factory` is not declared `async`: an async function returns a NEW
    // promise per call by construction, which would make this unwritable.
    expect(second).toBe(first);
    expect(await second).toBe(await first);
  });

  it('lets a failed load be retried instead of caching the rejection forever', async () => {
    vi.resetModules();
    let failNextRead = true;
    // Raised from the namespace's GETTER rather than from the factory body: a
    // factory that throws is reported as vitest's own "there was an error when
    // mocking a module", which would leave this case asserting on the harness's
    // wording instead of on what a failed chunk load actually produces.
    vi.doMock('hash-wasm', () => ({
      get createSHA256() {
        if (failNextRead) {
          failNextRead = false;
          throw new Error('chunk load failed');
        }
        return () => Promise.resolve({ init: () => {}, update: () => {}, digest: () => 'ok' });
      },
    }));
    const { getSha256Factory } = await import('../src/lib/lazySha256');

    await expect(getSha256Factory()).rejects.toThrow(/chunk load failed/);
    // The discriminating assertion: with `inFlight` left holding the rejected
    // promise, this second call would reject with the SAME error rather than
    // resolve — and a user whose network blipped during one upload would never be
    // able to transfer a document again without reloading the tab.
    await expect(getSha256Factory()).resolves.toBeTypeOf('function');
    expect(failNextRead).toBe(false);

    vi.doUnmock('hash-wasm');
    vi.resetModules();
  });
});
