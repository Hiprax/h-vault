import type zxcvbnType from 'zxcvbn';

let cachedZxcvbn: typeof zxcvbnType | null = null;
let inFlight: Promise<typeof zxcvbnType> | null = null;

/**
 * Lazily loads the zxcvbn library on first use and caches it for subsequent
 * calls. This avoids bundling the ~400KB library in the main chunk.
 *
 * The IN-FLIGHT load is memoized as well as the resolved module, and that gap is
 * the reason this function is not `async`. Three screens — Register, Reset
 * Password and Settings — call this from a mount effect AND from their submit
 * handler, so a user who types a password and submits before the chunk has landed
 * reaches the second call while the first is still loading. With only the
 * resolved value cached, `cachedZxcvbn` is still null at that moment and the
 * second caller starts the load path over: a second `import()` expression, a
 * second `__vitePreload` walk of the chunk's dependency list, and a second
 * `.then` chain, all for a module the first caller is already waiting on.
 *
 * What it does NOT cost is a second download. The ES module map keys on the
 * specifier and holds an entry for a graph that is still being fetched, so the
 * duplicate `import()` attaches to the in-flight load rather than issuing a
 * request — in the browser and under the test runner alike. That is worth stating
 * because it decides what can be asserted: the observable difference between the
 * two implementations is whether the second caller gets the FIRST caller's
 * promise, which is exactly what `lazyZxcvbn.test.ts` pins. Relying on the host's
 * module map to deduplicate is also the part worth removing on its own terms —
 * this module advertises a cache, and a cache that covers only the window after
 * the load resolves is not one.
 *
 * `inFlight` is cleared on rejection, so a load that failed because the network
 * dropped can be retried instead of leaving every later caller permanently
 * attached to the same rejected promise.
 */
export function getZxcvbn(): Promise<typeof zxcvbnType> {
  if (cachedZxcvbn) return Promise.resolve(cachedZxcvbn);
  inFlight ??= import('zxcvbn')
    .then((mod) => {
      cachedZxcvbn = mod.default;
      return mod.default;
    })
    .catch((error: unknown) => {
      inFlight = null;
      throw error;
    });
  return inFlight;
}
