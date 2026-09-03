/**
 * Lazy loader for `hash-wasm`'s incremental SHA-256.
 *
 * Web Crypto's `subtle.digest` is one-shot: it takes the whole message. A
 * document is walked in 8 MiB slices precisely so a 100 MB file is never resident
 * in full, so its whole-file digest has to be fed incrementally, which is the one
 * thing Web Crypto cannot do. `hash-wasm` provides it, is already a declared
 * dependency of this package, and inlines its WebAssembly rather than fetching
 * it.
 *
 * **The lazy `import()` is load-bearing, not a micro-optimisation.** The
 * documents store is reachable STATICALLY from `authStore` — a lock has to tear
 * an upload session down before it does any I/O, so the teardown cannot wait on a
 * dynamic import — and `authStore` is in the initial payload. A static
 * `import { createSHA256 } from 'hash-wasm'` anywhere on that path would drag the
 * hasher into the initial download for every user, including everyone who never
 * touches a document. Reaching it through `import()` keeps it in a chunk that is
 * fetched the first time someone actually transfers a file.
 *
 * The IN-FLIGHT load is memoized as well as the resolved value, for the reason
 * `lazyZxcvbn.ts` records: a caller arriving while the first load is still in
 * flight must attach to that load rather than start the path over. `inFlight` is
 * cleared on rejection so a load that failed because the network dropped can be
 * retried, instead of leaving every later caller attached to one rejected
 * promise.
 */

/** `hash-wasm`'s incremental SHA-256 constructor, typed without importing it. */
type Sha256Factory = (typeof import('hash-wasm'))['createSHA256'];

let cachedFactory: Sha256Factory | null = null;
let inFlight: Promise<Sha256Factory> | null = null;

/**
 * Resolve `hash-wasm`'s `createSHA256`, loading the chunk on first use.
 *
 * The FACTORY is cached, never a hasher: one `IHasher` holds mutable state, so a
 * shared instance would interleave two documents' bytes into one digest. Every
 * caller builds its own.
 */
export function getSha256Factory(): Promise<Sha256Factory> {
  if (cachedFactory) return Promise.resolve(cachedFactory);
  inFlight ??= import('hash-wasm')
    .then((mod) => {
      cachedFactory = mod.createSHA256;
      return mod.createSHA256;
    })
    .catch((error: unknown) => {
      inFlight = null;
      throw error;
    });
  return inFlight;
}
