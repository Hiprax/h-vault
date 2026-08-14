/**
 * The committed size budgets for the client bundle.
 *
 * `vite.config.ts` sets `chunkSizeWarningLimit` to 850 kB and nothing enforces
 * it: a warning during a build nobody reads is not a gate, and the measured
 * lazy `main` chunk is already ~800 KiB. Meanwhile three of this application's
 * deliberate architectural decisions are invisible to every other check —
 * zxcvbn (~400 kB), Argon2id/hash-wasm and the file-encryption tool all land in
 * DYNAMIC chunks on purpose, and a single static import moves any of them into
 * the initial payload with nothing turning red.
 *
 * These numbers are what makes that regression fail. They are ceilings with
 * headroom, not targets: the question each answers is "did something large move
 * into a chunk it does not belong in", which is a step change, not a drift.
 *
 * ONE definition, shared by `scripts/ci/bundle-gate.mjs` (which enforces them)
 * and `scripts/ci/ratchet-check.mjs` (which pins them, direction `lower`, so a
 * ceiling can be tightened but never quietly raised).
 */

/** Chunk names are `<base>-<hash>.js`; budgets are keyed by `<base>`. */
export const CHUNK_BUDGETS_KB = {
  /**
   * The lazily-loaded application chunk. Measured at ~800 KiB; 850 is the figure
   * `vite.config.ts` already warns at, so this makes that warning binding rather
   * than inventing a second number. zxcvbn arriving here would put it at ~1.2 MB.
   */
  main: 850,
  /**
   * The password-strength worker, which is where zxcvbn is SUPPOSED to be — it
   * carries the whole dictionary. Measured at ~800 KiB. The budget exists so the
   * worker itself cannot silently absorb something else too.
   */
  'passwordStrength.worker': 850,
  /** React and the router. Measured at ~218 KiB. */
  'vendor-react': 280,
  /** The `@hiprax/crypto` browser build's ESM entry. Measured at ~210 KiB. */
  'index.esm': 280,
  /** The item form, the largest single component. Measured at ~171 KiB. */
  VaultItemForm: 230,
  /** Axios, zod and the other shared runtime. Measured at ~154 KiB. */
  'vendor-core': 220,
};

/**
 * The ceiling for every chunk without an entry above.
 *
 * Set from the largest unlisted chunk (SettingsPage, ~88 KiB) with room for the
 * routes still to come. A new lazy route that lands here without needing an
 * entry of its own is the normal case; one that needs 128 KiB is a decision
 * worth writing down.
 */
export const DEFAULT_CHUNK_BUDGET_KB = 128;

/**
 * What a first-time visitor downloads before anything renders: `index.html`, the
 * entry module, every `modulepreload` it declares, and every stylesheet it links.
 *
 * This is the number that actually describes the application's start-up cost, and
 * the one a static import of a lazy library moves. Measured at ~580 KiB
 * (uncompressed; the stack serves this gzipped).
 */
export const INITIAL_PAYLOAD_BUDGET_KB = 700;

/** `index.html` itself: a shell, not an asset store. Measured at ~1 KiB. */
export const HTML_SHELL_BUDGET_KB = 8;

/**
 * `main-4aSwR9SA.js` → `main`. The trailing segment is the content hash.
 *
 * EXACTLY eight characters, not "eight or more". Rolldown's hash alphabet is
 * base64url, so it contains `-` and `_` — `vendor-core-1-AcZIh1.js` has a hash of
 * `1-AcZIh1` — and a `{8,}` quantifier over a class containing `-` swallows the
 * chunk name too, reducing both `vendor-core` and `vendor-react` to `vendor`.
 * Measured: it did, and the two then shared one budget.
 *
 * It lives HERE, beside the budgets it resolves keys for, rather than in
 * `bundle-gate.mjs`, because `gate-surface.test.ts` pins the strip and a gate
 * SCRIPT is not importable: `bundle-gate.mjs` reads the built client at module
 * scope and `process.exit(2)`s when it is absent, so importing it from a test
 * killed the whole server suite on any tree without `packages/client/dist`
 * (measured: `Test Files 1 failed`, `Tests no tests`, dying at the import), and
 * rewrote another task's report on every run that did have one.
 */
export function chunkBaseName(fileName) {
  return fileName.replace(/\.(?:js|css)$/, '').replace(/-[A-Za-z0-9_-]{8}$/, '');
}
