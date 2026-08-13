/**
 * The contract between the crash probe's two halves, in a module with NO side
 * effects.
 *
 * It is separate from `crashChild.ts` for a reason that is easy to rediscover
 * the hard way: the child runs its request at import time, so a parent that
 * imported the markers from it would spawn the whole doomed sequence inside the
 * test worker itself — measured, and it fails the suite before a single case
 * runs. Types and constants live here; behaviour lives on either side.
 */

/** The kill points a probe can be armed with; each is described in `crashChild.ts`. */
export type CrashScenario =
  | 'rotation-before-first-item-write'
  | 'rotation-before-vault-key-update'
  | 'import-before-insert'
  | 'import-after-insert-before-commit'
  | 'import-after-commit';

export interface CrashRequest {
  /** The mongod the child must use — the same database the parent is on. */
  uri: string;
  scenario: CrashScenario;
  /** The path to POST, e.g. `/api/v1/vault/items/bulk-reencrypt`. */
  path: string;
  /** A bearer token for the account under test. */
  token: string;
  body: Record<string, unknown>;
}

/**
 * The child's two stdout markers.
 *
 *   ready      the injection point is armed and the request is about to run, so
 *              a probe that died during startup cannot be mistaken for one that
 *              died where it was told to
 *   survived   the request RAN TO COMPLETION, which means the injection never
 *              fired and nothing the parent asserts afterwards is a claim about
 *              a crash
 */
export const CRASH_MARKERS = {
  ready: '__CRASH_PROBE_ARMED__',
  survived: '__CRASH_PROBE_SURVIVED__',
} as const;
