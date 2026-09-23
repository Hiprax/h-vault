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
  | 'reseal-after-first-item-write'
  | 'import-before-insert'
  | 'import-after-insert-before-commit'
  | 'import-after-commit'
  | 'document-part-before-ledger-write'
  | 'document-complete-before-row-insert'
  | 'document-purge-after-object-delete';

/**
 * The HTTP methods a probe can drive.
 *
 * The five original scenarios are all `POST` with a JSON body, which is why this
 * did not exist at first. The document drills need the other two shapes: a part
 * upload is a `PUT` carrying `application/octet-stream`, and a permanent delete is
 * a `DELETE` with no body at all.
 */
export type CrashMethod = 'POST' | 'PUT' | 'DELETE';

export interface CrashRequest {
  /** The mongod the child must use — the same database the parent is on. */
  uri: string;
  scenario: CrashScenario;
  /** Defaults to `POST` when absent, which is what the five original scenarios are. */
  method?: CrashMethod;
  /** The path to drive, e.g. `/api/v1/vault/items/bulk-reencrypt`. */
  path: string;
  /** A bearer token for the account under test. */
  token: string;
  /** A JSON body. Mutually exclusive with {@link bodyBase64}. */
  body?: Record<string, unknown>;
  /**
   * A RAW body, base64 for the wire.
   *
   * Base64 rather than a byte array because the whole request crosses as one
   * `JSON.stringify`d argv entry, and it is only ever used for a document part —
   * which is why the drill that needs one sends the FINAL part of its transfer,
   * the only part the framing rules allow to be short.
   */
  bodyBase64?: string;
  /** Extra request headers, e.g. the part digest. Applied after the CSRF pair. */
  headers?: Record<string, string>;
  /**
   * Install the storage bridge before the request runs.
   *
   * Off by default, and that default is load-bearing: the five original scenarios
   * run with the four `S3_*` variables empty, where `getStorage()` throws 503, so
   * an unconditional install would break every one of them.
   */
  storageBridge?: boolean;
}

/**
 * The child's stdout markers.
 *
 * They stay on STDOUT rather than moving to the IPC channel the storage bridge
 * added: `expectKilled` reads them out of the captured output, and splitting one
 * verdict across two transports buys nothing.
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
