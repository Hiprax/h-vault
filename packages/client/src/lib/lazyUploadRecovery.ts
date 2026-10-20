/**
 * Lazy loader for the document upload's recovery engine
 * (`services/documents/uploadRecovery.ts`).
 *
 * **The lazy `import()` is load-bearing, for the reason `lazySha256.ts` records.**
 * The documents store is reachable STATICALLY from `authStore`, which is in the
 * initial payload, and that payload sits within two kilobytes of its ratcheted
 * budget. Everything a transfer needs only once it is running (the retry driver,
 * its waits, the completion and the resume) lives behind this `import()`, so it is
 * fetched the first time someone uploads a file rather than by every user on
 * every visit.
 *
 * The IN-FLIGHT load is memoized, and kept after it succeeds, so two callers
 * share one load and every later caller gets the same module. It is cleared on
 * rejection, so a load that failed because the network dropped is attempted
 * again by the next upload instead of every later caller inheriting one rejected
 * promise. The rejection is translated into a sentence a person can act on.
 */

type UploadRecoveryModule = typeof import('../services/documents/uploadRecovery.js');

/** What an upload says when the engine itself could not be fetched. */
export const UPLOAD_ENGINE_UNAVAILABLE_MESSAGE =
  'Part of H-Vault needed for uploads did not load. Try again; if it keeps failing, reload the page.';

let inFlight: Promise<UploadRecoveryModule> | null = null;

/** Resolve the recovery engine, loading its chunk on first use. */
export function loadUploadRecovery(): Promise<UploadRecoveryModule> {
  inFlight ??= import('../services/documents/uploadRecovery.js').catch((error: unknown) => {
    inFlight = null;
    throw new Error(UPLOAD_ENGINE_UNAVAILABLE_MESSAGE, { cause: error });
  });
  return inFlight;
}
