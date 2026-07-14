/**
 * Lightweight tracker for in-flight background job promises.
 *
 * Background jobs (trash cleanup, token cleanup, backup scheduler) register
 * their execution promises here so that the graceful shutdown handler can
 * await them before closing the database connection.
 */

const runningJobs = new Set<Promise<void>>();

/**
 * Track a background job promise. The promise is automatically removed
 * from the set when it settles (resolves or rejects).
 *
 * The bookkeeping chain is terminated with `.catch(() => {})` on purpose:
 * `Promise.prototype.finally` returns a NEW promise that re-rejects when the
 * tracked promise rejects. Without a trailing catch, a job that rejects (e.g.
 * a transient MongoDB error thrown while acquiring/releasing its lock) would
 * surface here as an unhandled rejection — which `server.ts`'s
 * `unhandledRejection` handler escalates to `process.exit(1)`, taking down the
 * whole API server. The job's own error handling already logs the failure, so
 * this catch silently absorbs the bookkeeping chain's re-rejection only.
 */
export function trackJob(promise: Promise<void>): void {
  runningJobs.add(promise);
  void promise
    .finally(() => {
      runningJobs.delete(promise);
    })
    .catch(() => {
      // Rejection already handled by the job body; this guards the
      // bookkeeping chain from producing an unhandled rejection.
    });
}

/**
 * Return a snapshot of all currently running job promises.
 */
export function getRunningJobs(): Promise<void>[] {
  return Array.from(runningJobs);
}
