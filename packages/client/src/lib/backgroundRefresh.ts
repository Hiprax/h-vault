/**
 * Starts a re-read of a vault list without waiting for it, and never lets it
 * become an unhandled rejection.
 *
 * A re-read after an action is a convenience: the store has already applied the
 * action to the list it holds, and a refused re-read (the list budget, a dropped
 * connection) leaves that list as it was, for the next walk to refresh.
 */
export function refreshInBackground(walk: Promise<unknown>): void {
  walk.catch(() => undefined);
}
