import { screen, waitFor } from '@testing-library/react';

/**
 * Waits until the Settings page has no import in flight.
 *
 * An import keeps working after the request it sends: it checks every insert
 * landed under the id it was sealed to (a real WebCrypto digest per row), then
 * raises the summary toast and fires `fetchItems()`, and only then drops its
 * "Importing..." label. A test that stops at "the request was sent" therefore ends
 * with that tail still pending, and under load the tail runs inside the NEXT
 * test: after its `vi.clearAllMocks()`, so the stale summary toast is the first
 * one that test finds, and the stale `fetchItems()` consumes a
 * `mockResolvedValueOnce` the next test queued for itself. Measured under
 * `test:flake`: 2 of 10 shuffled runs failed that way, in two different files.
 *
 * Every step of that tail is synchronous once the digest settles, and the label
 * goes last (in the handler's `finally`), so its absence means the whole tail
 * has run. Call it from an `afterEach`, which runs before Testing Library's own
 * cleanup unmounts the page.
 */
export async function settleImportFlow(): Promise<void> {
  await waitFor(() => {
    // An import parked on the confirmation dialog has sent nothing and runs no
    // tail of its own: cleanup's unmount answers the prompt `false`, and the flow
    // then only reports the cancellation. That is settled.
    const parkedOnConfirmation = screen.queryByText('Confirm import changes') !== null;
    if (screen.queryByText(/^Importing/) !== null && !parkedOnConfirmation) {
      throw new Error('an import is still in flight');
    }
  });
}
