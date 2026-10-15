/**
 * `refreshInBackground`: a re-read started after an action, whose refusal (the
 * list budget, a dropped connection) must never surface as an unhandled
 * rejection. The page that started it has nothing to do about a failure: the
 * store keeps the list it holds.
 */
import { describe, it, expect } from 'vitest';
import { refreshInBackground } from '../src/lib/backgroundRefresh';

async function unhandledDuring(run: () => void): Promise<unknown[]> {
  const seen: unknown[] = [];
  const listener = (reason: unknown) => seen.push(reason);
  process.on('unhandledRejection', listener);
  try {
    run();
    // Node reports an unhandled rejection once the microtask queue has drained.
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    process.off('unhandledRejection', listener);
  }
  return seen;
}

describe('refreshInBackground', () => {
  it('absorbs a refused re-read', async () => {
    // A plain rejected promise, never a `vi.fn`'s: Vitest subscribes to a mock's
    // returned promise, which would handle the rejection on the helper's behalf.
    const refused = Promise.reject(new Error('Request failed with status code 429'));

    expect(await unhandledDuring(() => refreshInBackground(refused))).toEqual([]);
  });

  it('lets a successful re-read finish untouched', async () => {
    let finished = false;
    const walk = Promise.resolve().then(() => {
      finished = true;
    });

    expect(await unhandledDuring(() => refreshInBackground(walk))).toEqual([]);
    expect(finished).toBe(true);
  });
});
