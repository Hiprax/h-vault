import { describe, it, expect, vi } from 'vitest';
import { AxiosError, AxiosHeaders } from 'axios';
import {
  BULK_ABANDONED_MESSAGE,
  BULK_REQUEST_CONCURRENCY,
  MAX_BULK_RETRIES,
  MAX_BULK_RETRY_AFTER_SECONDS,
  sendPaced,
  useVaultStore,
} from '../src/stores/vaultStore';

/**
 * `sendPaced`: how a bulk action's one-request-per-row fan-out reaches the server.
 *
 * Behind the golden host nginx every request counts against a per-address rate
 * limit (40 a second, burst 40), so a bulk action that fired every request at
 * once was applied to about forty rows and refused for the rest. These tests pin
 * the pacing and the one kind of refusal it waits out.
 */

/** A genuine `AxiosError` with a status and, optionally, a `Retry-After`. */
function httpError(status: number, retryAfter?: string): AxiosError {
  const headers = new AxiosHeaders();
  if (retryAfter !== undefined) headers.set('retry-after', retryAfter);
  const error = new AxiosError(`Request failed with status code ${String(status)}`);
  error.response = {
    status,
    statusText: '',
    data: {},
    headers,
    config: { headers: new AxiosHeaders() },
  };
  return error;
}

/** A wait that returns at once and records what it was asked to wait. */
function recordingWait() {
  const waited: number[] = [];
  const wait = (ms: number): Promise<void> => {
    waited.push(ms);
    return Promise.resolve();
  };
  return { waited, wait };
}

describe('sendPaced', () => {
  it('never has more than the bounded number of requests in flight, and sends every one', async () => {
    let inFlight = 0;
    let peak = 0;
    const sent: number[] = [];
    const requests = Array.from({ length: 23 }, (_, index) => async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      sent.push(index);
      // Yield a few times so every worker is genuinely in flight together.
      for (let i = 0; i < 3; i++) await Promise.resolve();
      inFlight--;
      return index * 10;
    });

    const results = await sendPaced(requests);

    expect(BULK_REQUEST_CONCURRENCY).toBe(4);
    expect(peak).toBe(BULK_REQUEST_CONCURRENCY);
    expect([...sent].sort((a, b) => a - b)).toEqual(Array.from({ length: 23 }, (_, i) => i));
    // Settled and in the caller's order, so its reporting is unchanged.
    expect(results).toEqual(
      Array.from({ length: 23 }, (_, i) => ({ status: 'fulfilled', value: i * 10 })),
    );
  });

  it('waits out a short 429 for as long as it asks, then sends the request again', async () => {
    const { waited, wait } = recordingWait();
    const send = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(httpError(429, '5'))
      .mockResolvedValueOnce('tagged');

    const results = await sendPaced([send], wait);

    expect(results).toEqual([{ status: 'fulfilled', value: 'tagged' }]);
    expect(send).toHaveBeenCalledTimes(2);
    expect(waited).toEqual([5_000]);
  });

  it('waits out a 429 exactly at the bound, and not one second past it', async () => {
    const atBound = recordingWait();
    const accepted = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(httpError(429, String(MAX_BULK_RETRY_AFTER_SECONDS)))
      .mockResolvedValueOnce('ok');
    expect(await sendPaced([accepted], atBound.wait)).toEqual([
      { status: 'fulfilled', value: 'ok' },
    ]);
    expect(atBound.waited).toEqual([MAX_BULK_RETRY_AFTER_SECONDS * 1000]);

    const past = recordingWait();
    const refusal = httpError(429, String(MAX_BULK_RETRY_AFTER_SECONDS + 1));
    const refused = vi.fn<() => Promise<string>>().mockRejectedValue(refusal);
    expect(await sendPaced([refused], past.wait)).toEqual([
      { status: 'rejected', reason: refusal },
    ]);
    expect(refused).toHaveBeenCalledTimes(1);
    expect(past.waited).toEqual([]);
  });

  it("reports the app's own spent budget at once rather than waiting out its window", async () => {
    // A per-account limiter answers with the rest of its fifteen-minute window.
    const { waited, wait } = recordingWait();
    const spent = httpError(429, '900');
    const send = vi.fn<() => Promise<void>>().mockRejectedValue(spent);

    const results = await sendPaced([send], wait);

    expect(results).toEqual([{ status: 'rejected', reason: spent }]);
    expect(send).toHaveBeenCalledTimes(1);
    expect(waited).toEqual([]);
  });

  it('does not retry a 429 that names no wait, nor any other failure', async () => {
    const { waited, wait } = recordingWait();
    const bare = httpError(429);
    const serverError = httpError(500, '1');
    const plain = new Error('offline');
    const sends = [bare, serverError, plain].map((error) =>
      vi.fn<() => Promise<void>>().mockRejectedValue(error),
    );

    const results = await sendPaced(sends, wait);

    expect(results).toEqual([
      { status: 'rejected', reason: bare },
      { status: 'rejected', reason: serverError },
      { status: 'rejected', reason: plain },
    ]);
    for (const send of sends) expect(send).toHaveBeenCalledTimes(1);
    expect(waited).toEqual([]);
  });

  it('gives up after the bounded number of retries and reports the last refusal', async () => {
    const { waited, wait } = recordingWait();
    const refusals = Array.from({ length: MAX_BULK_RETRIES + 1 }, () => httpError(429, '1'));
    const send = vi.fn<() => Promise<void>>();
    for (const refusal of refusals) send.mockRejectedValueOnce(refusal);

    const results = await sendPaced([send], wait);

    expect(MAX_BULK_RETRIES).toBe(3);
    expect(send).toHaveBeenCalledTimes(MAX_BULK_RETRIES + 1);
    expect(waited).toEqual(Array.from({ length: MAX_BULK_RETRIES }, () => 1_000));
    expect(results).toEqual([{ status: 'rejected', reason: refusals[MAX_BULK_RETRIES] }]);
  });

  it('reports a request that cannot even be issued as rejected, and still sends the rest', async () => {
    const broken = new Error('request could not be built');
    const later = vi.fn<() => Promise<string>>().mockResolvedValue('sent');

    const results = await sendPaced([
      () => {
        throw broken;
      },
      later,
    ]);

    expect(results).toEqual([
      { status: 'rejected', reason: broken },
      { status: 'fulfilled', value: 'sent' },
    ]);
    expect(later).toHaveBeenCalledTimes(1);
  });

  it('sends nothing more once the vault is locked, and says why', async () => {
    const sent: number[] = [];
    const requests = Array.from({ length: 10 }, (_, index) => () => {
      sent.push(index);
      // The first request is where the lock lands: `clearStore()` is what a lock
      // and a sign-out both run.
      if (index === 0) useVaultStore.getState().clearStore();
      return Promise.resolve(index);
    });

    const results = await sendPaced(requests);

    // Only the request already under way when the lock landed went out.
    expect(sent).toEqual([0]);
    expect(results[0]).toEqual({ status: 'fulfilled', value: 0 });
    for (const result of results.slice(1)) {
      expect(result.status).toBe('rejected');
      expect((result as PromiseRejectedResult).reason).toEqual(new Error(BULK_ABANDONED_MESSAGE));
    }
  });

  it('does not resend a rate-limited request once a lock landed during its wait', async () => {
    const send = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(httpError(429, '1'))
      .mockResolvedValueOnce('too late');
    const lockDuringWait = (): Promise<void> => {
      useVaultStore.getState().clearStore();
      return Promise.resolve();
    };

    const results = await sendPaced([send], lockDuringWait);

    expect(send).toHaveBeenCalledTimes(1);
    expect(results).toEqual([{ status: 'rejected', reason: new Error(BULK_ABANDONED_MESSAGE) }]);
  });

  it('waits on the real clock by default', async () => {
    vi.useFakeTimers();
    try {
      const send = vi
        .fn<() => Promise<string>>()
        .mockRejectedValueOnce(httpError(429, '2'))
        .mockResolvedValueOnce('late');
      const pending = sendPaced([send]);

      await vi.advanceTimersByTimeAsync(1_999);
      expect(send).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(await pending).toEqual([{ status: 'fulfilled', value: 'late' }]);
      expect(send).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
