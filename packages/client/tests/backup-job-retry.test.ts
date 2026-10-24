/**
 * The retry helpers a full backup and a full restore share (`jobRetry.ts`), for
 * the cases their engine suites never reach: an error that is not a request at
 * all, the default timer behind every wait, and a rate limit that names no wait.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AxiosError,
  AxiosHeaders,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));
vi.mock('../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import { pause, sendWithRetries, statusOf } from '../src/services/backup/jobRetry';

const config = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;

function answered(status: number, headers: Record<string, string> = {}): AxiosError {
  const response = {
    status,
    statusText: 'Error',
    data: { success: false, message: 'nope', statusCode: status },
    headers,
    config,
  } as AxiosResponse;
  return new AxiosError('Request failed', 'ERR_BAD_RESPONSE', config, {}, response);
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('statusOf', () => {
  it('reads the status of a request that was answered', () => {
    expect(statusOf(answered(404))).toBe(404);
  });

  it('reads no status for a request that got no answer', () => {
    expect(statusOf(new AxiosError('Network Error', 'ERR_NETWORK', config, {}))).toBeNull();
  });

  it('reads no status for an error that is not a request at all', () => {
    expect(statusOf(new Error('The disk is full.'))).toBeNull();
    expect(statusOf(null)).toBeNull();
  });
});

describe('pause, with no wait seam', () => {
  it('waits the full time on a timer', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let done = false;
    void pause(1000, { signal: new AbortController().signal }).then(() => {
      done = true;
    });
    await vi.advanceTimersByTimeAsync(999);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toBe(true);
  });

  it('ends the moment the job is aborted, leaving no timer behind', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const controller = new AbortController();
    const waiting = pause(60_000, { signal: controller.signal });
    controller.abort('stopped');
    await waiting;
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('sendWithRetries, on a rate limit that names no wait', () => {
  it('waits sixty seconds in twenty-second steps, then sends the request again', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
    const waits: number[] = [];
    const announced: number[] = [];
    const send = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(answered(429))
      .mockResolvedValueOnce('sent');

    const answer = await sendWithRetries(send, {
      signal: new AbortController().signal,
      wait: (ms) => {
        waits.push(ms);
        return Promise.resolve();
      },
      onRateLimitWait: (until) => announced.push(until),
    });

    expect(answer).toBe('sent');
    expect(send).toHaveBeenCalledTimes(2);
    expect(waits).toEqual([20_000, 20_000, 20_000]);
    expect(announced).toEqual([1_800_000_000_000 + 60_000]);
  });

  it('uses the wait the server named instead, when it names one', async () => {
    const waits: number[] = [];
    const send = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(answered(429, { 'retry-after': '5' }))
      .mockResolvedValueOnce('sent');

    await sendWithRetries(send, {
      signal: new AbortController().signal,
      wait: (ms) => {
        waits.push(ms);
        return Promise.resolve();
      },
    });

    expect(waits).toEqual([5_000]);
  });
});
