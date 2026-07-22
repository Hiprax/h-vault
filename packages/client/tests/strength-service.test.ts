/**
 * Unit coverage for the password-strength service:
 *  - `scorePasswords` (pure): dedup, classification, progress, yielding, abort.
 *  - `strengthCache`: get/set/clear and the oldest-first eviction cap.
 *  - `analyzeStrength`: cache hit/miss, the main-thread fallback (jsdom has no
 *    Worker), the Web Worker path (via an injected fake factory), worker-error
 *    degradation, and abort.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockGetZxcvbn } = vi.hoisted(() => ({ mockGetZxcvbn: vi.fn() }));

vi.mock('../src/lib/lazyZxcvbn', () => ({
  getZxcvbn: (...args: unknown[]) => mockGetZxcvbn(...args),
}));

import {
  scorePasswords,
  WEAK_SCORE_THRESHOLD,
  type ZxcvbnScoreFn,
} from '../src/services/health/passwordStrength';
import {
  getScore,
  setScore,
  clearScoreCache,
  strengthCacheKey,
  STRENGTH_CACHE_MAX_ENTRIES,
} from '../src/services/health/strengthCache';
import {
  analyzeStrength,
  __setStrengthWorkerFactory,
  type StrengthEntry,
} from '../src/services/health/strengthAnalyzer';

/** Deterministic fake: score is the string length mod 5 (0..4). */
const fakeZxcvbn: ZxcvbnScoreFn = (password: string) => ({ score: password.length % 5 });

beforeEach(() => {
  vi.clearAllMocks();
  clearScoreCache();
  __setStrengthWorkerFactory(null); // force the main-thread fallback by default
  mockGetZxcvbn.mockResolvedValue(fakeZxcvbn);
});

afterEach(() => {
  __setStrengthWorkerFactory(undefined); // restore the environment default
  clearScoreCache();
});

// ---------------------------------------------------------------------------
// scorePasswords
// ---------------------------------------------------------------------------

describe('scorePasswords', () => {
  it('scores each UNIQUE password exactly once', async () => {
    const spy = vi.fn(fakeZxcvbn);
    const scores = await scorePasswords(['ab', 'ab', 'abc'], spy);
    expect(scores.get('ab')).toBe(2);
    expect(scores.get('abc')).toBe(3);
    expect(spy).toHaveBeenCalledTimes(2); // deduped
  });

  it('returns an empty map for no passwords and still reports 0/0 progress', async () => {
    const onProgress = vi.fn();
    const scores = await scorePasswords([], fakeZxcvbn, { onProgress });
    expect(scores.size).toBe(0);
    expect(onProgress).toHaveBeenCalledWith(0, 0);
  });

  it('reports progress and yields between chunks', async () => {
    const onProgress = vi.fn();
    const yieldFn = vi.fn().mockResolvedValue(undefined);
    const passwords = Array.from({ length: 30 }, (_, i) => `pw-${i}`);
    await scorePasswords(passwords, fakeZxcvbn, { onProgress, yieldFn });
    // A chunk boundary at 25, then a final call at 30.
    expect(onProgress).toHaveBeenCalledWith(25, 30);
    expect(onProgress).toHaveBeenLastCalledWith(30, 30);
    expect(yieldFn).toHaveBeenCalledTimes(1);
  });

  it('stops immediately and skips the final progress when already aborted', async () => {
    const onProgress = vi.fn();
    const controller = new AbortController();
    controller.abort();
    const scores = await scorePasswords(['a', 'b'], fakeZxcvbn, {
      onProgress,
      signal: controller.signal,
    });
    expect(scores.size).toBe(0);
    expect(onProgress).not.toHaveBeenCalled();
  });

  it('WEAK_SCORE_THRESHOLD is the documented boundary (3)', () => {
    expect(WEAK_SCORE_THRESHOLD).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// strengthCache
// ---------------------------------------------------------------------------

describe('strengthCache', () => {
  it('stores and retrieves by id + version key', () => {
    const key = strengthCacheKey('item1', '2026-07-22T00:00:00.000Z');
    expect(getScore(key)).toBeUndefined();
    setScore(key, 2);
    expect(getScore(key)).toBe(2);
  });

  it('clears every entry', () => {
    setScore(strengthCacheKey('a', 'v'), 1);
    clearScoreCache();
    expect(getScore(strengthCacheKey('a', 'v'))).toBeUndefined();
  });

  it('evicts the oldest entry once the cap is exceeded', () => {
    for (let i = 0; i < STRENGTH_CACHE_MAX_ENTRIES; i++) setScore(`k${i}`, 1);
    expect(getScore('k0')).toBe(1); // still present at exactly the cap
    setScore('overflow', 2); // one over the cap -> evict oldest (k0)
    expect(getScore('k0')).toBeUndefined();
    expect(getScore('overflow')).toBe(2);
  });

  it('updating an existing key at the cap does not evict', () => {
    for (let i = 0; i < STRENGTH_CACHE_MAX_ENTRIES; i++) setScore(`k${i}`, 1);
    setScore('k0', 9); // update in place — no new slot needed
    expect(getScore('k0')).toBe(9);
    expect(getScore('k1')).toBe(1); // nothing evicted
  });
});

// ---------------------------------------------------------------------------
// analyzeStrength — main-thread fallback (no Worker)
// ---------------------------------------------------------------------------

describe('analyzeStrength - fallback path', () => {
  const entries: StrengthEntry[] = [
    { id: 'a', password: 'abcd', version: 'v1' }, // score 4
    { id: 'b', password: 'ab', version: 'v1' }, // score 2
  ];

  it('scores entries via getZxcvbn when no worker is available', async () => {
    const scores = await analyzeStrength(entries);
    expect(scores.get('a')).toBe(4);
    expect(scores.get('b')).toBe(2);
    expect(mockGetZxcvbn).toHaveBeenCalledTimes(1);
  });

  it('returns cached scores on the second call without re-scoring', async () => {
    await analyzeStrength(entries);
    mockGetZxcvbn.mockClear();
    const onProgress = vi.fn();
    const scores = await analyzeStrength(entries, { onProgress });
    expect(scores.get('a')).toBe(4);
    expect(mockGetZxcvbn).not.toHaveBeenCalled(); // fully served from cache
    expect(onProgress).toHaveBeenCalledWith(entries.length, entries.length);
  });

  it('re-scores when an item version changes (cache key busts)', async () => {
    await analyzeStrength(entries);
    mockGetZxcvbn.mockClear();
    const changed: StrengthEntry[] = [{ id: 'a', password: 'abcdef', version: 'v2' }]; // score 1
    const scores = await analyzeStrength(changed);
    expect(scores.get('a')).toBe(1);
    expect(mockGetZxcvbn).toHaveBeenCalledTimes(1);
  });

  it('returns an empty map and reports 0/0 for no entries', async () => {
    const onProgress = vi.fn();
    const scores = await analyzeStrength([], { onProgress });
    expect(scores.size).toBe(0);
    expect(onProgress).toHaveBeenCalledWith(0, 0);
  });

  it('rejects when the fallback zxcvbn loader fails (no worker)', async () => {
    // With no worker and a failing lazy-zxcvbn import, analysis cannot complete;
    // it must reject so the caller can surface a failure rather than "all clear".
    mockGetZxcvbn.mockRejectedValue(new Error('chunk load failed'));
    await expect(analyzeStrength([{ id: 'a', password: 'x', version: 'v1' }])).rejects.toThrow(
      'chunk load failed',
    );
  });
});

// ---------------------------------------------------------------------------
// analyzeStrength — Web Worker path (injected fake factory)
// ---------------------------------------------------------------------------

interface WorkerMessage {
  data: unknown;
}

class FakeWorker {
  onmessage: ((event: WorkerMessage) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  terminated = false;

  postMessage(message: { passwords: string[] }): void {
    queueMicrotask(() => {
      if (this.terminated) return;
      this.onmessage?.({
        data: { type: 'progress', done: message.passwords.length, total: message.passwords.length },
      });
      const scores: [string, number][] = message.passwords.map((p) => [p, p.length % 5]);
      this.onmessage?.({ data: { type: 'result', scores } });
    });
  }

  terminate(): void {
    this.terminated = true;
  }
}

class ErrorWorker {
  onmessage: ((event: WorkerMessage) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(): void {
    queueMicrotask(() => this.onerror?.(new Event('error')));
  }
  terminate(): void {}
}

/**
 * Reports a scoring failure as an explicit `error` MESSAGE rather than an error
 * EVENT — what the real worker does when `scorePasswords` rejects. An unhandled
 * rejection inside a worker never fires `onerror`, so without that message the
 * host promise would hang forever.
 */
class ReportedFailureWorker {
  onmessage: ((event: WorkerMessage) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(): void {
    queueMicrotask(() => {
      this.onmessage?.({ data: { type: 'error', message: 'zxcvbn exploded' } });
    });
  }
  terminate(): void {}
}

/** Same, but with no `message` field — exercises the default-reason branch. */
class BareFailureWorker {
  onmessage: ((event: WorkerMessage) => void) | null = null;
  onerror: ((event: unknown) => void) | null = null;
  postMessage(): void {
    queueMicrotask(() => {
      this.onmessage?.({ data: { type: 'error' } });
    });
  }
  terminate(): void {}
}

describe('analyzeStrength - worker path', () => {
  const entries: StrengthEntry[] = [
    { id: 'a', password: 'abcd', version: 'v1' },
    { id: 'b', password: 'ab', version: 'v1' },
  ];

  it('scores via the worker and forwards its progress', async () => {
    __setStrengthWorkerFactory(() => new FakeWorker() as unknown as Worker);
    const onProgress = vi.fn();
    const scores = await analyzeStrength(entries, { onProgress });
    expect(scores.get('a')).toBe(4);
    expect(scores.get('b')).toBe(2);
    expect(onProgress).toHaveBeenCalledWith(2, 2);
    expect(mockGetZxcvbn).not.toHaveBeenCalled(); // never touched the fallback
  });

  it('falls back to the main thread when the worker errors', async () => {
    __setStrengthWorkerFactory(() => new ErrorWorker() as unknown as Worker);
    const scores = await analyzeStrength(entries);
    expect(scores.get('a')).toBe(4);
    expect(mockGetZxcvbn).toHaveBeenCalledTimes(1); // degraded gracefully
  });

  it('rejects with AbortError when the signal is already aborted', async () => {
    __setStrengthWorkerFactory(() => new FakeWorker() as unknown as Worker);
    const controller = new AbortController();
    controller.abort();
    await expect(analyzeStrength(entries, { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
  });

  it('settles and degrades when the worker reports a scoring failure by message', async () => {
    __setStrengthWorkerFactory(() => new ReportedFailureWorker() as unknown as Worker);
    const scores = await analyzeStrength(entries);
    expect(scores.get('a')).toBe(4);
    expect(mockGetZxcvbn).toHaveBeenCalledTimes(1); // degraded rather than hung
  });

  it('settles when the reported failure carries no message', async () => {
    __setStrengthWorkerFactory(() => new BareFailureWorker() as unknown as Worker);
    const scores = await analyzeStrength(entries);
    expect(scores.get('a')).toBe(4);
    expect(mockGetZxcvbn).toHaveBeenCalledTimes(1);
  });
});
