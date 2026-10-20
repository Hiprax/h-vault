/**
 * The document upload's recovery engine (`services/documents/uploadRecovery.ts`),
 * driven with a fake transfer context and scripted attempts: no crypto, no
 * WebAssembly, and only `setTimeout`/`clearTimeout` faked, so every wait is
 * measured to the millisecond.
 *
 * What these pin is the CLASSIFICATION, because it is the whole of the design: a
 * failure that never reached the server waits without limit, one where the
 * server cut a part off is bounded at the server's own allowance, and nothing
 * that is not an HTTP failure can loop at all. The store suite drives the same
 * engine through real transfers; this one measures it.
 */
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { AxiosError, AxiosHeaders, type InternalAxiosRequestConfig } from 'axios';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES, DOCUMENT_TAG_BYTES } from '@hvault/shared';
import { installTestClock } from './clock.js';

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

const api = vi.hoisted(() => ({
  getDocumentUploadApi: vi.fn(),
  getDocumentApi: vi.fn(),
  uploadDocumentPartApi: vi.fn(),
  completeDocumentUploadApi: vi.fn(),
  ensureCsrfToken: vi.fn(),
}));
vi.mock('../src/services/api/documentsApi.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  getDocumentUploadApi: api.getDocumentUploadApi,
  getDocumentApi: api.getDocumentApi,
  uploadDocumentPartApi: api.uploadDocumentPartApi,
  completeDocumentUploadApi: api.completeDocumentUploadApi,
}));
vi.mock('../src/services/api/client.js', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  ensureCsrfToken: api.ensureCsrfToken,
}));

import {
  GATEWAY_RETRY_DELAYS_MS,
  INTERRUPTED_ATTEMPTS,
  INTERRUPTED_MESSAGE,
  LEDGER_UNREADABLE_MESSAGE,
  LONG_ATTEMPT_MS,
  SERVER_UNAVAILABLE_MESSAGE,
  SESSION_ENDED_MESSAGE,
  UPLOAD_GONE_MESSAGE,
  FILE_UNREADABLE_MESSAGE,
  GENERIC_UPLOAD_MESSAGE,
  VAULT_KEY_CHANGED_AGAIN_MESSAGE,
  UnresumableUploadError,
  UploadStoppedError,
  classifyFailure,
  describeUploadFailure,
  prepareResume,
  retryStep,
  sendPart,
  toStoppedError,
  unreachedDelayMs,
  type TransferContext,
} from '../src/services/documents/uploadRecovery.js';
import { UploadCancelledError, type UploadSession } from '../src/stores/documentsStore.js';
import { ACCOUNT_LOCKED_MESSAGE } from '../src/services/auth/sessionFailure.js';
import { MAX_ERROR_MESSAGE_LENGTH, getApiErrorMessage } from '../src/lib/utils.js';

const ID = '66c0f1a2b3c4d5e6f7a8b9c0';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CONFIG = { headers: new AxiosHeaders() } as InternalAxiosRequestConfig;

/** A request that never got an answer: offline, DNS, a dropped socket. */
function noAnswer(): AxiosError {
  return new AxiosError('Network Error', AxiosError.ERR_NETWORK, CONFIG);
}

/** A request the server answered with `status`. */
function answered(status: number, data: unknown = { success: false, message: 'nope' }): AxiosError {
  return new AxiosError(
    `Request failed with status code ${String(status)}`,
    'ERR',
    CONFIG,
    undefined,
    {
      status,
      statusText: 'Error',
      data,
      headers: {},
      config: CONFIG,
    },
  );
}

interface Fake {
  ctx: TransferContext;
  controller: AbortController;
  reports: { status: string; waitReason?: string | undefined }[];
  session: UploadSession;
}

function fakeContext(): Fake {
  const controller = new AbortController();
  const reports: Fake['reports'] = [];
  const session = { wake: null } as unknown as UploadSession;
  return {
    controller,
    reports,
    session,
    ctx: {
      uploadId: ID,
      session,
      signal: controller.signal,
      report: (patch) => {
        reports.push({ status: patch.status, waitReason: patch.waitReason });
      },
    },
  };
}

type Attempt = (signal: AbortSignal, onBodyProgress: () => void) => Promise<unknown>;

/** An attempt script: each call takes the next outcome; an Error rejects, anything else resolves. */
function scripted(outcomes: unknown[]): Mock<Attempt> {
  let call = 0;
  return vi.fn<Attempt>(() => {
    const outcome = outcomes[call];
    call += 1;
    return outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);
  });
}

/** Lets settled promises run their continuations without moving the faked clock. */
async function flush(): Promise<void> {
  for (let turn = 0; turn < 10; turn += 1) await Promise.resolve();
}

/** Counts of listeners added and removed, by event type, on `window` and `document`. */
function listenerLedger(): { added: Map<string, number>; removed: Map<string, number> } {
  const added = new Map<string, number>();
  const removed = new Map<string, number>();
  const count = (map: Map<string, number>) => (type: string) => {
    map.set(type, (map.get(type) ?? 0) + 1);
  };
  const addCount = count(added);
  const removeCount = count(removed);
  for (const target of [window, document] as EventTarget[]) {
    const add = target.addEventListener.bind(target);
    const remove = target.removeEventListener.bind(target);
    vi.spyOn(target, 'addEventListener').mockImplementation((type, listener, options) => {
      addCount(type);
      add(type, listener, options);
    });
    vi.spyOn(target, 'removeEventListener').mockImplementation((type, listener, options) => {
      removeCount(type);
      remove(type, listener, options);
    });
  }
  return { added, removed };
}

beforeEach(() => {
  installTestClock({ timers: 'timeouts' });
  vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
  api.ensureCsrfToken.mockResolvedValue('csrf');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const mock of Object.values(api)) mock.mockReset();
});

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

describe('classifyFailure — decided on evidence of reaching the server', () => {
  const quiet = { progressed: false, long: false, ourAbort: null };
  const moved = { progressed: true, long: false, ourAbort: null };

  it.each([
    {
      label: 'no answer, nothing moved',
      error: noAnswer(),
      step: 'part',
      record: quiet,
      verdict: 'unreached',
    },
    {
      label: 'no answer after the body moved',
      error: noAnswer(),
      step: 'part',
      record: moved,
      verdict: 'interrupted',
    },
    {
      label: 'no answer after a long attempt',
      error: noAnswer(),
      step: 'part',
      record: { ...quiet, long: true },
      verdict: 'interrupted',
    },
    {
      label: 'no answer on a small step',
      error: noAnswer(),
      step: 'complete',
      record: moved,
      verdict: 'unreached',
    },
    {
      label: 'our own offline abort',
      error: noAnswer(),
      step: 'part',
      record: { ...moved, ourAbort: 'offline' },
      verdict: 'unreached',
    },
    {
      label: '"Retry now" ending an attempt',
      error: noAnswer(),
      step: 'part',
      record: { ...moved, ourAbort: 'manual' },
      verdict: 'unreached',
    },
    {
      label: 'a 408 on a part',
      error: answered(408),
      step: 'part',
      record: quiet,
      verdict: 'interrupted',
    },
    {
      label: 'a 408 on a small step',
      error: answered(408),
      step: 'resume',
      record: quiet,
      verdict: 'server',
    },
    { label: 'a 404', error: answered(404), step: 'part', record: quiet, verdict: 'abandon' },
    {
      label: 'a session that is over',
      error: answered(401),
      step: 'part',
      record: quiet,
      verdict: 'abandon',
    },
    { label: 'a 429', error: answered(429), step: 'part', record: quiet, verdict: 'fail' },
    { label: 'a 502', error: answered(502), step: 'part', record: quiet, verdict: 'gateway' },
    { label: 'a 503', error: answered(503), step: 'part', record: quiet, verdict: 'gateway' },
    { label: 'a 504', error: answered(504), step: 'part', record: quiet, verdict: 'gateway' },
    { label: 'a 500', error: answered(500), step: 'part', record: quiet, verdict: 'server' },
    {
      label: 'a completion 409 without a version',
      error: answered(409),
      step: 'complete',
      record: quiet,
      verdict: 'gateway',
    },
    {
      label: 'a completion 409 with a version',
      error: answered(409, { data: { vaultKeyVersion: 2 } }),
      step: 'complete',
      record: quiet,
      verdict: 'stale',
    },
    {
      label: 'a 409 on a part',
      error: answered(409),
      step: 'part',
      record: quiet,
      verdict: 'fail',
    },
    { label: 'a 400', error: answered(400), step: 'part', record: quiet, verdict: 'fail' },
    {
      label: 'something that is not an HTTP failure',
      error: new TypeError('boom'),
      step: 'part',
      record: quiet,
      verdict: 'fail',
    },
  ] as const)('$label → $verdict', ({ error, step, record, verdict }) => {
    expect(classifyFailure(error, step, record)).toBe(verdict);
  });

  it('treats a part that got no answer while the browser reports offline as unreached, moved or not', () => {
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    expect(classifyFailure(noAnswer(), 'part', moved)).toBe('unreached');
  });
});

// ---------------------------------------------------------------------------
// The ladders
// ---------------------------------------------------------------------------

describe('retryStep — what each class costs', () => {
  it('waits 1, 2, 4, 8, 16, then 30 s for ever when the server cannot be reached', async () => {
    expect([0, 1, 2, 3, 4, 5, 6, 40].map(unreachedDelayMs)).toEqual([
      1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000,
    ]);
    const { ctx } = fakeContext();
    const attempt = scripted([
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      'done',
    ]);
    const result = retryStep(ctx, 'part', attempt);

    for (const [index, delayMs] of [1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000].entries()) {
      await flush();
      expect(attempt, `before wait ${String(index)}`).toHaveBeenCalledTimes(index + 1);
      await vi.advanceTimersByTimeAsync(delayMs - 1);
      expect(attempt, `1 ms early on wait ${String(index)}`).toHaveBeenCalledTimes(index + 1);
      await vi.advanceTimersByTimeAsync(1);
    }
    // Seven failures that never reached the server, and still no failure.
    await expect(result).resolves.toBe('done');
    expect(attempt).toHaveBeenCalledTimes(8);
  });

  it('says why it waits: offline when the browser says so, connection otherwise', async () => {
    const { ctx, reports } = fakeContext();
    const attempt = scripted([noAnswer(), noAnswer(), 'done']);
    const result = retryStep(ctx, 'part', attempt);
    await flush();
    expect(reports.at(-1)).toEqual({ status: 'waiting', waitReason: 'connection' });

    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    expect(reports.at(-1)).toEqual({ status: 'waiting', waitReason: 'offline' });
    await vi.advanceTimersByTimeAsync(2_000);
    await expect(result).resolves.toBe('done');
  });

  it('gives an interrupted part four attempts and then stops with its own sentence', async () => {
    expect(INTERRUPTED_ATTEMPTS).toBe(4);
    const { ctx, reports } = fakeContext();
    // Each attempt reports that its body moved, then loses its answer.
    let calls = 0;
    const attempt = vi.fn((_signal: AbortSignal, moving: () => void) => {
      calls += 1;
      moving();
      return Promise.reject(noAnswer());
    });
    const result = retryStep(ctx, 'part', attempt);
    const guarded = result.catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(1_000 + 2_000 + 4_000);

    const error = await guarded;
    expect(error).toBeInstanceOf(UploadStoppedError);
    // Its OWN sentence, never `describeTransientFailure`'s "could not reach".
    expect((error as Error).message).toBe(INTERRUPTED_MESSAGE);
    expect(calls).toBe(4);
    expect(reports.filter((report) => report.waitReason === 'interrupted')).toHaveLength(3);
  });

  it('refunds an interrupted attempt when the browser goes offline during the wait after it', async () => {
    const { ctx } = fakeContext();
    let calls = 0;
    const attempt = vi.fn((_signal: AbortSignal, moving: () => void) => {
      calls += 1;
      moving();
      return calls <= 4 ? Promise.reject(noAnswer()) : Promise.resolve('done');
    });
    const result = retryStep(ctx, 'part', attempt);
    await flush();
    // The first failure's wait: the interface had gone away.
    window.dispatchEvent(new Event('offline'));
    await vi.advanceTimersByTimeAsync(1_000 + 1_000 + 2_000 + 4_000);
    // Four failures, but the first was refunded, so the fifth attempt was allowed.
    await expect(result).resolves.toBe('done');
    expect(calls).toBe(5);
  });

  it('counts a quiet part attempt as interrupted only once it has run 20 s', async () => {
    expect(LONG_ATTEMPT_MS).toBe(20_000);
    for (const [runMs, reason] of [
      [19_999, 'connection'],
      [20_000, 'interrupted'],
    ] as const) {
      const { ctx, reports } = fakeContext();
      let first = true;
      const attempt = vi.fn(
        () =>
          new Promise((resolve, reject) => {
            if (!first) {
              resolve('done');
              return;
            }
            first = false;
            setTimeout(() => {
              reject(noAnswer());
            }, runMs);
          }),
      );
      const result = retryStep(ctx, 'part', attempt);
      await vi.advanceTimersByTimeAsync(runMs);
      await flush();
      expect(reports.at(-1)?.waitReason, `after ${String(runMs)} ms`).toBe(reason);
      await vi.advanceTimersByTimeAsync(1_000);
      await expect(result).resolves.toBe('done');
      // The long-attempt timer does not outlive its attempt.
      expect(vi.getTimerCount()).toBe(0);
    }
  });

  it('waits about a minute for a gateway error, then stops', async () => {
    expect(GATEWAY_RETRY_DELAYS_MS).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000]);
    const { ctx } = fakeContext();
    const attempt = scripted(Array.from({ length: 7 }, () => answered(503)));
    const result = retryStep(ctx, 'part', attempt);
    const guarded = result.catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(61_000 - 1);
    expect(attempt).toHaveBeenCalledTimes(6);
    await vi.advanceTimersByTimeAsync(1);
    expect(((await guarded) as Error).message).toBe(SERVER_UNAVAILABLE_MESSAGE);
    expect(attempt).toHaveBeenCalledTimes(7);
  });

  it('keeps each bounded ladder on its own count', async () => {
    const { ctx } = fakeContext();
    // Three 500s and six 503s interleaved: neither ladder is exhausted by the other.
    const attempt = scripted([
      answered(500),
      answered(503),
      answered(500),
      answered(503),
      answered(500),
      answered(503),
      'done',
    ]);
    const result = retryStep(ctx, 'part', attempt);
    await vi.advanceTimersByTimeAsync(120_000);
    await expect(result).resolves.toBe('done');
  });

  it('stops at once on a failure that is not an HTTP failure at all', async () => {
    const { ctx, reports } = fakeContext();
    const attempt = scripted([new TypeError('a bug, not the network')]);
    await expect(retryStep(ctx, 'part', attempt)).rejects.toThrow('a bug, not the network');
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(reports).toEqual([]);
  });

  it('abandons on a 404, rethrows a stale completion raw, and fails a refusal resumably', async () => {
    const gone = fakeContext();
    await expect(retryStep(gone.ctx, 'part', scripted([answered(404)]))).rejects.toBeInstanceOf(
      UnresumableUploadError,
    );
    const stale = answered(409, { data: { vaultKeyVersion: 4 } });
    await expect(retryStep(fakeContext().ctx, 'complete', scripted([stale]))).rejects.toBe(stale);
    await expect(
      retryStep(fakeContext().ctx, 'part', scripted([answered(400)])),
    ).rejects.toBeInstanceOf(UploadStoppedError);
  });
});

// ---------------------------------------------------------------------------
// The waits
// ---------------------------------------------------------------------------

describe('retryStep — what ends a wait', () => {
  it('ends a wait the moment the browser comes back online', async () => {
    const { ctx } = fakeContext();
    const attempt = scripted([
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      noAnswer(),
      'done',
    ]);
    const result = retryStep(ctx, 'part', attempt);
    await vi.advanceTimersByTimeAsync(1_000 + 2_000 + 4_000 + 8_000 + 16_000);
    await flush();
    // Now on a 30 s wait: `online` cuts it short.
    window.dispatchEvent(new Event('online'));
    await expect(result).resolves.toBe('done');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ends a wait when the tab becomes visible, and not when it is hidden', async () => {
    const { ctx } = fakeContext();
    const attempt = scripted([noAnswer(), 'done']);
    const result = retryStep(ctx, 'part', attempt);
    await flush();
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    await flush();
    expect(attempt).toHaveBeenCalledTimes(1);
    visibility.mockReturnValue('visible');
    document.dispatchEvent(new Event('visibilitychange'));
    await expect(result).resolves.toBe('done');
  });

  it('ends a wait on "Retry now", once, and forgets the wake afterwards', async () => {
    const { ctx, session } = fakeContext();
    const attempt = scripted([noAnswer(), 'done']);
    const result = retryStep(ctx, 'part', attempt);
    await flush();
    expect(session.wake).toBeTypeOf('function');
    session.wake?.();
    await expect(result).resolves.toBe('done');
    expect(session.wake).toBeNull();
  });

  it('makes "Retry now" end a retry attempt that has not moved yet, for free, and try again at once', async () => {
    const { ctx, session } = fakeContext();
    let calls = 0;
    const attempt = vi.fn((signal: AbortSignal) => {
      calls += 1;
      if (calls === 1) return Promise.reject(noAnswer());
      if (calls === 2) {
        // A hung attempt: it ends only when its signal does.
        return new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => {
            reject(noAnswer());
          });
        });
      }
      return Promise.resolve('done');
    });
    const result = retryStep(ctx, 'part', attempt);
    await vi.advanceTimersByTimeAsync(1_000);
    await flush();
    expect(calls).toBe(2);
    session.wake?.();
    // No wait in between: the third attempt starts without the clock moving.
    await expect(result).resolves.toBe('done');
    expect(calls).toBe(3);
  });

  it('ends an attempt the moment the browser goes offline, as unreached and never as a cancel', async () => {
    const { ctx, reports } = fakeContext();
    let calls = 0;
    const attempt = vi.fn((signal: AbortSignal) => {
      calls += 1;
      if (calls > 1) return Promise.resolve('done');
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(noAnswer());
        });
      });
    });
    const result = retryStep(ctx, 'part', attempt);
    await flush();
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    window.dispatchEvent(new Event('offline'));
    await flush();
    expect(reports.at(-1)).toEqual({ status: 'waiting', waitReason: 'offline' });
    window.dispatchEvent(new Event('online'));
    await expect(result).resolves.toBe('done');
  });

  it('cancels during a wait, leaving no timer and no listener behind', async () => {
    const ledger = listenerLedger();
    const { ctx, controller } = fakeContext();
    const result = retryStep(ctx, 'part', scripted([noAnswer(), 'never reached']));
    await flush();
    controller.abort();
    await expect(result).rejects.toBeInstanceOf(UploadCancelledError);
    expect(vi.getTimerCount()).toBe(0);
    for (const type of ['online', 'offline', 'visibilitychange']) {
      expect(ledger.removed.get(type) ?? 0, type).toBe(ledger.added.get(type) ?? 0);
    }
  });

  it('does not end a part that shows progress and then waits, however long', async () => {
    const { ctx } = fakeContext();
    let release = (): void => {};
    const attempt = vi.fn(
      (_signal: AbortSignal, moving: () => void) =>
        new Promise((resolve) => {
          moving();
          release = () => {
            resolve('stored');
          };
        }),
    );
    const result = retryStep(ctx, 'part', attempt);
    await vi.advanceTimersByTimeAsync(300_000);
    expect(attempt).toHaveBeenCalledTimes(1);
    release();
    await expect(result).resolves.toBe('stored');
  });

  it('writes "finalizing" again when a completion retries online, and "uploading" when a part moves', async () => {
    const complete = fakeContext();
    const done = retryStep(complete.ctx, 'complete', scripted([noAnswer(), 'ok']));
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(done).resolves.toBe('ok');
    expect(complete.reports.at(-1)).toEqual({ status: 'finalizing', waitReason: undefined });

    const part = fakeContext();
    let calls = 0;
    const partAttempt = vi.fn((_signal: AbortSignal, moving: () => void) => {
      calls += 1;
      if (calls === 1) return Promise.reject(noAnswer());
      moving();
      return Promise.resolve('stored');
    });
    const stored = retryStep(part.ctx, 'part', partAttempt);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(stored).resolves.toBe('stored');
    expect(part.reports.at(-1)).toEqual({ status: 'uploading', waitReason: undefined });
  });
});

// ---------------------------------------------------------------------------
// The sentences
// ---------------------------------------------------------------------------

describe('describeUploadFailure — one sentence per kind of failure', () => {
  it.each([
    {
      label: 'no answer',
      error: noAnswer(),
      step: 'part',
      sentence: 'Could not reach the server. Check your connection and try again.',
    },
    {
      label: 'a 429',
      error: answered(429),
      step: 'part',
      sentence: 'Too many attempts. Please wait a moment and try again.',
    },
    {
      label: 'a 5xx',
      error: answered(500),
      step: 'part',
      sentence: 'The server is temporarily unavailable. Please try again in a moment.',
    },
    {
      label: 'a locked factor',
      error: answered(403, { message: 'ACCOUNT_LOCKED' }),
      step: 'part',
      sentence: ACCOUNT_LOCKED_MESSAGE,
    },
    { label: 'a 404', error: answered(404), step: 'part', sentence: UPLOAD_GONE_MESSAGE },
    {
      label: 'a session that is over',
      error: answered(401),
      step: 'part',
      sentence: SESSION_ENDED_MESSAGE,
    },
    {
      label: 'a second rotation',
      error: answered(409, { data: { vaultKeyVersion: 5 } }),
      step: 'complete',
      sentence: VAULT_KEY_CHANGED_AGAIN_MESSAGE,
    },
    {
      label: 'a refused part',
      error: answered(400, { message: 'Part 2 does not match its declared digest.' }),
      step: 'part',
      sentence:
        'The server refused part of this upload (Part 2 does not match its declared digest.). Select Retry to send it again, or cancel and upload the file again.',
    },
    {
      label: 'a refused completion',
      error: answered(400, { message: 'Storage quota exceeded.' }),
      step: 'complete',
      sentence: 'The upload could not be finished: Storage quota exceeded.',
    },
    {
      label: 'a file that cannot be read',
      error: new DOMException('gone', 'NotReadableError'),
      step: 'part',
      sentence: FILE_UNREADABLE_MESSAGE,
    },
    {
      label: "this client's own error",
      error: new Error('The file changed.'),
      step: 'part',
      sentence: 'The file changed.',
    },
    {
      label: 'something that is not an error',
      error: 'a string',
      step: 'part',
      sentence: GENERIC_UPLOAD_MESSAGE,
    },
  ] as const)('$label', ({ error, step, sentence }) => {
    expect(describeUploadFailure(error, step)).toBe(sentence);
  });

  it('keeps a stopped error as it is, and wraps anything else with its cause', () => {
    const stopped = new UploadStoppedError('already said', null);
    expect(toStoppedError(stopped)).toBe(stopped);
    const raw = answered(404);
    const wrapped = toStoppedError(raw);
    expect(wrapped.message).toBe(UPLOAD_GONE_MESSAGE);
    expect(wrapped.cause).toBe(raw);
  });
});

// ---------------------------------------------------------------------------
// A part, and a resume
// ---------------------------------------------------------------------------

describe('sendPart', () => {
  it('sends the SAME body on every attempt, with the attempt signal and progress', async () => {
    const { ctx } = fakeContext();
    const body = new Uint8Array([1, 2, 3]).buffer;
    const seen: { body: ArrayBuffer; signal: AbortSignal | undefined }[] = [];
    api.uploadDocumentPartApi.mockImplementation(
      (
        _id: string,
        _part: number,
        sent: ArrayBuffer,
        options: {
          signal?: AbortSignal;
          onUploadProgress?: (event: { loaded: number; total?: number }) => void;
        },
      ) => {
        seen.push({ body: sent, signal: options.signal });
        options.onUploadProgress?.({ loaded: 3, total: 3 });
        return seen.length === 1
          ? Promise.reject(noAnswer())
          : Promise.resolve({ data: { success: true } });
      },
    );
    const onAttempt = vi.fn();
    const onProgress = vi.fn();
    const sent = sendPart(ctx, 1, body, 'digest', { onAttempt, onProgress });
    await vi.advanceTimersByTimeAsync(1_000);
    await sent;

    expect(seen.map((entry) => entry.body)).toEqual([body, body]);
    expect(seen[0]?.signal).not.toBe(ctx.signal);
    expect(onAttempt).toHaveBeenCalledTimes(2);
    expect(onProgress).toHaveBeenCalledWith(3, 3);
  });

  it('abandons a CSRF token fetch that hangs when the browser goes offline', async () => {
    const { ctx } = fakeContext();
    api.ensureCsrfToken.mockReturnValueOnce(new Promise(() => {})).mockResolvedValue('csrf');
    api.uploadDocumentPartApi.mockResolvedValue({ data: { success: true } });
    const sent = sendPart(ctx, 1, new Uint8Array([1]).buffer, 'digest', {
      onAttempt: vi.fn(),
      onProgress: vi.fn(),
    });
    await flush();
    window.dispatchEvent(new Event('offline'));
    await flush();
    window.dispatchEvent(new Event('online'));
    await sent;
    expect(api.uploadDocumentPartApi).toHaveBeenCalledTimes(1);
  });
});

describe('prepareResume', () => {
  const LEDGER = {
    _id: ID,
    streamSalt: btoa(String.fromCharCode(...new Uint8Array(32))),
    noncePrefix: btoa(String.fromCharCode(...new Uint8Array(7))),
    declaredPlaintextBytes: 1,
    declaredChunkCount: 1,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    parts: [{ partNumber: 1, bytes: DOCUMENT_TAG_BYTES + 1 }],
    receivedBytes: DOCUMENT_TAG_BYTES + 1,
    createdAt: '2026-01-01T00:00:00.000Z',
    expiresAt: '2026-01-02T00:00:00.000Z',
  };
  const envelope = (data: unknown) => ({ data: { success: true, data } });

  it('reads the parts the server holds', async () => {
    api.getDocumentUploadApi.mockResolvedValue(envelope(LEDGER));
    const plan = await prepareResume(fakeContext().ctx);
    expect(plan).toEqual({ kind: 'resume', held: new Set([1]) });
  });

  it('refuses a ledger it cannot read, keeping the session for another try', async () => {
    api.getDocumentUploadApi.mockResolvedValue(envelope({ _id: 'nope' }));
    await expect(prepareResume(fakeContext().ctx)).rejects.toThrow(LEDGER_UNREADABLE_MESSAGE);
  });

  it('adopts a document that committed while its answer was lost', async () => {
    api.getDocumentUploadApi.mockRejectedValue(answered(404));
    api.getDocumentApi.mockResolvedValue(envelope({ _id: ID }));
    await expect(prepareResume(fakeContext().ctx)).resolves.toEqual({
      kind: 'committed',
      row: { _id: ID },
    });
  });

  it('waits for an answer when the probe cannot reach the server, then reports what it finds', async () => {
    api.getDocumentUploadApi.mockRejectedValue(answered(404));
    api.getDocumentApi.mockRejectedValueOnce(noAnswer()).mockRejectedValueOnce(answered(404));
    const plan = prepareResume(fakeContext().ctx);
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(plan).resolves.toEqual({ kind: 'gone', message: UPLOAD_GONE_MESSAGE });
  });

  it('gives up without the probe when the session itself is over', async () => {
    api.getDocumentUploadApi.mockRejectedValue(answered(401));
    await expect(prepareResume(fakeContext().ctx)).resolves.toEqual({
      kind: 'gone',
      message: SESSION_ENDED_MESSAGE,
    });
    expect(api.getDocumentApi).not.toHaveBeenCalled();
  });

  it('throws, keeping the session, when the probe exhausts the server ladder', async () => {
    api.getDocumentUploadApi.mockRejectedValue(answered(404));
    api.getDocumentApi.mockRejectedValue(answered(500));
    const plan = prepareResume(fakeContext().ctx).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(7_000);
    const error = await plan;
    expect(error).toBeInstanceOf(UploadStoppedError);
    expect((error as Error).message).toBe(SERVER_UNAVAILABLE_MESSAGE);
  });
});

// ---------------------------------------------------------------------------
// The toast's cap
// ---------------------------------------------------------------------------

describe('every sentence reaches a toast whole', () => {
  it('fits each fixed sentence inside the cap the toast cuts at, so a row and its toast agree', async () => {
    // Every `*_MESSAGE` the module exports, read from the module itself, so a
    // sentence added later is held to the same cap without anyone listing it.
    const engine = await import('../src/services/documents/uploadRecovery.js');
    const sentences = Object.entries(engine)
      .filter(([name, value]) => name.endsWith('_MESSAGE') && typeof value === 'string')
      .map(([, value]) => value as string);
    expect(sentences).toContain(INTERRUPTED_MESSAGE);
    expect(sentences).toHaveLength(8);
    for (const sentence of sentences) {
      // Through the very function the three toasts use, not a length compare.
      expect(getApiErrorMessage(new UploadStoppedError(sentence, null), 'fallback')).toBe(sentence);
    }
  });

  it.each([
    {
      step: 'part' as const,
      before: 'The server refused part of this upload (',
      after: '). Select Retry to send it again, or cancel and upload the file again.',
    },
    { step: 'complete' as const, before: 'The upload could not be finished: ', after: '' },
  ])(
    'quotes the server whole while it fits, and cuts the quotation, never the advice, past it ($step)',
    ({ step, before, after }) => {
      const room = MAX_ERROR_MESSAGE_LENGTH - before.length - after.length;
      const fits = 'a'.repeat(room);
      expect(describeUploadFailure(answered(400, { message: fits }), step)).toBe(
        `${before}${fits}${after}`,
      );

      const over = describeUploadFailure(answered(400, { message: 'b'.repeat(room + 1) }), step);
      expect(over).toBe(`${before}${'b'.repeat(room - 1)}…${after}`);
      expect(over).toHaveLength(MAX_ERROR_MESSAGE_LENGTH);
      expect(getApiErrorMessage(new UploadStoppedError(over, null), 'fallback')).toBe(over);
    },
  );
});

// ---------------------------------------------------------------------------
// The token fetch, and a retry that never reported progress
// ---------------------------------------------------------------------------

describe('sendPart — the CSRF token fetch fails', () => {
  it('waits out a token fetch that could not reach the server, sending no part until it can', async () => {
    const { ctx, reports } = fakeContext();
    api.ensureCsrfToken.mockRejectedValueOnce(noAnswer()).mockResolvedValue('csrf');
    api.uploadDocumentPartApi.mockResolvedValue({ data: { success: true } });

    const sent = sendPart(ctx, 1, new Uint8Array([1]).buffer, 'digest', {
      onAttempt: vi.fn(),
      onProgress: vi.fn(),
    });
    await flush();

    // Unreached: no part was sent, nothing was counted, and the row says why.
    expect(api.uploadDocumentPartApi).not.toHaveBeenCalled();
    expect(reports.at(-1)).toEqual({ status: 'waiting', waitReason: 'connection' });
    window.dispatchEvent(new Event('online'));
    await sent;
    expect(api.uploadDocumentPartApi).toHaveBeenCalledTimes(1);
  });

  it('stops at once, in words, on a token fetch that fails with something that is not an error', async () => {
    const { ctx } = fakeContext();
    api.ensureCsrfToken.mockImplementation(() => Promise.reject('refused by the extension'));

    const failure = await sendPart(ctx, 1, new Uint8Array([1]).buffer, 'digest', {
      onAttempt: vi.fn(),
      onProgress: vi.fn(),
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(UploadStoppedError);
    expect((failure as Error).message).toBe('refused by the extension');
    expect(api.ensureCsrfToken).toHaveBeenCalledTimes(1);
    expect(api.uploadDocumentPartApi).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('retryStep — a retried part stored without a progress event', () => {
  it('leaves the waiting state once the part is stored, even though no progress was reported', async () => {
    const { ctx, reports } = fakeContext();
    const stored = retryStep(ctx, 'part', scripted([noAnswer(), 'stored']));
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(stored).resolves.toBe('stored');
    expect(reports.at(-1)).toEqual({ status: 'uploading', waitReason: undefined });
  });

  it('writes nothing on a first attempt that succeeds, because nothing was waiting', async () => {
    const { ctx, reports } = fakeContext();

    await expect(retryStep(ctx, 'part', scripted(['stored']))).resolves.toBe('stored');
    expect(reports).toEqual([]);
  });
});
