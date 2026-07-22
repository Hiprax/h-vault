/**
 * Orchestrates password-strength analysis for the Vault Health page.
 *
 * The expensive part (zxcvbn) runs OFF the main thread in a dedicated Web Worker
 * so the page never freezes, however large the vault. Results already cached (by
 * item id + version) are returned instantly; only genuinely new passwords are sent
 * to the worker, deduplicated first. When Web Workers are unavailable (jsdom tests,
 * a browser without support, or a CSP block), it transparently falls back to
 * scoring on the main thread with cooperative yielding.
 *
 * This module is imported by the page, NOT by the worker — it references
 * `new Worker(...)`, which must never end up inside the worker's own bundle. The
 * pure scorer it shares with the worker lives in `./passwordStrength`.
 */
import { getZxcvbn } from '../../lib/lazyZxcvbn';
import { scorePasswords } from './passwordStrength';
import { getScore, setScore, strengthCacheKey } from './strengthCache';

/** One item to score: its id, current password, and a cache-busting version. */
export interface StrengthEntry {
  id: string;
  password: string;
  /** Any value that changes when the password might have (e.g. `updatedAt`). */
  version: string;
}

export interface StrengthAnalysisOptions {
  onProgress?: (done: number, total: number) => void;
  signal?: AbortSignal;
}

type WorkerFactory = () => Worker;

function defaultWorkerFactory(): WorkerFactory | null {
  if (typeof Worker === 'undefined') return null;
  return () => new Worker(new URL('../../workers/passwordStrength.worker.ts', import.meta.url));
}

let workerFactory: WorkerFactory | null = defaultWorkerFactory();

/**
 * Test seam: override the worker factory to exercise the worker path in an
 * environment without real Workers (jsdom). Pass `undefined` to restore the
 * environment default, or `null` to force the main-thread fallback.
 */
export function __setStrengthWorkerFactory(factory: WorkerFactory | null | undefined): void {
  workerFactory = factory === undefined ? defaultWorkerFactory() : factory;
}

/** Macrotask yield so the browser can paint/handle input between fallback chunks. */
function macrotaskYield(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

interface WorkerProgressMessage {
  type: 'progress';
  done: number;
  total: number;
}
interface WorkerResultMessage {
  type: 'result';
  scores: [string, number][];
}
/** The worker scored nothing and said so, rather than rejecting silently. */
interface WorkerErrorMessage {
  type: 'error';
  message?: string;
}
type WorkerMessage = WorkerProgressMessage | WorkerResultMessage | WorkerErrorMessage;

function computeScoresInWorker(
  factory: WorkerFactory,
  passwords: readonly string[],
  options: StrengthAnalysisOptions,
): Promise<Map<string, number>> {
  return new Promise<Map<string, number>>((resolve, reject) => {
    const worker = factory();
    let settled = false;

    const cleanup = (): void => {
      worker.terminate();
      options.signal?.removeEventListener('abort', onAbort);
    };
    const onAbort = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new DOMException('Strength analysis aborted', 'AbortError'));
    };

    if (options.signal) {
      if (options.signal.aborted) {
        onAbort();
        return;
      }
      options.signal.addEventListener('abort', onAbort, { once: true });
    }

    worker.onmessage = (event: MessageEvent<WorkerMessage>): void => {
      const message = event.data;
      if (message.type === 'progress') {
        options.onProgress?.(message.done, message.total);
        return;
      }
      if (settled) return;
      settled = true;
      cleanup();
      if (message.type === 'error') {
        reject(new Error(message.message ?? 'Password strength worker failed'));
        return;
      }
      resolve(new Map(message.scores));
    };
    worker.onerror = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error('Password strength worker failed'));
    };

    worker.postMessage({ passwords });
  });
}

async function computeScores(
  passwords: readonly string[],
  options: StrengthAnalysisOptions,
): Promise<Map<string, number>> {
  if (workerFactory) {
    try {
      return await computeScoresInWorker(workerFactory, passwords, options);
    } catch (error) {
      // An explicit abort must propagate; any other worker failure (CSP block,
      // load error, unsupported) degrades gracefully to the main-thread path.
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
    }
  }
  const zxcvbn = await getZxcvbn();
  return scorePasswords(passwords, (password) => zxcvbn(password), {
    ...options,
    yieldFn: macrotaskYield,
  });
}

/**
 * Analyze the strength of every entry. Returns `id -> zxcvbn score`. Cached
 * entries resolve without touching the worker; the rest are deduplicated by
 * password, scored once each, and cached by `${id}:${version}`.
 */
export async function analyzeStrength(
  entries: readonly StrengthEntry[],
  options: StrengthAnalysisOptions = {},
): Promise<Map<string, number>> {
  const { onProgress } = options;
  const result = new Map<string, number>();
  const toScore: StrengthEntry[] = [];

  for (const entry of entries) {
    const cached = getScore(strengthCacheKey(entry.id, entry.version));
    if (cached !== undefined) result.set(entry.id, cached);
    else toScore.push(entry);
  }

  if (toScore.length === 0) {
    onProgress?.(entries.length, entries.length);
    return result;
  }

  const uniquePasswords = [...new Set(toScore.map((entry) => entry.password))];
  const passwordScores = await computeScores(uniquePasswords, options);

  for (const entry of toScore) {
    const score = passwordScores.get(entry.password);
    // Undefined only when scoring was aborted before reaching this password;
    // the caller discards an aborted result, so leaving it unmapped is correct.
    if (score === undefined) continue;
    result.set(entry.id, score);
    setScore(strengthCacheKey(entry.id, entry.version), score);
  }

  return result;
}
