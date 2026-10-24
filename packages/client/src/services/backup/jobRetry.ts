/**
 * How a full backup and a full restore wait and retry one request, and how each
 * says why it stopped.
 *
 * Both are long jobs a person starts and then waits for, so a request that fails is
 * retried on the ladders the upload engine already uses (`uploadRecovery.ts`),
 * reached through its lazy loader like every other caller: about a minute for a
 * gateway answer, long enough for a container to restart during a deploy; the
 * patient unreached ladder, bounded here at ten minutes, for a server that cannot
 * be reached; and the server's own `Retry-After` for a rate limit, bounded at the
 * fifteen-minute window the per-account limiters use.
 *
 * Only a rate-limit wait counts as progress for the auto-lock pause: the server
 * asked for it, and the job resumes on its own. Waiting on a server that cannot be
 * reached does not, so a dead connection never holds the vault open.
 */

import { isAxiosError } from 'axios';
import { noteAutoLockProgress } from '../../hooks/useAutoLock.js';
import { loadUploadRecovery } from '../../lib/lazyUploadRecovery.js';
import { getApiErrorMessage } from '../../lib/utils.js';
import { isRateLimited, retryAfterSeconds } from '../auth/sessionFailure.js';
import { useAuthStore } from '../../stores/authStore.js';
import {
  documentsMutationGeneration,
  isAborted,
  useDocumentsStore,
} from '../../stores/documentsStore.js';
import { waitAbortably } from '../documents/download.js';

/** Why a job stopped before it finished. */
export type JobStopKind =
  'stopped' | 'vault-locked' | 'left' | 'rate-limited' | 'server-unavailable' | 'failed';

/** The reasons a job aborts its own controller with, so a lock is never reported as a Stop. */
type JobAbortReason = 'stopped' | 'vault-locked' | 'left';

/** A job stopping on purpose, with the one sentence its summary shows. */
export class JobStop extends Error {
  constructor(
    readonly stop: JobStopKind,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = 'JobStop';
  }
}

/** The longest server-requested wait a job sits through: the limiters' own window. */
export const MAX_RATE_LIMIT_WAIT_MS = 15 * 60 * 1000;

/** Waits one operation may make for the rate limit before the job stops. */
export const MAX_RATE_LIMIT_WAITS = 6;

/** The total a job waits, per operation, on a server it cannot reach. */
const MAX_UNREACHED_WAIT_MS = 10 * 60 * 1000;

/** What a job says when the server's rate limit outlasts what it waits for. */
export const RATE_LIMIT_STOP_MESSAGE =
  'The server asked this account to pause for longer than this waits. Try again later.';

/** How often a rate-limit wait records progress for the auto-lock pause. */
const WAIT_PROGRESS_INTERVAL_MS = 20_000;

/** What a retried request needs from the job running it. */
export interface RetryContext {
  signal: AbortSignal;
  /** How a wait is waited out; a seam for tests, defaulting to a timer. */
  wait?: (ms: number, signal: AbortSignal) => Promise<void>;
  /** Told when a rate-limit wait starts, with the instant it ends. */
  onRateLimitWait?: (until: number) => void;
}

/** A job's own abort signal, and what it watches to end the job by itself. */
export interface JobWatch {
  /** Aborted with the page's reason, or with `'vault-locked'` the moment either store says so. */
  signal: AbortSignal;
  /** Whether the vault locked or the session ended since the job started. */
  interrupted: () => boolean;
  /** Stop watching: the job is over. */
  release: () => void;
}

/**
 * Start watching for the job: the page's own Stop or departure (its signal's
 * reason is kept), and a lock or sign-out, read from BOTH stores, because
 * `logout()` clears the documents store at once but drops the vault key only after
 * its awaited request. `onChange` hears every other store change, while the job is
 * not interrupted.
 */
export function watchJob(pageSignal: AbortSignal, onChange?: () => void): JobWatch {
  const controller = new AbortController();
  const onPageAbort = (): void => {
    controller.abort(pageSignal.reason as JobAbortReason);
  };
  if (pageSignal.aborted) onPageAbort();
  else pageSignal.addEventListener('abort', onPageAbort, { once: true });

  const generation = documentsMutationGeneration();
  const interrupted = (): boolean =>
    generation !== documentsMutationGeneration() || useAuthStore.getState().vaultKey === null;
  const onStoreChange = (): void => {
    if (interrupted()) {
      if (!isAborted(controller.signal)) controller.abort('vault-locked' satisfies JobAbortReason);
      return;
    }
    onChange?.();
  };
  const unsubscribeAuth = useAuthStore.subscribe(onStoreChange);
  const unsubscribeDocuments = useDocumentsStore.subscribe(onStoreChange);
  onStoreChange();

  return {
    signal: controller.signal,
    interrupted,
    release: () => {
      unsubscribeAuth();
      unsubscribeDocuments();
      pageSignal.removeEventListener('abort', onPageAbort);
    },
  };
}

/** The retry context of a job: its signal, the test seam for waits, and who hears a rate-limit wait. */
export function retryContext(
  signal: AbortSignal,
  wait: RetryContext['wait'],
  onRateLimitWait: (until: number) => void,
): RetryContext {
  return { signal, ...(wait === undefined ? {} : { wait }), onRateLimitWait };
}

/** The sentence an abort is reported with, by the reason the job aborted with. */
export function abortedStop(signal: AbortSignal): JobStop {
  const reason: unknown = signal.reason;
  if (reason === 'vault-locked') {
    return new JobStop('vault-locked', 'The vault locked or you signed out.');
  }
  if (reason === 'left') return new JobStop('left', 'You left the page.');
  return new JobStop('stopped', 'You stopped it.');
}

/** The HTTP status of a failed request, or `null` when none came back. */
export function statusOf(error: unknown): number | null {
  return isAxiosError(error) ? (error.response?.status ?? null) : null;
}

/** Whether `error` is a request that got no answer at all. */
function isUnanswered(error: unknown): boolean {
  return isAxiosError(error) && error.response === undefined;
}

/**
 * Wait `ms` for a server-requested rate limit, recording progress for the auto-lock
 * pause every twenty seconds. Ends early when the job is aborted.
 */
export async function waitOutRateLimit(ms: number, context: RetryContext): Promise<void> {
  context.onRateLimitWait?.(Date.now() + ms);
  for (let left = ms; left > 0 && !isAborted(context.signal); left -= WAIT_PROGRESS_INTERVAL_MS) {
    noteAutoLockProgress();
    await pause(Math.min(left, WAIT_PROGRESS_INTERVAL_MS), context);
  }
}

/** Wait `ms`, or less if the job is aborted. */
export function pause(ms: number, context: RetryContext): Promise<void> {
  return (context.wait ?? waitAbortably)(ms, context.signal);
}

/**
 * Send `send`, retrying it on the ladders above. Resolves with its answer, or
 * rejects with:
 *
 * - {@link JobStop} when the job must stop (aborted, the rate limit or the server
 *   outlasted its ladder);
 * - the request's own error for anything else, a 5xx after the short ladder
 *   included, so the caller decides whether that one operation failed or the job.
 */
export async function sendWithRetries<T>(
  send: () => Promise<T>,
  context: RetryContext,
): Promise<T> {
  const recovery = await loadUploadRecovery();
  let rateLimitWaits = 0;
  let unreachedWaits = 0;
  let unreachedWaited = 0;
  let gatewayWaits = 0;
  let serverWaits = 0;
  for (;;) {
    if (isAborted(context.signal)) throw abortedStop(context.signal);
    try {
      return await send();
    } catch (error) {
      if (isAborted(context.signal)) throw abortedStop(context.signal);
      if (isRateLimited(error)) {
        const ms = (retryAfterSeconds(error) ?? 60) * 1000;
        if (ms > MAX_RATE_LIMIT_WAIT_MS || rateLimitWaits >= MAX_RATE_LIMIT_WAITS) {
          throw new JobStop('rate-limited', RATE_LIMIT_STOP_MESSAGE, { cause: error });
        }
        rateLimitWaits += 1;
        await waitOutRateLimit(ms, context);
        continue;
      }
      if (isUnanswered(error)) {
        const ms = recovery.unreachedDelayMs(unreachedWaits);
        if (unreachedWaited + ms > MAX_UNREACHED_WAIT_MS) {
          throw new JobStop('server-unavailable', 'Could not reach the server for ten minutes.', {
            cause: error,
          });
        }
        unreachedWaits += 1;
        unreachedWaited += ms;
        await pause(ms, context);
        continue;
      }
      const status = statusOf(error) ?? 0;
      if (status === 502 || status === 503 || status === 504) {
        const ms = recovery.GATEWAY_RETRY_DELAYS_MS[gatewayWaits];
        if (ms === undefined) {
          throw new JobStop(
            'server-unavailable',
            getApiErrorMessage(error, 'The server is temporarily unavailable.'),
            { cause: error },
          );
        }
        gatewayWaits += 1;
        await pause(ms, context);
        continue;
      }
      if (status >= 500) {
        const ms = recovery.SERVER_RETRY_DELAYS_MS[serverWaits];
        if (ms !== undefined) {
          serverWaits += 1;
          await pause(ms, context);
          continue;
        }
      }
      throw error;
    }
  }
}
