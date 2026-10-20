/**
 * How a document upload rides out a dropped connection, a slow link and a
 * restarting server.
 *
 * LAZY, and that is load-bearing. `documentsStore` is reachable statically from
 * `authStore` (a lock tears a transfer down before any I/O), so everything it
 * imports lands in the initial payload, which sits within two kilobytes of its
 * ratcheted budget. This module is reached ONLY through
 * `lib/lazyUploadRecovery.ts`'s `import()`, the same arrangement as
 * `lib/lazySha256.ts`, and so is fetched the first time someone uploads a file.
 * It imports the store's error type and helpers statically, which is safe: only a
 * store action ever reaches the `import()`, and by then the store has finished
 * evaluating.
 *
 * ## One driver, and a class decided on evidence
 *
 * Every network step of a live transfer (a part, the completion, a resume's
 * ledger read and its probe) runs through {@link retryStep}, which decides what a
 * failure means from whether the SERVER WAS REACHED, never from the bare absence
 * of a response:
 *
 *  - **Unreached** waits without limit and never fails the transfer: the browser
 *    reports offline, our own `offline` listener (or "Retry now") ended the
 *    attempt, a small non-part step got no answer, or a part got no answer
 *    before any of its body moved and before {@link LONG_ATTEMPT_MS} passed.
 *    Nothing reached the server, so waiting costs it nothing.
 *  - **Interrupted** is bounded at {@link INTERRUPTED_ATTEMPTS} per part: a part
 *    that got no answer AFTER its body was moving, or after a long attempt, or a
 *    408. That is the server deliberately cutting off a part that arrived too
 *    slowly (its body deadline destroys the socket), or a connection that keeps
 *    dropping mid-part, and retrying it for ever would hold one of the process's
 *    few part slots for ever. The allowance is the server's own
 *    `DOCUMENT_PART_RETRY_ALLOWANCE`, and an attempt is refunded if the browser
 *    reports offline during the wait that follows it.
 *  - **Gateway** (502, 503, 504, and a completion's version-less 409) waits about
 *    a minute: a restarting app during a deploy, and the inner nginx turns the
 *    app's own 503 into a 502 without `Retry-After`.
 *  - **Server** (any other 5xx) keeps the original 1 s / 2 s / 4 s.
 *  - 404 and a session that is over abandon; 429 and every other refusal fail
 *    resumably; anything that is not an HTTP failure at all fails at once, so no
 *    bug in this client can turn into an endless loop.
 *
 * There is deliberately NO stall watchdog. The server QUEUES a part whose slot is
 * busy with its body unread (`partSemaphore.ts`: "made to WAIT, not answered with
 * 429 or 503"), every proxy streams the body, and a waiter that gives up loses
 * its place, so "no progress for N seconds" cannot be told apart from legitimate
 * queueing. The server bounds that wait itself, with its whole-request deadline.
 */

import { isAxiosError } from 'axios';
import { documentUploadResponseSchema } from '@hvault/shared';
import { ensureCsrfToken } from '../api/client.js';
import {
  completeDocumentUploadApi,
  getDocumentApi,
  getDocumentUploadApi,
  uploadDocumentPartApi,
} from '../api/documentsApi.js';
import { staleVaultKeyVersion } from '../api/staleVaultKey.js';
import { getProfileApi } from '../api/userApi.js';
import {
  ACCOUNT_LOCKED_MESSAGE,
  describeTransientFailure,
  isAccountLocked,
  isSessionGone,
} from '../auth/sessionFailure.js';
import { cryptoService } from '../crypto/cryptoService.js';
import { deriveWrapKey, wrapDek } from '../crypto/documentCryptoService.js';
import { logger } from '../../lib/logger.js';
import { MAX_ERROR_MESSAGE_LENGTH, getApiErrorMessage } from '../../lib/utils.js';
import { useAuthStore } from '../../stores/authStore.js';
import {
  UploadCancelledError,
  isAborted,
  payloadOf,
  type DocumentUploadProgress,
  type UploadSession,
} from '../../stores/documentsStore.js';

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/** The waits of the ordinary server ladder: three retries, four attempts. */
export const SERVER_RETRY_DELAYS_MS = [1_000, 2_000, 4_000] as const;

/**
 * The waits of the patient ladder, about a minute in all: long enough for a
 * container to restart during a deploy, short enough that a server that is
 * really down is reported rather than waited on for ever.
 */
export const GATEWAY_RETRY_DELAYS_MS = [1_000, 2_000, 4_000, 8_000, 16_000, 30_000] as const;

/**
 * Attempts one part gets when the server keeps cutting it off part-way: the
 * first and one per wait of the server ladder, which is the server's own
 * `DOCUMENT_PART_RETRY_ALLOWANCE` of four.
 */
export const INTERRUPTED_ATTEMPTS = SERVER_RETRY_DELAYS_MS.length + 1;

/**
 * How long a part attempt may run before a failure without an answer counts as
 * having reached the server even though no upload progress was reported.
 *
 * The second signal beside progress, so that a browser which ever withheld
 * upload-progress events could not turn the server's own cut-off of a too-slow
 * part (about a minute) back into an endless loop. A connection that fails
 * before this has not got anywhere.
 */
export const LONG_ATTEMPT_MS = 20_000;

/** The longest an unreached step waits between attempts. */
export const MAX_UNREACHED_DELAY_MS = 30_000;

/** The unreached wait before attempt `n + 1`: 1, 2, 4, 8, 16, then 30 s for ever. */
export function unreachedDelayMs(waits: number): number {
  return Math.min(1_000 * 2 ** waits, MAX_UNREACHED_DELAY_MS);
}

// ---------------------------------------------------------------------------
// What a reader is told
// ---------------------------------------------------------------------------
//
// Every sentence here fits MAX_ERROR_MESSAGE_LENGTH: the row shows it whole, and
// the toast beside it goes through `getApiErrorMessage`, which cuts at that
// length. A longer one would reach the toast cut off mid-word.

export const INTERRUPTED_MESSAGE =
  'The upload kept being interrupted part-way: the connection keeps dropping or is too slow (fewer uploads at once can help). The parts already sent are kept: select Retry to try again.';
export const SERVER_UNAVAILABLE_MESSAGE =
  'The server could not take this upload just now. The parts already sent are kept: select Retry in a moment to continue.';
export const UPLOAD_GONE_MESSAGE =
  'This upload is no longer on the server: it expired or was cancelled in another tab. Upload the file again.';
export const SESSION_ENDED_MESSAGE =
  'Your session ended, so this upload stopped. Sign in and upload the file again.';
export const VAULT_KEY_CHANGED_AGAIN_MESSAGE =
  'The vault key changed again while this upload was finishing. Select Retry to finish it.';
export const LEDGER_UNREADABLE_MESSAGE =
  "The server's record of this upload could not be read, so it was not resumed. Select Retry to try again.";
export const FILE_UNREADABLE_MESSAGE =
  'The file could not be read any more (it may have been moved, changed or deleted). Choose it again to upload it.';
export const GENERIC_UPLOAD_MESSAGE = 'The upload stopped. Select Retry to try again.';

/**
 * A transfer that stopped, carrying the sentence the row and the toast both
 * show, and the failure behind it as `cause`.
 */
export class UploadStoppedError extends Error {
  constructor(
    message: string,
    readonly cause: unknown,
  ) {
    super(message);
    this.name = 'UploadStoppedError';
  }
}

/** A refusal no retry could survive, so the session ends with it. */
export class UnresumableUploadError extends Error {
  constructor(
    readonly cause: unknown,
    step: RecoveryStep = 'part',
  ) {
    super(describeUploadFailure(cause, step));
    this.name = 'UnresumableUploadError';
  }
}

/** Which kind of request a step is: they differ in what a silent failure means. */
export type RecoveryStep = 'part' | 'complete' | 'resume';

function isNotReadable(error: unknown): boolean {
  // Checked by NAME, before `instanceof Error`: under jsdom a `DOMException` is
  // not an `Error`, and a file that can no longer be read rejects with one.
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    error.name === 'NotReadableError'
  );
}

/**
 * The sentence for a failure that is not one of the driver's own exhausted
 * ladders, which name themselves.
 */
export function describeUploadFailure(error: unknown, step: RecoveryStep): string {
  const transient = describeTransientFailure(error);
  if (transient !== null) return transient;
  if (isAccountLocked(error)) return ACCOUNT_LOCKED_MESSAGE;
  if (isAxiosError(error) && error.response?.status === 404) return UPLOAD_GONE_MESSAGE;
  if (isSessionGone(error)) return SESSION_ENDED_MESSAGE;
  if (staleVaultKeyVersion(error) !== null) return VAULT_KEY_CHANGED_AGAIN_MESSAGE;
  if (isAxiosError(error) && error.response !== undefined) {
    const server = getApiErrorMessage(error, GENERIC_UPLOAD_MESSAGE);
    return step === 'part'
      ? quoting(
          'The server refused part of this upload (',
          server,
          '). Select Retry to send it again, or cancel and upload the file again.',
        )
      : quoting('The upload could not be finished: ', server, '');
  }
  if (isNotReadable(error)) return FILE_UNREADABLE_MESSAGE;
  if (error instanceof Error) return error.message;
  return GENERIC_UPLOAD_MESSAGE;
}

/**
 * A sentence quoting the server, with the quotation cut (and marked) so that the
 * whole of it fits the toast's cap: cut from the end instead, the advice after
 * the quotation would be what a reader lost.
 */
function quoting(before: string, server: string, after: string): string {
  const room = MAX_ERROR_MESSAGE_LENGTH - before.length - after.length;
  const quoted = server.length <= room ? server : `${server.slice(0, room - 1)}…`;
  return `${before}${quoted}${after}`;
}

/** `error` as an {@link UploadStoppedError}, keeping one that already is. */
export function toStoppedError(error: unknown, step: RecoveryStep = 'part'): UploadStoppedError {
  if (error instanceof UploadStoppedError) return error;
  return new UploadStoppedError(describeUploadFailure(error, step), error);
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/** What one transfer hands the driver. */
export interface TransferContext {
  readonly uploadId: string;
  readonly session: UploadSession;
  /** The TRANSFER's signal: a lock, a logout or a cancel. Never one attempt's. */
  readonly signal: AbortSignal;
  /** Write a non-terminal status. The driver never writes `failed`. */
  report(patch: Pick<DocumentUploadProgress, 'status' | 'waitReason'>): void;
}

type WaitReason = NonNullable<DocumentUploadProgress['waitReason']>;

/** What the driver learned about one attempt while it ran. */
interface AttemptRecord {
  progressed: boolean;
  long: boolean;
  /** Set when WE ended the attempt: the browser went offline, or "Retry now". */
  ourAbort: 'offline' | 'manual' | null;
}

type Verdict = 'unreached' | 'interrupted' | 'gateway' | 'server' | 'stale' | 'fail' | 'abandon';

function isBrowserOnline(): boolean {
  return navigator.onLine;
}

/** What a failed attempt means, from the evidence of whether it reached the server. */
export function classifyFailure(
  error: unknown,
  step: RecoveryStep,
  record: Readonly<AttemptRecord>,
): Verdict {
  if (record.ourAbort !== null) return 'unreached';
  if (!isAxiosError(error)) return 'fail';
  const status = error.response?.status;
  if (status === undefined) {
    if (step !== 'part' || !isBrowserOnline()) return 'unreached';
    return record.progressed || record.long ? 'interrupted' : 'unreached';
  }
  if (status === 404) return 'abandon';
  if (isSessionGone(error)) return 'abandon';
  if (status === 429) return 'fail';
  if (status === 408) return step === 'part' ? 'interrupted' : 'server';
  if (status === 502 || status === 503 || status === 504) return 'gateway';
  if (status >= 500) return 'server';
  if (step === 'complete' && status === 409) {
    return staleVaultKeyVersion(error) === null ? 'gateway' : 'stale';
  }
  return 'fail';
}

/**
 * Wait before the next attempt, or until something says it is worth trying now.
 *
 * Ends on the timer, on `online`, on the tab becoming visible, on "Retry now"
 * (`session.wake`) and on the transfer being aborted, and removes every listener
 * and the timer on each of those exits. An `offline` event does NOT end it: it
 * changes what the row says, and tells the caller an interrupted attempt was
 * really the network going away.
 */
export function waitToRetry(
  ctx: TransferContext,
  reason: WaitReason,
  ms: number,
): Promise<{ wentOffline: boolean }> {
  return new Promise((resolve) => {
    let wentOffline = false;
    ctx.report({ status: 'waiting', waitReason: reason });
    const timer = setTimeout(finish, ms);
    const onVisible = (): void => {
      if (document.visibilityState === 'visible') finish();
    };
    const onOffline = (): void => {
      wentOffline = true;
      ctx.report({ status: 'waiting', waitReason: 'offline' });
    };
    ctx.signal.addEventListener('abort', finish);
    window.addEventListener('online', finish);
    window.addEventListener('offline', onOffline);
    document.addEventListener('visibilitychange', onVisible);
    ctx.session.wake = finish;

    function finish(): void {
      clearTimeout(timer);
      ctx.signal.removeEventListener('abort', finish);
      window.removeEventListener('online', finish);
      window.removeEventListener('offline', onOffline);
      document.removeEventListener('visibilitychange', onVisible);
      if (ctx.session.wake === finish) ctx.session.wake = null;
      resolve({ wentOffline });
    }
  });
}

/**
 * Settle with `promise`, or reject as soon as `signal` aborts.
 *
 * For the one call in an attempt that takes no signal of its own (the CSRF
 * token fetch): abandoning it leaves it to finish in the background, where its
 * answer is cached for the next attempt.
 */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const onAbort = (): void => {
      reject(new DOMException('The attempt was abandoned', 'AbortError'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/**
 * Run one step until it succeeds, waiting and retrying as its class allows.
 *
 * `attempt` receives the ATTEMPT's signal, which ends when the transfer ends,
 * when the browser goes offline, and when "Retry now" is pressed while a retry
 * is still showing `waiting`; and a callback to report that the request's body
 * is moving. Every counter is local, so a ladder starts again for every step: a
 * confirmed part restores its whole allowance.
 */
export async function retryStep<T>(
  ctx: TransferContext,
  step: RecoveryStep,
  attempt: (signal: AbortSignal, onBodyProgress: () => void) => Promise<T>,
): Promise<T> {
  let unreachedWaits = 0;
  // Retries spent per bounded ladder. Interrupted parts climb the server ladder
  // with a count of their own, so a 503 does not eat into a part's allowance.
  const retries = { interrupted: 0, gateway: 0, server: 0 };
  let waited = false;

  for (;;) {
    if (isAborted(ctx.signal)) throw new UploadCancelledError();
    // A completion can take minutes on the server, and a row still reading
    // "Cannot reach the server" while it does would be wrong. Only when online:
    // an attempt that is about to fail at once must not flash a different state.
    if (waited && step === 'complete' && isBrowserOnline()) {
      ctx.report({ status: 'finalizing', waitReason: undefined });
    }

    const record: AttemptRecord = { progressed: false, long: false, ourAbort: null };
    const controller = new AbortController();
    const abortAttempt = (reason: 'offline' | 'manual'): void => {
      record.ourAbort ??= reason;
      controller.abort();
    };
    // A lock, a logout or a cancel ends a part or a resume read in flight. It does
    // NOT end a completion already on the wire: the server commits from that body
    // either way, so ending it would only turn a committed upload into a reported
    // cancellation, and `adoptCommittedRow` already drops the answer when one
    // arrives after a lock. Waits still end on the transfer's signal.
    const linkTransferAbort = step !== 'complete';
    const onTransferAbort = (): void => {
      controller.abort();
    };
    const onOffline = (): void => {
      abortAttempt('offline');
    };
    const manualWake = (): void => {
      abortAttempt('manual');
    };
    if (linkTransferAbort) ctx.signal.addEventListener('abort', onTransferAbort);
    window.addEventListener('offline', onOffline);
    const longTimer =
      step === 'part'
        ? setTimeout(() => {
            record.long = true;
          }, LONG_ATTEMPT_MS)
        : undefined;
    // After a wait the row still says why it waited, so "Retry now" is still on
    // screen: it must do something, and what it can do is end this attempt and
    // start the next one at once.
    if (waited) ctx.session.wake = manualWake;

    try {
      const result = await attempt(controller.signal, () => {
        if (record.progressed) return;
        record.progressed = true;
        if (ctx.session.wake === manualWake) ctx.session.wake = null;
        if (waited && step === 'part') ctx.report({ status: 'uploading', waitReason: undefined });
      });
      // A retried part the server stored without the browser ever reporting
      // progress still has to leave the waiting state: nothing else would.
      if (waited && step === 'part' && !record.progressed) {
        ctx.report({ status: 'uploading', waitReason: undefined });
      }
      return result;
    } catch (error) {
      // FIRST, before the status is looked at: an aborted request has no response,
      // and reading a lock as "offline" would sleep and then seal again under a
      // key that has just been zeroed.
      if (isAborted(ctx.signal) || error instanceof UploadCancelledError) {
        throw new UploadCancelledError();
      }
      const verdict = classifyFailure(error, step, record);
      if (verdict === 'abandon') throw new UnresumableUploadError(error, step);
      if (verdict === 'stale') throw error;
      if (verdict === 'fail') throw toStoppedError(error, step);

      if (verdict === 'unreached') {
        if (record.ourAbort === 'manual') {
          logger.info('Retrying a document upload step now, as asked', { step });
          waited = true;
          continue;
        }
        const delayMs = unreachedDelayMs(unreachedWaits);
        unreachedWaits += 1;
        await waitToRetry(ctx, isBrowserOnline() ? 'connection' : 'offline', delayMs);
      } else {
        const ladder = verdict === 'gateway' ? GATEWAY_RETRY_DELAYS_MS : SERVER_RETRY_DELAYS_MS;
        const delayMs = ladder[retries[verdict]];
        if (delayMs === undefined) {
          throw new UploadStoppedError(
            verdict === 'interrupted' ? INTERRUPTED_MESSAGE : SERVER_UNAVAILABLE_MESSAGE,
            error,
          );
        }
        retries[verdict] += 1;
        const { wentOffline } = await waitToRetry(
          ctx,
          verdict === 'interrupted' ? 'interrupted' : 'server',
          delayMs,
        );
        // The interface dropped and the error merely arrived before the event did:
        // that was the network going away, not the server cutting the part off.
        if (verdict === 'interrupted' && wentOffline) retries.interrupted -= 1;
      }
      logger.warn('Retrying a document upload step', { step, verdict });
      waited = true;
    } finally {
      if (linkTransferAbort) ctx.signal.removeEventListener('abort', onTransferAbort);
      window.removeEventListener('offline', onOffline);
      if (longTimer !== undefined) clearTimeout(longTimer);
      if (ctx.session.wake === manualWake) ctx.session.wake = null;
    }
  }
}

// ---------------------------------------------------------------------------
// The steps
// ---------------------------------------------------------------------------

/** What the store wants to hear while a part is on the wire. */
export interface PartHooks {
  /** Called at the start of every attempt, the first included. */
  onAttempt(): void;
  onProgress(loaded: number, total: number): void;
}

/**
 * Send one sealed part until the server stores it.
 *
 * `body` is sealed ONCE by the caller and re-sent byte for byte: two different
 * plaintexts under one segment nonce would hand anyone holding both their XOR,
 * and the server replaces a re-sent part's ledger entry rather than adding one.
 *
 * The CSRF token is resolved as its own step, raced against the attempt, so a
 * token fetch that fails offline is classified here like the part itself rather
 * than arriving later as a rejection of a request this caller never made.
 */
export async function sendPart(
  ctx: TransferContext,
  partNumber: number,
  body: ArrayBuffer,
  digest: string,
  hooks: PartHooks,
): Promise<void> {
  await retryStep(ctx, 'part', async (signal, onBodyProgress) => {
    hooks.onAttempt();
    await untilAborted(ensureCsrfToken(), signal);
    await uploadDocumentPartApi(ctx.uploadId, partNumber, body, {
      digest,
      signal,
      onUploadProgress: (event) => {
        const total = event.total ?? body.byteLength;
        if (event.loaded > 0) onBodyProgress();
        hooks.onProgress(event.loaded, total);
      },
    });
  });
}

/**
 * Re-derive the account's CURRENT vault key from the server's copy and the MEK.
 *
 * Deliberately does NOT write it into `authStore`: adopting a rotated vault key
 * mid-session is a decision about the whole session, and making it as a side
 * effect of finishing one upload would be a hidden state change nobody could
 * reason about later. The key returned here lives for one rewrap and is cleared.
 */
async function currentVaultKey(signal: AbortSignal): Promise<CryptoKey> {
  const { mek } = useAuthStore.getState();
  if (!mek) throw new Error('Vault is locked. Unlock it before performing document operations.');
  const profile = payloadOf(await getProfileApi(signal), 'read the profile');
  const raw = await cryptoService.decryptVaultKey(
    profile.encryptedVaultKey,
    profile.vaultKeyIv,
    profile.vaultKeyTag,
    mek,
  );
  try {
    return await cryptoService.importVaultKey(raw);
  } finally {
    cryptoService.clearKey(raw);
  }
}

/**
 * Commit the transfer, recovering once from a vault-key rotation that landed
 * mid-upload, and riding out the connection like every other step.
 *
 * The wrapped key is sent HERE, not taken from the staging row, which is why a
 * rotation costs one request instead of the whole file: on a 409 carrying a
 * version the profile is re-read, the DEK this session still holds is rewrapped
 * under the new vault key, and THIS request alone is retried. Exactly one rewrap:
 * a second stale answer means a second rotation landed inside the recovery, and
 * is the user's to resolve. A repeated completion is safe, because the server
 * answers a committed upload with the document it already committed.
 *
 * `vaultKeyVersion` is THIS SESSION'S generation, never the number init echoed:
 * the echo is the server's own, and sending it back would ask the server to
 * compare a number with itself.
 */
export async function completeTransfer(
  ctx: TransferContext,
  sealedMeta: { encryptedMeta: string; metaIv: string; metaTag: string },
  vaultKey: CryptoKey,
  vaultKeyVersion: number,
): Promise<unknown> {
  const send = async (key: CryptoKey, version: number, signal: AbortSignal): Promise<unknown> => {
    const wrapKey = await deriveWrapKey(key, ctx.uploadId);
    // Checked immediately before the DEK is read, with nothing awaited in
    // between: `clearStore()` aborts and then SYNCHRONOUSLY zeroes, so a check
    // any earlier leaves a window in which this wraps 32 zero bytes, and the
    // server commits the row from THIS body.
    if (isAborted(ctx.signal)) throw new UploadCancelledError();
    const wrapped = await wrapDek(ctx.session.dek, wrapKey);
    return payloadOf(
      await completeDocumentUploadApi(
        ctx.uploadId,
        { ...sealedMeta, ...wrapped, vaultKeyVersion: version },
        signal,
      ),
      'complete the upload',
    );
  };

  try {
    return await retryStep(ctx, 'complete', (signal) => send(vaultKey, vaultKeyVersion, signal));
  } catch (error) {
    const version = staleVaultKeyVersion(error);
    if (version === null) throw error;
    logger.info('Rewrapping a document key after a vault key rotation', {
      uploadId: ctx.uploadId,
      version,
    });
    // The profile read and the send are ONE unit, retried together: a connection
    // lost between them is recovered like any other, and every rotated key the
    // unit builds is cleared on its way out.
    return retryStep(ctx, 'complete', async (signal) => {
      const rotatedKey = await currentVaultKey(signal);
      try {
        if (isAborted(ctx.signal)) throw new UploadCancelledError();
        return await send(rotatedKey, version, signal);
      } finally {
        await cryptoService.clearCryptoKey(rotatedKey);
      }
    });
  }
}

/** What a resume found out about its transfer before sending anything. */
export type ResumePlan =
  | { readonly kind: 'resume'; readonly held: Set<number> }
  | { readonly kind: 'committed'; readonly row: unknown }
  | { readonly kind: 'gone'; readonly message: string };

/**
 * Read the staging ledger, or find out why there is none.
 *
 * A 404 is not necessarily the end: a completion that committed while its
 * answer was lost deletes the staging row, so the document itself is asked for
 * before the transfer is given up, and a committed one is adopted rather than
 * uploaded twice. Both reads ride out the connection like every other step, so a
 * Retry pressed while still offline waits and resumes by itself.
 */
export async function prepareResume(ctx: TransferContext): Promise<ResumePlan> {
  let ledger: unknown;
  try {
    ledger = await retryStep(ctx, 'resume', async (signal) =>
      payloadOf(await getDocumentUploadApi(ctx.uploadId, signal), 'read the upload'),
    );
  } catch (error) {
    if (!(error instanceof UnresumableUploadError)) throw error;
    if (!(isAxiosError(error.cause) && error.cause.response?.status === 404)) {
      return { kind: 'gone', message: error.message };
    }
    try {
      const row = await retryStep(ctx, 'resume', async (signal) =>
        payloadOf(await getDocumentApi(ctx.uploadId, signal), 'read the document'),
      );
      return { kind: 'committed', row };
    } catch (probeError) {
      if (probeError instanceof UnresumableUploadError) {
        return { kind: 'gone', message: probeError.message };
      }
      throw probeError;
    }
  }
  // Validated, like every row this client reads: the part numbers decide which
  // segments are re-sent, so a malformed ledger would silently re-send everything
  // or fail somewhere less obvious than here.
  const parsed = documentUploadResponseSchema.safeParse(ledger);
  if (!parsed.success) throw new UploadStoppedError(LEDGER_UNREADABLE_MESSAGE, parsed.error);
  return { kind: 'resume', held: new Set(parsed.data.parts.map((part) => part.partNumber)) };
}
