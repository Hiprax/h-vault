/**
 * Putting a full backup's documents back, after its vault rows have been restored.
 *
 * A document's id is HKDF input for all three of its keys, and the server mints ids,
 * so a document cannot be restored by sending its stored bytes back: each one is
 * read from the FILE with the ONE verified read (`download.ts`, under the backup's
 * own vault key) and uploaded again through the ordinary upload path, under this
 * account's key, as a new document. The upload seals `restoredFrom`, the id it had
 * in the backup, so restoring the same backup again recognises it.
 *
 * ## Matching mirrors the vault rows exactly
 *
 * A backup document matches a document this account holds by its own id first,
 * then by that sealed provenance, never by content (the rule the vault restore's
 * items follow, `backupController.ts`). Then, as the items do:
 *
 * - a match in the TRASH is restored from the trash and given the backup's details,
 *   whatever the strategy;
 * - a live match is left alone (`skip`), given the backup's details (`overwrite`),
 *   or kept beside a fresh copy (`keep_both`);
 * - no match (or one already being permanently deleted) is uploaded.
 *
 * So re-running the same restore with Skip continues where an interrupted one
 * stopped, without a second copy of anything it already restored.
 *
 * ## How it stops
 *
 * One function decides what every refusal means, keyed by where it came from: a
 * start refused before the transfer existed arrives as the raw request error, a
 * transfer that failed afterwards as an `UploadStoppedError` whose own ladders are
 * already spent. "Retry" always re-sends the operation that failed. A refusal about
 * one document is recorded and the run goes on; a refusal that would refuse every
 * document after it stops the run, and every stop cancels the transfer in flight.
 */

import type { AxiosError } from 'axios';
import {
  MAX_DOCUMENTS_PER_USER,
  documentExtension,
  type DocumentMeta,
  type DocumentResponse,
} from '@hvault/shared';
import { noteAutoLockProgress } from '../../hooks/useAutoLock.js';
import { loadUploadRecovery } from '../../lib/lazyUploadRecovery.js';
import { getApiErrorMessage } from '../../lib/utils.js';
import {
  DOCUMENT_TYPE_LOCKED_MESSAGE,
  DocumentDetailsRefusedError,
  isAborted,
  payloadOf,
  useDocumentsStore,
  type DecryptedDocument,
  type StartUploadInput,
} from '../../stores/documentsStore.js';
import { readDocumentsConfigFresh } from '../api/configApi.js';
import { getDocumentUsageApi } from '../api/documentsApi.js';
import { isRateLimited, isSessionGone, retryAfterSeconds } from '../auth/sessionFailure.js';
import { cryptoService } from '../crypto/cryptoService.js';
import {
  decryptMeta,
  deriveMetaKey,
  deriveWrapKey,
  unwrapDek,
  zeroDek,
} from '../crypto/documentCryptoService.js';
import { UNOPENABLE_DOCUMENT_NAME } from '../documents/documentNames.js';
import { DocumentIntegrityError, streamDocumentPlaintext } from '../documents/download.js';
import { isAuthenticationFailure } from '../vault/vaultRows.js';
import type { FullBackupEntry, OpenedFullBackup } from './fullBackupFormat.js';
import {
  retryContext,
  watchJob,
  JobStop,
  MAX_RATE_LIMIT_WAIT_MS,
  MAX_RATE_LIMIT_WAITS,
  RATE_LIMIT_STOP_MESSAGE,
  abortedStop,
  pause,
  sendWithRetries,
  statusOf,
  waitOutRateLimit,
  type JobStopKind,
  type RetryContext,
} from './jobRetry.js';

/** The init refusal that only means "another start is being decided right now". */
const INIT_LOCK_BUSY_MESSAGE =
  'Another transfer is already being opened for this account. Please wait a moment and retry.';

/** How long to wait, and how often, before re-trying a start refused for that reason. */
const INIT_LOCK_BUSY_WAIT_MS = 2_000;
const INIT_LOCK_BUSY_RETRIES = 5;

/** The 404 a start answers when the folder it names is not this account's. */
const FOLDER_NOT_FOUND_MESSAGE = 'Target folder not found';

/** The 400s at upload start that would refuse every document after this one. */
const ACCOUNT_LIMIT_PATTERN =
  /^(Too many uploads in progress|Document limit reached|Storage quota exceeded)/;

/** Where a restore is, for the progress line. */
export interface DocumentRestoreProgress {
  index: number;
  total: number;
  name: string;
  /** The upload in flight for this document, when there is one. */
  uploadId?: string;
  /** While the server asked for a pause: when it ends (epoch milliseconds). */
  waitUntil?: number;
}

/** A document that was not restored, by the name the backup gives it, and why. */
interface UnrestoredDocument {
  name: string;
  reason: string;
}

/** What a restore of the documents did, accounting for every entry. */
export interface DocumentRestoreReport {
  total: number;
  uploaded: number;
  restoredFromTrash: number;
  updated: number;
  alreadyPresent: number;
  notRestored: UnrestoredDocument[];
  /** Entries a stop left unread. */
  notAttempted: number;
  /** Things worth saying about documents that WERE restored (a folder that was gone). */
  notes: string[];
  /** Documents the account held when the backup was made that are not in the file. */
  missingFromBackup: number;
  /**
   * Documents the backup itself could not include when it was made (left out as
   * unreadable, deleted or missing their stored file, or rows it could not read).
   */
  leftOutOfBackup: number;
  /** Present when the run stopped before the last entry. */
  stopped?: { stop: JobStopKind; message: string };
}

export interface RestoreDocumentsOptions {
  backup: OpenedFullBackup;
  /** The vault key the backup's documents are wrapped under. */
  backupVaultKey: CryptoKey;
  /** From the vault restore's answer; absent from a server before 0.22.0. */
  folderIdMap: { backupId: string; folderId: string }[] | undefined;
  conflictStrategy: 'skip' | 'overwrite' | 'keep_both';
  /** Aborted by the page, with `'stopped'` or `'left'`. */
  signal: AbortSignal;
  onProgress?: (progress: DocumentRestoreProgress) => void;
  /** A seam for tests; waits are abortable timers otherwise. */
  wait?: RetryContext['wait'];
}

/** The transfer in flight, whose stored parts are the run's progress. */
interface InFlightTransfer {
  id: string | null;
  /** The highest `sentBytes` seen for it. */
  sent: number;
  /** Told the moment the store registers it, so the page can show its bytes. */
  announce: (uploadId: string) => void;
}

/** A refusal about one document: recorded, and the run goes on. */
class NotRestored extends Error {}

/** A backup entry's sealed metadata, opened under the backup's key, or `null`. */
async function openEntryMeta(row: DocumentResponse, key: CryptoKey): Promise<DocumentMeta | null> {
  let dek: Uint8Array<ArrayBuffer> | null = null;
  try {
    dek = await unwrapDek(row, await deriveWrapKey(key, row._id));
    const salt = new Uint8Array(cryptoService.base64ToArrayBuffer(row.streamSalt));
    return await decryptMeta(await deriveMetaKey(dek, salt, row._id), row);
  } catch {
    return null;
  } finally {
    if (dek) zeroDek(dek);
  }
}

/** Two tag lists, equal element by element. */
function sameTags(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((tag, index) => tag === b[index]);
}

/**
 * Restore every document of `backup`, in order, and report what happened to each.
 *
 * Resolves, always: a stop is part of the report, never a rejection.
 */
export async function restoreFullBackupDocuments(
  options: RestoreDocumentsOptions,
): Promise<DocumentRestoreReport> {
  const { backup } = options;
  const entries = backup.manifest.documents;
  const report: DocumentRestoreReport = {
    total: entries.length,
    uploaded: 0,
    restoredFromTrash: 0,
    updated: 0,
    alreadyPresent: 0,
    notRestored: [],
    notAttempted: entries.length,
    notes: [],
    missingFromBackup: 0,
    leftOutOfBackup: backup.manifest.omitted.length + backup.manifest.unlisted,
  };
  const summary = backup.manifest.vault.documentSummary as { count?: unknown } | undefined;
  if (typeof summary?.count === 'number') {
    report.missingFromBackup = Math.max(
      0,
      summary.count - entries.length - backup.manifest.omitted.length - backup.manifest.unlisted,
    );
  }

  let last: DocumentRestoreProgress = { index: 0, total: entries.length, name: '' };
  const current: InFlightTransfer = {
    id: null,
    sent: 0,
    announce: (uploadId) => {
      last = { ...last, uploadId };
      options.onProgress?.(last);
    },
  };
  // The transfer's stored parts are the run's progress for the auto-lock pause.
  const { signal, interrupted, release } = watchJob(options.signal, () => {
    if (current.id === null) return;
    const sent = useDocumentsStore.getState().uploads[current.id]?.sentBytes ?? 0;
    if (sent > current.sent) {
      current.sent = sent;
      noteAutoLockProgress();
    }
  });
  const retry = retryContext(signal, options.wait, (until) => {
    options.onProgress?.({ ...last, waitUntil: until });
  });

  try {
    await run(options, report, signal, interrupted, retry, current, (progress) => {
      last = progress;
      options.onProgress?.(progress);
    });
  } catch (error) {
    // Every abort reaches here as a JobStop: each step checks the signal and turns
    // it into one. Anything else is a fault this run did not expect.
    if (current.id !== null) useDocumentsStore.getState().cancelUpload(current.id);
    const stop =
      error instanceof JobStop
        ? error
        : new JobStop('failed', getApiErrorMessage(error, 'The documents could not be restored.'));
    report.stopped = { stop: stop.stop, message: stop.message };
  } finally {
    release();
  }
  return report;
}

/** The run itself; every stop is thrown as a {@link JobStop}. */
async function run(
  options: RestoreDocumentsOptions,
  report: DocumentRestoreReport,
  signal: AbortSignal,
  interrupted: () => boolean,
  retry: RetryContext,
  current: InFlightTransfer,
  progress: (progress: DocumentRestoreProgress) => void,
): Promise<void> {
  const { backup, backupVaultKey, conflictStrategy } = options;
  const entries = backup.manifest.documents;
  if (entries.length === 0) return;

  const config = await readDocumentsConfigFresh();
  if (config === null) {
    throw new JobStop(
      'failed',
      "Could not confirm this server's document storage. Documents were not restored; run the same restore again with Skip.",
    );
  }
  if (!config.enabled) {
    throw new JobStop(
      'failed',
      "This server does not store documents, so the backup's documents were not restored.",
    );
  }

  const store = (): ReturnType<typeof useDocumentsStore.getState> => useDocumentsStore.getState();
  await sendWithRetries(() => store().fetchDocuments(), retry);
  await sendWithRetries(() => store().fetchTrash(), retry);
  const usage = payloadOf(
    await sendWithRetries(() => getDocumentUsageApi(), retry),
    'read document usage',
  );
  if (isAborted(signal) || interrupted()) throw abortedStop(signal);

  const byId = new Map<string, DecryptedDocument>();
  const byProvenance = new Map<string, DecryptedDocument>();
  for (const doc of [...store().documents, ...store().trashDocuments]) {
    if (doc.purgePending === true) continue;
    byId.set(doc.id, doc);
    const from = doc.meta?.restoredFrom;
    if (from !== undefined && !byProvenance.has(from)) byProvenance.set(from, doc);
  }
  const folders = new Map(
    (options.folderIdMap ?? []).map((pair) => [pair.backupId, pair.folderId]),
  );
  if (
    options.folderIdMap === undefined &&
    entries.some((entry) => entry.row.folderId !== undefined)
  ) {
    report.notes.push(
      "This server did not say which folders the backup's folders became, so documents were restored outside any folder.",
    );
  }

  let { documentCount, usedBytes } = usage;
  const maxBytes = config.maxSizeMB === undefined ? null : config.maxSizeMB * 1024 * 1024;
  const allowed = config.allowedExtensions ?? [];
  const recovery = await loadUploadRecovery();

  for (const [position, entry] of entries.entries()) {
    if (isAborted(signal) || interrupted()) throw abortedStop(signal);
    const meta = await openEntryMeta(entry.row, backupVaultKey);
    const name = meta?.name ?? UNOPENABLE_DOCUMENT_NAME;
    progress({ index: position + 1, total: entries.length, name });
    report.notAttempted -= 1;

    if (meta === null) {
      report.notRestored.push({
        name,
        reason: "Its details could not be opened with the backup's key, so it was not restored.",
      });
      continue;
    }

    const mapped = entry.row.folderId === undefined ? null : folders.get(entry.row.folderId);
    // A document already being permanently deleted was left out of both indexes,
    // so it matches nothing and the backup's copy is uploaded.
    const match = byId.get(entry.row._id) ?? byProvenance.get(entry.row._id);

    // Set the moment this entry's outcome is counted, so a stop that lands after
    // it (on a favorite, say) does not count the entry a second time as unread.
    let settled = false;
    try {
      if (match?.deletedAt !== undefined) {
        const trashed = match;
        const refusal = await sendWrite(() => store().restoreDocument(trashed.id), retry);
        if (refusal !== null)
          throw new NotRestored(`It could not be taken out of the trash: ${refusal}.`);
        report.restoredFromTrash += 1;
        settled = true;
        await applyDetails(trashed, meta, entry.row, mapped, retry, report, name);
        noteAutoLockProgress();
        continue;
      }
      if (match !== undefined && conflictStrategy === 'skip') {
        report.alreadyPresent += 1;
        continue;
      }
      if (match !== undefined && conflictStrategy === 'overwrite') {
        const changed = await applyDetails(match, meta, entry.row, mapped, retry, report, name);
        if (changed) report.updated += 1;
        else report.alreadyPresent += 1;
        noteAutoLockProgress();
        continue;
      }

      // An upload: a document this account does not have, or a keep-both copy.
      if (maxBytes !== null && meta.plaintextBytes > maxBytes) {
        throw new NotRestored(
          `It is larger than this server accepts (${String(config.maxSizeMB)} MB).`,
        );
      }
      if (allowed.length > 0 && !allowed.includes(documentExtension(meta.name))) {
        throw new NotRestored(`This server asks for these file types only: ${allowed.join(', ')}.`);
      }
      if (documentCount >= MAX_DOCUMENTS_PER_USER) {
        throw new JobStop(
          'failed',
          `Document limit reached: an account can hold ${String(MAX_DOCUMENTS_PER_USER)} documents.`,
        );
      }
      if (usedBytes + meta.plaintextBytes > usage.quotaBytes) {
        throw new NotRestored('There is not enough storage left for it.');
      }
      const input: StartUploadInput = {
        source: new Blob([]),
        name: meta.name,
        ...(meta.originalName === undefined ? {} : { originalName: meta.originalName }),
        mime: meta.mime,
        ...(mapped === null || mapped === undefined ? {} : { folderId: mapped }),
        tags: meta.tags,
        ...(meta.note === undefined ? {} : { note: meta.note }),
        ...(meta.transform === undefined ? {} : { transform: meta.transform }),
        restored: { from: entry.row._id, capturedAt: meta.capturedAt },
      };
      input.source = await readFromBackup(backup, entry, backupVaultKey, signal, meta.mime);
      const id = await uploadOnce(input, signal, retry, current, recovery, report, name);
      documentCount += 1;
      usedBytes += meta.plaintextBytes;
      report.uploaded += 1;
      settled = true;
      noteAutoLockProgress();
      if (entry.row.favorite) {
        const refusal = await sendWrite(() => store().setFavorite(id, true), retry);
        if (refusal !== null) report.notes.push(`${name}: ${refusal}.`);
      }
    } catch (error) {
      if (error instanceof NotRestored) {
        report.notRestored.push({ name, reason: error.message });
        continue;
      }
      if (!settled) report.notAttempted += 1;
      throw error;
    }
  }
}

/**
 * Read one entry from the backup FILE with the verified read, under the backup's
 * key, into a Blob of its plaintext. A file that can no longer be read stops the run.
 */
async function readFromBackup(
  backup: OpenedFullBackup,
  entry: FullBackupEntry,
  key: CryptoKey,
  signal: AbortSignal,
  mime: string,
): Promise<Blob> {
  const parts: Blob[] = [];
  try {
    await streamDocumentPlaintext(
      entry.row._id,
      {
        write: (segment) => {
          parts.push(new Blob([segment]));
          return Promise.resolve();
        },
        discard: () => {
          parts.length = 0;
          return Promise.resolve();
        },
      },
      {
        row: entry.row,
        signal,
        source: {
          vaultKey: key,
          readSegment: async (index) => {
            const sealed = await backup.readSegment(entry, index);
            noteAutoLockProgress();
            return sealed;
          },
        },
      },
    );
  } catch (error) {
    if (isAborted(signal)) throw abortedStop(signal);
    if (error instanceof DocumentIntegrityError || isAuthenticationFailure(error)) {
      throw new NotRestored(
        'It could not be read from the backup and verified, so it was not restored.',
      );
    }
    if ((error as { name?: unknown } | null)?.name === 'NotReadableError') {
      throw new JobStop('failed', 'The backup file could not be read. Was it moved or changed?');
    }
    throw error;
  }
  return new Blob(parts, { type: mime });
}

/** The server's message on a failed request, or `''`. */
function messageOf(error: unknown): string {
  return getApiErrorMessage(error, '');
}

/** Whether a 409 carries the generation of a vault key this page no longer holds. */
function isStaleVaultKey(error: AxiosError): boolean {
  const body = error.response?.data as { data?: { vaultKeyVersion?: unknown } } | undefined;
  return typeof body?.data?.vaultKeyVersion === 'number';
}

/**
 * Upload one document, deciding every refusal by where it came from. Resolves with
 * the new document's id.
 *
 * A start refused before the transfer existed is the raw request error, and the
 * run's ladders retry it through {@link sendWithRetries} by starting again. A
 * transfer that failed after it was registered arrives wrapped, its own ladders
 * spent; only a rate limit is worth waiting out for it, and then the SAME transfer
 * is resumed, never a second one started.
 */
async function uploadOnce(
  input: StartUploadInput,
  signal: AbortSignal,
  retry: RetryContext,
  current: InFlightTransfer,
  recovery: Awaited<ReturnType<typeof loadUploadRecovery>>,
  report: DocumentRestoreReport,
  name: string,
): Promise<string> {
  const store = useDocumentsStore.getState;
  let rateLimitWaits = 0;
  let lockWaits = 0;
  let movedToTopLevel = false;
  current.id = null;
  current.sent = 0;
  // Read through a call: `onRegistered` sets it from inside the store, which the
  // type checker cannot see, so a direct read would be narrowed to `null`.
  const registeredId = (): string | null => current.id;
  for (;;) {
    try {
      const registered = registeredId();
      const id = await sendWithRetries(
        () =>
          registered === null
            ? store().startUpload({
                ...input,
                onRegistered: (uploadId) => {
                  current.id = uploadId;
                  if (isAborted(signal)) store().cancelUpload(uploadId);
                  else current.announce(uploadId);
                },
              })
            : store().retryUpload(registered),
        retry,
      );
      current.id = null;
      return id;
    } catch (error) {
      // An abort always arrives as a JobStop: the run's ladders check the signal.
      if (error instanceof JobStop) throw error;
      const wrapped = error instanceof recovery.UploadStoppedError;
      const raw: unknown = wrapped ? error.cause : error;
      const status = statusOf(raw);
      const message = messageOf(raw);
      const sentence = (fallback: string): string => getApiErrorMessage(raw, fallback);

      if (isSessionGone(raw)) throw new JobStop('vault-locked', 'Your session ended.');
      if (wrapped && isRateLimited(raw)) {
        const ms = (retryAfterSeconds(raw) ?? 60) * 1000;
        if (ms > MAX_RATE_LIMIT_WAIT_MS || rateLimitWaits >= MAX_RATE_LIMIT_WAITS) {
          throw new JobStop('rate-limited', RATE_LIMIT_STOP_MESSAGE, { cause: raw });
        }
        rateLimitWaits += 1;
        await waitOutRateLimit(ms, retry);
        continue;
      }
      if (!wrapped && status === 409 && message === INIT_LOCK_BUSY_MESSAGE) {
        if (lockWaits >= INIT_LOCK_BUSY_RETRIES) throw new JobStop('failed', message);
        lockWaits += 1;
        await pause(INIT_LOCK_BUSY_WAIT_MS, retry);
        continue;
      }
      if (status === 409) {
        const refusal = sentence('The server refused the upload.');
        throw new JobStop(
          'failed',
          isStaleVaultKey(raw as AxiosError) ? `${refusal} Reload the page.` : refusal,
        );
      }
      if (status === 400 && ACCOUNT_LIMIT_PATTERN.test(message))
        throw new JobStop('failed', message);
      if (
        !wrapped &&
        status === 404 &&
        message === FOLDER_NOT_FOUND_MESSAGE &&
        input.folderId !== undefined &&
        !movedToTopLevel
      ) {
        movedToTopLevel = true;
        delete input.folderId;
        report.notes.push(
          `${name}: its folder no longer exists, so it was restored outside any folder.`,
        );
        continue;
      }
      if (status === 403) throw new JobStop('failed', sentence('The server refused the request.'));
      if (wrapped && (status === null || status === 408 || status >= 500)) {
        // The transfer's own ladders are spent: the server is gone.
        throw new JobStop('server-unavailable', error.message);
      }
      if (status !== null && status >= 500) {
        // A start that kept failing past the run's own ladder.
        throw new JobStop('server-unavailable', sentence('The server is temporarily unavailable.'));
      }
      if (status !== null) {
        // A refusal about this one document: its transfer is dropped, the run goes on.
        const dropped = registeredId();
        if (dropped !== null) store().cancelUpload(dropped);
        current.id = null;
        throw new NotRestored(sentence('The server refused it.'));
      }
      // Not a request at all. Details this one document cannot have stored are
      // about the document, so the run goes on; anything else (a locked vault, the
      // upload engine not loading) would refuse every document after it.
      if (raw instanceof DocumentDetailsRefusedError) throw new NotRestored(raw.message);
      throw new JobStop('failed', sentence('The upload could not be started.'));
    }
  }
}

/**
 * Send one write (a favorite, a move, a rename, a way out of the trash) on the run's
 * ladders. Resolves `null` when it was applied, or the sentence a refusal about this
 * document alone is recorded with; rejects with a {@link JobStop} for a refusal that
 * would refuse every document after it.
 */
async function sendWrite(send: () => Promise<void>, retry: RetryContext): Promise<string | null> {
  try {
    await sendWithRetries(send, retry);
    return null;
  } catch (error) {
    if (error instanceof JobStop) throw error;
    if (isSessionGone(error)) throw new JobStop('vault-locked', 'Your session ended.');
    const status = statusOf(error);
    if (status === 403 || status === 409) {
      throw new JobStop('failed', getApiErrorMessage(error, 'The server refused a change.'));
    }
    if (status !== null && status >= 500) {
      throw new JobStop(
        'server-unavailable',
        getApiErrorMessage(error, 'The server is temporarily unavailable.'),
      );
    }
    // A 4xx about this one document, or the store refusing it before any request
    // (a document it does not hold, a rename that would change the file type).
    if (error instanceof Error && error.message === DOCUMENT_TYPE_LOCKED_MESSAGE) {
      return 'its file type differs here, so its name, tags and note were not replaced';
    }
    if (status === 404 && messageOf(error) === FOLDER_NOT_FOUND_MESSAGE) {
      return 'its folder no longer exists, so it was left where it is';
    }
    return getApiErrorMessage(error, 'a change to it was refused');
  }
}

/**
 * Give a matched document the backup's details: its name, tags and note, its
 * folder and its favorite flag, each only where it differs. Answers whether
 * anything changed; a change refused for this document alone becomes a note.
 */
async function applyDetails(
  match: DecryptedDocument,
  meta: DocumentMeta,
  row: DocumentResponse,
  mapped: string | null | undefined,
  retry: RetryContext,
  report: DocumentRestoreReport,
  name: string,
): Promise<boolean> {
  const store = useDocumentsStore.getState;
  const writes: (() => Promise<void>)[] = [];
  if (match.meta === null) {
    report.notes.push(`${name}: its details here could not be opened, so they were not replaced.`);
  } else {
    const changes: { name?: string; tags?: string[]; note?: string | null } = {};
    if (match.meta.name !== meta.name) changes.name = meta.name;
    if (!sameTags(match.meta.tags, meta.tags)) changes.tags = meta.tags;
    if ((match.meta.note ?? null) !== (meta.note ?? null)) changes.note = meta.note ?? null;
    if (Object.keys(changes).length > 0)
      writes.push(() => store().updateDocumentMeta(match.id, changes));
  }
  // The folder moves only when the backup's folder maps here, or the backup filed
  // it nowhere. A backup folder that maps to nothing leaves the document alone.
  if (mapped !== undefined && (match.folderId ?? null) !== mapped) {
    writes.push(() => store().moveToFolder(match.id, mapped));
  }
  if (match.favorite !== row.favorite) {
    writes.push(() => store().setFavorite(match.id, row.favorite));
  }
  let changed = false;
  for (const write of writes) {
    const refusal = await sendWrite(write, retry);
    if (refusal === null) changed = true;
    else report.notes.push(`${name}: ${refusal}.`);
  }
  return changed;
}
