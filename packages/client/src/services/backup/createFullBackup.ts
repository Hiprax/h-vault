/**
 * Making a full backup: the vault backup and every live document, verified, into
 * one signed file (`fullBackupFormat.ts`).
 *
 * ## The order is the safety argument
 *
 * 1. **The vault first, then a key check.** The vault part carries the account's
 *    vault key wrapped under the master key; it is opened with the master key this
 *    session holds and compared with the vault key this session holds. Every
 *    document below is verified under that held key, so the check is what ties the
 *    documents in the file to the key the file carries. Without it, a rotation
 *    landing between the two reads would produce a file whose documents no key in
 *    it can open.
 * 2. **Then the rows**, listed after the vault, and counted against the vault's own
 *    `documentSummary`: a list that comes back shorter than the server's count is a
 *    list that changed (or was emptied by a lock), and nothing is saved from it.
 * 3. **Each document is read with the ONE verified read** (`download.ts`), from the
 *    server, keeping the sealed segments it fetched. Only a document that passed
 *    every check is written; one that did not is listed in the file by id and in the
 *    summary by name.
 * 4. **Before the file is committed, the account's key is checked again**, so a
 *    rotation or a master password change during the run is never saved.
 *
 * ## Every early end saves nothing
 *
 * A Stop, a lock, leaving the page, a server that stays down: the target is
 * discarded and the summary says nothing was saved. A backup that might pass for a
 * complete one is exactly what the vault backup's `documentSummary` breadcrumb was
 * added to prevent, so this run never finishes a partial file.
 *
 * ## Keys
 *
 * The run subscribes to BOTH stores: the auth store (the vault key cleared, a lock)
 * and the documents store, whose generation `clearStore` moves synchronously at
 * sign-out, before the auth store's own state changes after its awaited request. Either
 * aborts the run at once, which ends every request and every wait, and the
 * document key in hand is zeroed by the read's own `finally`.
 */

import type { DocumentResponse } from '@hvault/shared';
import { noteAutoLockProgress } from '../../hooks/useAutoLock.js';
import { getApiErrorMessage } from '../../lib/utils.js';
import { useAuthStore } from '../../stores/authStore.js';
import {
  isAborted,
  useDocumentsStore,
  type DecryptedDocument,
} from '../../stores/documentsStore.js';
import { api } from '../api/client.js';
import { getProfileApi } from '../api/userApi.js';
import { isSessionGone } from '../auth/sessionFailure.js';
import { cryptoService } from '../crypto/cryptoService.js';
import type { DocumentBytes } from '../crypto/documentCryptoService.js';
import type { ArchiveTarget } from '../documents/archiveTarget.js';
import { UNOPENABLE_DOCUMENT_NAME } from '../documents/documentNames.js';
import {
  DocumentDownloadCancelledError,
  DocumentIntegrityError,
  streamDocumentPlaintext,
} from '../documents/download.js';
import { isAuthenticationFailure } from '../vault/vaultRows.js';
import {
  FULL_BACKUP_FOOTER_BYTES,
  FULL_BACKUP_HEADER_BYTES,
  FullBackupWriter,
  unbackupableRow,
  vaultBackupTooLarge,
  type OmittedDocument,
  type OmittedReason,
} from './fullBackupFormat.js';
import {
  retryContext,
  watchJob,
  JobStop,
  abortedStop,
  sendWithRetries,
  statusOf,
  type JobStopKind,
  type RetryContext,
} from './jobRetry.js';

/** How long one segment request may take before it is abandoned and retried. */
const SEGMENT_TIMEOUT_MS = 5 * 60 * 1000;

/** Documents in a row that may fail on a server fault before the run stops. */
const CONSECUTIVE_FAILURES_TO_STOP = 3;

/** Room the manifest's own structure takes beside the rows and the vault, in bytes. */
const MANIFEST_ALLOWANCE_BYTES = 4_096;

/** The server's sentence for a document whose stored object is gone (`getSegment`). */
const CONTENTS_MISSING_PATTERN = /stored contents/i;

/** Where a run is, for the progress line. */
export type FullBackupProgress = (
  | { phase: 'vault' }
  | {
      phase: 'documents';
      /** 1-based position of the document now being read. */
      index: number;
      total: number;
      name: string;
      /** Bytes of stored documents read so far. */
      bytesRead: number;
    }
  | { phase: 'finishing' }
) & {
  /** While the server asked for a pause: when it ends (epoch milliseconds). */
  waitUntil?: number;
};

/** A document the run left out: its name as the list shows it, and why. */
interface LeftOutDocument {
  name: string;
  reason: string;
}

/** How a run ended. */
export type FullBackupResult =
  | {
      saved: true;
      fileName: string;
      kind: ArchiveTarget['kind'];
      bytes: number;
      itemCount: number;
      folderCount: number;
      documentCount: number;
      leftOut: LeftOutDocument[];
      /** Rows the server listed that this client could not read at all. */
      unlisted: number;
    }
  | {
      saved: false;
      stop: JobStopKind | 'key-changed' | 'list-changed' | 'too-large' | 'save-failed';
      message: string;
    };

export interface CreateFullBackupOptions {
  /** Aborted by the page, with `'stopped'` or `'left'`. */
  signal: AbortSignal;
  /** The manifest's signing key, derived from the backup password at Save. */
  signingKey: CryptoKey;
  onProgress?: (progress: FullBackupProgress) => void;
  /** A seam for tests; waits are abortable timers otherwise. */
  wait?: RetryContext['wait'];
  now?: () => Date;
}

const REASON_SENTENCES: Record<OmittedReason, string> = {
  unreadable: 'It could not be read and verified, so it was left out.',
  deleted: 'It was deleted while the backup was being made.',
  'contents-missing': 'Its stored file is missing on the server.',
};

/** A document refused for a reason of its own, recorded and passed over. */
class Omitted extends Error {
  constructor(
    readonly reason: OmittedReason,
    readonly detail: string,
    /** Whether it counts towards the consecutive-failure stop (a 400 or a 5xx). */
    readonly serverFault: boolean,
  ) {
    super(detail);
  }
}

/** Numbers the vault part reports about itself, read defensively. */
function vaultCounts(vault: Record<string, unknown>): {
  items: number;
  folders: number;
  documents: number | null;
} {
  const metadata = vault.metadata as { itemCount?: unknown; folderCount?: unknown } | undefined;
  const summary = vault.documentSummary as { count?: unknown } | undefined;
  const number = (value: unknown): number | null =>
    typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
  return {
    items: number(metadata?.itemCount) ?? 0,
    folders: number(metadata?.folderCount) ?? 0,
    documents: number(summary?.count),
  };
}

/** Whether the vault part's wrapped key opens, under `mek`, to exactly `vaultKey`. */
async function vaultPartHoldsKey(
  vault: Record<string, unknown>,
  mek: CryptoKey,
  vaultKey: CryptoKey,
): Promise<boolean> {
  const { encryptedVaultKey, vaultKeyIv, vaultKeyTag } = vault;
  if (
    typeof encryptedVaultKey !== 'string' ||
    typeof vaultKeyIv !== 'string' ||
    typeof vaultKeyTag !== 'string'
  ) {
    return false;
  }
  let raw: ArrayBuffer;
  try {
    raw = await cryptoService.decryptVaultKey(encryptedVaultKey, vaultKeyIv, vaultKeyTag, mek);
  } catch {
    return false;
  }
  try {
    return await cryptoService.vaultKeyEqualsRaw(vaultKey, raw);
  } finally {
    cryptoService.clearKey(raw);
  }
}

/**
 * Make one full backup into `target`, and say what happened.
 *
 * Resolves, always: every way the run can end is a result the panel renders. The
 * target is committed only on success and discarded on every other path.
 */
export async function createFullBackup(
  target: ArchiveTarget,
  options: CreateFullBackupOptions,
): Promise<FullBackupResult> {
  const { signal, interrupted, release } = watchJob(options.signal);

  // The last progress reported, so a rate-limit wait is shown against the step it
  // interrupted, and cleared again by the next report.
  let last: FullBackupProgress = { phase: 'vault' };
  const report = (progress: FullBackupProgress): void => {
    last = progress;
    options.onProgress?.(progress);
  };
  const retry = retryContext(signal, options.wait, (until) => {
    options.onProgress?.({ ...last, waitUntil: until });
  });

  try {
    const result = await run(
      target,
      { ...options, onProgress: report },
      signal,
      interrupted,
      retry,
    );
    if (!result.saved) await target.discard();
    return result;
  } catch (error) {
    // Every abort reaches here as a JobStop: each step checks the signal and turns
    // it into one. Anything else is a fault this run did not expect.
    await target.discard();
    if (error instanceof JobStop) return { saved: false, stop: error.stop, message: error.message };
    return {
      saved: false,
      stop: 'failed',
      message: getApiErrorMessage(error, 'The full backup could not be made.'),
    };
  } finally {
    release();
  }
}

/** The run itself; any rejection is turned into a result by the caller. */
async function run(
  target: ArchiveTarget,
  options: CreateFullBackupOptions & { onProgress: (progress: FullBackupProgress) => void },
  signal: AbortSignal,
  interrupted: () => boolean,
  retry: RetryContext,
): Promise<FullBackupResult> {
  // ONE snapshot: the key, its generation and the master key are a statement
  // about the same instant, which the two key checks below depend on.
  const { mek, vaultKey, vaultKeyVersion } = useAuthStore.getState();
  if (mek === null || vaultKey === null) throw abortedStop(signal);

  options.onProgress({ phase: 'vault' });
  const text = (
    await sendWithRetries(
      () => api.get<string>('/backup/download', { responseType: 'text', signal }),
      retry,
    )
  ).data;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new JobStop('failed', 'The server sent a vault backup this page could not read.');
  }
  const vault = parsed as Record<string, unknown>;
  if (vaultBackupTooLarge(vault)) {
    return {
      saved: false,
      stop: 'too-large',
      message:
        'Your vault is larger than a restore accepts, so a full backup of it could not be restored.',
    };
  }
  if (!(await vaultPartHoldsKey(vault, mek, vaultKey))) {
    return {
      saved: false,
      stop: 'key-changed',
      message: 'Your vault key changed. Reload the page and start again.',
    };
  }

  const counts = vaultCounts(vault);
  const rows = await listDocuments(retry, signal, interrupted, counts.documents);
  const { documents, invalid } = rows;

  // The in-memory target holds the whole file until it is saved.
  const estimate =
    FULL_BACKUP_HEADER_BYTES +
    FULL_BACKUP_FOOTER_BYTES +
    MANIFEST_ALLOWANCE_BYTES +
    text.length +
    documents.reduce(
      (total, doc) => total + doc._raw.ciphertextBytes + JSON.stringify(doc._raw).length + 64,
      0,
    );
  if (target.kind === 'download' && estimate > target.limitBytes) {
    return {
      saved: false,
      stop: 'too-large',
      message:
        'This full backup is too large for this browser to build in memory. Desktop Chrome or Edge can save it straight to disk.',
    };
  }

  const writer = new FullBackupWriter(target);
  try {
    await writer.begin();
  } catch (error) {
    return {
      saved: false,
      stop: 'save-failed',
      message: getApiErrorMessage(error, 'Your browser could not write the backup file.'),
    };
  }
  const omitted: OmittedDocument[] = [];
  const leftOut: LeftOutDocument[] = [];
  let consecutiveServerFaults = 0;
  let bytesRead = 0;

  for (const [position, doc] of documents.entries()) {
    const name = doc.meta?.name ?? UNOPENABLE_DOCUMENT_NAME;
    options.onProgress({
      phase: 'documents',
      index: position + 1,
      total: documents.length,
      name,
      bytesRead,
    });

    const leaveOut = (reason: OmittedReason, detail: string): void => {
      omitted.push({ id: doc.id, reason });
      leftOut.push({ name, reason: detail });
    };
    if (doc.meta === null || unbackupableRow(doc._raw) !== null) {
      leaveOut('unreadable', REASON_SENTENCES.unreadable);
      continue;
    }

    let segments: Blob[];
    try {
      segments = await readStoredDocument(doc._raw, vaultKey, signal, retry, (bytes) => {
        bytesRead += bytes;
      });
    } catch (error) {
      if (!(error instanceof Omitted)) throw error;
      leaveOut(error.reason, error.detail);
      // Only a 400 or 5xx counts; a 404, a document that fails its checks and a
      // degraded row neither count nor reset the run (only a written one does).
      if (error.serverFault) consecutiveServerFaults += 1;
      if (consecutiveServerFaults >= CONSECUTIVE_FAILURES_TO_STOP) {
        throw new JobStop(
          'server-unavailable',
          'The storage server failed on several documents in a row, so the backup stopped.',
        );
      }
      continue;
    }
    consecutiveServerFaults = 0;
    try {
      await writer.addDocument(doc._raw, segments);
    } catch (error) {
      return {
        saved: false,
        stop: 'save-failed',
        message: getApiErrorMessage(error, 'Your browser could not write the backup file.'),
      };
    }
    noteAutoLockProgress();
  }

  options.onProgress({ phase: 'finishing' });
  const profile = (await sendWithRetries(() => getProfileApi(signal), retry)).data;
  if (
    !profile.success ||
    profile.data.encryptedVaultKey !== vault.encryptedVaultKey ||
    (profile.data.vaultKeyVersion ?? 0) !== vaultKeyVersion
  ) {
    return {
      saved: false,
      stop: 'key-changed',
      message: 'Your vault key or master password changed during the backup.',
    };
  }

  let written;
  try {
    written = await writer.finish(
      {
        createdAt: (options.now ?? (() => new Date()))().toISOString(),
        vault,
        omitted,
        unlisted: invalid,
      },
      options.signingKey,
    );
    // The last moment a lock could have landed before the file is handed over.
    if (isAborted(signal)) throw abortedStop(signal);
    await target.commit();
  } catch (error) {
    if (error instanceof JobStop) throw error;
    return {
      saved: false,
      stop: 'save-failed',
      message: getApiErrorMessage(error, 'Your browser could not write the backup file.'),
    };
  }

  return {
    saved: true,
    fileName: target.name,
    kind: target.kind,
    bytes: written.bytes,
    itemCount: counts.items,
    folderCount: counts.folders,
    documentCount: written.documentCount,
    leftOut,
    unlisted: invalid,
  };
}

/**
 * The live documents, read through the documents store, after the vault part.
 *
 * The store's own walk validates every row and opens its metadata (for the names
 * the summary shows); schema-invalid rows are only counted. A list shorter than the
 * server's own count is read once more, and a second short read stops the run.
 */
async function listDocuments(
  retry: RetryContext,
  signal: AbortSignal,
  interrupted: () => boolean,
  expected: number | null,
): Promise<{ documents: DecryptedDocument[]; invalid: number }> {
  for (let attempt = 0; ; attempt += 1) {
    await sendWithRetries(() => useDocumentsStore.getState().fetchDocuments(), retry);
    if (isAborted(signal) || interrupted()) throw abortedStop(signal);
    const { documents, invalidCount } = useDocumentsStore.getState();
    const live = documents.filter((doc) => doc.deletedAt === undefined);
    if (expected === null || live.length + invalidCount >= expected) {
      return { documents: live, invalid: invalidCount };
    }
    if (attempt >= 1) {
      throw new JobStop(
        'failed',
        'Your documents changed while the backup was starting. Try again.',
      );
    }
  }
}

/**
 * Read one stored document, verified, keeping the sealed segments the server sent.
 *
 * Rejects with {@link Omitted} for a refusal about this document alone, with
 * {@link JobStop} when the run must stop, and with the abort when it was aborted.
 */
async function readStoredDocument(
  row: DocumentResponse,
  vaultKey: CryptoKey,
  signal: AbortSignal,
  retry: RetryContext,
  onBytes: (bytes: number) => void,
): Promise<Blob[]> {
  const kept: Blob[] = [];
  const stride = row.chunkPlaintextBytes + 16;
  const expectedLength = (index: number): number =>
    index === row.chunkCount - 1 ? row.ciphertextBytes - index * stride : stride;

  const readSegment = async (index: number): Promise<DocumentBytes> => {
    const expected = expectedLength(index);
    const response = await sendWithRetries(
      () =>
        api.get<ArrayBuffer>(`/documents/${row._id}/segments/${String(index)}`, {
          responseType: 'arraybuffer',
          signal,
          timeout: SEGMENT_TIMEOUT_MS,
          onDownloadProgress: (event) => {
            // Only the body of THIS segment counts: an error body (a 429's or a
            // 502's) has a different length and is never progress.
            if (event.total === expected) noteAutoLockProgress();
          },
        }),
      retry,
    );
    const sealed = new Uint8Array(response.data);
    if (sealed.length !== expected) {
      throw new Omitted('unreadable', REASON_SENTENCES.unreadable, false);
    }
    kept.push(new Blob([sealed]));
    onBytes(sealed.length);
    noteAutoLockProgress();
    return sealed;
  };

  try {
    await streamDocumentPlaintext(
      row._id,
      { write: () => Promise.resolve(), discard: () => Promise.resolve() },
      { row, signal, source: { vaultKey, readSegment } },
    );
    return kept;
  } catch (error) {
    if (error instanceof JobStop || error instanceof Omitted) throw error;
    if (error instanceof DocumentDownloadCancelledError || isAborted(signal))
      throw abortedStop(signal);
    if (isSessionGone(error)) throw new JobStop('vault-locked', 'Your session ended.');
    const status = statusOf(error);
    if (status === 404) {
      const message = getApiErrorMessage(error, '');
      throw CONTENTS_MISSING_PATTERN.test(message)
        ? new Omitted('contents-missing', REASON_SENTENCES['contents-missing'], false)
        : new Omitted('deleted', REASON_SENTENCES.deleted, false);
    }
    if (status !== null && (status === 400 || status >= 500)) {
      throw new Omitted('unreadable', getApiErrorMessage(error, REASON_SENTENCES.unreadable), true);
    }
    if (status !== null) {
      throw new JobStop('failed', getApiErrorMessage(error, 'The server refused a document read.'));
    }
    // A verification failure (an integrity check, or a key or segment that would
    // not authenticate) is about this document alone. Anything else is a fault in
    // this page, and stops the run rather than being passed off as a bad document.
    if (error instanceof DocumentIntegrityError || isAuthenticationFailure(error)) {
      throw new Omitted('unreadable', REASON_SENTENCES.unreadable, false);
    }
    throw error;
  }
}
