/**
 * Encrypted document store, client side.
 *
 * Mirrors `vaultStore`: a fetch generation and a mutation generation re-checked
 * before every state write, in-flight fetch deduplication, and a `clearStore()`
 * that a lock or a logout calls. What it adds is the one thing a password vault
 * never needed — a TRANSFER, which outlives a render, holds a key while it runs
 * and has to be torn down deterministically.
 *
 * ## Three properties this module exists to hold
 *
 * 1. **The server never sees a filename, a MIME type, a tag, a note or a byte of
 *    content.** Everything that would name a document is sealed under a key
 *    derived from a per-document DEK before it leaves here, and the plaintext
 *    columns the server does hold (`favorite`, `folderId`, sizes) are exactly the
 *    ones it needs to do range arithmetic and enforce a quota.
 * 2. **One crypto segment is one uploaded part.** There is no mapping table
 *    between the two chunkings, so a whole class of off-by-one cannot happen.
 *    Segment indices are 0-based (the index is the counter inside the AEAD nonce)
 *    and part numbers are 1-based (S3 part numbers are), so part `n` carries
 *    segment `n - 1` and the two names are never blurred.
 * 3. **A retry re-sends the identical bytes.** The DEK, the salt, the nonce prefix
 *    and the plaintext slice are all fixed for the life of a transfer, and
 *    `encryptSegment` is deterministic given them, so a re-sent part is
 *    byte-identical to the one that failed. That is what makes retrying safe at
 *    all: two DIFFERENT plaintexts sealed under one (key, nonce) pair hand anyone
 *    holding both their XOR. Within one pass a part is sealed once and the same
 *    buffer is re-sent; across a resume the slice is re-read from the source, and
 *    {@link DocumentsState.retryUpload} refuses when the source's size or
 *    modification time has moved under it. It is also why an upload is not
 *    resumable across a page RELOAD, which is a stated non-goal rather than an
 *    oversight: the DEK is memory-only by design, and one that survived a reload
 *    would have to be persisted somewhere the vault key is not.
 *
 * ## Where a transfer's state lives, and why it is in two places
 *
 * `uploads` in the store holds only what the UI renders and only values that are
 * JSON-serializable: the name, the two byte counts, a status and a message. The
 * `AbortController` and the raw DEK live in a module-level map beside it.
 *
 * That split is this package's existing shape rather than a novelty —
 * `vaultStore` keeps its in-flight promises, its generation counters and its
 * in-flight delete sets at module scope for the same reason — and here it also
 * buys something specific. A `CryptoKey` is an opaque handle: `JSON.stringify`
 * yields `{}` and nothing can read its bytes synchronously. A raw 32-byte DEK is
 * an ordinary `Uint8Array` that serializes to `{"0":137,…}`, so keeping it out of
 * the state tree makes "no document key is ever persisted, cached or logged" true
 * by construction instead of by a rule someone has to remember — which is exactly
 * the rule `authStore` has to maintain by hand, through `partialize`, for the one
 * key it does keep in state.
 *
 * The hazard the split creates is named rather than left implicit: two structures
 * can desync, and an entry dropped from one while its session lingers in the other
 * is a live controller and an unzeroed key with no visible symptom. So exactly one
 * function, {@link endSession}, removes from both, every removal goes through it,
 * and the map is the authority on which transfers are live.
 *
 * ## Lock, logout and auto-lock
 *
 * An in-flight upload does NOT extend the auto-lock deadline, and `useAutoLock` is
 * untouched: auto-lock exists to protect an unattended unlocked vault, and a long
 * background transfer is exactly when an attacker benefits from it not firing. So
 * a lock DURING a long upload is the expected outcome, and {@link clearStore}
 * makes it clean — it aborts every controller, ZEROES every held DEK (a key that
 * decrypts user plaintext must not outlive the lock) and fires the abort endpoint
 * per live upload, un-awaited, under the same bounded timeout `lockApi` uses.
 *
 * The store is module-level, so `ProtectedRoute` swapping the layout out does not
 * kill a transfer. Only a lock, a logout or an explicit cancel does.
 */

import { create } from 'zustand';
import {
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  documentChunkCountFor,
  documentExtension,
  documentMetaSchema,
  documentResponseSchema,
  documentUploadResponseSchema,
} from '@hvault/shared';
import type {
  ApiResponse,
  DocumentMeta,
  DocumentResponse,
  DocumentUsageResponse,
  PaginatedResponse,
  UpdateDocumentInput,
} from '@hvault/shared';
import type { EmptyDocumentTrashResult } from '../services/api/documentsApi.js';
import {
  DOCUMENT_PAGE_SIZE,
  MAX_DOCUMENT_PAGES,
  abortDocumentUploadApi,
  completeDocumentUploadApi,
  deleteDocumentApi,
  emptyDocumentTrashApi,
  getDocumentUploadApi,
  getDocumentUsageApi,
  initDocumentUploadApi,
  listDocumentTrashApi,
  listDocumentsApi,
  purgeDocumentApi,
  restoreDocumentApi,
  staleVaultKeyVersion,
  updateDocumentApi,
  uploadDocumentPartApi,
} from '../services/api/documentsApi.js';
import { getProfileApi } from '../services/api/userApi.js';
import { ensureCsrfToken } from '../services/api/client.js';
import { isSessionGone } from '../services/auth/sessionFailure.js';
import { cryptoService } from '../services/crypto/cryptoService.js';
import {
  decryptMeta,
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  encryptMeta,
  encryptSegment,
  generateDek,
  unwrapDek,
  wrapDek,
  zeroDek,
  type DocumentBytes,
} from '../services/crypto/documentCryptoService.js';
import { getSha256Factory } from '../lib/lazySha256.js';
import { logger } from '../lib/logger.js';
import { useAuthStore } from './authStore.js';
import { DECRYPTION_CONCURRENCY, mapWithConcurrency } from './vaultStore.js';

// ---------------------------------------------------------------------------
// Client-side decrypted types
// ---------------------------------------------------------------------------

/**
 * A document row with its metadata opened.
 *
 * `meta` is `null` for a DEGRADED row — the wrapped key would not unwrap, or the
 * sealed blob would not open or would not satisfy the shared schema. Such a row is
 * still listed rather than hidden, because the operations that do not need the
 * metadata (move, favorite, trash, restore, purge) are exactly the ones a user
 * needs in order to get rid of it. What is NOT possible on such a row is a rename:
 * a document's name lives inside the sealed blob, so unlike an undecodable vault
 * item — whose name is a separate ciphertext field — there is no name to rewrite
 * and no key to rewrite it with.
 */
export interface DecryptedDocument {
  id: string;
  folderId?: string | undefined;
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | undefined;
  purgePending?: boolean | undefined;
  /** The opened metadata, or `null` when this row is degraded. */
  meta: DocumentMeta | null;
  /**
   * The validated row exactly as the API sent it.
   *
   * Kept so a metadata re-seal or a rewrap needs no second request, and because
   * the framing fields on it are what a reader must compare against the
   * authenticated copy inside the blob.
   */
  _raw: DocumentResponse;
}

/**
 * Where a transfer is, as the UI needs to describe it.
 *
 * There is deliberately no `completed`: a finished transfer leaves the registry in
 * the same breath as the document joins the list, so a "completed upload" is a
 * state nothing can observe and nothing should have to render.
 *
 * Not exported, because nothing outside this module names it today and a reader
 * reaches it through {@link DocumentUploadProgress}'s own `status` field. The
 * dead-code gate is answered by removing an `export` keyword, never by an ignore
 * entry.
 */
type DocumentUploadStatus = 'uploading' | 'finalizing' | 'failed';

/**
 * The renderable half of one transfer: every field serializable, `error` already a
 * string rather than a thrown value.
 */
export interface DocumentUploadProgress {
  /** The upload id, which is also the future document id. */
  id: string;
  fileName: string;
  /** Plaintext bytes in the whole document. */
  totalBytes: number;
  /** Plaintext bytes sent so far, measured from the start of the current part. */
  sentBytes: number;
  status: DocumentUploadStatus;
  error?: string | undefined;
}

/**
 * There is deliberately no `resumable` flag beside `status`. A transfer that
 * cannot be resumed — the staging row is gone, the session is over — has its
 * entry REMOVED along with its session, so `status: 'failed'` is exactly the set
 * of transfers a Retry can be offered for. A boolean that was always true beside
 * it would be a field that cannot lie about anything.
 */

/**
 * Whether a transfer is still moving bytes.
 *
 * The ONE definition of the question, because two readers ask it for decisions
 * that must never disagree: the unload guard uses it to decide whether closing
 * the tab costs anything, and `DocumentTransfers` uses it to decide whether to
 * say so. A failed transfer holds no socket and is reading nothing from its file —
 * its parts are already stored and a retry re-sends only what the server does
 * not hold — so closing the tab on one costs nothing a confirmation would save.
 *
 * A predicate rather than two `!== 'failed'` comparisons, so a fourth status
 * cannot be added in a way that leaves the guard and the transfer list
 * answering differently. {@link DocumentUploadStatus} stays unexported deliberately, which
 * is why this is the shape the answer travels in.
 */
export function isLiveTransfer(transfer: DocumentUploadProgress): boolean {
  return transfer.status !== 'failed';
}

/** The handles, key material and inputs one transfer needs, kept out of the state tree. */
interface UploadSession {
  controller: AbortController;
  dek: DocumentBytes;
  source: Blob;
  /**
   * The source's size and modification time as they were when the transfer
   * started, compared again before a resume re-reads it.
   *
   * `lastModified` is `null` for a `Blob` that is not a `File` — a transformed
   * upload, which is held in memory and cannot change underneath us. For a real
   * `File` the File API says a changed file must fail the read rather than return
   * different bytes, but "must" is a guarantee to assert rather than to lean on:
   * two different plaintexts under one AEAD nonce is the catastrophic outcome, not
   * the annoying one.
   */
  sourceSize: number;
  sourceLastModified: number | null;
  name: string;
  mime: string;
  tags: string[];
  note?: string | undefined;
  transform?: DocumentMeta['transform'];
  capturedAt: string;
  streamSalt: DocumentBytes;
  noncePrefix: DocumentBytes;
  chunkCount: number;
  chunkPlaintextBytes: number;
  vaultKeyVersion: number;
}

/** What {@link DocumentsState.startUpload} needs to seal and store a file. */
export interface StartUploadInput {
  /**
   * The bytes to store. A `File` straight from the picker, or a `Blob` built from
   * text an in-browser transform produced — the store does not care which, and
   * deliberately does not read `File.name`, so a transformed upload cannot end up
   * named after the file it no longer is.
   */
  source: Blob;
  /** The document's name, sealed into the metadata and never sent in the clear. */
  name: string;
  /** The MIME type, which may legitimately be empty for a type the OS did not recognise. */
  mime: string;
  folderId?: string | undefined;
  tags?: string[] | undefined;
  note?: string | undefined;
  transform?: DocumentMeta['transform'];
}

/** The metadata fields a caller may rewrite after a document is committed. */
export interface DocumentMetaUpdate {
  name?: string;
  tags?: string[];
  /** `null` removes the note; `undefined` leaves it alone. */
  note?: string | null;
}

interface DocumentsState {
  documents: DecryptedDocument[];
  trashDocuments: DecryptedDocument[];
  usage: DocumentUsageResponse | null;
  /** Live transfers, keyed by upload id. */
  uploads: Record<string, DocumentUploadProgress>;
  documentsLoading: boolean;
  trashLoading: boolean;
  usageLoading: boolean;
  /**
   * Whether a `fetchTrash` has SUCCEEDED in this session.
   *
   * The trash list has to be told apart from a trash list that was never read,
   * and `trashDocuments.length > 0` cannot do it: an account whose trash was
   * loaded and is empty looks exactly like one whose trash was never loaded, so
   * the first delete would vanish from both lists and the Trash count would stay
   * at zero. `deleteDocument` reads this flag instead.
   */
  trashLoaded: boolean;
  /** Rows in the most recent fetch whose metadata would not open. */
  degradedCount: number;
  /** Rows dropped entirely because the response did not satisfy the shared schema. */
  invalidCount: number;
  /**
   * The same two counts for the TRASH listing.
   *
   * Separate fields rather than one pair, because the two lists are fetched
   * independently and the reader is only ever looking at one of them: a banner
   * that reported the active list's failures over a trash view would be counting
   * rows that are not on screen. `fetchTrash` used to discard these numbers
   * entirely, which meant a trashed row whose key will not unwrap disappeared
   * from the trash with nothing said about it.
   */
  trashDegradedCount: number;
  trashInvalidCount: number;

  /**
   * Which rows the list is showing. The four are MUTUALLY EXCLUSIVE, which is
   * what lets the page render one `switch` and exactly four empty states.
   *
   * Deliberately stricter than `vaultStore`, where a folder and the favorites
   * filter can be on together. The divergence lives in the two scope hooks, so
   * the shared rail behaves identically in both places and no vault behaviour
   * changes.
   */
  selectedFolder: string | null;
  showFavorites: boolean;
  showTrash: boolean;
  searchQuery: string;

  fetchDocuments: () => Promise<void>;
  fetchTrash: () => Promise<void>;
  fetchUsage: () => Promise<void>;
  startUpload: (input: StartUploadInput) => Promise<string>;
  retryUpload: (uploadId: string) => Promise<string>;
  cancelUpload: (uploadId: string) => void;
  updateDocumentMeta: (id: string, changes: DocumentMetaUpdate) => Promise<void>;
  setFavorite: (id: string, favorite: boolean) => Promise<void>;
  moveToFolder: (id: string, folderId: string | null) => Promise<void>;
  deleteDocument: (id: string) => Promise<void>;
  restoreDocument: (id: string) => Promise<void>;
  purgeDocument: (id: string) => Promise<void>;
  emptyTrash: () => Promise<EmptyDocumentTrashResult>;
  setSelectedFolder: (folderId: string | null) => void;
  toggleFavorites: () => void;
  toggleTrash: () => void;
  setSearchQuery: (query: string) => void;
  clearFilters: () => void;
  /**
   * Reconcile local rows after `vaultStore.deleteFolder` swept the server.
   *
   * The server applies ONE `updateMany` to `VaultItem` and to `Document`
   * (`folderController.deleteFolder`), so a folder deletion changes documents
   * whether or not the reader was looking at them. `parentId` is the deleted
   * folder's own parent, because that is where `move` puts its members.
   */
  applyFolderDeleted: (
    folderId: string,
    action: 'move' | 'delete',
    parentId: string | undefined,
  ) => void;
  clearStore: () => void;
}

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/**
 * The waits before each retry of one part, in order.
 *
 * Three retries after the first attempt, so a part is attempted four times in
 * total before the transfer is marked failed. The doubling matters more than the
 * count: a transient drop clears in under a second, while a captive portal or a
 * sleeping radio does not, and a fixed short delay would spend the whole budget
 * inside the outage. After the last one the upload stops and stays RESUMABLE — the
 * parts already stored are still stored, and a retry re-reads the ledger and skips
 * them.
 */
const PART_RETRY_DELAYS_MS = [1_000, 2_000, 4_000] as const;

/**
 * Bounded per-call timeout for the best-effort abort fired during a lock or a
 * logout. The same five seconds `lockApi` and `logoutApi` are given, and for the
 * same reason: local teardown must never wait on a stalled connection. A per-call
 * timeout deliberately, never a global Axios timeout, which would abort the
 * legitimately-long part and rotation requests.
 */
const ABORT_TIMEOUT_MS = 5_000;

// ---------------------------------------------------------------------------
// Module state: generations, dedup, and the live sessions
// ---------------------------------------------------------------------------

// Every fetch bumps its counter and re-checks it before each state write, so a
// slow response that resolves AFTER a lock, a logout or a newer fetch cannot write
// decrypted plaintext back into a store that has just been emptied. The mutation
// counter does the same for the single-row writes, whose server-side effect has
// already happened by the time the guard fires — only the LOCAL write is
// suppressed.
let fetchDocumentsGeneration = 0;
let fetchTrashGeneration = 0;
let fetchUsageGeneration = 0;
let mutationGeneration = 0;

let fetchDocumentsInFlight: Promise<void> | null = null;
let fetchTrashInFlight: Promise<void> | null = null;
let fetchUsageInFlight: Promise<void> | null = null;

/**
 * Rows deleted while a listing was still in flight.
 *
 * `fetchAllPages` reads every page and writes the whole list in ONE terminal
 * `set`, guarded only by its own fetch generation — which a single-row delete
 * does not bump, because bumping it would discard a listing the reader is
 * waiting for. So without these, a document deleted mid-load is put back by the
 * pages that were read before it went: it reappears in the list, and the trash
 * it was optimistically moved into disagrees with the list beside it.
 *
 * The mechanism is `vaultStore`'s, for the same reason and with the same
 * lifetime: an id is recorded on the delete, filtered out of any listing that
 * lands afterwards, and forgotten when a FRESH fetch starts — by which point the
 * server's own answer already excludes it.
 */
const inFlightDeletedDocumentIds = new Set<string>();
const inFlightDeletedTrashIds = new Set<string>();

/**
 * Bumped when the trash is emptied, so a listing already in flight cannot write
 * back the rows that purge destroyed.
 *
 * The id sets above cannot cover this one, and the reason is worth stating.
 * `purgeDocument` and `restoreDocument` record their id AFTER the running listing
 * cleared the set, so the set still holds it when that listing resolves.
 * `emptyTrash` has no id to record: it derives them from the very list the
 * running listing emptied on its way in, so it finds nothing to suppress — and on
 * a clean purge it does not re-read either. Without this counter the listing then
 * writes back everything it read before the purge.
 *
 * A separate counter rather than a bump of `fetchTrashGeneration`, because that
 * generation also guards the `finally` that clears `trashLoading` and releases
 * `fetchTrashInFlight`: bumping it from outside the run would strand the spinner
 * on and the handle set for the life of the tab.
 */
let trashInvalidatedAt = 0;

/**
 * The live transfers' handles and keys.
 *
 * The AUTHORITY on which transfers exist: `clearStore()` iterates this rather than
 * the state, so a session that somehow outlived its progress entry is still
 * aborted and still zeroed.
 */
const sessions = new Map<string, UploadSession>();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * The unlocked vault key, or a throw.
 *
 * Read from `authStore` at CALL time, never at module evaluation. The two stores
 * import each other — `authStore` needs this one for its lock and logout teardown,
 * this one needs the vault key — and a module-scope read would resolve to whatever
 * the bundler happened to evaluate first.
 */
function getVaultKey(): CryptoKey {
  const { vaultKey } = useAuthStore.getState();
  if (!vaultKey) {
    throw new Error('Vault is locked. Unlock it before performing document operations.');
  }
  return vaultKey;
}

/** `length` cryptographically random bytes. */
function randomBytes(length: number): DocumentBytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/** Base64 of raw bytes, through the client's single encoder. */
function bytesToBase64(bytes: DocumentBytes): string {
  return cryptoService.arrayBufferToBase64(bytes.buffer);
}

/**
 * Decode one of the row's base64 framing fields.
 *
 * `cryptoService.base64ToArrayBuffer` is the single decoder in this client, used
 * here rather than a local `atob` loop so a padding or alphabet decision is made in
 * exactly one place.
 */
function base64ToBytes(value: string): DocumentBytes {
  return new Uint8Array(cryptoService.base64ToArrayBuffer(value));
}

/**
 * The payload of a successful envelope, or a throw.
 *
 * `ApiResponse<T>` is a union whose failure arm carries no `data`, so every reader
 * has to narrow it. Written once rather than at each call site: a caller reaching
 * for `.data.data` without narrowing would not compile, and a caller narrowing with
 * its own ad-hoc message would give one failure a different name on every route. In
 * practice the failure arm does not arrive — this API's errors are FLAT and carry a
 * non-2xx status, so axios has already rejected — which is exactly why this must
 * throw rather than fall back: a 200 that says `success: false` means something is
 * wrong that nothing else would notice.
 */
function payloadOf<T>(response: { data: ApiResponse<T> }, action: string): T {
  const body = response.data;
  if (!body.success) throw new Error(`Failed to ${action}`);
  return body.data;
}

/** Lowercase hexadecimal of raw bytes. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Lowercase hexadecimal SHA-256 of one sealed segment, the shape the part header takes. */
async function sealedSegmentDigest(segment: DocumentBytes): Promise<string> {
  return toHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', segment)));
}

/**
 * A fresh 24-character hex id, used only for the provisional DEK wrap at init.
 *
 * Never stored, never sent as an id, never derived from again.
 */
function randomDocumentId(): string {
  return toHex(randomBytes(12));
}

/**
 * Whether the transfer has been aborted, read through a call.
 *
 * A plain `signal.aborted` would be narrowed by the type checker after the first
 * check in a function and every later re-check would look redundant to
 * `no-unnecessary-condition` — but the value changes UNDERNEATH the reader, which
 * is the entire point: a lock, a logout or a cancel can land during any await, and
 * the re-check after each one is what stops the loop sealing another segment under
 * a key that has just been zeroed.
 */
function isAborted(signal: AbortSignal): boolean {
  return signal.aborted;
}

/**
 * A digest-shaped placeholder for the pre-flight.
 *
 * Not a real digest and never sealed: the file has not been read when the bounds
 * are checked. Every SHA-256 renders to the same 64 characters, so a placeholder
 * makes the pre-flight measure exactly the byte budget the real blob will have.
 */
const PLACEHOLDER_DIGEST = '0'.repeat(64);

/**
 * Everything about a document's metadata that is known before the file is read.
 *
 * One definition, called twice: once by the pre-flight with a placeholder digest,
 * once by the seal with the real one. Written out twice, a bound checked up front
 * and a value sealed at the end could describe different documents.
 */
function metaShapeFor(
  source: {
    name: string;
    mime: string;
    tags?: string[] | undefined;
    note?: string | undefined;
    transform?: DocumentMeta['transform'];
  },
  plaintextBytes: number,
  chunkCount: number,
  capturedAt: string,
): Omit<DocumentMeta, 'sha256'> {
  return {
    name: source.name,
    mime: source.mime,
    ext: documentExtension(source.name),
    plaintextBytes,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount,
    tags: source.tags ?? [],
    ...(source.note === undefined ? {} : { note: source.note }),
    ...(source.transform === undefined ? {} : { transform: source.transform }),
    capturedAt,
  };
}

/**
 * A promise that settles after `ms`, or as soon as the transfer is aborted.
 *
 * There is deliberately NO "already aborted on entry" guard. The one caller checks
 * the signal in its own `catch` and throws, with nothing awaited between that check
 * and this call, so entering here aborted is impossible by construction — and a
 * branch that cannot be reached is a branch no test can fail on.
 */
function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    function finish(): void {
      clearTimeout(timer);
      signal.removeEventListener('abort', finish);
      resolve();
    }
    const timer = setTimeout(finish, ms);
    signal.addEventListener('abort', finish, { once: true });
  });
}

/**
 * Raised when a transfer stops because the user cancelled it, or because a lock or
 * a logout tore the session down.
 *
 * A distinct type rather than a flag on a generic error, because cancellation is
 * the one outcome that must never be retried and must never be reported as a
 * failure of the file — and because an aborted request rejects with no `response`,
 * which is indistinguishable from "offline" to anything that only looks at the
 * status. A classifier that got that wrong would sleep a second after a LOCK and
 * then seal another segment under a DEK that had just been filled with zeroes.
 */
export class UploadCancelledError extends Error {
  constructor(message = 'Upload cancelled') {
    super(message);
    this.name = 'UploadCancelledError';
  }
}

/**
 * Open one row: validate the shape, unwrap the DEK, open the metadata blob.
 *
 * Returns `null` for a row that does not satisfy `documentResponseSchema`. That is
 * a REFUSAL rather than a degradation, and the difference is deliberate: the row's
 * `_id` is HKDF material for all three of this document's keys, and its framing
 * fields decide where every segment starts, so a row this client cannot vouch for
 * is one it must not derive a key from or compute a byte range with.
 *
 * A row that IS well-formed but whose key or blob will not open comes back with
 * `meta: null` instead. The DEK is zeroed on every path, including the failures:
 * listing a document must not leave behind a key that decrypts its contents.
 */
async function openDocumentRow(
  raw: unknown,
  vaultKey: CryptoKey,
): Promise<DecryptedDocument | null> {
  const parsed = documentResponseSchema.safeParse(raw);
  if (!parsed.success) {
    logger.error('Document response validation failed', { issues: parsed.error.issues.length });
    return null;
  }
  const row = parsed.data;

  const base: Omit<DecryptedDocument, 'meta'> = {
    id: row._id,
    ...(row.folderId === undefined ? {} : { folderId: row.folderId }),
    favorite: row.favorite,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ...(row.deletedAt === undefined ? {} : { deletedAt: row.deletedAt }),
    ...(row.purgePending === undefined ? {} : { purgePending: row.purgePending }),
    _raw: row,
  };

  let dek: DocumentBytes | null = null;
  try {
    dek = await unwrapDek(row, await deriveWrapKey(vaultKey, row._id));
    const metaKey = await deriveMetaKey(dek, base64ToBytes(row.streamSalt), row._id);
    return { ...base, meta: await decryptMeta(metaKey, row) };
  } catch (error) {
    logger.warn('Document metadata could not be opened', { id: row._id, error });
    return { ...base, meta: null };
  } finally {
    if (dek) zeroDek(dek);
  }
}

/**
 * The state a fresh document store holds — and the state a lock returns it to.
 *
 * ONE definition, spread at creation and re-applied by `clearStore()`, because
 * these two were the same object written twice and drifting apart was a silent
 * failure: a field added here but forgotten in the teardown survives a lock, and
 * a decrypted row or a previous account's folder id outliving a lock is exactly
 * what this store exists to prevent.
 */
const EMPTY_DOCUMENTS_STATE = {
  documents: [],
  trashDocuments: [],
  usage: null,
  uploads: {},
  documentsLoading: false,
  trashLoading: false,
  usageLoading: false,
  trashLoaded: false,
  degradedCount: 0,
  invalidCount: 0,
  trashDegradedCount: 0,
  trashInvalidCount: 0,
  selectedFolder: null,
  showFavorites: false,
  showTrash: false,
  searchQuery: '',
} as const satisfies Omit<
  DocumentsState,
  | 'fetchDocuments'
  | 'fetchTrash'
  | 'fetchUsage'
  | 'startUpload'
  | 'retryUpload'
  | 'cancelUpload'
  | 'updateDocumentMeta'
  | 'setFavorite'
  | 'moveToFolder'
  | 'deleteDocument'
  | 'restoreDocument'
  | 'purgeDocument'
  | 'emptyTrash'
  | 'setSelectedFolder'
  | 'toggleFavorites'
  | 'toggleTrash'
  | 'setSearchQuery'
  | 'clearFilters'
  | 'applyFolderDeleted'
  | 'clearStore'
>;

export const useDocumentsStore = create<DocumentsState>((set, get) => ({
  ...EMPTY_DOCUMENTS_STATE,

  // -----------------------------------------------------------------------
  // Reads
  // -----------------------------------------------------------------------

  fetchDocuments: async (): Promise<void> => {
    if (fetchDocumentsInFlight) return fetchDocumentsInFlight;
    fetchDocumentsGeneration += 1;
    const myGeneration = fetchDocumentsGeneration;

    const run = async (): Promise<void> => {
      try {
        const vaultKey = getVaultKey();
        // Cleared HERE, at the start of a fresh read: from this point the
        // server's own answer already excludes anything deleted before now, so
        // remembering those ids longer would filter rows out of a listing that
        // never contained them.
        inFlightDeletedDocumentIds.clear();
        set({ documentsLoading: true, documents: [], degradedCount: 0, invalidCount: 0 });
        const opened = await fetchAllPages(
          (page) => listDocumentsApi({ page, limit: DOCUMENT_PAGE_SIZE }),
          vaultKey,
        );
        // A lock, a logout or a newer fetch superseded this run while its pages
        // were in flight. The captured vault key would still decrypt — clearing a
        // key zeroes an exported copy, not the live handle — so without this the
        // just-emptied store would be repopulated with plaintext.
        if (myGeneration !== fetchDocumentsGeneration) return;
        set({
          // A row deleted while these pages were being read is NOT put back. The
          // pages predate the delete, and a generation guard cannot help: a
          // single-row write must not discard a listing the reader is waiting for.
          documents: opened.documents.filter((doc) => !inFlightDeletedDocumentIds.has(doc.id)),
          degradedCount: opened.degraded,
          invalidCount: opened.invalid,
        });
      } finally {
        if (myGeneration === fetchDocumentsGeneration) set({ documentsLoading: false });
      }
    };

    fetchDocumentsInFlight = run().finally(() => {
      if (myGeneration === fetchDocumentsGeneration) fetchDocumentsInFlight = null;
    });
    return fetchDocumentsInFlight;
  },

  fetchTrash: async (): Promise<void> => {
    if (fetchTrashInFlight) return fetchTrashInFlight;
    fetchTrashGeneration += 1;
    const myGeneration = fetchTrashGeneration;

    // Captured with the generation, and checked beside it: this run is stale if
    // the trash was emptied while it was reading.
    const myInvalidation = trashInvalidatedAt;

    const run = async (): Promise<void> => {
      try {
        const vaultKey = getVaultKey();
        inFlightDeletedTrashIds.clear();
        set({
          trashLoading: true,
          trashDocuments: [],
          trashDegradedCount: 0,
          trashInvalidCount: 0,
        });
        const opened = await fetchAllPages(
          (page) => listDocumentTrashApi({ page, limit: DOCUMENT_PAGE_SIZE }),
          vaultKey,
        );
        if (myGeneration !== fetchTrashGeneration || myInvalidation !== trashInvalidatedAt) return;
        // `trashLoaded` is set HERE, in the success path, and never in the
        // `finally` below: the `finally` also runs when the request failed, and a
        // failed read has loaded nothing. `deleteDocument` moves a row into this
        // list only when it was genuinely read, so a flag set on failure would
        // produce a trash holding exactly one document and hiding the rest.
        //
        // The two counts are recorded rather than discarded. They used to be
        // thrown away, which was invisible only because nothing rendered the
        // trash: a trashed row whose key will not unwrap was simply absent, with
        // nothing said about it.
        set({
          trashDocuments: opened.documents.filter((doc) => !inFlightDeletedTrashIds.has(doc.id)),
          trashDegradedCount: opened.degraded,
          trashInvalidCount: opened.invalid,
          trashLoaded: true,
        });
      } finally {
        if (myGeneration === fetchTrashGeneration) set({ trashLoading: false });
      }
    };

    fetchTrashInFlight = run().finally(() => {
      if (myGeneration === fetchTrashGeneration) fetchTrashInFlight = null;
    });
    return fetchTrashInFlight;
  },

  fetchUsage: async (): Promise<void> => {
    if (fetchUsageInFlight) return fetchUsageInFlight;
    fetchUsageGeneration += 1;
    const myGeneration = fetchUsageGeneration;

    const run = async (): Promise<void> => {
      try {
        set({ usageLoading: true });
        const usage = payloadOf(await getDocumentUsageApi(), 'read document usage');
        if (myGeneration !== fetchUsageGeneration) return;
        set({ usage });
      } finally {
        if (myGeneration === fetchUsageGeneration) set({ usageLoading: false });
      }
    };

    fetchUsageInFlight = run().finally(() => {
      if (myGeneration === fetchUsageGeneration) fetchUsageInFlight = null;
    });
    return fetchUsageInFlight;
  },

  // -----------------------------------------------------------------------
  // Upload
  // -----------------------------------------------------------------------

  startUpload: async (input: StartUploadInput): Promise<string> => {
    const vaultKey = getVaultKey();

    const totalBytes = input.source.size;
    const chunkCount = documentChunkCountFor(totalBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    const capturedAt = new Date().toISOString();

    // The metadata bounds are checked HERE, before a byte crosses the network,
    // rather than only inside `encryptMeta` at the very end. A name, a note or a
    // serialized blob over its bound would otherwise be discovered after the whole
    // file had been uploaded, and the retry would re-read and re-hash all of it
    // only to fail the same way — the shape `vaultStore` avoids by running
    // `assertValidItemData` before it encrypts anything.
    //
    // The digest is not known yet, so a placeholder of the right SHAPE stands in
    // for it. Every SHA-256 is the same length, so the byte budget this checks is
    // the byte budget the real blob will have.
    documentMetaSchema.parse({
      ...metaShapeFor(input, totalBytes, chunkCount, capturedAt),
      sha256: PLACEHOLDER_DIGEST,
    });

    const dek = generateDek();
    const streamSalt = randomBytes(DOCUMENT_STREAM_SALT_BYTES);
    const noncePrefix = randomBytes(DOCUMENT_NONCE_PREFIX_BYTES);

    const myGeneration = mutationGeneration;
    let init: { uploadId: string; vaultKeyVersion: number; chunkPlaintextBytes: number };
    try {
      // The wrapped key sent HERE is provisional, and the server never reads it
      // back: the committed row takes its key from the COMPLETION body, and the
      // staging row's copy is echoed to nobody. It has to be well-formed because
      // the wire schema requires it, and it cannot be the real one because the real
      // one is bound to the document id — which is the id this very request mints.
      // So it is a genuine wrap under a discarded id: indistinguishable from the
      // real thing on the wire, openable by no one, and revealing nothing.
      const provisional = await wrapDek(dek, await deriveWrapKey(vaultKey, randomDocumentId()));
      init = payloadOf(
        await initDocumentUploadApi({
          ...provisional,
          streamSalt: bytesToBase64(streamSalt),
          noncePrefix: bytesToBase64(noncePrefix),
          declaredPlaintextBytes: totalBytes,
          declaredChunkCount: chunkCount,
          ...(input.folderId === undefined ? {} : { folderId: input.folderId }),
        }),
        'start the upload',
      );
    } catch (error) {
      // Nothing was registered, so there is no session to end and no key to zero
      // but this one. Zeroing here rather than in a `finally` further down keeps
      // the DEK's lifetime equal to the transfer's, with no window in which a
      // refused init leaves one resident.
      zeroDek(dek);
      throw error;
    }

    const { uploadId, vaultKeyVersion, chunkPlaintextBytes } = init;

    // A lock, a logout or a teardown landed while this transfer was being opened.
    // Registering it now would put a live key and a progress row into a store that
    // has just been emptied, and `clearStore()` has already been past this map — so
    // the session is ended before it exists rather than after.
    if (myGeneration !== mutationGeneration) {
      zeroDek(dek);
      fireAbort(uploadId);
      throw new UploadCancelledError();
    }

    // The server states the framing it will record, and the client declared a
    // chunk count derived from its own constant. If the two disagree, every
    // segment boundary after the first is wrong and the file would be stored
    // mis-framed, so the transfer stops before a byte is sealed.
    if (chunkPlaintextBytes !== DOCUMENT_PLAINTEXT_CHUNK_BYTES) {
      zeroDek(dek);
      fireAbort(uploadId);
      throw new Error(
        'This server frames documents differently from this client; the upload was not started.',
      );
    }

    sessions.set(uploadId, {
      controller: new AbortController(),
      dek,
      source: input.source,
      sourceSize: totalBytes,
      sourceLastModified: sourceLastModifiedOf(input.source),
      name: input.name,
      mime: input.mime,
      tags: input.tags ?? [],
      ...(input.note === undefined ? {} : { note: input.note }),
      ...(input.transform === undefined ? {} : { transform: input.transform }),
      capturedAt,
      streamSalt,
      noncePrefix,
      chunkCount,
      chunkPlaintextBytes,
      vaultKeyVersion,
    });
    set((state) => ({
      uploads: {
        ...state.uploads,
        [uploadId]: {
          id: uploadId,
          fileName: input.name,
          totalBytes,
          sentBytes: 0,
          status: 'uploading',
        },
      },
    }));

    return runTransfer(set, uploadId, new Set<number>());
  },

  retryUpload: async (uploadId: string): Promise<string> => {
    const progress = get().uploads[uploadId];
    const session = sessions.get(uploadId);
    if (!progress || !session) throw new Error('That upload is no longer available to retry.');
    if (progress.status !== 'failed') {
      throw new Error('Only a failed upload can be retried.');
    }

    // Two different plaintexts under one (key, nonce) pair is the catastrophic
    // failure this whole design is arranged to prevent, and a resume is the one
    // moment a slice is read a second time. If the file on disk moved underneath
    // us, the safe answer is to refuse rather than to re-seal segment `i` over
    // different bytes.
    if (
      session.source.size !== session.sourceSize ||
      sourceLastModifiedOf(session.source) !== session.sourceLastModified
    ) {
      endSession(set, uploadId, { zero: true });
      throw new Error('The file changed since the upload started; start it again.');
    }

    // The ledger, not a local guess, decides what still has to be sent. A part the
    // server already holds is skipped, but its slice is still read and hashed
    // below: the whole-file digest has to cover bytes that are not being re-sent.
    const held = new Set<number>();
    try {
      // Validated, like every committed row this client reads: the part numbers
      // below decide which segments are re-sent, so a malformed ledger would
      // silently re-send everything or throw somewhere less obvious than here.
      const staging = documentUploadResponseSchema.parse(
        payloadOf(await getDocumentUploadApi(uploadId), 'read the upload'),
      );
      for (const part of staging.parts) held.add(part.partNumber);
    } catch (error) {
      // The staging row is gone — its TTL fired, or it was cancelled elsewhere — so
      // there is nothing to resume onto and the DEK must not outlive the attempt.
      endSession(set, uploadId, { zero: true });
      throw error;
    }

    session.controller = new AbortController();
    updateProgress(set, uploadId, (current) => ({
      ...current,
      status: 'uploading',
      error: undefined,
      sentBytes: 0,
    }));

    return runTransfer(set, uploadId, held);
  },

  cancelUpload: (uploadId: string): void => {
    const session = sessions.get(uploadId);
    if (!session) return;
    session.controller.abort();
    fireAbort(uploadId);
    endSession(set, uploadId, { zero: true });
  },

  // -----------------------------------------------------------------------
  // Single-row writes
  // -----------------------------------------------------------------------

  updateDocumentMeta: async (id: string, changes: DocumentMetaUpdate): Promise<void> => {
    const vaultKey = getVaultKey();
    const current = findDocument(get(), id);
    if (!current) throw new Error('Document not found');
    if (!current.meta) {
      // The name, the tags and the note all live inside the sealed blob, so there
      // is nothing to rewrite when it will not open — and sealing a fresh blob
      // would replace the authenticated framing with values taken from the very
      // row a reader is supposed to check against it.
      throw new Error('This document cannot be renamed: its metadata could not be opened.');
    }

    const next: DocumentMeta = { ...current.meta };
    if (changes.name !== undefined) next.name = changes.name;
    if (changes.tags !== undefined) next.tags = changes.tags;
    if (changes.note === null) delete next.note;
    else if (changes.note !== undefined) next.note = changes.note;

    const myGeneration = mutationGeneration;
    let dek: DocumentBytes | null = null;
    let sealed;
    try {
      dek = await unwrapDek(current._raw, await deriveWrapKey(vaultKey, id));
      // The SAME DEK, so the stream key is untouched and no segment is re-sealed.
      // `encryptMeta` mints a fresh IV of its own on every call, which is what
      // makes a rename safe: the metadata key is fixed for the document's whole
      // life, and two seals under one key with one IV hand anyone holding both
      // blobs the XOR of the two plaintexts.
      sealed = await encryptMeta(
        await deriveMetaKey(dek, base64ToBytes(current._raw.streamSalt), id),
        next,
      );
    } finally {
      if (dek) zeroDek(dek);
    }

    const row = payloadOf(await updateDocumentApi(id, sealed), 'update the document');
    const opened = await openDocumentRow(row, vaultKey);
    if (myGeneration !== mutationGeneration || !opened) return;
    applyUpdatedDocument(set, opened);
  },

  setFavorite: async (id: string, favorite: boolean): Promise<void> => {
    await patchDocument(set, id, { favorite });
  },

  moveToFolder: async (id: string, folderId: string | null): Promise<void> => {
    await patchDocument(set, id, { folderId });
  },

  /**
   * Soft-delete a document, and move the row it removes into the trash.
   *
   * `DELETE /documents/:id` answers `{ success, message }` with NO data, so the
   * row captured before the request is the only copy there will be until the
   * next `fetchTrash`. The timestamp is stamped on the DECRYPTED wrapper and
   * never on `_raw`: `_raw` is the server's row, it is what a later metadata
   * re-seal derives this document's key material from (`updateDocumentMeta`
   * reads `_raw.streamSalt`), and inventing a field on it would be inventing
   * server state inside key derivation.
   *
   * Prepended rather than appended, because `listDocumentTrashSchema` sorts
   * `deletedAt` descending: appending would drop the document a reader has just
   * deleted to the bottom of a list that virtualizes above fifty rows.
   */
  deleteDocument: async (id: string): Promise<void> => {
    const myGeneration = mutationGeneration;
    const doomed = get().documents.find((doc) => doc.id === id);
    await deleteDocumentApi(id);
    inFlightDeletedDocumentIds.add(id);
    if (myGeneration !== mutationGeneration) return;
    const deletedAt = new Date().toISOString();
    set((state) => ({
      documents: state.documents.filter((doc) => doc.id !== id),
      // Only when the trash has actually been READ. Pushing one row into a list
      // that was never loaded would render a trash containing exactly that row
      // and hiding every other.
      ...(state.trashLoaded && doomed
        ? { trashDocuments: [{ ...doomed, deletedAt }, ...state.trashDocuments] }
        : {}),
    }));
  },

  restoreDocument: async (id: string): Promise<void> => {
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;
    const row = payloadOf(await restoreDocumentApi(id), 'restore the document');
    const opened = await openDocumentRow(row, vaultKey);
    inFlightDeletedTrashIds.add(id);
    if (myGeneration !== mutationGeneration) return;
    set((state) => ({
      trashDocuments: state.trashDocuments.filter((doc) => doc.id !== id),
      documents: opened ? [opened, ...state.documents] : state.documents,
    }));
  },

  purgeDocument: async (id: string): Promise<void> => {
    const myGeneration = mutationGeneration;
    await purgeDocumentApi(id);
    inFlightDeletedTrashIds.add(id);
    if (myGeneration !== mutationGeneration) return;
    set((state) => ({ trashDocuments: state.trashDocuments.filter((doc) => doc.id !== id) }));
  },

  /**
   * Destroy every document that was in the trash when the request arrived.
   *
   * The result is RETURNED rather than swallowed, and a partial run is read
   * back. The server counts a failed object delete instead of throwing: the row
   * keeps `deletedAt`, is left marked `purgePending`, and `GET /documents/trash`
   * still returns it. Emptying the local list unconditionally would therefore
   * report "all gone" about documents that are still there.
   */
  emptyTrash: async (): Promise<EmptyDocumentTrashResult> => {
    const myGeneration = mutationGeneration;
    const result = payloadOf(await emptyDocumentTrashApi(), 'empty the document trash');
    if (myGeneration !== mutationGeneration) return result;

    // The suppression set is populated ONLY when the purge was total. Its job is
    // to stop a listing that was already in flight from putting back rows that no
    // longer exist — which is exactly right when everything went, and pointless
    // when it did not: on the partial path the very next thing this does is read
    // the list again, and a set of ids can only subtract from what that read
    // returns. The server leaves a row it could not delete marked `purgePending`
    // and still listed, so those rows have to survive the read.
    // Bumped BEFORE the write, so a listing that is mid-flight right now is
    // already stale by the time it resolves. See `trashInvalidatedAt`.
    trashInvalidatedAt += 1;

    if (result.failedCount === 0) {
      for (const doc of get().trashDocuments) inFlightDeletedTrashIds.add(doc.id);
      set({ trashDocuments: [] });
      return result;
    }

    set({ trashDocuments: [] });
    await get().fetchTrash();
    return result;
  },

  // -----------------------------------------------------------------------
  // Filters
  //
  // No generation guard on any of these. The counters exist to suppress a stale
  // ASYNCHRONOUS write — a response that lands after a lock, a logout or a newer
  // fetch. A synchronous user gesture cannot be stale.
  // -----------------------------------------------------------------------

  setSelectedFolder: (folderId: string | null): void => {
    set({ selectedFolder: folderId, showFavorites: false, showTrash: false });
  },

  toggleFavorites: (): void => {
    set((state) => ({
      showFavorites: !state.showFavorites,
      showTrash: false,
      selectedFolder: null,
    }));
  },

  toggleTrash: (): void => {
    set((state) => ({
      showTrash: !state.showTrash,
      showFavorites: false,
      selectedFolder: null,
    }));
  },

  setSearchQuery: (query: string): void => {
    set({ searchQuery: query });
  },

  clearFilters: (): void => {
    set({ selectedFolder: null, showFavorites: false, showTrash: false });
  },

  /**
   * Mirror `folderController.deleteFolder`'s sweep onto the local rows.
   *
   * The server's two branches are NOT symmetrical, and copying one onto the other
   * is how this goes wrong (`folderController.ts:354-363`):
   *
   *   - `delete` filters `{ folderId, userId, deletedAt: null }` — ACTIVE rows
   *     only — and stamps `deletedAt`. A row already in the trash keeps the dead
   *     folder id, which is why `trashDocuments` is untouched on this branch.
   *   - `move` filters `{ folderId, userId }` with NO `deletedAt` clause, so it
   *     reaches trashed rows too, and it re-parents to the deleted folder's OWN
   *     PARENT rather than to the root. A client that cleared `folderId` here
   *     would show a document at the root that the server has filed one level up,
   *     and would disagree with it until the next full reload.
   */
  applyFolderDeleted: (
    folderId: string,
    action: 'move' | 'delete',
    parentId: string | undefined,
  ): void => {
    const reparent = (doc: DecryptedDocument): DecryptedDocument =>
      doc.folderId !== folderId
        ? doc
        : parentId === undefined
          ? { ...doc, folderId: undefined }
          : { ...doc, folderId: parentId };
    set((state) => ({
      documents:
        action === 'delete'
          ? state.documents.filter((doc) => doc.folderId !== folderId)
          : state.documents.map(reparent),
      // `move` reaches the trash; `delete` does not.
      trashDocuments:
        action === 'delete' ? state.trashDocuments : state.trashDocuments.map(reparent),
      selectedFolder: state.selectedFolder === folderId ? null : state.selectedFolder,
    }));
    // The swept rows are in the trash now — but read it back only if it was
    // already read. An unread trash is filled correctly by the next `fetchTrash`.
    //
    // The rejection is swallowed deliberately. This is a background refresh of a
    // list the reader may not even be looking at, fired from a synchronous
    // handler that has already reported the folder deletion; an unhandled
    // rejection here would surface a failure nobody can act on, and the next
    // `fetchTrash` corrects the list anyway.
    if (action === 'delete' && get().trashLoaded) {
      void get()
        .fetchTrash()
        .catch(() => {
          /* see above */
        });
    }
  },

  // -----------------------------------------------------------------------
  // Teardown
  // -----------------------------------------------------------------------

  /**
   * End the session: stop every transfer, zero every key, empty every list.
   *
   * The order is the whole point and it is not interchangeable. The controller is
   * aborted FIRST, so the in-flight request stops and the transfer loop — which
   * re-checks the signal before every step — cannot reach another `encryptSegment`
   * or another `complete` with a key that is about to become zeroes. Then the DEK
   * is zeroed, because a key that decrypts user plaintext must not outlive the
   * lock. Only then is the abort endpoint called, un-awaited and bounded, because
   * it is a courtesy to the server's quota and must never delay local teardown.
   *
   * It iterates `sessions` rather than the store's `uploads`, because that map is
   * the authority on which transfers are live: a session that somehow outlived its
   * progress entry is still aborted and still zeroed here.
   *
   * Called by `authStore.lock()` inside its secure-local-state-first block, and by
   * `authStore.logout()` BEFORE its awaited server call — `logout` deliberately
   * inverts that ordering so the interceptor can still attach a Bearer token, so
   * putting the teardown after the await would leave keys resident and transfers
   * running for the whole five-second timeout of a stalled connection.
   */
  clearStore: (): void => {
    fetchDocumentsGeneration += 1;
    fetchTrashGeneration += 1;
    fetchUsageGeneration += 1;
    mutationGeneration += 1;
    fetchDocumentsInFlight = null;
    fetchTrashInFlight = null;
    fetchUsageInFlight = null;
    inFlightDeletedDocumentIds.clear();
    inFlightDeletedTrashIds.clear();
    trashInvalidatedAt += 1;

    for (const [uploadId, session] of sessions) {
      session.controller.abort();
      zeroDek(session.dek);
      fireAbort(uploadId);
    }
    sessions.clear();

    // The filters reset with everything else, and that is not tidiness.
    // `selectedFolder` is a folder id belonging to the account that just ended:
    // leaving it would carry one bit of the previous account's structure into the
    // next sign-in on this tab and drop that user into an empty folder view with
    // no explanation, and a `showTrash` left true would open their unlock
    // straight into the trash.
    set({ ...EMPTY_DOCUMENTS_STATE });
  },
}));

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

type SetState = (
  partial: Partial<DocumentsState> | ((state: DocumentsState) => Partial<DocumentsState>),
) => void;

/** A `File`'s modification time, or `null` for a plain in-memory `Blob`. */
function sourceLastModifiedOf(source: Blob): number | null {
  return 'lastModified' in source && typeof source.lastModified === 'number'
    ? source.lastModified
    : null;
}

/** Tell the server a transfer is over, best-effort and bounded. */
function fireAbort(uploadId: string): void {
  void abortDocumentUploadApi(uploadId, ABORT_TIMEOUT_MS).catch((err: unknown) => {
    logger.warn('Failed to cancel an upload server-side', err);
  });
}

/**
 * Remove one transfer from BOTH structures.
 *
 * The only place either is removed from. Two containers holding one lifetime can
 * desync, and the desync has no visible symptom — a session left behind is a live
 * controller and an unzeroed key that the UI has already forgotten about — so the
 * removal is one function rather than a rule about calling two.
 */
function endSession(set: SetState, uploadId: string, options: { zero: boolean }): void {
  const session = sessions.get(uploadId);
  if (session) {
    if (options.zero) zeroDek(session.dek);
    sessions.delete(uploadId);
  }
  set((state) => {
    if (!(uploadId in state.uploads)) return {};
    const { [uploadId]: _removed, ...rest } = state.uploads;
    return { uploads: rest };
  });
}

/** Apply a change to one progress entry, leaving the rest of the registry alone. */
function updateProgress(
  set: SetState,
  uploadId: string,
  change: (current: DocumentUploadProgress) => DocumentUploadProgress,
): void {
  set((state) => {
    const current = state.uploads[uploadId];
    if (!current) return {};
    return { uploads: { ...state.uploads, [uploadId]: change(current) } };
  });
}

/** Find a document in either list. */
function findDocument(state: DocumentsState, id: string): DecryptedDocument | undefined {
  return (
    state.documents.find((doc) => doc.id === id) ??
    state.trashDocuments.find((doc) => doc.id === id)
  );
}

/** Write an updated row back into whichever list holds it. */
function applyUpdatedDocument(set: SetState, updated: DecryptedDocument): void {
  const replace = (list: DecryptedDocument[]): DecryptedDocument[] =>
    list.map((doc) => (doc.id === updated.id ? updated : doc));
  set((state) => ({
    documents: replace(state.documents),
    trashDocuments: replace(state.trashDocuments),
  }));
}

/**
 * The plaintext-column write both `setFavorite` and `moveToFolder` are.
 *
 * One function because they are one request with one field changed: `PUT
 * /documents/:id` cannot reach a framing field, the wrapped key or the object key,
 * so neither of these touches ciphertext and neither needs the vault key. Two
 * copies of the guard-and-write would be two places for the generation check to be
 * forgotten.
 */
async function patchDocument(set: SetState, id: string, body: UpdateDocumentInput): Promise<void> {
  const myGeneration = mutationGeneration;
  const updated = payloadOf(await updateDocumentApi(id, body), 'update the document');
  const parsed = documentResponseSchema.safeParse(updated);
  // The id check is not ceremony: `_raw` is what a later re-seal derives this
  // document's metadata key from, so writing another document's row into this
  // entry would produce a rename sealed under keys the row was never sealed with.
  // A response about a different document is dropped; the next fetch reads the
  // truth.
  if (myGeneration !== mutationGeneration || !parsed.success || parsed.data._id !== id) return;
  const row = parsed.data;
  set((state) => {
    const patch = (doc: DecryptedDocument): DecryptedDocument =>
      doc.id === id
        ? {
            ...doc,
            favorite: row.favorite,
            folderId: row.folderId,
            updatedAt: row.updatedAt,
            _raw: row,
          }
        : doc;
    return {
      documents: state.documents.map(patch),
      trashDocuments: state.trashDocuments.map(patch),
    };
  });
}

/** Page through a list endpoint, opening every row as it arrives. */
async function fetchAllPages(
  request: (page: number) => Promise<{ data: PaginatedResponse<DocumentResponse> }>,
  vaultKey: CryptoKey,
): Promise<{ documents: DecryptedDocument[]; degraded: number; invalid: number }> {
  const documents: DecryptedDocument[] = [];
  let degraded = 0;
  let invalid = 0;
  let page = 1;
  let totalPages = 1;

  do {
    const body = (await request(page)).data;
    if (!body.success) throw new Error('Failed to list documents');
    totalPages = Math.min(body.pagination.totalPages, MAX_DOCUMENT_PAGES);
    const opened = await mapWithConcurrency(body.data, DECRYPTION_CONCURRENCY, (raw) =>
      openDocumentRow(raw, vaultKey),
    );
    for (const result of opened) {
      // `openDocumentRow` catches its own failures and answers `null` for a row it
      // refuses, so a rejection here is a fault in this client rather than in the
      // data. It is counted with the refusals rather than thrown, because one bad
      // row must not cost the user every other one.
      if (result.status === 'rejected' || !result.value) {
        invalid += 1;
        continue;
      }
      if (!result.value.meta) degraded += 1;
      documents.push(result.value);
    }
    page += 1;
  } while (page <= totalPages);

  return { documents, degraded, invalid };
}

/**
 * How a failed part is answered.
 *
 * `retry` re-sends the identical sealed buffer after a backoff. `fail` stops the
 * transfer but leaves it RESUMABLE, because the parts already stored are still
 * stored. `abandon` stops it and takes the session with it, for the refusals where
 * a Retry button could only ever fail the same way.
 */
type PartVerdict = 'retry' | 'fail' | 'abandon';

/**
 * What to do about one failed part.
 *
 * A 401, and a 403 that is a CSRF rejection, never reach here as themselves: the
 * shared axios interceptor refreshes the access token and replays, and refreshes
 * the CSRF token and replays once, before either can surface. What arrives is
 * whatever the REPLAY produced, which is why a 401 seen here means the refresh
 * itself failed — the session is over, not the part.
 */
function classifyPartFailure(error: unknown): PartVerdict {
  const status = httpStatusOf(error);

  // No response at all: offline, DNS, a dropped socket. The plan's named case, and
  // the only one where waiting is the whole remedy.
  if (status === null) return 'retry';

  // The staging row is gone — expired, or cancelled from another tab. Every
  // remaining part will answer the same way, `GET /uploads/:id` will too, and the
  // object key and framing all belonged to that row. Offering a Retry here would
  // be offering a button that 404s for ever.
  if (status === 404) return 'abandon';

  // The session, not the transfer, is what failed. The interceptor has already
  // refreshed and replayed, and on an authoritative refusal it may already have
  // begun logging out.
  if (isSessionGone(error)) return 'abandon';

  // The user-keyed part budget is a FIFTEEN MINUTE window. A 1s/2s/4s backoff
  // exhausts itself in seven seconds and then fails anyway, having spent three
  // more slots out of a budget that is already empty — so this fails at once and
  // stays resumable, which is the outcome those seven seconds were going to reach.
  if (status === 429) return 'fail';

  // 5xx, including the 503 of a storage engine that is briefly unreachable.
  if (status >= 500) return 'retry';

  // Everything else is the server refusing this exact request on its merits: a
  // missing length (411), a body over the parser's limit (413) or of the wrong
  // type (415), a part outside the transfer, a length that is not the framing's,
  // or a digest that does not match (400). Re-sending identical bytes cannot
  // change any of them.
  return 'fail';
}

/** The HTTP status behind a rejection, or `null` when no response ever arrived. */
function httpStatusOf(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || !('response' in error)) return null;
  const response: unknown = error.response;
  if (typeof response !== 'object' || response === null || !('status' in response)) return null;
  const status: unknown = response.status;
  return typeof status === 'number' ? status : null;
}

/** Raised for a refusal that no retry could survive, so the session ends with it. */
class UnresumableUploadError extends Error {
  constructor(readonly cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = 'UnresumableUploadError';
  }
}

/**
 * Send one part, retrying a transient failure with the backoff above.
 *
 * The abort check comes FIRST in the catch, before the status is even looked at.
 * An aborted request rejects with no `response`, which the classifier would read as
 * "offline" and answer with a sleep and a re-send — after a lock, that means
 * sealing another segment under a DEK that has just been filled with zeroes.
 */
async function sendPartWithRetry(
  uploadId: string,
  partNumber: number,
  body: ArrayBuffer,
  digest: string,
  signal: AbortSignal,
  onProgress: (loaded: number, total: number) => void,
): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    if (isAborted(signal)) throw new UploadCancelledError();
    try {
      // The CSRF token is resolved as an explicit step of this transfer rather
      // than left to the request interceptor, which would also await it. The
      // difference is not which token the part carries, and it is NOT that a
      // replay is avoided — the interceptor's own fetch-and-replay already
      // guarantees that, for every write in this application. What it buys is
      // attribution: a token fetch that fails offline, or that the csrf-token
      // endpoint's own limiter refuses, surfaces HERE, where it is known to be a
      // token failure, instead of arriving as a rejection carrying the token
      // request's config that this classifier would have to identify by sniffing
      // a URL. It is retried by the loop below either way.
      await ensureCsrfToken();
      await uploadDocumentPartApi(uploadId, partNumber, body, {
        digest,
        signal,
        onUploadProgress: (event) => {
          onProgress(event.loaded, event.total ?? body.byteLength);
        },
      });
      return;
    } catch (error) {
      if (isAborted(signal) || error instanceof UploadCancelledError) {
        throw new UploadCancelledError();
      }
      const verdict = classifyPartFailure(error);
      if (verdict === 'abandon') throw new UnresumableUploadError(error);
      const nextDelay = PART_RETRY_DELAYS_MS[attempt];
      if (verdict === 'fail' || nextDelay === undefined) throw error;
      logger.warn('Retrying a document part', { uploadId, partNumber, attempt: attempt + 1 });
      await delay(nextDelay, signal);
    }
  }
}

/**
 * Walk the file: hash every slice, seal and send the parts the server does not
 * already hold, then seal the metadata and commit.
 *
 * `alreadyHeld` carries PART numbers (1-based) from the staging ledger. Every slice
 * is still read and hashed even when its part is skipped, because the digest in the
 * metadata covers the whole file and a resumed transfer must arrive at the same
 * one.
 */
async function runTransfer(
  set: SetState,
  uploadId: string,
  alreadyHeld: Set<number>,
): Promise<string> {
  const session = sessions.get(uploadId);
  if (!session) throw new UploadCancelledError();
  const { signal } = session.controller;

  try {
    const vaultKey = getVaultKey();
    const streamKey = await deriveStreamKey(session.dek, session.streamSalt, uploadId);
    const createSHA256 = await getSha256Factory();
    const hasher = await createSHA256();
    hasher.init();

    for (let index = 0; index < session.chunkCount; index += 1) {
      if (isAborted(signal)) throw new UploadCancelledError();
      const start = index * session.chunkPlaintextBytes;
      const slice = new Uint8Array(
        await session.source.slice(start, start + session.chunkPlaintextBytes).arrayBuffer(),
      );
      hasher.update(slice);

      const partNumber = index + 1;
      if (!alreadyHeld.has(partNumber)) {
        const sealed = await encryptSegment(
          streamKey,
          { noncePrefix: session.noncePrefix, index, isLast: index === session.chunkCount - 1 },
          slice,
        );
        await sendPartWithRetry(
          uploadId,
          partNumber,
          sealed.buffer,
          await sealedSegmentDigest(sealed),
          signal,
          // Progress is ABSOLUTE — the completed prefix plus this part's own
          // fraction — never an accumulator. The interceptor replays a whole part
          // after a token refresh and `onUploadProgress` restarts it at zero, so a
          // running total would count those bytes twice and push the bar past the
          // end of the file.
          (loaded, total) => {
            const fraction = total > 0 ? Math.min(1, loaded / total) : 0;
            updateProgress(set, uploadId, (current) => ({
              ...current,
              sentBytes: Math.min(current.totalBytes, start + Math.round(slice.length * fraction)),
            }));
          },
        );
      }
      updateProgress(set, uploadId, (current) => ({
        ...current,
        sentBytes: Math.min(current.totalBytes, start + slice.length),
      }));
    }

    if (isAborted(signal)) throw new UploadCancelledError();
    updateProgress(set, uploadId, (current) => ({ ...current, status: 'finalizing' }));

    const meta: DocumentMeta = {
      ...metaShapeFor(session, session.sourceSize, session.chunkCount, session.capturedAt),
      sha256: hasher.digest('hex'),
    };
    const sealedMeta = await encryptMeta(
      await deriveMetaKey(session.dek, session.streamSalt, uploadId),
      meta,
    );

    const row = await completeTransfer(session, uploadId, sealedMeta, vaultKey, signal);
    endSession(set, uploadId, { zero: true });
    // The document IS committed, so this is not a failure and nothing is thrown —
    // but opening it for the list is a LOCAL write, and a lock or a logout that
    // landed while the completion was in flight must not have it put decrypted
    // plaintext back into a store `clearStore()` has just emptied. The captured
    // vault key would still decrypt: clearing a key zeroes an exported copy, not
    // the live handle.
    if (isAborted(signal)) return uploadId;

    // FROM HERE ON THE SIGNAL CAN NO LONGER MOVE, WHICH IS WHY THE GUARD CHANGES.
    // `endSession` has removed this transfer from `sessions`, and that map is the
    // only thing `clearStore()` and `cancelUpload` iterate — so nothing in this
    // codebase can abort this controller any more, and a second `isAborted` check
    // here would be a guard that cannot fire, reading as protection while
    // providing none. `mutationGeneration` is what a lock or a logout actually
    // moves, and it is the guard every other post-await writer in this file uses.
    // That counter is incremented in exactly one place, `clearStore()`, so it says
    // "everything was discarded" and nothing else — an ordinary delete or rename
    // does not move it, and capturing it here rather than earlier is simply the
    // narrowest honest window rather than a way to dodge one.
    // Without it, a lock landing inside `openDocumentRow` — which is
    // several Web Crypto round trips — put a fully decrypted name, type, note and
    // digest into the store the lock had just emptied, where it survived until the
    // next fetch and, on the logout path, into the next account on the same tab.
    const myGeneration = mutationGeneration;
    const opened = await openDocumentRow(row, vaultKey);
    if (myGeneration !== mutationGeneration) return uploadId;
    // The committed row is added to the list only when it is the row this transfer
    // asked about. A response describing a DIFFERENT document is not something to
    // recover from here — the upload did commit — but inserting it would put a row
    // under an id whose keys it was not sealed with, and the next fetch reads the
    // truth anyway.
    if (opened?.id === uploadId) {
      set((state) => ({ documents: [opened, ...state.documents] }));
    }
    return uploadId;
  } catch (error) {
    if (error instanceof UploadCancelledError || isAborted(signal)) {
      // Cancellation is not a failure of the file and leaves nothing to retry:
      // `cancelUpload` and `clearStore` have already aborted and zeroed, so there
      // is deliberately no entry left to mark.
      throw error instanceof UploadCancelledError ? error : new UploadCancelledError();
    }
    if (error instanceof UnresumableUploadError) {
      endSession(set, uploadId, { zero: true });
      throw error.cause;
    }
    updateProgress(set, uploadId, (current) => ({
      ...current,
      status: 'failed',
      error: error instanceof Error ? error.message : String(error),
    }));
    throw error;
  }
}

/**
 * Commit the transfer, recovering once from a vault-key rotation that landed
 * mid-upload.
 *
 * The wrapped key is sent HERE, not taken from the staging row, and that is the
 * whole reason a rotation costs one request instead of the entire file: the id is
 * bound into every derivation, so re-initiating would mint a new id and force every
 * segment to be re-encrypted and re-sent. On a 409 carrying a version the client
 * re-reads its profile, decrypts the NEW vault key with the MEK it still holds,
 * rewraps the DEK it still holds, and retries THIS request alone — no part is
 * re-sent, and the negative that proves it is that no part request is issued.
 *
 * Exactly one retry. A second 409 means a second rotation landed inside the
 * recovery, which is a race for the user to resolve by retrying, not one to spin
 * on.
 */
async function completeTransfer(
  session: UploadSession,
  uploadId: string,
  sealedMeta: { encryptedMeta: string; metaIv: string; metaTag: string },
  vaultKey: CryptoKey,
  signal: AbortSignal,
): Promise<unknown> {
  const send = async (key: CryptoKey, version: number): Promise<unknown> => {
    const wrapKey = await deriveWrapKey(key, uploadId);
    // Checked immediately before the DEK is read, with nothing awaited in between.
    // `clearStore()` aborts and then SYNCHRONOUSLY zeroes, so a check any earlier
    // leaves a window in which this wraps 32 zero bytes — and the server commits
    // the row from THIS body, so the result is a document whose segments nothing
    // can ever open. Web Crypto copies its input when `encrypt` is called, which
    // is reached synchronously from here, so the copy is of the real key.
    if (isAborted(signal)) throw new UploadCancelledError();
    const wrapped = await wrapDek(session.dek, wrapKey);
    return payloadOf(
      await completeDocumentUploadApi(uploadId, {
        ...sealedMeta,
        ...wrapped,
        vaultKeyVersion: version,
      }),
      'complete the upload',
    );
  };

  try {
    return await send(vaultKey, session.vaultKeyVersion);
  } catch (error) {
    // Discriminated on the PRESENCE of an integer `data.vaultKeyVersion`, never on
    // the message: this is the one refusal in the surface that carries a number,
    // and a 409 without one is an ordinary conflict.
    const version = staleVaultKeyVersion(error);
    if (version === null) throw error;
    if (isAborted(signal)) throw new UploadCancelledError();

    logger.info('Rewrapping a document key after a vault key rotation', { uploadId, version });
    const rotatedKey = await currentVaultKey();
    // The profile read is a full round trip, and an auto-lock is a wall-clock
    // deadline that does not wait for it.
    if (isAborted(signal)) {
      await cryptoService.clearCryptoKey(rotatedKey);
      throw new UploadCancelledError();
    }
    try {
      return await send(rotatedKey, version);
    } finally {
      await cryptoService.clearCryptoKey(rotatedKey);
    }
  }
}

/**
 * Re-derive the account's CURRENT vault key from the server's copy and the MEK.
 *
 * Deliberately does NOT write it into `authStore`. Adopting a rotated vault key
 * mid-session is a decision about the whole session — every item already in memory
 * was decrypted under the old one — and making it as a side effect of finishing one
 * upload would be exactly the kind of hidden state change nobody can reason about
 * later. The key returned here lives for one rewrap and is then cleared.
 */
async function currentVaultKey(): Promise<CryptoKey> {
  const { mek } = useAuthStore.getState();
  if (!mek) throw new Error('Vault is locked. Unlock it before performing document operations.');
  const profile = payloadOf(await getProfileApi(), 'read the profile');
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
