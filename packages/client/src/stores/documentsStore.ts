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
 *    the transfer ends unless its SHA-256 equals the one recorded when that index
 *    was first read (`UploadSession.sliceDigests`), checked before the slice is
 *    sealed or hashed, held parts included. It is also why an upload is not
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
import { isAxiosError } from 'axios';
import {
  DOCUMENT_NONCE_PREFIX_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_STREAM_SALT_BYTES,
  documentChunkCountFor,
  documentExtension,
  documentMetaSchema,
  documentResponseSchema,
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
  deleteDocumentApi,
  emptyDocumentTrashApi,
  getDocumentUsageApi,
  initDocumentUploadApi,
  listDocumentTrashApi,
  listDocumentsApi,
  purgeDocumentApi,
  restoreDocumentApi,
  updateDocumentApi,
} from '../services/api/documentsApi.js';
import { checkHeldVaultKey } from './heldVaultKey.js';
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
import type { TransferContext } from '../services/documents/uploadRecovery.js';
import { getSha256Factory } from '../lib/lazySha256.js';
import { loadUploadRecovery } from '../lib/lazyUploadRecovery.js';
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
type DocumentUploadStatus = 'uploading' | 'waiting' | 'finalizing' | 'failed';

/**
 * Why a `waiting` transfer is not moving bytes, which decides what its row says.
 *
 * `offline` and `connection` are waits that cost the server nothing and never
 * end the transfer: the browser reports offline, or the server could not be
 * reached at all. `interrupted` is a part the server WAS reached for and cut off
 * part-way, which is retried a bounded number of times. `server` is the server
 * answering with an error, retried on its own ladder.
 */
type DocumentUploadWaitReason = 'offline' | 'connection' | 'interrupted' | 'server';

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
  /**
   * How far the transfer has got, in plaintext bytes: ABSOLUTE (the confirmed
   * prefix plus the current part's fraction, never an accumulation) and a
   * HIGH-WATER MARK, so it never moves backwards. A part re-sent after an
   * interruption covers ground the bar already shows rather than dragging it back,
   * and a part's in-flight bytes stop one short of its end until the server has
   * confirmed it, so nothing reads as stored before it is.
   */
  sentBytes: number;
  status: DocumentUploadStatus;
  /** Present only while `status` is `waiting`. */
  waitReason?: DocumentUploadWaitReason | undefined;
  /** True while a part that had already shown progress is being sent again. */
  resending?: boolean | undefined;
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
 * A `waiting` transfer IS live: it is paused for the network or the server and
 * resumes by itself, and closing the tab is the one thing that loses that resume
 * (the DEK is memory-only).
 *
 * A predicate rather than two `!== 'failed'` comparisons, so a fifth status
 * cannot be added in a way that leaves the guard and the transfer list
 * answering differently. {@link DocumentUploadStatus} stays unexported deliberately, which
 * is why this is the shape the answer travels in.
 */
export function isLiveTransfer(transfer: DocumentUploadProgress): boolean {
  return transfer.status !== 'failed';
}

/** The handles, key material and inputs one transfer needs, kept out of the state tree. */
export interface UploadSession {
  controller: AbortController;
  /**
   * The recovery engine this transfer was started with. A session exists only
   * once the engine has loaded, so a resume reads it from here rather than
   * awaiting a load that can no longer fail.
   */
  recovery: UploadRecoveryModule;
  /**
   * What "Retry now" calls, or `null` when there is nothing to cut short.
   *
   * Set only by the recovery engine while a transfer waits to retry (it ends the
   * wait) or makes the attempt that follows a wait (it ends that attempt, which
   * costs the server nothing, and starts the next at once). It never creates a
   * controller or a loop, so it cannot orphan one.
   */
  wake: (() => void) | null;
  /**
   * Whether a resume is being PREPARED for this transfer right now.
   *
   * The claim {@link DocumentsState.retryUpload} takes before its first `await`,
   * and the reason it is a field on the session rather than a second module-level
   * registry: `endSession` removes the session, so the claim cannot outlive the
   * thing it describes, and a retry that finds no session is already refused for
   * a different and more accurate reason.
   *
   * It covers exactly the window `status` cannot. The flip to `'uploading'`
   * happens only once the staging ledger has answered, and a second Retry taken
   * inside that round trip would pass the `status !== 'failed'` guard, install its
   * own `controller` over the first one's, and leave the first loop running with a
   * controller nothing in this module can reach any more.
   */
  retrying: boolean;
  dek: DocumentBytes;
  source: Blob;
  /** The source's size when the transfer started, which fixes the framing. */
  sourceSize: number;
  /**
   * The SHA-256 of each plaintext slice as it was FIRST read, by segment index.
   *
   * A resume re-reads the file, and segment `i`'s nonce is fixed for the life of
   * the transfer, so the slice read now must be the slice sealed then: two
   * different plaintexts under one AES-GCM nonce hand anyone holding both their
   * XOR. `size` and `lastModified` cannot answer that question, because a `File`
   * reports the values it was picked with, not the disk's; the File API says a
   * changed file must fail the read, but that is a guarantee to assert rather than
   * to lean on. So the bytes themselves are compared, in `runTransfer`, before the
   * slice is hashed into the whole-file digest or sealed — including a slice whose
   * part the server already holds, which is never re-sent but whose bytes the
   * sealed digest still describes.
   *
   * Raw bytes rather than hex, so that the end of the session can zero them like
   * the DEK: a digest of a plaintext slice confirms a guess at that slice.
   */
  sliceDigests: DocumentBytes[];
  name: string;
  originalName: string;
  mime: string;
  tags: string[];
  note?: string | undefined;
  transform?: DocumentMeta['transform'];
  capturedAt: string;
  streamSalt: DocumentBytes;
  noncePrefix: DocumentBytes;
  chunkCount: number;
  chunkPlaintextBytes: number;
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
  /**
   * The name of the file as it was handed over, sealed beside `name` and never
   * rewritten afterwards. Defaults to `name`: a caller that does not let anyone
   * rename the file first (the authenticator import) uploads it under its own
   * name, and only the upload panel, where the name can be edited before the
   * upload starts, has two different values to pass.
   */
  originalName?: string | undefined;
  /** The MIME type, which may legitimately be empty for a type the OS did not recognise. */
  mime: string;
  folderId?: string | undefined;
  tags?: string[] | undefined;
  note?: string | undefined;
  transform?: DocumentMeta['transform'];
  /**
   * Called, synchronously, the moment the transfer is registered and has a row
   * of its own. Until then nothing is on screen for it, which is why the upload
   * panel keeps the file and the details it collected until this fires: a start
   * the server refuses, or one attempted offline, must not throw them away.
   */
  onRegistered?: ((uploadId: string) => void) | undefined;
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
  /** Cut a waiting transfer's wait short ("Retry now"); a no-op otherwise. */
  resumeUploadNow: (uploadId: string) => void;
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

/** The recovery engine's module, typed without importing it eagerly. */
type UploadRecoveryModule = typeof import('../services/documents/uploadRecovery.js');

/**
 * What the store says when a rename would change a document's file type.
 *
 * Defined HERE, in the store that enforces it, and imported by the detail
 * helpers that pre-check it, never the other way round: those helpers live in
 * lazy page chunks, and this store is in the initial payload.
 */
export const DOCUMENT_TYPE_LOCKED_MESSAGE =
  "A document's file type is fixed when it is added: rename the part of the name before the extension.";

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

/**
 * The current mutation generation, for a caller that queues its own writes (a
 * bulk action paced through `sendPaced`) and must stop once a lock or sign-out
 * has cleared this store.
 */
export function documentsMutationGeneration(): number {
  return mutationGeneration;
}

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
 * The `trashInvalidatedAt` the run currently holding `fetchTrashInFlight` captured.
 *
 * The dedup handle alone is not enough to answer "is this run still worth waiting
 * for". A run that started before an `emptyTrash` has already been superseded: its
 * terminal write is suppressed, so handing it back to a new caller resolves that
 * caller on a read which writes NOTHING. `emptyTrash`'s partial path is exactly
 * that caller — it bumps the counter and then asks for the list again — and the
 * result was a trash rendered EMPTY while `purgePending` rows were still listed,
 * still charged to the quota, and named by a toast pointing at this very list as
 * the authoritative answer.
 *
 * So a run is shared only while the invalidation it captured is still current.
 * Recorded beside the handle rather than derived from it, because the value lives
 * in the run's closure and nothing outside can read it there.
 */
let inFlightTrashInvalidation = 0;

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
 * The unlocked vault key AND the generation it belongs to, or a throw.
 *
 * Read from `authStore` at CALL time, never at module evaluation. The two stores
 * import each other — `authStore` needs this one for its lock and logout teardown,
 * this one needs the vault key — and a module-scope read would resolve to whatever
 * the bundler happened to evaluate first.
 *
 * The two come out of ONE snapshot, never two reads. The number is only
 * meaningful as a statement about the key beside it, and a lock or a rotation
 * landing between two separate `getState()` calls would pair a key with a version
 * that names a different one — precisely the confusion the version exists to
 * prevent.
 */
function requireVaultKey(): { vaultKey: CryptoKey; vaultKeyVersion: number } {
  const { vaultKey, vaultKeyVersion } = useAuthStore.getState();
  if (!vaultKey) {
    throw new Error('Vault is locked. Unlock it before performing document operations.');
  }
  return { vaultKey, vaultKeyVersion };
}

/** The unlocked vault key alone, for the callers that bind nothing to its generation. */
function getVaultKey(): CryptoKey {
  return requireVaultKey().vaultKey;
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
export function payloadOf<T>(response: { data: ApiResponse<T> }, action: string): T {
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
export function isAborted(signal: AbortSignal): boolean {
  return signal.aborted;
}

/**
 * A digest-shaped placeholder for the pre-flight.
 *
 * Not a real digest and never sealed: the file has not been read when the bounds
 * are checked. Every SHA-256 renders to the same 64 characters, so a placeholder
 * makes the pre-flight measure exactly the byte budget the real blob will have.
 */
export const PLACEHOLDER_DIGEST = '0'.repeat(64);

/**
 * Everything about a document's metadata that is known before the file is read.
 *
 * One definition, called three times: by the upload panel's own pre-check and by
 * the store's pre-flight, each with a placeholder digest, and by the seal with
 * the real one. Written out more than once, a bound checked up front and a value
 * sealed at the end could describe different documents.
 *
 * The original name falls back to `name` here, in the one place the blob is
 * shaped, so the store's session and the pre-checks cannot disagree about it.
 */
export function metaShapeFor(
  source: {
    name: string;
    originalName?: string | undefined;
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
    originalName: source.originalName ?? source.name,
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
  | 'resumeUploadNow'
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
        // A row whose key this vault key cannot unwrap may mean the vault key itself
        // was replaced by a rotation in another session; asked in the background.
        if (opened.degraded > 0) checkHeldVaultKey(vaultKey);
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
    // Shared only while it can still answer. A run that captured an older
    // `trashInvalidatedAt` was superseded by an `emptyTrash` after it started, so
    // its terminal write is already suppressed below and handing it back would
    // resolve this caller on a read that writes nothing — leaving the list exactly
    // as `emptyTrash` emptied it. Starting a second run instead is safe by the same
    // guards: the older run's generation no longer matches, so neither its write nor
    // its `finally` can touch the state or the handle this one owns.
    if (fetchTrashInFlight && inFlightTrashInvalidation === trashInvalidatedAt) {
      return fetchTrashInFlight;
    }
    fetchTrashGeneration += 1;
    const myGeneration = fetchTrashGeneration;

    // Captured with the generation, and checked beside it: this run is stale if
    // the trash was emptied while it was reading.
    const myInvalidation = trashInvalidatedAt;
    inFlightTrashInvalidation = myInvalidation;

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
        if (opened.degraded > 0) checkHeldVaultKey(vaultKey);
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
    // Captured FIRST, before anything is awaited: a lock that lands while the
    // recovery engine is being fetched, or while the transfer is being opened,
    // moves this, and both windows are checked against the same capture.
    const myGeneration = mutationGeneration;
    // The engine is the FIRST await, so a chunk that cannot be fetched fails the
    // start before a key exists or a staging row is opened, and leaves nothing to
    // clean up.
    const recovery = await loadUploadRecovery();
    if (myGeneration !== mutationGeneration) throw new UploadCancelledError();
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
    // the byte budget the real blob will have. A refusal is the first issue's own
    // sentence, never a serialized issue list: the upload panel runs the fuller
    // `uploadRefusal` before it calls this, so this is the backstop for any other
    // caller.
    const preflight = documentMetaSchema.safeParse({
      ...metaShapeFor(input, totalBytes, chunkCount, capturedAt),
      sha256: PLACEHOLDER_DIGEST,
    });
    if (!preflight.success) {
      throw new Error(
        preflight.error.issues[0]?.message ?? 'These document details cannot be stored.',
      );
    }

    const dek = generateDek();
    const streamSalt = randomBytes(DOCUMENT_STREAM_SALT_BYTES);
    const noncePrefix = randomBytes(DOCUMENT_NONCE_PREFIX_BYTES);

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

    // `init.vaultKeyVersion` is deliberately NOT kept: it is the SERVER's current
    // generation, which says nothing about the key this session holds, and the
    // completion needs the one thing it cannot answer. See `completeTransfer`.
    const { uploadId, chunkPlaintextBytes } = init;

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
      recovery,
      wake: null,
      retrying: false,
      dek,
      source: input.source,
      sourceSize: totalBytes,
      sliceDigests: [],
      name: input.name,
      originalName: input.originalName ?? input.name,
      mime: input.mime,
      tags: input.tags ?? [],
      ...(input.note === undefined ? {} : { note: input.note }),
      ...(input.transform === undefined ? {} : { transform: input.transform }),
      capturedAt,
      streamSalt,
      noncePrefix,
      chunkCount,
      chunkPlaintextBytes,
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
    // The transfer has its row now, so the caller may let go of what it holds. A
    // callback that throws is the caller's bug and must not strand a registered
    // transfer with nothing running it.
    try {
      input.onRegistered?.(uploadId);
    } catch (error) {
      logger.error('An upload registration callback failed', { error });
    }

    return runTransfer(set, uploadId, new Set<number>());
  },

  retryUpload: async (uploadId: string): Promise<string> => {
    const progress = get().uploads[uploadId];
    const session = sessions.get(uploadId);
    if (!progress || !session) throw new Error('That upload is no longer available to retry.');
    if (progress.status !== 'failed') {
      throw new Error('Only a failed upload can be retried.');
    }
    // THE CLAIM, and it is taken here — synchronously, before the first `await` —
    // rather than left to the status flip at the bottom, which cannot happen until
    // the ledger has answered. A second Retry taken inside that round trip would
    // pass every guard above it, and the cost is not a duplicated request: both
    // calls reach `session.controller = new AbortController()` and the second
    // OVERWRITES the first's, so the first loop keeps running against a controller
    // nothing in this module holds. `cancelUpload` then aborts the surviving
    // controller and zeroes the DEK, while the orphan — whose own signal was never
    // aborted, so the completion's abort check cannot help it — walks on to
    // `wrapDek` and commits a key made of 32 zero bytes. The metadata key derives
    // from the same zeroes, so the row LISTS with its real name while its segments,
    // sealed under the stream key derived from the REAL DEK, can never be opened
    // by anyone again; and the account cannot rotate its vault key at all until
    // that row is destroyed, because the rotation aborts on the first row it
    // cannot unwrap.
    if (session.retrying) {
      throw new Error('That upload is already being retried.');
    }
    session.retrying = true;

    // The ledger, not a local guess, decides what still has to be sent. A part the
    // server already holds is skipped, but its slice is still read and hashed: the
    // whole-file digest has to cover bytes that are not being re-sent. Whether a
    // re-read slice is the SAME slice is decided by its bytes, in `runTransfer`
    // (see `UploadSession.sliceDigests`).
    const { recovery } = session;
    let plan: Awaited<ReturnType<UploadRecoveryModule['prepareResume']>>;
    try {
      try {
        // Through the recovery engine, on the session's existing controller: a
        // Retry pressed while still offline WAITS and resumes by itself, and a
        // Cancel or a lock still ends it.
        plan = await recovery.prepareResume(transferContext(set, uploadId, session));
      } catch (error) {
        // Ended from outside while it was being prepared: a cancel, a lock or a
        // logout, which has already torn the session down and must not be
        // reported as a failure of the file.
        if (
          sessions.get(uploadId) !== session ||
          error instanceof UploadCancelledError ||
          isAborted(session.controller.signal)
        ) {
          throw new UploadCancelledError();
        }
        // Anything else KEEPS the transfer. Only a staging row that is really gone
        // ends it (below), and that was the defect here: an offline ledger read
        // used to be treated as one, ending the session and destroying a
        // perfectly resumable upload together with its key.
        const stopped = recovery.toStoppedError(error, 'resume');
        updateProgress(set, uploadId, (current) => ({
          ...withoutWaitState(current),
          status: 'failed',
          error: stopped.message,
        }));
        throw stopped;
      }
      if (sessions.get(uploadId) !== session) throw new UploadCancelledError();

      if (plan.kind === 'resume') {
        session.controller = new AbortController();
        // `sentBytes` is deliberately NOT reset: the bar never moves backwards, and
        // the parts the ledger holds are still held.
        updateProgress(set, uploadId, (current) => ({
          ...withoutWaitState(current),
          status: 'uploading',
          error: undefined,
        }));
      }
    } finally {
      // Released on EVERY exit, including the throwing ones above. On the way out
      // through the bottom the status is already `'uploading'`, so the status
      // guard takes over from here — which is what lets a resume that fails again
      // be resumed once more. `runTransfer` is deliberately started OUTSIDE this
      // block: the claim covers the preparation, never the transfer.
      session.retrying = false;
    }

    if (plan.kind === 'gone') {
      // The staging row is gone (its TTL fired, or it was cancelled elsewhere) and
      // no document committed under its id: nothing to resume onto, and the DEK
      // must not outlive the attempt.
      endSession(set, uploadId, { zero: true });
      throw new Error(plan.message);
    }
    if (plan.kind === 'committed') {
      // The completion committed but its answer never arrived: adopt the document
      // rather than ask for the file to be uploaded a second time.
      return adoptCommittedRow(set, uploadId, plan.row, getVaultKey(), session.controller.signal);
    }
    return runTransfer(set, uploadId, plan.held);
  },

  resumeUploadNow: (uploadId: string): void => {
    sessions.get(uploadId)?.wake?.();
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
    // The file type is fixed when the document is added. The preview, the
    // renderer and the download all key on the name's extension, so a rename that
    // moved it would silently change how the document opens. Compared with the
    // CURRENT name, so a document renamed to another extension before this rule
    // existed keeps the one it shows today.
    if (
      changes.name !== undefined &&
      documentExtension(changes.name) !== documentExtension(current.meta.name)
    ) {
      throw new Error(DOCUMENT_TYPE_LOCKED_MESSAGE);
    }

    // The spread carries everything the caller cannot change forward unchanged:
    // the original name above all, which is recorded once at upload.
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
    // The id check is `patchDocument`'s, for the same reason and with a second one
    // of its own. `_raw` is what a later re-seal derives this document's metadata
    // key from, so writing another document's row into an entry would produce a
    // rename sealed under keys that row was never sealed with. And here the write
    // lands by id, so a response about a different document would not even correct
    // the entry that was renamed: it would overwrite an UNTOUCHED document — with a
    // row this vault key may well fail to open, since the metadata key is derived
    // from the id, replacing a healthy entry with a degraded one the reader never
    // asked about. Dropped; the next fetch reads the truth.
    //
    // `opened?.id !== id` covers the SCHEMA-INVALID row as well, because `id` is a
    // string: `openDocumentRow` answers `null` for a row it cannot vouch for, and
    // `undefined` never equals a string. (A row that is well-formed but will not
    // OPEN is a different outcome — it comes back non-null with `meta: null` — and
    // is deliberately still applied, exactly as a listing lists it.)
    if (myGeneration !== mutationGeneration || opened?.id !== id) return;
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

    // The re-read is guaranteed to be a FRESH one. `fetchTrash` shares a run only
    // while the `trashInvalidatedAt` it captured is still current, and the bump
    // above has just made any run started before this point stale — so this cannot
    // be answered by the listing that was already in flight, whose own terminal
    // write is suppressed. It used to be, and the trash then rendered empty with
    // every `purgePending` row still on the server and still charged to the quota.
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
    // Reset with the counter it is compared against, not because a stale value
    // could be read — the share guard is conjunctive with `fetchTrashInFlight`,
    // which is nulled three lines up — but because a teardown list that does not
    // name every module-level variable is exactly the drift `EMPTY_DOCUMENTS_STATE`
    // exists to prevent, and the omission would be silent.
    inFlightTrashInvalidation = trashInvalidatedAt;

    for (const [uploadId, session] of sessions) {
      session.controller.abort();
      zeroDek(session.dek);
      zeroSliceDigests(session);
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

/**
 * Tell the server a transfer is over, best-effort and bounded.
 *
 * An abort that got NO answer (the vault locked while offline, which a transfer
 * that waits for the network makes the ordinary way for one to end) is tried
 * ONCE more, on the next `online` event while this tab is open: otherwise the
 * dead staging row would hold one of the account's three concurrent-upload slots
 * and its reserved bytes until it expired a day later. A second failure is left
 * to that expiry; this is a courtesy, never a loop.
 */
function fireAbort(uploadId: string, retryWhenOnline = true): void {
  void abortDocumentUploadApi(uploadId, ABORT_TIMEOUT_MS).catch((err: unknown) => {
    logger.warn('Failed to cancel an upload server-side', err);
    if (retryWhenOnline && isAxiosError(err) && err.response === undefined) {
      window.addEventListener(
        'online',
        () => {
          fireAbort(uploadId, false);
        },
        { once: true },
      );
    }
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
    zeroSliceDigests(session);
    sessions.delete(uploadId);
  }
  set((state) => {
    if (!(uploadId in state.uploads)) return {};
    const { [uploadId]: _removed, ...rest } = state.uploads;
    return { uploads: rest };
  });
}

/**
 * Zero every slice digest a transfer recorded.
 *
 * The zeroed records are left in place rather than dropped: a loop that somehow
 * outlived its session would then compare every re-read against zeroes and
 * refuse, where an emptied list would accept any bytes as a first read.
 */
function zeroSliceDigests(session: UploadSession): void {
  for (const digest of session.sliceDigests) digest.fill(0);
}

/** What a resume answers when a re-read slice is not the slice first read. */
const SOURCE_CHANGED_MESSAGE = 'The file changed since the upload started; start it again.';

/**
 * Whether the slice just read at `index` is the one this transfer read there first.
 *
 * The first read of an index records its digest and answers `true`. Every later
 * read compares against that record, and the comparison value is zeroed as soon
 * as it has answered. Called BEFORE the slice is hashed or sealed: segment
 * `index` has one nonce for the life of the transfer, so a slice that differs
 * must never reach `encryptSegment`, and one whose part the server already holds
 * must never reach the whole-file digest either.
 *
 * A lock that lands while the digest is computed has already zeroed this
 * session's records, so the new digest is zeroed rather than stored into a
 * session that is over.
 */
async function isSliceFirstRead(
  session: UploadSession,
  index: number,
  slice: DocumentBytes,
  signal: AbortSignal,
): Promise<boolean> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', slice));
  if (isAborted(signal)) {
    digest.fill(0);
    throw new UploadCancelledError();
  }
  const recorded = session.sliceDigests[index];
  if (recorded === undefined) {
    session.sliceDigests[index] = digest;
    return true;
  }
  const same = recorded.every((b, i) => b === digest[i]);
  digest.fill(0);
  return same;
}

/**
 * Apply a change to one progress entry, leaving the rest of the registry alone.
 *
 * A change that hands back the entry it was given writes NOTHING: the callback
 * returns the state itself, which zustand recognises as no change and does not
 * announce, so a progress tick that does not move the high-water mark costs no
 * render.
 */
function updateProgress(
  set: SetState,
  uploadId: string,
  change: (current: DocumentUploadProgress) => DocumentUploadProgress,
): void {
  set((state) => {
    const current = state.uploads[uploadId];
    if (!current) return state;
    const next = change(current);
    if (next === current) return state;
    return { uploads: { ...state.uploads, [uploadId]: next } };
  });
}

/** `current` without the fields that only describe a wait. */
function withoutWaitState(current: DocumentUploadProgress): DocumentUploadProgress {
  const { waitReason: _waitReason, resending: _resending, ...rest } = current;
  return rest;
}

/** The handle the recovery engine drives one transfer through. */
function transferContext(set: SetState, uploadId: string, session: UploadSession): TransferContext {
  return {
    uploadId,
    session,
    signal: session.controller.signal,
    report: (patch) => {
      updateProgress(set, uploadId, (current) =>
        current.status === patch.status && current.waitReason === patch.waitReason
          ? current
          : { ...current, status: patch.status, waitReason: patch.waitReason },
      );
    },
  };
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
 * Walk the file: hash every slice, seal and send the parts the server does not
 * already hold, then seal the metadata and commit.
 *
 * `alreadyHeld` carries PART numbers (1-based) from the staging ledger. Every slice
 * is still read and hashed even when its part is skipped, because the digest in the
 * metadata covers the whole file and a resumed transfer must arrive at the same
 * one. Every request goes through the recovery engine, which decides what a
 * failure means (see `services/documents/uploadRecovery.ts`).
 */
async function runTransfer(
  set: SetState,
  uploadId: string,
  alreadyHeld: Set<number>,
): Promise<string> {
  const session = sessions.get(uploadId);
  if (!session) throw new UploadCancelledError();
  const { signal } = session.controller;
  const { recovery } = session;
  const ctx = transferContext(set, uploadId, session);

  try {
    // The key and the generation it belongs to, read together — the completion
    // has to say WHICH vault key it wrapped with, and only a pair read from one
    // snapshot can say that truthfully.
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
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
      if (!(await isSliceFirstRead(session, index, slice, signal))) {
        // The file changed under a resume. Sealing this slice would put a second
        // plaintext under segment `index`'s nonce, and skipping a held part would
        // seal a whole-file digest of bytes the server does not hold: the transfer
        // cannot continue either way, so it ends here, key zeroed, row released.
        fireAbort(uploadId);
        throw new recovery.UnresumableUploadError(new Error(SOURCE_CHANGED_MESSAGE));
      }
      hasher.update(slice);

      const partNumber = index + 1;
      if (!alreadyHeld.has(partNumber)) {
        // Sealed ONCE and re-sent byte for byte by every retry of this part.
        const sealed = await encryptSegment(
          streamKey,
          { noncePrefix: session.noncePrefix, index, isLast: index === session.chunkCount - 1 },
          slice,
        );
        // A part's in-flight bytes stop one short of its end: the browser can hand
        // a whole part over before the server has stored it, and the bar must not
        // read as stored until it is. A zero-byte part caps at its own start.
        const inFlightCap = Math.max(0, slice.length - 1);
        await recovery.sendPart(ctx, partNumber, sealed.buffer, await sealedSegmentDigest(sealed), {
          // A part that had already shown progress is being sent again: say so,
          // because the bar will not move until the re-send passes it.
          onAttempt: () => {
            updateProgress(set, uploadId, (current) =>
              current.sentBytes > start && current.resending !== true
                ? { ...current, resending: true }
                : current,
            );
          },
          // Progress is ABSOLUTE (the completed prefix plus this part's own
          // fraction, never an accumulator) and a HIGH-WATER mark: a retried part
          // restarts at zero, and a running total or a plain write would drag the
          // bar backwards on every attempt.
          onProgress: (loaded, total) => {
            const fraction = total > 0 ? Math.min(1, loaded / total) : 0;
            const reached = start + Math.min(Math.round(slice.length * fraction), inFlightCap);
            updateProgress(set, uploadId, (current) =>
              reached > current.sentBytes
                ? { ...current, sentBytes: Math.min(current.totalBytes, reached) }
                : current,
            );
          },
        });
      }
      updateProgress(set, uploadId, (current) => {
        const confirmed = Math.min(current.totalBytes, start + slice.length);
        if (confirmed <= current.sentBytes && current.resending === undefined) return current;
        const { resending: _resending, ...rest } = current;
        return { ...rest, sentBytes: Math.max(current.sentBytes, confirmed) };
      });
    }

    if (isAborted(signal)) throw new UploadCancelledError();
    updateProgress(set, uploadId, (current) => ({
      ...withoutWaitState(current),
      status: 'finalizing',
    }));

    const meta: DocumentMeta = {
      ...metaShapeFor(session, session.sourceSize, session.chunkCount, session.capturedAt),
      sha256: hasher.digest('hex'),
    };
    const sealedMeta = await encryptMeta(
      await deriveMetaKey(session.dek, session.streamSalt, uploadId),
      meta,
    );

    const row = await recovery.completeTransfer(ctx, sealedMeta, vaultKey, vaultKeyVersion);
    return await adoptCommittedRow(set, uploadId, row, vaultKey, signal);
  } catch (error) {
    if (error instanceof UploadCancelledError || isAborted(signal)) {
      // Cancellation is not a failure of the file and leaves nothing to retry:
      // `cancelUpload` and `clearStore` have already aborted and zeroed, so there
      // is deliberately no entry left to mark.
      throw error instanceof UploadCancelledError ? error : new UploadCancelledError();
    }
    if (error instanceof recovery.UnresumableUploadError) {
      endSession(set, uploadId, { zero: true });
      throw new recovery.UploadStoppedError(error.message, error.cause);
    }
    // RESUMABLE: the entry and the DEK both survive, so the UI can offer a retry
    // that re-sends under the same key (parts the server holds would otherwise
    // become garbage). The row and the error say the same sentence.
    const stopped = recovery.toStoppedError(error);
    updateProgress(set, uploadId, (current) => ({
      ...withoutWaitState(current),
      status: 'failed',
      error: stopped.message,
    }));
    throw stopped;
  }
}

/**
 * Put a committed document in front of the reader and end its transfer.
 *
 * Shared by the ordinary end of a transfer and by a resume that found the
 * completion had already committed while its answer was lost, so the two cannot
 * differ. The session ends here, exactly once, with its key zeroed.
 *
 * The committed row is opened only while nothing has discarded the store:
 * opening it is a LOCAL write, and a lock or a logout that landed while the
 * completion was in flight must not have it put decrypted plaintext back into a
 * store `clearStore()` has just emptied. The captured vault key would still
 * decrypt: clearing a key zeroes an exported copy, not the live handle.
 */
async function adoptCommittedRow(
  set: SetState,
  uploadId: string,
  row: unknown,
  vaultKey: CryptoKey,
  signal: AbortSignal,
): Promise<string> {
  endSession(set, uploadId, { zero: true });
  if (isAborted(signal)) return uploadId;

  // FROM HERE ON THE SIGNAL CAN NO LONGER MOVE, WHICH IS WHY THE GUARD CHANGES.
  // `endSession` has removed this transfer from `sessions`, and that map is the
  // only thing `clearStore()` and `cancelUpload` iterate — so nothing in this
  // codebase can abort this controller any more. `mutationGeneration` is what a
  // lock or a logout actually moves, and it is the guard every other post-await
  // writer in this file uses.
  const myGeneration = mutationGeneration;
  const opened = await openDocumentRow(row, vaultKey);
  if (myGeneration !== mutationGeneration) return uploadId;
  // The committed row is added only when it is the row this transfer asked about:
  // a row under another id was not sealed with this transfer's keys, and the next
  // fetch reads the truth anyway. Inserted with a dedupe filter, because a
  // listing that ran meanwhile may already hold it.
  if (opened?.id === uploadId) {
    set((state) => {
      if (opened.deletedAt === undefined) {
        return { documents: [opened, ...state.documents.filter((doc) => doc.id !== uploadId)] };
      }
      // `GET /documents/:id` also answers for a trashed row: it belongs in the
      // trash, and only in a trash that has actually been read.
      return state.trashLoaded
        ? {
            trashDocuments: [opened, ...state.trashDocuments.filter((doc) => doc.id !== uploadId)],
          }
        : state;
    });
  }
  return uploadId;
}
