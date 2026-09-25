/**
 * Vault Zustand store.
 *
 * Manages the decrypted vault items and folders on the client side.
 * All encryption/decryption is performed via the CryptoService using the
 * vault key held in the auth store. The server only ever sees ciphertext.
 */

import { create } from 'zustand';
import { cryptoService } from '../services/crypto/cryptoService.js';
import { buildPasswordHistoryPayload } from '../services/crypto/passwordHistory.js';
import {
  assertStoredUnder,
  decryptVaultField,
  encryptVaultField,
  newBoundRow,
} from '../services/crypto/vaultField.js';
import { offlineCache, offlineCacheErrorType } from '../services/offlineCache.js';
import { clearScoreCache } from '../services/health/strengthCache.js';
import { logger } from '../lib/logger.js';
import { isRateLimited, retryAfterSeconds } from '../services/auth/sessionFailure.js';
import { useAuthStore } from './authStore.js';
import { noteStaleVaultKey, useUIStore } from './uiStore.js';
// Folders are ONE collection shared by vault items and documents, so deleting a
// folder has to reach both stores. The cycle this closes (`documentsStore`
// imports `mapWithConcurrency` from here) is the shape `authStore` already has
// with both of these, and it is safe for the same reason: neither side reads the
// other at module scope, only inside a function that runs later.
import { useDocumentsStore } from './documentsStore.js';
import {
  listItemsApi,
  getItemApi,
  createItemApi,
  updateItemApi,
  deleteItemApi,
  permanentDeleteApi,
  emptyTrashApi,
  restoreItemApi,
  listFoldersApi,
  createFolderApi,
  updateFolderApi,
  deleteFolderApi,
  listTrashApi,
} from '../services/api/vaultApi.js';
import {
  vaultItemDataSchemas,
  vaultItemResponseSchema,
  folderResponseSchema,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_ENCRYPTED_DATA_LENGTH,
} from '@hvault/shared';
import type {
  IVaultItemResponse,
  IFolderResponse,
  UpdateVaultItemInput,
  ExportResponse,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Client-side decrypted types
// ---------------------------------------------------------------------------

export interface DecryptedVaultItem {
  /** Original server-side ID */
  id: string;
  itemType: ItemType;
  folderId?: string | undefined;
  tags: string[];
  favorite: boolean;
  /** Decrypted item name */
  name: string;
  /** Decrypted structured data (JSON-parsed) */
  data: Record<string, unknown>;
  searchHash?: string | undefined;
  createdAt: string;
  updatedAt: string;
  deletedAt?: string | undefined;
  /** Keep the raw encrypted response for updating without re-fetching */
  _raw: IVaultItemResponse;
}

export interface DecryptedFolder {
  id: string;
  name: string;
  parentId?: string | undefined;
  icon?: string | undefined;
  color?: string | undefined;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
  _raw: IFolderResponse;
}

// ---------------------------------------------------------------------------
// State shape
// ---------------------------------------------------------------------------

export type SortBy = 'name' | 'dateCreated' | 'dateModified' | 'type';
export type SortOrder = 'asc' | 'desc';

/**
 * The plaintext, non-encrypted fields of a vault item. These are the only
 * fields {@link VaultState.updateItemMeta} is allowed to change; `folderId:
 * null` clears the folder (server-side `$unset`), `undefined` leaves it alone.
 */
export interface ItemMetaUpdate {
  favorite?: boolean;
  folderId?: string | null;
  tags?: string[];
}

interface VaultState {
  items: DecryptedVaultItem[];
  trashItems: DecryptedVaultItem[];
  folders: DecryptedFolder[];
  /** True when either items or trash are loading */
  loading: boolean;
  itemsLoading: boolean;
  trashLoading: boolean;
  /**
   * Decryption progress for the active fetch. `total` is `null` when unknown
   * (e.g. before the first page response arrives) and `0` when no fetch is in
   * flight. The UI surfaces "Loading X / Y" while {@link itemsLoading} is true
   * and progressively appends decrypted items to {@link items} so the user
   * sees rows render before all pages have been fetched/decrypted.
   */
  itemsLoaded: number;
  itemsTotal: number | null;
  /** Number of entries that failed to decrypt in the most recent fetch */
  decryptionFailures: number;
  /**
   * Diagnostic info about the most recent decryption failure.
   * Populated by any of the fetch methods (items, trash, folders); cleared
   * on {@link clearStore}. Useful when the user clicks "Re-sync" in the banner
   * and support needs a clue about what went wrong.
   */
  lastDecryptionError: string | null;
  searchQuery: string;
  selectedFolder: string | null;
  selectedType: ItemType | null;
  showFavorites: boolean;
  showTrash: boolean;
  sortBy: SortBy;
  sortOrder: SortOrder;

  // Actions
  fetchItems: () => Promise<void>;
  fetchTrashItems: () => Promise<void>;
  fetchFolders: () => Promise<void>;
  createItem: (
    itemType: ItemType,
    name: string,
    data: Record<string, unknown>,
    options?: { folderId?: string; tags?: string[]; favorite?: boolean },
  ) => Promise<void>;
  /**
   * Re-encrypt and replace an item's whole decrypted payload.
   *
   * `itemType` is passed EXPLICITLY, mirroring {@link createItem}. It used to be
   * inferred from `get().items.find(...)`, which meant the pre-flight schema check
   * silently did nothing whenever the row was not in `items` — and `items` is not a
   * reliable oracle: a TRASHED item lives in `trashItems`. Every caller knows the
   * type, so nothing has to guess.
   */
  updateItem: (
    id: string,
    itemType: ItemType,
    name: string,
    data: Record<string, unknown>,
    options?: {
      folderId?: string | null;
      tags?: string[];
      favorite?: boolean;
    },
  ) => Promise<void>;
  /**
   * Metadata-only update: sends ONLY `favorite` / `folderId` / `tags` and never
   * re-encrypts the item. See the action's implementation for why routing a
   * favorite toggle or a folder move through {@link updateItem} is unsafe.
   */
  updateItemMeta: (id: string, meta: ItemMetaUpdate) => Promise<void>;
  /**
   * NAME-ONLY update: re-encrypts the name (and its `searchHash`) and sends nothing
   * else. The item's `encryptedData`/`dataIv`/`dataTag` are not in the payload at
   * all, so its ciphertext is left byte-identical.
   *
   * This is the one write an UNDECODABLE item can safely take. See the action's
   * implementation for why {@link updateItem} cannot serve that case.
   */
  renameItem: (id: string, name: string) => Promise<void>;
  deleteItem: (id: string) => Promise<void>;
  permanentDeleteItem: (id: string) => Promise<void>;
  emptyTrash: () => Promise<void>;
  restoreItem: (id: string) => Promise<void>;
  /** Count of items after all filters are applied (set by VaultList) */
  filteredItemCount: number | null;
  setFilteredItemCount: (count: number | null) => void;
  setSearchQuery: (query: string) => void;
  setSelectedFolder: (folderId: string | null) => void;
  setSelectedType: (type: ItemType | null) => void;
  setShowFavorites: (value: boolean) => void;
  setShowTrash: (value: boolean) => void;
  toggleFavorites: () => void;
  toggleTrash: () => void;
  setSortBy: (sortBy: SortBy) => void;
  setSortOrder: (sortOrder: SortOrder) => void;
  createFolder: (
    name: string,
    options?: { parentId?: string; icon?: string; color?: string },
  ) => Promise<void>;
  updateFolder: (
    id: string,
    name: string,
    options?: { color?: string; sortOrder?: number },
  ) => Promise<void>;
  deleteFolder: (id: string, action?: 'move' | 'delete') => Promise<void>;
  clearStore: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Deduplication guards: if a fetch is already in flight, subsequent callers
// await the existing promise instead of firing a duplicate request.
let fetchItemsInFlight: Promise<void> | null = null;
let fetchTrashInFlight: Promise<void> | null = null;
let fetchFoldersInFlight: Promise<void> | null = null;

// Race tracking for fetchItems progressive append:
//
// fetchItems streams pages and appends decrypted rows to `state.items` between
// network requests. If a `deleteItem` (or `permanentDeleteItem`) lands while
// pages are still in flight, the deleted id can be reintroduced by the next
// page-append because the delete already mutated state.items but a later page
// containing the same id has not yet been appended.
//
// Mitigation:
//   * Each fetchItems / fetchTrashItems invocation bumps a generation counter.
//     Stale page results from a superseded fetch are dropped.
//   * Concurrent deletes record their ids into a per-generation Set so
//     in-flight pages from the active fetch filter the delete out before
//     appending. The Set is cleared when the fetch settles.
let fetchItemsGeneration = 0;
let fetchTrashGeneration = 0;

// fetchFolders has no delete-race (folders aren't streamed page-by-page), but
// it still needs a generation counter so a slow fetch (online or offline) that
// resolves AFTER a lock/logout cannot write decrypted folders back into the
// just-cleared store, nor re-persist ciphertext via the fire-and-forget cache
// write after offlineCache.clear(). clearStore() bumps this on lock/logout.
let fetchFoldersGeneration = 0;
// Bumped by clearStore() (lock/logout). The vault mutation methods
// (createItem/updateItem/updateItemMeta/restoreItem/createFolder/updateFolder)
// capture this at the start and re-check it immediately before their post-await
// set(). A mutation whose network round-trip resolves AFTER a lock/logout must
// NOT write the item/folder back into the just-cleared store (for the
// decrypting methods the captured CryptoKey still decrypts, because
// clearCryptoKey() only zeroes an exported copy, not the live handle;
// updateItemMeta decrypts nothing but must not repopulate the store either).
// This mirrors the fetch-path generation guards. The server-side write already
// happened — only the local write is suppressed.
let mutationGeneration = 0;
/**
 * The current `fetchItems` generation.
 *
 * A caller that needs the COMPLETE item set — import conflict resolution is the
 * one that does — cannot rely on awaiting `fetchItems()` alone: a run that is
 * superseded mid-stream (by `clearStore()` on lock/logout, or by a newer fetch)
 * RESOLVES rather than rejecting, and `clearStore()` has already emptied
 * `items`. Resolving an import against that empty list would classify the whole
 * file as new and duplicate a vault the user still owns.
 *
 * So read this immediately after calling `fetchItems()` and compare it again
 * after the await: an unchanged value means the run you awaited is the one that
 * finished, and `items` is that run's complete result.
 */
export function getItemsFetchGeneration(): number {
  return fetchItemsGeneration;
}

// Bumped by clearStore() (lock/logout). The Vault Health page captures this
// before loading/persisting its encrypted results cache and re-checks it before
// writing decrypted findings into React state, so a scan that resolves AFTER a
// lock cannot repopulate results (the captured CryptoKey still decrypts, exactly
// like the mutation-generation guard). One counter covers breach + strength.
let healthGeneration = 0;
export function getHealthGeneration(): number {
  return healthGeneration;
}

const inFlightDeletedItemIds = new Set<string>();
const inFlightDeletedTrashIds = new Set<string>();

/**
 * Minimum number of decryption failures required to dispatch the
 * `vault-decryption-failures` event. Kept at 1 (any failure) so the AppLayout
 * banner surfaces even a single corrupted item — this is a privacy/integrity
 * issue the user should know about, not a "systematic" threshold.
 */
export const DECRYPTION_FAILURE_THRESHOLD = 1;

/**
 * Bounded concurrency cap for client-side decryption. Web Crypto operations
 * are queued onto a fixed pool of background workers in the browser, so
 * issuing thousands of concurrent decrypt() calls just bloats the GC heap
 * with pending promise objects without speeding anything up. 16 keeps the
 * pool saturated on typical hardware while bounding heap growth.
 */
export const DECRYPTION_CONCURRENCY = 16;

/**
 * Hard cap on the number of pages the client will fetch in a single
 * fetchItems / fetchTrashItems call. With PAGE_SIZE = 200 this matches
 * MAX_ITEMS_PER_USER (10,000) on the server. Defends against a runaway
 * pagination loop if the server ever returns an inflated `totalPages`.
 */
const MAX_PAGES = 50;

/**
 * Runs `task(item)` over `items` with at most `concurrency` running
 * concurrently. Resolves with PromiseSettledResult-style entries so the
 * caller can report failures without aborting the batch.
 *
 * Exported so `documentsStore` opens a page of documents through the same
 * bounded pool this opens a page of vault items with, and so both can be unit
 * tested directly. Order is preserved.
 */
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  concurrency: number,
  task: (item: T, index: number) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length) as PromiseSettledResult<R>[];
  let cursor = 0;
  const limit = Math.max(1, Math.min(concurrency, items.length || 1));

  async function worker(): Promise<void> {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      const item = items[index] as T;
      try {
        const value = await task(item, index);
        results[index] = { status: 'fulfilled', value };
      } catch (reason: unknown) {
        results[index] = { status: 'rejected', reason };
      }
    }
  }

  const workers: Promise<void>[] = [];
  for (let i = 0; i < limit; i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

/** How many of one bulk action's requests are in flight at once. */
export const BULK_REQUEST_CONCURRENCY = 4;

/**
 * The longest `Retry-After` a bulk action waits out by itself, in seconds. A
 * rate-limiting proxy in front of the app asks for seconds (the golden host nginx
 * sends `5`); the app's own per-account budgets answer with the rest of their
 * window, up to fifteen minutes, and that is a refusal to report, not a pause.
 */
export const MAX_BULK_RETRY_AFTER_SECONDS = 10;

/** How many times one request of a bulk action is sent again after such a 429. */
export const MAX_BULK_RETRIES = 3;

/** What a request a lock or sign-out overtook is rejected with, unsent. */
export const BULK_ABANDONED_MESSAGE =
  'The vault was locked, so the rest of this action was not sent.';

const waitMs = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/**
 * Sends one request per row for a bulk action (tagging, permanent deletion, a
 * folder reorder) PACED rather than all at once, and waits out a short 429.
 *
 * These actions have always been one request per row, which the app's own
 * limiters are sized for, but they used to fire every request in the same
 * instant. A rate-limiting proxy counts each one: the golden host nginx a
 * deployment puts in front of the app allows each address 40 requests a second
 * with a burst of 40, so a bulk tag of a hundred items applied to about forty of
 * them and refused the rest. No burst setting fixes an unpaced fan-out, because
 * its arrival rate grows with the selection; pacing and retrying does, behind any
 * such proxy. So at most {@link BULK_REQUEST_CONCURRENCY} are in flight, and a
 * request refused with a 429 whose `Retry-After` is at most
 * {@link MAX_BULK_RETRY_AFTER_SECONDS} is sent again after that wait, up to
 * {@link MAX_BULK_RETRIES} times. Resending is safe: a 429 is answered before the
 * request's handler runs, and each of these writes sets a value rather than
 * adding one. Any other failure, or a longer wait, is the request's result as
 * before.
 *
 * Every request is attempted, and the results are settled and in order, so a
 * caller reports failures exactly as it did before. A request that throws before
 * it is even sent is reported as rejected, like one the server refused.
 *
 * Except after a lock or a sign-out. Pacing means requests are still QUEUED when
 * one lands, where before every one was already on the wire, so each request
 * checks the store's mutation generation (which `clearStore()` moves) before it
 * is sent and again after every wait; once it has moved, the rest are rejected
 * with {@link BULK_ABANDONED_MESSAGE} without being sent. A locked vault must not
 * go on writing, and after a sign-out each would be a 401 into the refresh path.
 */
export async function sendPaced<R>(
  requests: readonly (() => Promise<R>)[],
  wait: (ms: number) => Promise<void> = waitMs,
): Promise<PromiseSettledResult<R>[]> {
  const generation = mutationGeneration;
  return mapWithConcurrency(requests, BULK_REQUEST_CONCURRENCY, async (send) => {
    for (let retries = 0; ; retries++) {
      if (generation !== mutationGeneration) throw new Error(BULK_ABANDONED_MESSAGE);
      try {
        return await send();
      } catch (error: unknown) {
        const seconds = isRateLimited(error) ? retryAfterSeconds(error) : null;
        if (
          seconds === null ||
          seconds > MAX_BULK_RETRY_AFTER_SECONDS ||
          retries >= MAX_BULK_RETRIES
        ) {
          throw error;
        }
        await wait(seconds * 1000);
      }
    }
  });
}

type DecryptionContext = 'vault items' | 'trash items' | 'folders';

/**
 * Inspects a batch of Promise.allSettled results from decryption calls,
 * logs and reports failures consistently, and dispatches a
 * `vault-decryption-failures` event so the AppLayout banner can surface
 * the problem to the user.
 *
 * Exported for unit testing. Returns the failure count and a
 * human-readable error message describing the first failure.
 */
export function reportDecryptionFailures(
  results: readonly PromiseSettledResult<unknown>[],
  context: DecryptionContext,
): { failedCount: number; errorMessage: string | null } {
  const rejected = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
  const failedCount = rejected.length;

  if (failedCount < DECRYPTION_FAILURE_THRESHOLD) {
    return { failedCount: 0, errorMessage: null };
  }

  const firstReason: unknown = rejected[0]?.reason;
  const firstMessage = firstReason instanceof Error ? firstReason.message : String(firstReason);
  const errorMessage = `${context}: ${firstMessage}`;

  logger.error(`Failed to decrypt ${String(failedCount)} ${context}: ${firstMessage}`);

  // Notify UI components via custom event so the AppLayout banner can
  // surface the failure. Guarded for non-browser test environments.
  if (typeof window !== 'undefined') {
    window.dispatchEvent(
      new CustomEvent('vault-decryption-failures', { detail: { count: failedCount } }),
    );
  }

  return { failedCount, errorMessage };
}

/**
 * Thrown when the encrypted output exceeds the server-side max length limits.
 * Caught by the form so it can show a user-friendly message instead of
 * letting the user submit and receive a cryptic 400 from the server.
 */
export class EncryptedFieldTooLargeError extends Error {
  readonly field: 'name' | 'data';
  readonly actualLength: number;
  readonly maxLength: number;
  constructor(field: 'name' | 'data', actualLength: number, maxLength: number) {
    super(
      field === 'name'
        ? 'Item name is too large to save. Please shorten it.'
        : 'Item data is too large to save. Please remove some content (e.g. shorten notes, remove custom fields, or clear password history).',
    );
    this.name = 'EncryptedFieldTooLargeError';
    this.field = field;
    this.actualLength = actualLength;
    this.maxLength = maxLength;
  }
}

/**
 * Thrown when a decrypted `data` payload does not satisfy the shared schema for
 * its item type. Surfaced by the form the same way
 * {@link EncryptedFieldTooLargeError} is.
 */
export class VaultItemDataInvalidError extends Error {
  readonly itemType: ItemType;
  /** The first few Zod issues, as `path: message` strings. Never carries a VALUE. */
  readonly issues: string[];
  /**
   * EVERY issue, structured, so a caller can put each one on the control that owns
   * it. `path` is the STORED-schema path (`address.city`, `customFields.0.value`),
   * which is not always the form's field name — mapping it is the form's job, and
   * `VaultItemForm.formFieldForStoredPath` does it explicitly.
   *
   * Carries paths and Zod messages only, never a field VALUE: the payload is full
   * of secrets and these strings reach the DOM.
   */
  readonly fieldIssues: readonly { path: string; message: string }[];
  constructor(
    itemType: ItemType,
    issues: string[],
    fieldIssues: readonly { path: string; message: string }[] = [],
  ) {
    // The FIELD NAMES lead. This message is the FALLBACK channel: the form maps
    // these issues onto their controls when it can, and only shows the message in a
    // toast when a path has no control that would render it.
    //
    // Kept short deliberately. `getApiErrorMessage` truncates at
    // MAX_ERROR_MESSAGE_LENGTH (200), so a long tail would be cut mid-sentence —
    // which is why the field list comes FIRST and the advice, being the expendable
    // part, comes last.
    super(`Cannot save this ${itemType} — ${issues.join('; ')}. Shorten or correct these fields.`);
    this.name = 'VaultItemDataInvalidError';
    this.itemType = itemType;
    this.issues = issues;
    this.fieldIssues = fieldIssues;
  }
}

/**
 * How many Zod issues the error message reports before it stops listing them.
 *
 * Two, not more: the message is truncated at 200 characters downstream, and a
 * Zod issue message plus its path is easily 60, so a third entry mostly buys a
 * cut-off string.
 */
const MAX_REPORTED_VALIDATION_ISSUES = 2;

/**
 * Pre-flight schema check, run BEFORE `data` is encrypted.
 *
 * `vaultItemDataSchemas` used to be consulted only on the way OUT
 * ({@link decryptItem}), which is the asymmetry that enabled the whole
 * undecodable-item class: anything at all could be written, and the failure
 * surfaced on the NEXT read — by which point the real ciphertext had already been
 * overwritten and, this being a zero-knowledge vault, there was no server-side
 * plaintext to recover it from. Validating on the way IN turns permanent, silent
 * data loss into a rejected save the user can act on.
 *
 * The issue list carries paths and Zod messages only, never field VALUES: this
 * message reaches a toast, and the payload is full of secrets.
 */
function assertValidItemData(itemType: ItemType, data: Record<string, unknown>): void {
  const result = vaultItemDataSchemas[itemType].safeParse(data);
  if (result.success) return;
  const fieldIssues = result.error.issues.map((issue) => ({
    path: issue.path.map((segment) => String(segment)).join('.'),
    message: issue.message,
  }));
  const issues = fieldIssues
    .slice(0, MAX_REPORTED_VALIDATION_ISSUES)
    .map(({ path, message }) => (path ? `${path}: ${message}` : message));
  throw new VaultItemDataInvalidError(itemType, issues, fieldIssues);
}

/**
 * Pre-flight size check: the server enforces max-length on encrypted fields
 * via Mongoose validators, so catching oversized payloads on the client
 * avoids an unhelpful 400 after the user has already filled out the form.
 */
function assertEncryptedNameSize(encryptedName: { encrypted: string }): void {
  if (encryptedName.encrypted.length > MAX_ENCRYPTED_NAME_LENGTH) {
    throw new EncryptedFieldTooLargeError(
      'name',
      encryptedName.encrypted.length,
      MAX_ENCRYPTED_NAME_LENGTH,
    );
  }
}

function assertEncryptedSizes(
  encryptedName: { encrypted: string },
  encryptedData: { encrypted: string },
): void {
  assertEncryptedNameSize(encryptedName);
  if (encryptedData.encrypted.length > MAX_ENCRYPTED_DATA_LENGTH) {
    throw new EncryptedFieldTooLargeError(
      'data',
      encryptedData.encrypted.length,
      MAX_ENCRYPTED_DATA_LENGTH,
    );
  }
}

/**
 * The unlocked vault key together with the generation it belongs to, read from
 * ONE `getState()`.
 *
 * One read and not two, for the reason `documentsStore.requireVaultKey` gives:
 * the number is what the server matches the ciphertext against, so a key taken
 * from one snapshot and a generation from another could name a pair that never
 * existed at the same instant.
 *
 * The generation needs no vault key of its own, which is why
 * {@link vaultKeyGeneration} exists beside this for the metadata-only path.
 */
function requireVaultKey(): { vaultKey: CryptoKey; vaultKeyVersion: number } {
  const { vaultKey, vaultKeyVersion } = useAuthStore.getState();
  if (!vaultKey) {
    throw new Error('Vault is locked. Unlock it before performing vault operations.');
  }
  // CryptoKey is an opaque handle — no need to copy (unlike ArrayBuffer).
  return { vaultKey, vaultKeyVersion };
}

/**
 * Refuses an update naming an item type other than the one the row is stored with.
 *
 * Read from this store when the row is in it (active or trashed), and otherwise
 * from the server, because a caller the store cannot see is precisely the caller
 * whose type nothing here has checked. Under format v1 a wrong type cost nothing
 * at write time; under v2 the data is bound to the type it names, so a wrong one
 * is a row whose data never opens again.
 */
async function assertStoredItemType(
  id: string,
  itemType: ItemType,
  get: () => VaultState,
): Promise<void> {
  const { items, trashItems } = get();
  let stored = (items.find((item) => item.id === id) ?? trashItems.find((item) => item.id === id))
    ?.itemType;
  if (stored === undefined) {
    const response = await getItemApi(id);
    if (response.data.success) stored = response.data.data.itemType;
  }
  if (stored !== itemType) {
    throw new Error(
      `This entry is stored as ${stored === undefined ? 'an unknown type' : `a ${stored}`}, so it cannot be saved as a ${itemType}.`,
    );
  }
}

/**
 * This session's own user id, which a created row's id is derived from.
 *
 * Read beside the vault key rather than from a response, because it is the id
 * the SERVER derives from too (the authenticated caller's), and the two must
 * agree or the row is stored under an id its fields were not sealed to.
 */
function requireUserId(): string {
  const userId = useAuthStore.getState().user?.userId;
  if (!userId) {
    throw new Error('Vault is locked. Unlock it before performing vault operations.');
  }
  return userId;
}

/** The unlocked vault key alone, for callers that seal nothing to a generation. */
function getVaultKey(): CryptoKey {
  return requireVaultKey().vaultKey;
}

/**
 * This session's vault-key generation, WITHOUT requiring the key itself.
 *
 * `updateItemMeta` encrypts nothing and deliberately holds no key, yet it posts
 * to the same endpoint as a full update — and that endpoint is guarded as a
 * whole, because a server that decided from which fields the body happened to
 * carry would be deciding a security control from a value the caller chooses.
 * So the metadata path carries the generation too, and this is how it reads one
 * without acquiring a key it has no use for.
 */
function vaultKeyGeneration(): number {
  return useAuthStore.getState().vaultKeyVersion;
}

/**
 * Runs a write that seals ciphertext under the vault key, recording the
 * superseded-key refusal for the application chrome before re-throwing.
 *
 * Every rejection is RE-THROWN, including this one. The caller's own error
 * handling is what tells the user their change did not land; this only raises
 * the app-wide notice that explains WHY nothing from this tab will save until
 * it is reloaded. Swallowing it would report a save that was refused.
 *
 * It never retries and never adopts the generation the server reported — see
 * `noteStaleVaultKey`, where that rule and its reason live.
 */
async function withStaleVaultKeyNotice<T>(write: () => Promise<T>): Promise<T> {
  try {
    return await write();
  } catch (error) {
    noteStaleVaultKey(error);
    throw error;
  }
}

async function decryptItem(
  raw: IVaultItemResponse,
  vaultKey: CryptoKey,
): Promise<DecryptedVaultItem> {
  // Validate the API response shape before attempting decryption.
  // Missing or malformed encryption fields would cause cryptic Web Crypto errors.
  const validation = vaultItemResponseSchema.safeParse(raw);
  if (!validation.success) {
    logger.error('Vault item response validation failed', { id: raw._id });
    throw new Error(`Invalid vault item response for item ${raw._id}`);
  }

  // Each field is opened against the row it was served as, so a format-v2 field
  // the server moved from another row, another slot or another item type is
  // refused here (see `vaultField.ts`). A v1 field opens exactly as before.
  const name = await decryptVaultField(
    { encrypted: raw.encryptedName, iv: raw.nameIv, tag: raw.nameTag },
    { role: 'item.name', rowId: raw._id },
    vaultKey,
  );

  const dataJson = await decryptVaultField(
    { encrypted: raw.encryptedData, iv: raw.dataIv, tag: raw.dataTag },
    { role: 'item.data', rowId: raw._id, itemType: raw.itemType },
    vaultKey,
  );

  let data: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(dataJson);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      const schema = vaultItemDataSchemas[raw.itemType];
      const result = schema.safeParse(parsed);
      data = result.success
        ? (result.data as Record<string, unknown>)
        : { ...(parsed as Record<string, unknown>), _validationError: true };
    } else {
      data = { _raw: parsed };
    }
  } catch {
    data = { _raw: dataJson };
  }

  return {
    id: raw._id,
    itemType: raw.itemType,
    folderId: raw.folderId,
    tags: raw.tags,
    favorite: raw.favorite,
    name,
    data,
    searchHash: raw.searchHash,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    deletedAt: raw.deletedAt,
    _raw: raw,
  };
}

async function decryptFolder(raw: IFolderResponse, vaultKey: CryptoKey): Promise<DecryptedFolder> {
  // Validate the API response shape before attempting decryption.
  const validation = folderResponseSchema.safeParse(raw);
  if (!validation.success) {
    logger.error('Folder response validation failed', { id: raw._id });
    throw new Error(`Invalid folder response for folder ${raw._id}`);
  }

  const name = await decryptVaultField(
    { encrypted: raw.encryptedName, iv: raw.nameIv, tag: raw.nameTag },
    { role: 'folder.name', rowId: raw._id },
    vaultKey,
  );

  return {
    id: raw._id,
    name,
    parentId: raw.parentId,
    icon: raw.icon,
    color: raw.color,
    sortOrder: raw.sortOrder,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    _raw: raw,
  };
}

/**
 * Build an undecodable PLACEHOLDER for a ciphertext row that could not be
 * decrypted at all (wrong/rotated vault key, corrupt blob, or a malformed
 * response shape that made {@link decryptItem} throw).
 *
 * The placeholder carries `_raw` inside `data`, so {@link isUndecodableData}
 * recognizes it and `toPortableItems` reports it in its `skipped` list instead
 * of exporting it. `name` is intentionally empty — it is exactly what could not
 * be recovered. No plaintext is fabricated; the original ciphertext response row
 * is preserved on `_raw`.
 */
function toUndecodableItem(raw: IVaultItemResponse): DecryptedVaultItem {
  return {
    id: raw._id,
    itemType: raw.itemType,
    folderId: raw.folderId,
    tags: raw.tags,
    favorite: raw.favorite,
    name: '',
    data: { _raw: null },
    searchHash: raw.searchHash,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
    deletedAt: raw.deletedAt,
    _raw: raw,
  };
}

/**
 * Decrypt the authoritative ciphertext set returned by `POST /tools/export`
 * (the response is opaque ciphertext — see {@link ExportResponse}) into the same
 * `DecryptedVaultItem` / `DecryptedFolder` shapes the store holds. This is the
 * decryption BRIDGE the portable plaintext export (Phase 10 `ExportDataPage`)
 * consumes: `decryptItem`/`decryptFolder` are module-private, and the plaintext
 * export must decrypt the server's complete set (not whatever the store happens
 * to have loaded) to guarantee completeness.
 *
 * The plaintext export must be COMPLETE or LOUD about what it could not include
 * (PLAN §1.2 principle 8) — the user is often about to delete their account — so
 * one corrupt row never aborts the whole export:
 *
 * - An item whose ciphertext cannot be decrypted becomes an undecodable
 *   PLACEHOLDER via {@link toUndecodableItem}, flowing into `toPortableItems`'s
 *   `skipped` report rather than throwing.
 * - A folder that cannot be decrypted is dropped from the result (items in it
 *   then resolve to an empty folder path, matching the tree builder's tolerance
 *   of a dangling parent); the failure is logged, never surfaced as plaintext.
 *
 * This function performs NO state, storage, or cache writes — the returned
 * plaintext is handed straight back to the caller, which owns its lifetime.
 */
export async function decryptExportResponse(
  response: ExportResponse,
  vaultKey: CryptoKey,
): Promise<{ items: DecryptedVaultItem[]; folders: DecryptedFolder[] }> {
  const itemResults = await mapWithConcurrency(response.items, DECRYPTION_CONCURRENCY, (raw) =>
    decryptItem(raw, vaultKey),
  );
  const items = itemResults.map((result, index) =>
    result.status === 'fulfilled'
      ? result.value
      : // index is in-bounds: mapWithConcurrency preserves length and order.
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        toUndecodableItem(response.items[index]!),
  );

  const folderResults = await mapWithConcurrency(response.folders, DECRYPTION_CONCURRENCY, (raw) =>
    decryptFolder(raw, vaultKey),
  );
  const folders: DecryptedFolder[] = [];
  for (const result of folderResults) {
    if (result.status === 'fulfilled') {
      folders.push(result.value);
    } else {
      logger.warn('Skipping undecryptable folder during portable export', result.reason);
    }
  }

  return { items, folders };
}

// ---------------------------------------------------------------------------
// Store
//
// SECURITY NOTE: Decrypted vault items (items, trashItems, folders) persist
// in Zustand store memory as plaintext JavaScript objects until clearStore()
// is called (on lock/logout). JavaScript does not provide a reliable mechanism
// to zero heap memory — strings and objects remain until garbage collected,
// and V8 may keep copies in optimized JIT code, closures, or prior GC
// generations. This is an inherent limitation of browser-based encryption.
// The clearStore() method replaces the arrays with empty ones, making the
// data unreachable for GC, but cannot guarantee immediate physical zeroing.
// ---------------------------------------------------------------------------

export const useVaultStore = create<VaultState>()((set, get) => ({
  items: [],
  trashItems: [],
  folders: [],
  loading: false,
  itemsLoading: false,
  trashLoading: false,
  itemsLoaded: 0,
  itemsTotal: null,
  decryptionFailures: 0,
  lastDecryptionError: null,
  searchQuery: '',
  selectedFolder: null,
  selectedType: null,
  showFavorites: false,
  showTrash: false,
  // Default sort matches the server default (updatedAt desc) for consistency
  sortBy: 'dateModified',
  sortOrder: 'desc',

  // -----------------------------------------------------------------------
  // Fetch & decrypt all items (paginated — fetches all pages automatically)
  // -----------------------------------------------------------------------
  fetchItems: async (): Promise<void> => {
    // Deduplicate: if a fetch is already in flight, await it instead of firing another
    if (fetchItemsInFlight) return fetchItemsInFlight;

    // Bump generation and reset the in-flight delete tracker for this fetch
    // (see comment on `fetchItemsGeneration` above). Any deleteItem that lands
    // before this fetch settles will record its id in `inFlightDeletedItemIds`
    // so subsequent page-appends filter it out.
    fetchItemsGeneration += 1;
    const myGeneration = fetchItemsGeneration;
    inFlightDeletedItemIds.clear();

    const doFetch = async (): Promise<void> => {
      try {
        // getVaultKey() THROWS when the vault is locked. It sits inside this
        // try so the `finally` below — which resets the loading flags and the
        // in-flight delete tracker — always runs, including when a prologue
        // throws. The dedup guard itself is reset by the `.finally()` chained
        // onto this promise (see the assignment at the end of fetchItems for
        // why it cannot live in this block).
        const vaultKey = getVaultKey();
        // Reset items immediately so the progressive append doesn't blend with
        // a previous fetch's contents. itemsTotal is set from the first page's
        // pagination metadata.
        set({
          itemsLoading: true,
          loading: true,
          items: [],
          itemsLoaded: 0,
          itemsTotal: null,
        });

        try {
          const PAGE_SIZE = 200;
          let currentPage = 1;
          let allRawItems: IVaultItemResponse[] = [];
          // Assigned from the first page's response inside the do-while body,
          // before the loop condition ever reads it — no initializer needed.
          let totalPages: number;
          const allResults: PromiseSettledResult<DecryptedVaultItem>[] = [];

          // Fetch and decrypt page-by-page. After each page is decrypted we
          // append to state so the UI can render rows progressively while
          // later pages are still being fetched.
          do {
            const response = await listItemsApi({ page: currentPage, limit: PAGE_SIZE });
            const result = response.data;
            if (!result.success) throw new Error('Failed to fetch vault items');
            // Drop page results from a superseded fetch so they cannot
            // resurrect items the user has since deleted (or otherwise stomp
            // on the active generation's state).
            if (myGeneration !== fetchItemsGeneration) return;
            allRawItems = allRawItems.concat(result.data);
            totalPages = Math.min(result.pagination.totalPages, MAX_PAGES);
            const totalForBadge = Math.min(result.pagination.total, MAX_PAGES * PAGE_SIZE);

            const pageResults = await mapWithConcurrency(
              result.data,
              DECRYPTION_CONCURRENCY,
              (item) => decryptItem(item, vaultKey),
            );
            if (myGeneration !== fetchItemsGeneration) return;
            allResults.push(...pageResults);

            const decryptedPage = pageResults
              .filter(
                (r): r is PromiseFulfilledResult<DecryptedVaultItem> => r.status === 'fulfilled',
              )
              .map((r) => r.value)
              // Filter out items the user deleted while this page was being
              // fetched/decrypted — without this, a delete that races the
              // streaming append would briefly reintroduce the deleted row.
              .filter((item) => !inFlightDeletedItemIds.has(item.id));

            set((state) => ({
              items: [...state.items, ...decryptedPage],
              itemsLoaded: state.itemsLoaded + decryptedPage.length,
              itemsTotal: totalForBadge,
            }));

            currentPage++;
            if (currentPage > MAX_PAGES) {
              logger.warn(
                `fetchItems: page cap (${String(MAX_PAGES)}) reached; some items may be missing`,
              );
              set({
                lastDecryptionError:
                  'Vault item count exceeds expected limit; some items may be missing',
              });
              break;
            }
          } while (currentPage <= totalPages);

          const { failedCount, errorMessage } = reportDecryptionFailures(allResults, 'vault items');
          set((state) => ({
            decryptionFailures: failedCount,
            lastDecryptionError: errorMessage ?? state.lastDecryptionError,
          }));

          // Cache raw encrypted items for offline access.
          //
          // BOTH outcomes are recorded, not just the failure: the status is a
          // banner the user sees, and a warning that can only ever be turned ON
          // states something false the moment the next write succeeds. One
          // transient failure used to latch it for the rest of the session.
          offlineCache.cacheItems(allRawItems).then(
            () => {
              useUIStore.getState().setOfflineCacheError(null);
            },
            (error: unknown) => {
              logger.warn('Offline cache write failed (items):', error);
              useUIStore.getState().setOfflineCacheError(offlineCacheErrorType(error));
            },
          );
        } catch (error) {
          // If offline, try loading from cache
          if (!navigator.onLine) {
            const cachedItems = await offlineCache.getCachedItems<IVaultItemResponse>();
            const cachedResults = await mapWithConcurrency(
              cachedItems,
              DECRYPTION_CONCURRENCY,
              (item) => decryptItem(item, vaultKey),
            );
            const decrypted = cachedResults
              .filter(
                (r): r is PromiseFulfilledResult<DecryptedVaultItem> => r.status === 'fulfilled',
              )
              .map((r) => r.value);
            // Bail if a lock/logout (or a newer fetch) superseded this run while
            // the cached items were being read/decrypted. Without this guard a
            // slow offline decrypt would write decrypted PLAINTEXT back into a
            // store that clearStore() has already emptied — the captured
            // vaultKey still decrypts because clearCryptoKey() only zeroes an
            // exported copy, not the live CryptoKey handle.
            if (myGeneration !== fetchItemsGeneration) return;
            set({
              items: decrypted,
              itemsLoaded: decrypted.length,
              itemsTotal: decrypted.length,
            });
          } else {
            throw error;
          }
        }
      } finally {
        // Only clear the active fetch's state. If another fetch superseded
        // us mid-stream the new generation owns the dedup machinery; we
        // mustn't trample it.
        if (myGeneration === fetchItemsGeneration) {
          inFlightDeletedItemIds.clear();
          set((state) => ({ itemsLoading: false, loading: state.trashLoading }));
        }
      }
    };

    // The dedup-guard reset is chained onto the promise rather than done in
    // doFetch's `finally`, and that placement is load-bearing: getVaultKey()
    // throws BEFORE doFetch's first `await` (vault locked), so doFetch's body —
    // `finally` included — runs synchronously inside the doFetch() call below.
    // A reset there would therefore execute BEFORE the assignment, and the
    // assignment would immediately re-wedge the guard with the now-rejected
    // promise: every later fetchItems() would replay that rejection without
    // ever hitting the network. A `.finally()` callback always runs in a
    // microtask, so it is guaranteed to see the assigned guard.
    //
    // The ownership gate is unchanged: a run superseded by clearStore() (or by
    // a newer fetch) must not null the newer run's guard, or a duplicate
    // concurrent fetch could slip through.
    fetchItemsInFlight = doFetch().finally(() => {
      if (myGeneration === fetchItemsGeneration) {
        fetchItemsInFlight = null;
      }
    });
    return fetchItemsInFlight;
  },

  fetchTrashItems: async (): Promise<void> => {
    // Deduplicate: if a fetch is already in flight, await it instead of firing another
    if (fetchTrashInFlight) return fetchTrashInFlight;

    fetchTrashGeneration += 1;
    const myGeneration = fetchTrashGeneration;
    inFlightDeletedTrashIds.clear();

    const doFetch = async (): Promise<void> => {
      try {
        // Inside the try so a locked-vault throw still runs the `finally` that
        // resets the loading flags and the delete tracker (see fetchItems).
        const vaultKey = getVaultKey();
        // Reset trashItems immediately so the progressive append below doesn't
        // blend with leftovers from a prior fetch.
        set({ trashLoading: true, loading: true, trashItems: [] });

        const PAGE_SIZE = 200;
        let currentPage = 1;
        // Assigned from the first page's response inside the do-while body,
        // before the loop condition ever reads it — no initializer needed.
        let totalPages: number;
        const allResults: PromiseSettledResult<DecryptedVaultItem>[] = [];

        do {
          const response = await listTrashApi({ page: currentPage, limit: PAGE_SIZE });
          const trashResult = response.data;
          if (!trashResult.success) throw new Error('Failed to fetch trash items');
          if (myGeneration !== fetchTrashGeneration) return;
          totalPages = Math.min(trashResult.pagination.totalPages, MAX_PAGES);

          const pageResults = await mapWithConcurrency(
            trashResult.data,
            DECRYPTION_CONCURRENCY,
            (item) => decryptItem(item, vaultKey),
          );
          if (myGeneration !== fetchTrashGeneration) return;
          allResults.push(...pageResults);

          const decryptedPage = pageResults
            .filter(
              (r): r is PromiseFulfilledResult<DecryptedVaultItem> => r.status === 'fulfilled',
            )
            .map((r) => r.value)
            // Filter out items the user permanently-deleted (or restored) from
            // trash while this page was streaming.
            .filter((item) => !inFlightDeletedTrashIds.has(item.id));

          set((state) => ({
            trashItems: [...state.trashItems, ...decryptedPage],
          }));

          currentPage++;
          if (currentPage > MAX_PAGES) {
            logger.warn(
              `fetchTrashItems: page cap (${String(MAX_PAGES)}) reached; some items may be missing`,
            );
            set({
              lastDecryptionError:
                'Trash item count exceeds expected limit; some items may be missing',
            });
            break;
          }
        } while (currentPage <= totalPages);

        const { errorMessage } = reportDecryptionFailures(allResults, 'trash items');
        set((state) => ({
          lastDecryptionError: errorMessage ?? state.lastDecryptionError,
        }));
      } finally {
        // Ownership-gate the state cleanup (see fetchItems for rationale).
        if (myGeneration === fetchTrashGeneration) {
          inFlightDeletedTrashIds.clear();
          set((state) => ({ trashLoading: false, loading: state.itemsLoading }));
        }
      }
    };

    // Chained, not in doFetch's `finally` — see fetchItems for why the ordering
    // matters when getVaultKey() throws synchronously (vault locked).
    fetchTrashInFlight = doFetch().finally(() => {
      if (myGeneration === fetchTrashGeneration) {
        fetchTrashInFlight = null;
      }
    });
    return fetchTrashInFlight;
  },

  // -----------------------------------------------------------------------
  // Fetch & decrypt all folders
  // -----------------------------------------------------------------------
  fetchFolders: async (): Promise<void> => {
    // Deduplicate: if a fetch is already in flight, await it instead of firing another
    if (fetchFoldersInFlight) return fetchFoldersInFlight;

    // Bump the generation so a lock/logout (or a newer fetch) that lands while
    // this run is in flight supersedes it: stale decrypted folders must not be
    // written back into a cleared store, and the fire-and-forget cache write
    // must not re-persist ciphertext after offlineCache.clear().
    fetchFoldersGeneration += 1;
    const myGeneration = fetchFoldersGeneration;

    const doFetch = async (): Promise<void> => {
      // getVaultKey() throws when the vault is locked. Unlike fetchItems /
      // fetchTrashItems there is no loading flag to reset here, so this method
      // needs no try/finally of its own: the dedup guard is reset by the
      // `.finally()` chained below, which runs whether doFetch resolves or
      // rejects.
      const vaultKey = getVaultKey();

      try {
        const response = await listFoldersApi();
        const foldersResult = response.data;
        if (!foldersResult.success) throw new Error('Failed to fetch folders');
        const rawFolders: IFolderResponse[] = foldersResult.data;

        const folderResults = await mapWithConcurrency(
          rawFolders,
          DECRYPTION_CONCURRENCY,
          (folder) => decryptFolder(folder, vaultKey),
        );
        // Drop results from a superseded fetch before touching state or the
        // cache. This single guard protects both the set(...) below and the
        // fire-and-forget cacheFolders() write (no await separates them).
        if (myGeneration !== fetchFoldersGeneration) return;
        const decrypted = folderResults
          .filter((r): r is PromiseFulfilledResult<DecryptedFolder> => r.status === 'fulfilled')
          .map((r) => r.value);

        const { errorMessage } = reportDecryptionFailures(folderResults, 'folders');
        set((state) => ({
          folders: decrypted,
          lastDecryptionError: errorMessage ?? state.lastDecryptionError,
        }));

        // Cache raw encrypted folders for offline access. Both outcomes are
        // recorded, for the reason spelled out in fetchItems.
        offlineCache.cacheFolders(rawFolders).then(
          () => {
            useUIStore.getState().setOfflineCacheError(null);
          },
          (error: unknown) => {
            logger.warn('Offline cache write failed (folders):', error);
            useUIStore.getState().setOfflineCacheError(offlineCacheErrorType(error));
          },
        );
      } catch (error) {
        // If offline, try loading from cache
        if (!navigator.onLine) {
          const cachedFolders = await offlineCache.getCachedFolders<IFolderResponse>();
          const cachedFolderResults = await mapWithConcurrency(
            cachedFolders,
            DECRYPTION_CONCURRENCY,
            (folder) => decryptFolder(folder, vaultKey),
          );
          const decrypted = cachedFolderResults
            .filter((r): r is PromiseFulfilledResult<DecryptedFolder> => r.status === 'fulfilled')
            .map((r) => r.value);
          // Same guard as the online path: a slow offline decrypt that finishes
          // after lock/logout must not repopulate the cleared store.
          if (myGeneration !== fetchFoldersGeneration) return;
          set({ folders: decrypted });
        } else {
          throw error;
        }
      }
    };

    // Chained, not in doFetch's `finally` — see fetchItems for why the ordering
    // matters when getVaultKey() throws synchronously (vault locked).
    fetchFoldersInFlight = doFetch().finally(() => {
      if (myGeneration === fetchFoldersGeneration) {
        fetchFoldersInFlight = null;
      }
    });
    return fetchFoldersInFlight;
  },

  // -----------------------------------------------------------------------
  // Create an item (encrypt, send, add to local state)
  // -----------------------------------------------------------------------
  createItem: async (
    itemType: ItemType,
    name: string,
    data: Record<string, unknown>,
    options?: { folderId?: string; tags?: string[]; favorite?: boolean },
  ): Promise<void> => {
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
    const myGeneration = mutationGeneration;

    // Pre-flight schema check, BEFORE encryption: a payload the shared schema
    // rejects encrypts perfectly well and only fails on the next READ, by which
    // point it is the only copy that exists.
    assertValidItemData(itemType, data);

    // The id the row WILL have, derived before it exists, so both fields can be
    // sealed to it (format v2). The server stores the row under the id the same
    // nonce derives on its side.
    const row = await newBoundRow(requireUserId());
    const encryptedName = await encryptVaultField(
      name,
      { role: 'item.name', rowId: row.rowId },
      vaultKey,
    );
    const encryptedData = await encryptVaultField(
      JSON.stringify(data),
      { role: 'item.data', rowId: row.rowId, itemType },
      vaultKey,
    );
    // Pre-flight size check: the server enforces these via Mongoose validators,
    // so bail out early with a user-friendly error instead of round-tripping
    // to receive a cryptic 400.
    assertEncryptedSizes(encryptedName, encryptedData);
    const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

    // `vaultKeyVersion` names the generation the six ciphertext fields above
    // were sealed under. The server refuses the row rather than storing one
    // nothing can ever decrypt, and on that refusal the notice tells the user to
    // reload — this store never re-derives a key the server named.
    const response = await withStaleVaultKeyNotice(() =>
      createItemApi({
        itemType,
        encryptedName: encryptedName.encrypted,
        nameIv: encryptedName.iv,
        nameTag: encryptedName.tag,
        encryptedData: encryptedData.encrypted,
        dataIv: encryptedData.iv,
        dataTag: encryptedData.tag,
        searchHash,
        ...(options?.folderId != null ? { folderId: options.folderId } : {}),
        tags: options?.tags ?? [],
        favorite: options?.favorite ?? false,
        idNonce: row.idNonce,
        vaultKeyVersion,
      }),
    );

    const createResult = response.data;
    if (createResult.success) {
      const rawItem = createResult.data;
      assertStoredUnder(row.rowId, rawItem._id);
      const decrypted = await decryptItem(rawItem, vaultKey);
      // Skip the local plaintext write if a lock/logout landed while the
      // request was in flight — clearStore() bumped the generation and emptied
      // the store; writing the decrypted item back would repopulate it.
      if (myGeneration !== mutationGeneration) return;
      set((state) => ({ items: [decrypted, ...state.items] }));
    }
  },

  // -----------------------------------------------------------------------
  // Update an item
  // -----------------------------------------------------------------------
  updateItem: async (
    id: string,
    itemType: ItemType,
    name: string,
    data: Record<string, unknown>,
    options?: {
      folderId?: string | null;
      tags?: string[];
      favorite?: boolean;
    },
  ): Promise<void> => {
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
    const myGeneration = mutationGeneration;

    // Pre-flight schema check, BEFORE encryption: same rationale as createItem, and
    // UNCONDITIONAL now that the type is a parameter. It used to be gated on finding
    // the row in `items`, so a caller the store could not see skipped validation
    // entirely — a gap in a data-integrity control, and `items` was never a sound
    // oracle for it anyway (a trashed item lives in `trashItems`).
    assertValidItemData(itemType, data);

    // Still looked up, but only for password history — which genuinely needs the
    // PREVIOUS plaintext and the previous ciphertext history, neither of which a
    // caller can supply.
    const existingItem = get().items.find((item) => item.id === id);

    // The data is sealed to the item type it will be READ under, so it must be the
    // type the row actually has: data bound to any other type never opens again.
    // Type is immutable after create, so a caller naming another is refused here,
    // before anything is sealed.
    await assertStoredItemType(id, itemType, get);

    const encryptedName = await encryptVaultField(name, { role: 'item.name', rowId: id }, vaultKey);
    const encryptedData = await encryptVaultField(
      JSON.stringify(data),
      { role: 'item.data', rowId: id, itemType },
      vaultKey,
    );
    // Pre-flight size check: same rationale as createItem.
    assertEncryptedSizes(encryptedName, encryptedData);
    const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

    // Build password history for login items when the password changes. The
    // detection + payload construction is shared with the import flow via
    // buildPasswordHistoryPayload so the two paths cannot diverge.
    const passwordHistoryPayload =
      existingItem?.itemType === 'login'
        ? await buildPasswordHistoryPayload({
            existingRawHistory: existingItem._raw.passwordHistory,
            oldPassword: existingItem.data.password,
            newPassword: data.password,
            rowId: id,
            vaultKey,
          })
        : undefined;

    // The generation every ciphertext field here was sealed under — including
    // the password-history entries, which are encrypted under the same key.
    const response = await withStaleVaultKeyNotice(() =>
      updateItemApi(id, {
        encryptedName: encryptedName.encrypted,
        nameIv: encryptedName.iv,
        nameTag: encryptedName.tag,
        encryptedData: encryptedData.encrypted,
        dataIv: encryptedData.iv,
        dataTag: encryptedData.tag,
        searchHash,
        ...(options?.folderId !== undefined ? { folderId: options.folderId } : {}),
        ...(options?.tags !== undefined ? { tags: options.tags } : {}),
        ...(options?.favorite !== undefined ? { favorite: options.favorite } : {}),
        ...(passwordHistoryPayload !== undefined
          ? { passwordHistory: passwordHistoryPayload }
          : {}),
        vaultKeyVersion,
      }),
    );

    const updateResult = response.data;
    if (updateResult.success) {
      const rawItem = updateResult.data;
      const decrypted = await decryptItem(rawItem, vaultKey);
      // Skip the local plaintext write if a lock/logout superseded us (see
      // createItem). Also avoids re-inserting an item into a store the user
      // has locked mid-edit.
      if (myGeneration !== mutationGeneration) return;
      set((state) => ({
        items: state.items.map((item) => (item.id === id ? decrypted : item)),
      }));
    }
  },

  // -----------------------------------------------------------------------
  // Metadata-only update (favorite / folder / tags)
  //
  // Sends ONLY the plaintext metadata fields — never encryptedName,
  // encryptedData or searchHash — so the item's ciphertext is left untouched.
  //
  // This is not merely an optimization. When an item's decrypted payload fails
  // schema validation or JSON parsing, decryptItem() keeps a PLACEHOLDER in
  // `item.data` (`{...parsed, _validationError: true}` or `{_raw: ...}`).
  // Routing a favorite toggle or a folder move through updateItem() would then
  // run encryptData(JSON.stringify(placeholder)) and overwrite the item's real
  // ciphertext with the wrapper — destroying the only copy of the user's data.
  // updateItemMeta() cannot do that: it encrypts nothing.
  //
  // The response is applied WITHOUT decrypting it: the new metadata values are
  // already known locally, and decrypting an undecodable item would just fail
  // again.
  // -----------------------------------------------------------------------
  updateItemMeta: async (id: string, meta: ItemMetaUpdate): Promise<void> => {
    // No vault key is needed — nothing is encrypted here. The mutation
    // generation is still captured so a lock/logout that lands while the
    // request is in flight cannot repopulate the just-cleared store (mirrors
    // createItem/updateItem).
    const myGeneration = mutationGeneration;

    const payload: UpdateVaultItemInput = {
      ...(meta.favorite !== undefined ? { favorite: meta.favorite } : {}),
      ...(meta.folderId !== undefined ? { folderId: meta.folderId } : {}),
      ...(meta.tags !== undefined ? { tags: meta.tags } : {}),
    };
    // Nothing to change: skip the round-trip rather than send an empty update.
    // Counted BEFORE the generation is added, so an update carrying nothing but
    // a generation is still recognised as empty and never sent.
    if (Object.keys(payload).length === 0) return;

    // This path encrypts nothing, yet it still names the generation: it posts to
    // the same endpoint as a full update, and that endpoint is guarded as a
    // whole rather than by inspecting which fields the body happens to carry.
    // Reading the number needs no vault key, which is what lets this path keep
    // its promise never to hold one.
    const response = await withStaleVaultKeyNotice(() =>
      updateItemApi(id, { ...payload, vaultKeyVersion: vaultKeyGeneration() }),
    );
    const metaResult = response.data;
    if (!metaResult.success) return;

    // Skip the local write if a lock/logout superseded us (see createItem).
    if (myGeneration !== mutationGeneration) return;

    const { updatedAt } = metaResult.data;

    set((state) => ({
      items: state.items.map((item) => {
        if (item.id !== id) return item;
        const favorite = meta.favorite ?? item.favorite;
        const tags = meta.tags ?? item.tags;
        const folderId = meta.folderId === undefined ? item.folderId : (meta.folderId ?? undefined);
        return {
          ...item,
          favorite,
          tags,
          folderId,
          updatedAt,
          // Mirror the new metadata into _raw so a later edit-and-save starts
          // from consistent state. Every encrypted field is carried over
          // byte-for-byte — that is the whole point of this path.
          _raw: { ...item._raw, favorite, tags, folderId, updatedAt },
        };
      }),
    }));
  },

  // -----------------------------------------------------------------------
  // Name-only update
  //
  // Sends the `encryptedName`/`nameIv`/`nameTag` trio plus the `searchHash` derived
  // from it, and NOTHING else. `updateVaultItemSchema` permits exactly this: the
  // name trio must travel together, the data trio may be omitted entirely, and
  // `searchHash` is optional — it is an HMAC of the NAME, so it has to be refreshed
  // or the server's duplicate detection would still be keyed to the old one.
  //
  // This exists because renaming was the one safe operation an UNDECODABLE item
  // could not be offered. `updateItem` re-encrypts `JSON.stringify(item.data)`
  // wholesale, and for such an item `data` is only the placeholder wrapper, so a
  // rename through it would overwrite the item's real — and only — ciphertext.
  // `updateItemMeta` cannot help either: it sends plaintext metadata only and has
  // no way to change a name, which is encrypted.
  //
  // Like `updateItemMeta`, the response is applied WITHOUT decrypting it: the new
  // plaintext name is already known here, and decrypting an undecodable item would
  // just fail again and throw away a write that has already succeeded.
  // -----------------------------------------------------------------------
  renameItem: async (id: string, name: string): Promise<void> => {
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await encryptVaultField(name, { role: 'item.name', rowId: id }, vaultKey);
    assertEncryptedNameSize(encryptedName);
    const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

    // Name-only, but still ciphertext: a rename sealed under a superseded key
    // strands the one field this path exists to repair.
    const response = await withStaleVaultKeyNotice(() =>
      updateItemApi(id, {
        encryptedName: encryptedName.encrypted,
        nameIv: encryptedName.iv,
        nameTag: encryptedName.tag,
        searchHash,
        vaultKeyVersion,
      }),
    );

    const renameResult = response.data;
    if (!renameResult.success) return;

    // Skip the local write if a lock/logout superseded us (see createItem).
    if (myGeneration !== mutationGeneration) return;

    const { updatedAt } = renameResult.data;

    set((state) => ({
      items: state.items.map((item) => {
        if (item.id !== id) return item;
        return {
          ...item,
          name,
          searchHash,
          updatedAt,
          // Only the NAME ciphertext is replaced. `encryptedData`/`dataIv`/`dataTag`
          // are carried over byte-for-byte — that is the whole point of this path.
          _raw: {
            ...item._raw,
            encryptedName: encryptedName.encrypted,
            nameIv: encryptedName.iv,
            nameTag: encryptedName.tag,
            searchHash,
            updatedAt,
          },
        };
      }),
    }));
  },

  // -----------------------------------------------------------------------
  // Soft-delete an item
  // -----------------------------------------------------------------------
  deleteItem: async (id: string): Promise<void> => {
    // Capture the item before removing it from items so we can add it to trash
    const deletedItem = get().items.find((item) => item.id === id);

    await deleteItemApi(id);

    // Record the id so any fetchItems pages still streaming for the active
    // generation filter this item out before appending. Without this an
    // in-flight page response can briefly resurrect the deleted row in the
    // UI until the next manual reload. See the `fetchItemsGeneration` doc.
    inFlightDeletedItemIds.add(id);

    set((state) => {
      const newItems = state.items.filter((item) => item.id !== id);

      // Add the deleted item to trashItems only if trash has been fetched
      // (non-empty trashItems). If trash was never loaded, skip to avoid
      // partial state — the next fetchTrashItems will include it.
      if (deletedItem && state.trashItems.length > 0) {
        const trashedItem: DecryptedVaultItem = {
          ...deletedItem,
          deletedAt: new Date().toISOString(),
        };
        return { items: newItems, trashItems: [...state.trashItems, trashedItem] };
      }

      return { items: newItems };
    });
  },

  // -----------------------------------------------------------------------
  // Permanently delete an item from trash
  // -----------------------------------------------------------------------
  permanentDeleteItem: async (id: string): Promise<void> => {
    await permanentDeleteApi(id);
    inFlightDeletedTrashIds.add(id);
    set((state) => ({
      trashItems: state.trashItems.filter((item) => item.id !== id),
    }));
  },

  // -----------------------------------------------------------------------
  // Empty all trash
  // -----------------------------------------------------------------------
  emptyTrash: async (): Promise<void> => {
    // Snapshot trash ids before the API call so any in-flight fetchTrashItems
    // page filters them out before appending.
    const trashedIds = get().trashItems.map((item) => item.id);
    await emptyTrashApi();
    for (const id of trashedIds) inFlightDeletedTrashIds.add(id);
    set({ trashItems: [] });
  },

  // -----------------------------------------------------------------------
  // Restore a trashed item
  // -----------------------------------------------------------------------
  restoreItem: async (id: string): Promise<void> => {
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;
    const response = await restoreItemApi(id);
    const restoreResult = response.data;
    if (restoreResult.success) {
      // The id is no longer trash on the server, so any in-flight trash page
      // must not reintroduce it. It IS now an active item, so we don't add it
      // to the items in-flight set.
      inFlightDeletedTrashIds.add(id);
      const rawItem = restoreResult.data;
      const decrypted = await decryptItem(rawItem, vaultKey);
      // Skip the local plaintext write if a lock/logout superseded us (see
      // createItem).
      if (myGeneration !== mutationGeneration) return;
      set((state) => ({
        // Remove from trash items
        trashItems: state.trashItems.filter((item) => item.id !== id),
        // Add to regular items
        items: [...state.items, decrypted],
      }));
    }
  },

  // -----------------------------------------------------------------------
  // Client-side filtering
  // -----------------------------------------------------------------------
  filteredItemCount: null,
  setFilteredItemCount: (count: number | null): void => {
    set({ filteredItemCount: count });
  },
  setSearchQuery: (query: string): void => {
    set({ searchQuery: query });
  },

  setSelectedFolder: (folderId: string | null): void => {
    set({ selectedFolder: folderId });
  },

  setSelectedType: (type: ItemType | null): void => {
    set({ selectedType: type });
  },

  setShowFavorites: (value: boolean): void => {
    set({ showFavorites: value });
  },

  setShowTrash: (value: boolean): void => {
    set({ showTrash: value });
  },

  toggleFavorites: (): void => {
    set((state) => ({ showFavorites: !state.showFavorites, showTrash: false }));
  },

  toggleTrash: (): void => {
    set((state) => ({ showTrash: !state.showTrash, showFavorites: false }));
  },

  setSortBy: (sortBy: SortBy): void => {
    set({ sortBy });
  },

  setSortOrder: (sortOrder: SortOrder): void => {
    set({ sortOrder });
  },

  // -----------------------------------------------------------------------
  // Folder operations
  // -----------------------------------------------------------------------
  createFolder: async (
    name: string,
    options?: { parentId?: string; icon?: string; color?: string },
  ): Promise<void> => {
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
    const myGeneration = mutationGeneration;

    // Sealed to the id the folder WILL have; see `createItem`.
    const row = await newBoundRow(requireUserId());
    const encryptedName = await encryptVaultField(
      name,
      { role: 'folder.name', rowId: row.rowId },
      vaultKey,
    );

    // Assign a sortOrder higher than any existing folder so new folders appear at the end
    const existingFolders = get().folders;
    const maxSortOrder = existingFolders.reduce((max, f) => Math.max(max, f.sortOrder), -1);

    const response = await withStaleVaultKeyNotice(() =>
      createFolderApi({
        encryptedName: encryptedName.encrypted,
        nameIv: encryptedName.iv,
        nameTag: encryptedName.tag,
        sortOrder: maxSortOrder + 1,
        ...(options?.parentId != null ? { parentId: options.parentId } : {}),
        ...(options?.icon != null ? { icon: options.icon } : {}),
        ...(options?.color != null ? { color: options.color } : {}),
        idNonce: row.idNonce,
        vaultKeyVersion,
      }),
    );

    const createFolderResult = response.data;
    if (createFolderResult.success) {
      const rawFolder = createFolderResult.data;
      assertStoredUnder(row.rowId, rawFolder._id);
      const decrypted = await decryptFolder(rawFolder, vaultKey);
      // Skip the local plaintext write if a lock/logout superseded us (see
      // createItem).
      if (myGeneration !== mutationGeneration) return;
      set((state) => ({ folders: [...state.folders, decrypted] }));
    }
  },

  updateFolder: async (
    id: string,
    name: string,
    options?: { color?: string; sortOrder?: number },
  ): Promise<void> => {
    const { vaultKey, vaultKeyVersion } = requireVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await encryptVaultField(
      name,
      { role: 'folder.name', rowId: id },
      vaultKey,
    );

    const response = await withStaleVaultKeyNotice(() =>
      updateFolderApi(id, {
        encryptedName: encryptedName.encrypted,
        nameIv: encryptedName.iv,
        nameTag: encryptedName.tag,
        ...(options?.color !== undefined ? { color: options.color } : {}),
        ...(options?.sortOrder !== undefined ? { sortOrder: options.sortOrder } : {}),
        vaultKeyVersion,
      }),
    );

    const updateFolderResult = response.data;
    if (updateFolderResult.success) {
      const rawFolder = updateFolderResult.data;
      const decrypted = await decryptFolder(rawFolder, vaultKey);
      // Skip the local plaintext write if a lock/logout superseded us (see
      // createItem).
      if (myGeneration !== mutationGeneration) return;
      set((state) => ({
        folders: state.folders.map((f) => (f.id === id ? decrypted : f)),
      }));
    }
  },

  deleteFolder: async (id: string, action?: 'move' | 'delete'): Promise<void> => {
    // Captured BEFORE the folder leaves local state: `move` re-parents this
    // folder's members to ITS OWN PARENT rather than to the root, so reconciling
    // the local rows needs to know what that parent was.
    const deleted = get().folders.find((f) => f.id === id);
    await deleteFolderApi(id, action);
    set((state) => {
      const base = {
        folders: state.folders.filter((f) => f.id !== id),
        selectedFolder: state.selectedFolder === id ? null : state.selectedFolder,
      };

      if (action === 'delete') {
        // Remove items that belonged to this folder from the active list
        // (server has soft-deleted them by setting deletedAt)
        return {
          ...base,
          items: state.items.filter((item) => item.folderId !== id),
        };
      }

      // Default/move: clear folderId so items appear in root
      return {
        ...base,
        items: state.items.map((item) =>
          item.folderId === id ? { ...item, folderId: undefined } : item,
        ),
      };
    });

    // A folder holds vault items AND documents: `folderController.deleteFolder`
    // builds ONE member filter and ONE update and applies both to `VaultItem` and
    // to `Document`. So the document store has to be told, or its rows keep
    // pointing at a folder that no longer exists and its counts stay wrong until
    // the next full reload.
    //
    // Reached through `getState()` inside this body and never through a
    // module-scope destructure — the rule `documentsStore.getVaultKey` records.
    // These two stores already reference each other (`documentsStore` imports
    // `mapWithConcurrency` from here), and reading late is what keeps that safe.
    useDocumentsStore
      .getState()
      .applyFolderDeleted(id, action === 'delete' ? 'delete' : 'move', deleted?.parentId);

    // If items were soft-deleted, refresh trash to show them.
    //
    // The rejection is swallowed deliberately, and it is not decoration: this is
    // a background refresh fired from a handler that has already reported the
    // deletion, so a locked vault or a dropped connection here produced an
    // UNHANDLED rejection that no caller could ever have caught. The next
    // `fetchTrashItems` corrects the list.
    if (action === 'delete') {
      const { fetchTrashItems } = get();
      void fetchTrashItems().catch(() => {
        /* see above */
      });
    }
  },

  // -----------------------------------------------------------------------
  // Clear all store data (called on lock/logout to remove decrypted data)
  // -----------------------------------------------------------------------
  clearStore: (): void => {
    // Reset fetch dedup guards so stale in-flight promises from the previous
    // session don't suppress fetches after a fresh login/unlock.
    fetchItemsInFlight = null;
    fetchTrashInFlight = null;
    fetchFoldersInFlight = null;
    // Reset race-tracking generation counters and in-flight delete sets so a
    // fresh fetch on a new session is not influenced by leftover state.
    fetchItemsGeneration += 1;
    fetchTrashGeneration += 1;
    fetchFoldersGeneration += 1;
    // Bump the mutation generation so any in-flight create/update/restore whose
    // response resolves after this clear cannot write decrypted plaintext back
    // into the just-emptied store.
    mutationGeneration += 1;
    // Invalidate any in-flight Vault Health hydrate/persist so a scan resolving
    // after this clear cannot write results back into the just-emptied session.
    healthGeneration += 1;
    inFlightDeletedItemIds.clear();
    inFlightDeletedTrashIds.clear();
    // Drop cached password-strength scores (keyed by item id + version). They hold
    // no secret, but a fresh session must not reuse the previous vault's scores.
    clearScoreCache();

    set({
      items: [],
      trashItems: [],
      folders: [],
      loading: false,
      itemsLoading: false,
      trashLoading: false,
      itemsLoaded: 0,
      itemsTotal: null,
      decryptionFailures: 0,
      lastDecryptionError: null,
      filteredItemCount: null,
      searchQuery: '',
      selectedFolder: null,
      selectedType: null,
      showFavorites: false,
      showTrash: false,
      sortBy: 'dateModified' as SortBy,
      sortOrder: 'desc' as SortOrder,
    });
  },
}));
