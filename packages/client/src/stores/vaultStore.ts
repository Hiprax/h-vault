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
import { offlineCache } from '../services/offlineCache.js';
import { logger } from '../lib/logger.js';
import { useAuthStore } from './authStore.js';
import { useUIStore } from './uiStore.js';
import {
  listItemsApi,
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
import type { IVaultItemResponse, IFolderResponse, UpdateVaultItemInput } from '@hvault/shared';
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
  updateItem: (
    id: string,
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
 * Exported for unit testing. Order is preserved.
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
 * Pre-flight size check: the server enforces max-length on encrypted fields
 * via Mongoose validators, so catching oversized payloads on the client
 * avoids an unhelpful 400 after the user has already filled out the form.
 */
function assertEncryptedSizes(
  encryptedName: { encrypted: string },
  encryptedData: { encrypted: string },
): void {
  if (encryptedName.encrypted.length > MAX_ENCRYPTED_NAME_LENGTH) {
    throw new EncryptedFieldTooLargeError(
      'name',
      encryptedName.encrypted.length,
      MAX_ENCRYPTED_NAME_LENGTH,
    );
  }
  if (encryptedData.encrypted.length > MAX_ENCRYPTED_DATA_LENGTH) {
    throw new EncryptedFieldTooLargeError(
      'data',
      encryptedData.encrypted.length,
      MAX_ENCRYPTED_DATA_LENGTH,
    );
  }
}

function getVaultKey(): CryptoKey {
  const { vaultKey } = useAuthStore.getState();
  if (!vaultKey) {
    throw new Error('Vault is locked. Unlock it before performing vault operations.');
  }
  // CryptoKey is an opaque handle — no need to copy (unlike ArrayBuffer).
  return vaultKey;
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

  const name = await cryptoService.decryptData(
    raw.encryptedName,
    raw.nameIv,
    raw.nameTag,
    vaultKey,
  );

  const dataJson = await cryptoService.decryptData(
    raw.encryptedData,
    raw.dataIv,
    raw.dataTag,
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

  const name = await cryptoService.decryptData(
    raw.encryptedName,
    raw.nameIv,
    raw.nameTag,
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

          // Cache raw encrypted items for offline access
          offlineCache.cacheItems(allRawItems).catch((error: unknown) => {
            logger.warn('Offline cache write failed (items):', error);
            useUIStore.getState().setOfflineCacheAvailable(false);
          });
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

        // Cache raw encrypted folders for offline access
        offlineCache.cacheFolders(rawFolders).catch((error: unknown) => {
          logger.warn('Offline cache write failed (folders):', error);
          useUIStore.getState().setOfflineCacheAvailable(false);
        });
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
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await cryptoService.encryptData(name, vaultKey);
    const encryptedData = await cryptoService.encryptData(JSON.stringify(data), vaultKey);
    // Pre-flight size check: the server enforces these via Mongoose validators,
    // so bail out early with a user-friendly error instead of round-tripping
    // to receive a cryptic 400.
    assertEncryptedSizes(encryptedName, encryptedData);
    const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

    const response = await createItemApi({
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
    });

    const createResult = response.data;
    if (createResult.success) {
      const rawItem = createResult.data;
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
    name: string,
    data: Record<string, unknown>,
    options?: {
      folderId?: string | null;
      tags?: string[];
      favorite?: boolean;
    },
  ): Promise<void> => {
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await cryptoService.encryptData(name, vaultKey);
    const encryptedData = await cryptoService.encryptData(JSON.stringify(data), vaultKey);
    // Pre-flight size check: same rationale as createItem.
    assertEncryptedSizes(encryptedName, encryptedData);
    const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

    // Build password history for login items when the password changes. The
    // detection + payload construction is shared with the import flow via
    // buildPasswordHistoryPayload so the two paths cannot diverge.
    const existingItem = get().items.find((item) => item.id === id);
    const passwordHistoryPayload =
      existingItem?.itemType === 'login'
        ? await buildPasswordHistoryPayload({
            existingRawHistory: existingItem._raw.passwordHistory,
            oldPassword: existingItem.data.password,
            newPassword: data.password,
            vaultKey,
          })
        : undefined;

    const response = await updateItemApi(id, {
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
      ...(passwordHistoryPayload !== undefined ? { passwordHistory: passwordHistoryPayload } : {}),
    });

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
    if (Object.keys(payload).length === 0) return;

    const response = await updateItemApi(id, payload);
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
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await cryptoService.encryptData(name, vaultKey);

    // Assign a sortOrder higher than any existing folder so new folders appear at the end
    const existingFolders = get().folders;
    const maxSortOrder = existingFolders.reduce((max, f) => Math.max(max, f.sortOrder), -1);

    const response = await createFolderApi({
      encryptedName: encryptedName.encrypted,
      nameIv: encryptedName.iv,
      nameTag: encryptedName.tag,
      sortOrder: maxSortOrder + 1,
      ...(options?.parentId != null ? { parentId: options.parentId } : {}),
      ...(options?.icon != null ? { icon: options.icon } : {}),
      ...(options?.color != null ? { color: options.color } : {}),
    });

    const createFolderResult = response.data;
    if (createFolderResult.success) {
      const rawFolder = createFolderResult.data;
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
    const vaultKey = getVaultKey();
    const myGeneration = mutationGeneration;

    const encryptedName = await cryptoService.encryptData(name, vaultKey);

    const response = await updateFolderApi(id, {
      encryptedName: encryptedName.encrypted,
      nameIv: encryptedName.iv,
      nameTag: encryptedName.tag,
      ...(options?.color !== undefined ? { color: options.color } : {}),
      ...(options?.sortOrder !== undefined ? { sortOrder: options.sortOrder } : {}),
    });

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

    // If items were soft-deleted, refresh trash to show them
    if (action === 'delete') {
      const { fetchTrashItems } = get();
      void fetchTrashItems();
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
    inFlightDeletedItemIds.clear();
    inFlightDeletedTrashIds.clear();

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
