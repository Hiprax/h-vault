/**
 * Encrypted document store API service.
 *
 * One thin wrapper per route under `/api/v1/documents`, and nothing else: no
 * retry policy, no schema validation and no crypto. Those belong to
 * `stores/documentsStore.ts`, which is the module that knows what a failure
 * means. What lives here is the request each endpoint expects — the verb, the
 * path, the payload shape and, for the two binary routes, the headers and the
 * response type — because that IS the contract, and getting one of them wrong is
 * a shippable bug rather than a stylistic one.
 *
 * Two things the server does that shape every caller:
 *
 *  - Every route sits behind `requireStorage`, which answers **503** when the
 *    operator has configured no object storage. In production the error
 *    middleware redacts a 5xx body to its status text, so there is nothing here
 *    to parse: the client learns whether the feature exists from `GET /config`'s
 *    `documents` block (`getDocumentsConfig()`) and hides the section, and the
 *    503 exists for a direct API caller.
 *  - `POST /uploads/:id/complete` answers **409 with a body** when the vault key
 *    was rotated mid-upload — `{ success: false, message, data: { vaultKeyVersion } }`.
 *    That is deliberate and is the one refusal in this surface carrying a number
 *    the caller must read, which is why {@link staleVaultKeyVersion} exists.
 *
 * Segment indices are 0-based (the index is the counter inside the AEAD nonce)
 * while part numbers are 1-based (S3 part numbers are), so part `n` carries
 * segment `n - 1`. The two are never the same number and the names never blur.
 */

import { isAxiosError, type AxiosProgressEvent, type AxiosResponse } from 'axios';
import { MAX_DOCUMENTS_PER_ROTATION, PAGINATION_DEFAULTS } from '@hvault/shared';
import type {
  ApiResponse,
  CompleteDocumentUploadInput,
  DocumentResponse,
  DocumentUploadResponse,
  DocumentUsageResponse,
  InitDocumentUploadInput,
  InitDocumentUploadResponse,
  PaginatedResponse,
  UpdateDocumentInput,
} from '@hvault/shared';
import { api } from './client.js';

// ---------------------------------------------------------------------------
// How a document list is paged
// ---------------------------------------------------------------------------

/**
 * One page of documents, for any caller that walks the whole list.
 *
 * The server's `paginationSchema` caps `limit` at `PAGINATION_DEFAULTS.MAX_LIMIT`,
 * so asking for more is refused rather than clamped.
 *
 * It lives beside the two list wrappers rather than inside one caller because two
 * callers now walk the same lists for different reasons — the store, which opens
 * every row it reads, and the vault-key rotation, which reads the same rows and
 * decrypts nothing at all — and a page size that drifted between them would be a
 * paging bug in whichever one was not being looked at.
 */
export const DOCUMENT_PAGE_SIZE = PAGINATION_DEFAULTS.MAX_LIMIT;

/**
 * Hard ceiling on the pages one walk may read, derived from the two numbers that
 * bound it rather than written as a literal: a loop that ran past this is
 * following an inflated `totalPages` rather than reading real rows.
 *
 * Derived from `MAX_DOCUMENTS_PER_ROTATION` and NOT from `MAX_DOCUMENTS_PER_USER`,
 * because the question this ceiling asks is "how many rows can this account
 * ACTUALLY hold", not "when does the server refuse a new one". Those two numbers
 * differ: the count is checked only when a transfer is opened, so an account can
 * finish `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1` rows past the advertised
 * limit. Derived from the advertised limit, this ceiling stops a page short on
 * exactly those accounts — and it does so SILENTLY, which costs two different
 * things at once: the rotation walk drops rows it is required never to drop and
 * the account can never rotate its vault key again, and the list view simply never
 * shows those documents, so their owner cannot open, download, trash or
 * permanently delete them while their bytes keep counting against the quota.
 */
export const MAX_DOCUMENT_PAGES = Math.ceil(MAX_DOCUMENTS_PER_ROTATION / DOCUMENT_PAGE_SIZE);

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

/**
 * `GET /documents`. There is no `name` sort and no `trash` flag: the name lives
 * inside the encrypted blob so the server cannot order by it, and trashed
 * documents have their own route, exactly as trashed vault items do.
 */
export interface ListDocumentsParams {
  page?: number;
  limit?: number;
  folderId?: string;
  favorite?: boolean;
  sortBy?: 'createdAt' | 'updatedAt' | 'favorite';
  sortOrder?: 'asc' | 'desc';
}

/** `GET /documents/trash`. */
export interface ListDocumentTrashParams {
  page?: number;
  limit?: number;
  sortBy?: 'deletedAt' | 'createdAt' | 'updatedAt';
  sortOrder?: 'asc' | 'desc';
}

/** What one part upload needs beyond its bytes. */
export interface UploadPartOptions {
  /** SHA-256 of the sealed segment, 64 lowercase hexadecimal characters. */
  digest: string;
  /** Cancels the transfer — a lock, a logout, or the user pressing Cancel. */
  signal?: AbortSignal;
  onUploadProgress?: (event: AxiosProgressEvent) => void;
}

/** What one part upload reports back. */
export interface UploadPartResult {
  partNumber: number;
  bytes: number;
  receivedBytes: number;
}

/** What emptying the document trash reports back. */
export interface EmptyDocumentTrashResult {
  deletedCount: number;
  failedCount: number;
}

/**
 * The header carrying the client's SHA-256 of the sealed segment it is sending.
 *
 * Lower-case, matching `PART_DIGEST_HEADER` in the server's document controller:
 * Node lower-cases every incoming header name, so this is the form the handler
 * reads.
 */
export const PART_DIGEST_HEADER = 'x-hv-part-sha256';

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

export function listDocumentsApi(
  params?: ListDocumentsParams,
): Promise<AxiosResponse<PaginatedResponse<DocumentResponse>>> {
  return api.get('/documents', { params });
}

export function listDocumentTrashApi(
  params?: ListDocumentTrashParams,
): Promise<AxiosResponse<PaginatedResponse<DocumentResponse>>> {
  return api.get('/documents/trash', { params });
}

export function getDocumentUsageApi(): Promise<AxiosResponse<ApiResponse<DocumentUsageResponse>>> {
  return api.get('/documents/usage');
}

export function emptyDocumentTrashApi(): Promise<
  AxiosResponse<ApiResponse<EmptyDocumentTrashResult>>
> {
  return api.delete('/documents/trash/empty');
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

export function listDocumentUploadsApi(): Promise<
  AxiosResponse<ApiResponse<DocumentUploadResponse[]>>
> {
  return api.get('/documents/uploads');
}

export function initDocumentUploadApi(
  data: InitDocumentUploadInput,
): Promise<AxiosResponse<ApiResponse<InitDocumentUploadResponse>>> {
  return api.post('/documents/uploads', data);
}

export function getDocumentUploadApi(
  id: string,
): Promise<AxiosResponse<ApiResponse<DocumentUploadResponse>>> {
  return api.get(`/documents/uploads/${id}`);
}

/**
 * `PUT /documents/uploads/:id/parts/:partNumber` — one sealed segment.
 *
 * The body is the segment's own `ArrayBuffer` rather than a view over a larger
 * one: `encryptSegment` returns a `Uint8Array` over a buffer it has just
 * allocated, so the view spans the buffer exactly and `.buffer` is the segment
 * and nothing else.
 *
 * `Content-Type` is overridden per call because the shared instance defaults to
 * `application/json`, and the route's `express.raw({ type: 'application/octet-stream' })`
 * parser SKIPS a body whose type does not match rather than refusing it — leaving
 * `req.body` undefined and the handler answering 400 for a part that was sent
 * perfectly well. `Content-Length` is set by the browser from the buffer's length,
 * and the server answers **411** without it, so it is right by construction rather
 * than by a header written here.
 */
export function uploadDocumentPartApi(
  id: string,
  partNumber: number,
  body: ArrayBuffer,
  options: UploadPartOptions,
): Promise<AxiosResponse<ApiResponse<UploadPartResult>>> {
  return api.put(`/documents/uploads/${id}/parts/${String(partNumber)}`, body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      [PART_DIGEST_HEADER]: options.digest,
    },
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.onUploadProgress ? { onUploadProgress: options.onUploadProgress } : {}),
  });
}

export function completeDocumentUploadApi(
  id: string,
  data: CompleteDocumentUploadInput,
): Promise<AxiosResponse<ApiResponse<DocumentResponse>>> {
  return api.post(`/documents/uploads/${id}/complete`, data);
}

/**
 * `DELETE /documents/uploads/:id` — cancel a transfer.
 *
 * `timeoutMs` mirrors `logoutApi`'s per-call bound and exists for the same
 * reason: a lock or a logout fires this best-effort for every live upload and
 * must not be delayed by a stalled connection. A per-call timeout is used
 * deliberately instead of a global Axios timeout, which would abort the
 * legitimately-long part and rotation requests.
 */
export function abortDocumentUploadApi(
  id: string,
  timeoutMs?: number,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(
    `/documents/uploads/${id}`,
    timeoutMs !== undefined ? { timeout: timeoutMs } : {},
  );
}

// ---------------------------------------------------------------------------
// One document
// ---------------------------------------------------------------------------

export function getDocumentApi(id: string): Promise<AxiosResponse<ApiResponse<DocumentResponse>>> {
  return api.get(`/documents/${id}`);
}

/**
 * `GET /documents/:id/segments/:index` — one sealed segment, as bytes.
 *
 * `responseType: 'arraybuffer'` is mandatory rather than a preference: the
 * default `'json'` hands the body to `JSON.parse`, and ciphertext is not text.
 * The byte window is computed server-side from the row, so there is no `Range`
 * header to send.
 */
export function getDocumentSegmentApi(
  id: string,
  index: number,
  signal?: AbortSignal,
): Promise<AxiosResponse<ArrayBuffer>> {
  return api.get(`/documents/${id}/segments/${String(index)}`, {
    responseType: 'arraybuffer',
    ...(signal ? { signal } : {}),
  });
}

export function updateDocumentApi(
  id: string,
  data: UpdateDocumentInput,
): Promise<AxiosResponse<ApiResponse<DocumentResponse>>> {
  return api.put(`/documents/${id}`, data);
}

export function deleteDocumentApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/documents/${id}`);
}

export function restoreDocumentApi(
  id: string,
): Promise<AxiosResponse<ApiResponse<DocumentResponse>>> {
  return api.post(`/documents/${id}/restore`);
}

export function purgeDocumentApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/documents/${id}/permanent`);
}

// ---------------------------------------------------------------------------
// The one refusal that carries a number
// ---------------------------------------------------------------------------

/**
 * The vault key version a stale-completion 409 reports, or `null` when the
 * rejection is anything else.
 *
 * Completion sends the wrapped document key a second time precisely so this
 * refusal costs one request rather than the whole file: on a 409 the caller
 * rewraps the DEK it still holds in memory under the new vault key and retries
 * the completion alone. That recovery is only possible if the NUMBER survives
 * the trip, so this reads it defensively — a 409 whose body does not carry a
 * non-negative integer is treated as an ordinary conflict, never as version
 * zero.
 */
export function staleVaultKeyVersion(error: unknown): number | null {
  if (!isAxiosError(error) || error.response?.status !== 409) return null;
  const data: unknown = error.response.data;
  if (typeof data !== 'object' || data === null || !('data' in data)) return null;
  const payload: unknown = data.data;
  if (typeof payload !== 'object' || payload === null || !('vaultKeyVersion' in payload)) {
    return null;
  }
  const version: unknown = payload.vaultKeyVersion;
  return typeof version === 'number' && Number.isInteger(version) && version >= 0 ? version : null;
}
