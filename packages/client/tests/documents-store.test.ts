/**
 * Tests for the encrypted document store (`stores/documentsStore.ts`).
 *
 * ## How this suite is wired, and why
 *
 * Everything below the store is REAL: `documentCryptoService` (Web Crypto, never
 * mocked — it is the thing whose framing these tests depend on), `cryptoService`,
 * `documentsApi`, and `services/api/client` with its request and response
 * interceptors intact. Only the transport is replaced, by a stub Axios adapter
 * installed on both the shared instance and the global one (`ensureCsrfToken`
 * reaches for the bare `axios`, not for `api`).
 *
 * That costs a bigger harness and buys the thing that matters: the store's error
 * classification consumes real `AxiosError`s with real `response.status` values,
 * and the two behaviours the plan names — a part replayed after a token refresh,
 * and a CSRF token fetched between parts — are produced by the interceptors that
 * actually ship rather than by a mock imitating them.
 *
 * ## Reading a DEK's lifetime without a seam
 *
 * No test here reaches into the store for key material, and none could: the DEK
 * lives in a module-level map deliberately. Instead `globalThis.crypto
 * .getRandomValues` is wrapped in a pass-through that records the 32-byte buffers
 * it returns — entropy is a boundary a test may touch, and `getRandomValues`
 * returns the very array it was handed, so a later `fill(0)` is visible through
 * the recorded reference. An upload draws exactly two 32-byte buffers, the DEK and
 * the stream salt, so "exactly one of them was zeroed" pins both the positive (the
 * key is gone) and the negative (the salt, which is not a secret and is stored in
 * plaintext on the row, was left alone).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, {
  AxiosError,
  type AxiosAdapter,
  type AxiosProgressEvent,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_NAME_LENGTH,
  documentChunkCountFor,
} from '@hvault/shared';
import type { DocumentMeta, DocumentResponse } from '@hvault/shared';
import { installTestClock } from './clock.js';

// ---------------------------------------------------------------------------
// Mocks: only the two modules that would otherwise reach real browser storage.
// ---------------------------------------------------------------------------

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

vi.mock('../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import { cryptoService } from '../src/services/crypto/cryptoService.js';
import {
  decryptMeta,
  decryptSegment,
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  encryptMeta,
  generateDek,
  unwrapDek,
  wrapDek,
  zeroDek,
  type DocumentBytes,
} from '../src/services/crypto/documentCryptoService.js';
import { api, clearCsrfToken } from '../src/services/api/client.js';
import { useAuthStore } from '../src/stores/authStore.js';
import { UploadCancelledError, useDocumentsStore } from '../src/stores/documentsStore.js';

// ---------------------------------------------------------------------------
// The stub server
// ---------------------------------------------------------------------------

interface RecordedRequest {
  method: string;
  url: string;
  data: unknown;
  headers: Record<string, unknown>;
}

/** Every request the adapter saw, in order, including the CSRF and refresh ones. */
let requests: RecordedRequest[] = [];

/** Rows `GET /documents` answers with, and the pages they are split into. */
let listPages: DocumentResponse[][] = [];
let trashRows: DocumentResponse[] = [];

/** The id `POST /documents/uploads` mints, and the framing it advertises. */
let uploadId = '';
let advertisedChunkPlaintextBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES;
let advertisedVaultKeyVersion = 0;

/** Part numbers the staging ledger already holds, for a resume. */
let ledgerParts: number[] = [];

/** How each part attempt is answered: `null` succeeds, a number fails with that status. */
let partOutcomes: (number | null)[] = [];
let partAttempt = 0;

/** How each completion attempt is answered. */
let completeOutcomes: ('ok' | { status: number; data?: unknown })[] = ['ok'];
let completeAttempt = 0;

/** The row a successful completion commits, and the bodies it was sent. */
let committedRow: DocumentResponse | null = null;
let completeBodies: Record<string, unknown>[] = [];

/** The profile `GET /user/profile` answers with, for the rewrap path. */
let profileBody: Record<string, unknown> | null = null;

/** Bumped on each `/auth/refresh`; the adapter 401s a part until one has happened. */
let refreshCount = 0;
let partsNeedFreshToken = false;

/** When true, the best-effort cancel endpoint refuses. */
let abortFails = false;

/** When true, the list and usage reads answer a `success: false` envelope on a 200. */
let listEnvelopeFails = false;

/** When true, the TRASH listing alone answers a `success: false` envelope. */
let trashEnvelopeFails = false;

/**
 * Held open to keep a listing IN FLIGHT while something else happens.
 *
 * The only way to reproduce the window a delete can land in: `fetchAllPages`
 * reads every page and writes once at the end, so a test needs the read to be
 * unfinished at the moment the delete is issued.
 */
let listGate: Promise<void> | null = null;

/** The same, for the TRASH listing. */
let trashGate: Promise<void> | null = null;

/** What `DELETE /documents/trash/empty` reports. */
let emptyTrashResult = { deletedCount: 2, failedCount: 0 };

/** When false, progress events carry no `total`, as a chunked transport's do not. */
let progressReportsTotal = true;

/** One upload-progress tick, in the shape axios really hands a caller. */
function progressEvent(loaded: number, total?: number): AxiosProgressEvent {
  return {
    loaded,
    ...(total === undefined ? {} : { total }),
    bytes: loaded,
    lengthComputable: total !== undefined,
  };
}

function ok(data: unknown, config: AxiosResponse['config'], status = 200): AxiosResponse {
  return { data, status, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function fail(status: number, config: AxiosResponse['config'], data?: unknown): Promise<never> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(status)}`,
      AxiosError.ERR_BAD_REQUEST,
      config as InternalAxiosRequestConfig,
      undefined,
      {
        status,
        statusText: 'Error',
        data: data ?? { success: false, message: 'nope', statusCode: status },
        headers: {},
        config: config as InternalAxiosRequestConfig,
      },
    ),
  );
}

/** A rejection with no `response` at all — offline, DNS, a dropped socket. */
function offline(config: AxiosResponse['config']): Promise<never> {
  return Promise.reject(
    new AxiosError('Network Error', AxiosError.ERR_NETWORK, config as InternalAxiosRequestConfig),
  );
}

const adapter: AxiosAdapter = (config) => {
  const url = config.url ?? '';
  const method = (config.method ?? 'get').toUpperCase();
  requests.push({
    method,
    url,
    data: config.data,
    headers: config.headers as unknown as Record<string, unknown>,
  });

  if (url.includes('csrf-token')) {
    return Promise.resolve(ok({ data: { csrfToken: `csrf-${String(requests.length)}` } }, config));
  }
  if (url === '/auth/refresh') {
    refreshCount += 1;
    return Promise.resolve(ok({ success: true, data: { accessToken: 'fresh-token' } }, config));
  }
  if (url === '/user/profile') {
    return Promise.resolve(ok({ success: true, data: profileBody }, config));
  }

  // Part upload: PUT /documents/uploads/:id/parts/:n
  const part = /^\/documents\/uploads\/[a-f0-9]{24}\/parts\/(\d+)$/.exec(url);
  if (part && method === 'PUT') {
    if (partsNeedFreshToken && refreshCount === 0) return fail(401, config);
    const outcome = partOutcomes[partAttempt] ?? null;
    partAttempt += 1;
    if (outcome === -1) return offline(config);
    if (outcome !== null) return fail(outcome, config);
    const bytes = (config.data as ArrayBuffer).byteLength;
    // Real transports report progress while a body is on the wire, and the store's
    // absolute-progress arithmetic only runs when they do.
    if (progressReportsTotal) {
      config.onUploadProgress?.(progressEvent(Math.floor(bytes / 2), bytes));
      config.onUploadProgress?.(progressEvent(bytes, bytes));
    } else {
      // A transport that cannot know the length up front reports none, or reports
      // a zero — the two shapes that would divide by nothing.
      config.onUploadProgress?.(progressEvent(0, 0));
      config.onUploadProgress?.(progressEvent(bytes));
    }
    return Promise.resolve(
      ok(
        { success: true, data: { partNumber: Number(part[1]), bytes, receivedBytes: bytes } },
        config,
      ),
    );
  }

  if (url.endsWith('/complete') && method === 'POST') {
    completeBodies.push(JSON.parse(config.data as string) as Record<string, unknown>);
    const outcome = completeOutcomes[completeAttempt] ?? 'ok';
    completeAttempt += 1;
    if (outcome !== 'ok') return fail(outcome.status, config, outcome.data);
    return Promise.resolve(ok({ success: true, data: committedRow }, config, 201));
  }

  if (url === '/documents/uploads' && method === 'POST') {
    return Promise.resolve(
      ok(
        {
          success: true,
          data: {
            uploadId,
            vaultKeyVersion: advertisedVaultKeyVersion,
            chunkPlaintextBytes: advertisedChunkPlaintextBytes,
          },
        },
        config,
        201,
      ),
    );
  }

  if (/^\/documents\/uploads\/[a-f0-9]{24}$/.test(url)) {
    if (method === 'DELETE') {
      return abortFails
        ? fail(500, config)
        : Promise.resolve(ok({ success: true, message: 'Upload cancelled' }, config));
    }
    return Promise.resolve(
      ok(
        {
          success: true,
          data: {
            _id: uploadId,
            // Real encodings, because the client validates this row: the byte
            // counts are pinned exactly, and a salt one byte short is still valid
            // base64 that any generous `.max()` would admit.
            streamSalt: cryptoService.arrayBufferToBase64(new Uint8Array(32).buffer),
            noncePrefix: cryptoService.arrayBufferToBase64(new Uint8Array(7).buffer),
            declaredPlaintextBytes: 1,
            declaredChunkCount: 1,
            chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
            vaultKeyVersion: 0,
            parts: ledgerParts.map((partNumber) => ({
              partNumber,
              bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
            })),
            receivedBytes: 0,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          },
        },
        config,
      ),
    );
  }

  if (url === '/documents' && method === 'GET') {
    if (listEnvelopeFails) {
      return Promise.resolve(ok({ success: false, message: 'nope' }, config));
    }
    const page = Number((config.params as { page?: number } | undefined)?.page ?? 1);
    const rows = listPages[page - 1] ?? [];
    const body = ok(
      {
        success: true,
        data: rows,
        pagination: { page, limit: 200, total: 0, totalPages: Math.max(1, listPages.length) },
      },
      config,
    );
    const gate = listGate;
    return gate === null ? Promise.resolve(body) : gate.then(() => body);
  }

  if (url === '/documents/trash' && method === 'GET') {
    if (trashEnvelopeFails) {
      return Promise.resolve(ok({ success: false, message: 'nope' }, config));
    }
    const body = ok(
      {
        success: true,
        data: trashRows,
        pagination: { page: 1, limit: 200, total: trashRows.length, totalPages: 1 },
      },
      config,
    );
    const gate = trashGate;
    return gate === null ? Promise.resolve(body) : gate.then(() => body);
  }

  if (url === '/documents/usage') {
    if (listEnvelopeFails) {
      return Promise.resolve(ok({ success: false, message: 'nope' }, config));
    }
    return Promise.resolve(
      ok(
        {
          success: true,
          data: {
            documentCount: 3,
            usedBytes: 1024,
            quotaBytes: 2_147_483_648,
            maxDocumentSizeBytes: 104_857_600,
          },
        },
        config,
      ),
    );
  }

  if (url === '/documents/trash/empty') {
    return Promise.resolve(ok({ success: true, data: emptyTrashResult }, config));
  }

  const single = /^\/documents\/([a-f0-9]{24})(\/restore|\/permanent)?$/.exec(url);
  if (single) {
    if (method === 'DELETE') return Promise.resolve(ok({ success: true, data: null }, config));
    if (method === 'POST' || method === 'PUT') {
      return Promise.resolve(ok({ success: true, data: committedRow }, config));
    }
  }

  return fail(404, config);
};

// ---------------------------------------------------------------------------
// Entropy capture (see the file header)
// ---------------------------------------------------------------------------

let captured32: Uint8Array[] = [];
let realGetRandomValues: typeof globalThis.crypto.getRandomValues;

// `adapter` is exact-optional on axios' defaults, but restoring the original means
// writing `undefined` back when an instance had none. Same objects, through a slot
// that admits the absent value — the idiom `coverage-auth-crypto.test.ts` already
// uses for the same restore.
interface AdapterSlot {
  adapter?: typeof axios.defaults.adapter | undefined;
}
const axiosDefaults: AdapterSlot = axios.defaults;
const apiDefaults: AdapterSlot = api.defaults;
const originalGlobalAdapter = axios.defaults.adapter;
const originalApiAdapter = api.defaults.adapter;

function isAllZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

// ---------------------------------------------------------------------------
// Driving the retry backoff
// ---------------------------------------------------------------------------

/**
 * Yield to the REAL event loop once.
 *
 * `setImmediate` is deliberately not faked by `timers: 'timeouts'`, so this is a
 * turn the WebAssembly instantiation, the Web Crypto calls and `Blob.arrayBuffer()`
 * between two parts can actually make progress on. `vi.advanceTimersByTimeAsync`
 * flushes MICROTASKS between its ticks and nothing more, so advancing ten seconds
 * in one call runs past a `setTimeout` the transfer has not reached yet — the
 * classic shape of a fake-timer test that hangs rather than fails.
 */
function realTurn(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

/**
 * How long a step may take, in REAL milliseconds.
 *
 * A turn budget is the wrong unit and was measurably wrong here: `setImmediate`
 * costs microseconds, so five hundred turns can elapse in a few milliseconds while
 * the first `hash-wasm` instantiation is still compiling — a step that is making
 * perfectly good progress then "times out". Wall time is what these waits are
 * actually bounded by. `Date` is never faked in this file (`timers: 'timeouts'`
 * fakes `setTimeout` alone), so this reads a real clock.
 *
 * It exists to make a STUCK transfer fail loudly, naming what it was waiting for,
 * rather than hang until the runner's own timeout, which reports nothing.
 */
const MAX_WAIT_MS = 10_000;

/** Real turns until `condition` holds, or a failure that says what it was waiting for. */
async function until(condition: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + MAX_WAIT_MS;
  while (Date.now() < deadline) {
    if (condition()) return;
    await realTurn();
  }
  throw new Error(`Timed out waiting for ${what}`);
}

/** Real turns until `count` part requests have been recorded. */
function untilParts(count: number): Promise<void> {
  return until(() => partRequests().length >= count, `${String(count)} part request(s)`);
}

/**
 * Real turns until the retry deadline is actually armed.
 *
 * Without this, a step-by-step timing test measures from the moment the REQUEST
 * was recorded rather than from the moment it FAILED, and the gap between the two
 * is however long the runner took to settle a rejection — so the same advance
 * lands before the timer on a quiet machine and after it on a busy one. Only the
 * backoff's own `setTimeout` is faked here (`timers: 'timeouts'`), so a pending
 * timer means the deadline and nothing else.
 */
function untilRetryArmed(): Promise<void> {
  return until(() => vi.getTimerCount() > 0, 'the retry deadline to be armed');
}

/**
 * Settles a transfer that sleeps on the 1s/2s/4s backoff.
 *
 * Alternates a real turn (so the awaited crypto and file reads progress) with a
 * one-second advance of the faked `setTimeout` (so the next retry becomes due),
 * which is the only ordering that works when a promise chain contains both.
 */
async function settleWithBackoff<T>(promise: Promise<T>): Promise<T> {
  let settled = false;
  const tracked = promise.finally(() => {
    settled = true;
  });
  // Keeps a rejection from being reported as unhandled while we pump; the caller
  // still receives it by awaiting the returned promise.
  const guarded = tracked.catch(() => undefined);
  const deadline = Date.now() + MAX_WAIT_MS;
  while (!settled && Date.now() < deadline) {
    // SEVERAL real turns per advance, not one: the chain between two parts needs a
    // turn each for the WebAssembly instantiation, the crypto and the file read,
    // and one turn per faked second starves it.
    for (let turn = 0; turn < 10 && !settled; turn += 1) await realTurn();
    if (!settled) await vi.advanceTimersByTimeAsync(1_000);
  }
  if (!settled) throw new Error('The transfer never settled within the pump budget');
  await guarded;
  return tracked;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';
/** A third id, standing in for the deleted folder's own parent. */
const ID_C = '66c0f1a2b3c4d5e6f7a8b9c2';

let vaultKey: CryptoKey;
let mek: CryptoKey;

/** A metadata blob whose framing matches a document of `plaintextBytes` bytes. */
function metaFor(plaintextBytes: number, name: string): DocumentMeta {
  return {
    name,
    mime: 'text/plain',
    ext: 'txt',
    plaintextBytes,
    sha256: 'a'.repeat(64),
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount: documentChunkCountFor(plaintextBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES),
    tags: [],
    capturedAt: '2026-01-01T00:00:00.000Z',
  };
}

/**
 * A committed row exactly as the API sends one, sealed under a real DEK.
 *
 * `wrapUnder` lets a test bind the DEK to a DIFFERENT document id, which is what
 * produces a degraded row: the wrap is authenticated over the id, so the unwrap
 * fails rather than returning nonsense.
 */
async function makeRow(
  id: string,
  name: string,
  options: { plaintextBytes?: number; wrapUnder?: string } = {},
): Promise<DocumentResponse> {
  const plaintextBytes = options.plaintextBytes ?? 5;
  const chunkCount = documentChunkCountFor(plaintextBytes, DOCUMENT_PLAINTEXT_CHUNK_BYTES);
  const dek = generateDek();
  const streamSalt = randomBytes(32);
  const noncePrefix = randomBytes(7);
  const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, options.wrapUnder ?? id));
  const sealed = await encryptMeta(
    await deriveMetaKey(dek, streamSalt, id),
    metaFor(plaintextBytes, name),
  );
  zeroDek(dek);
  return {
    _id: id,
    favorite: false,
    ...wrapped,
    streamSalt: cryptoService.arrayBufferToBase64(streamSalt.buffer),
    noncePrefix: cryptoService.arrayBufferToBase64(noncePrefix.buffer),
    ...sealed,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    chunkCount,
    ciphertextBytes: plaintextBytes + DOCUMENT_TAG_BYTES * chunkCount,
    plaintextBytes,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  };
}

/**
 * Bytes with their buffer type pinned.
 *
 * `new Uint8Array([...])` widens to `Uint8Array<ArrayBufferLike>`, which admits a
 * `SharedArrayBuffer` and is therefore not assignable to what Web Crypto and this
 * feature's own `DocumentBytes` accept. Naming the exact shape once here keeps
 * every fixture below honest without a cast.
 */
function bytes(...values: number[]): DocumentBytes {
  return new Uint8Array(values) as DocumentBytes;
}

/** `length` random bytes, with the same buffer type pinned. */
function randomBytes(length: number): DocumentBytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(length)) as DocumentBytes;
}

/** Lowercase hexadecimal SHA-256, for checking the digest the store sealed. */
async function sha256Hex(input: DocumentBytes): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Requests the adapter saw for one HTTP method, filtered by a path fragment. */
function requestsFor(method: string, fragment: string): RecordedRequest[] {
  return requests.filter((r) => r.method === method && r.url.includes(fragment));
}

/** The part uploads seen, in order. */
function partRequests(): RecordedRequest[] {
  return requests.filter((r) => r.method === 'PUT' && r.url.includes('/parts/'));
}

beforeEach(async () => {
  requests = [];
  listPages = [];
  trashRows = [];
  trashEnvelopeFails = false;
  listGate = null;
  trashGate = null;
  emptyTrashResult = { deletedCount: 2, failedCount: 0 };
  ledgerParts = [];
  partOutcomes = [];
  partAttempt = 0;
  completeOutcomes = ['ok'];
  completeAttempt = 0;
  completeBodies = [];
  committedRow = null;
  profileBody = null;
  refreshCount = 0;
  partsNeedFreshToken = false;
  abortFails = false;
  listEnvelopeFails = false;
  progressReportsTotal = true;
  uploadId = ID_A;
  advertisedChunkPlaintextBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES;
  advertisedVaultKeyVersion = 0;
  captured32 = [];

  // A PASS-THROUGH, never a stub: the real entropy is still what fills the buffer,
  // and what is recorded is the buffer itself, so a later `fill(0)` inside the
  // store is visible through this reference. Entropy is one of the boundaries a
  // test may touch; the key material derived from it is not faked.
  realGetRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
  vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation((<
    T extends ArrayBufferView | null,
  >(
    array: T,
  ): T => {
    const filled = realGetRandomValues(array as unknown as Uint8Array<ArrayBuffer>);
    if (filled.length === 32) captured32.push(filled);
    return array;
  }) as typeof globalThis.crypto.getRandomValues);

  // BOTH instances: `ensureCsrfToken` reaches for the bare `axios`, everything
  // else goes through `api`. Restored in `afterEach` — a global adapter left
  // installed is exactly the cross-file contamination the suite's shuffled order
  // exists to expose.
  axios.defaults.adapter = adapter;
  api.defaults.adapter = adapter;
  clearCsrfToken();

  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  mek = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  // `vaultKeyVersion` is set EXPLICITLY, beside the key it names: the completion
  // sends this session's number, so leaving it to a default would make every
  // assertion about that number incidental — and would let a rotated version leak
  // from a neighbouring test under the suite's shuffled order.
  useAuthStore.setState({
    accessToken: 'access-token',
    vaultKey,
    mek,
    vaultKeyVersion: 0,
    isAuthenticated: true,
  });
  useDocumentsStore.setState({
    documents: [],
    trashDocuments: [],
    usage: null,
    uploads: {},
    degradedCount: 0,
    invalidCount: 0,
  });
});

afterEach(() => {
  // Ends every session the test left behind, so a live controller cannot outlive
  // the file it belongs to.
  useDocumentsStore.getState().clearStore();
  axiosDefaults.adapter = originalGlobalAdapter;
  apiDefaults.adapter = originalApiAdapter;
  vi.restoreAllMocks();
  vi.useRealTimers();
});

// ===========================================================================
// Reads
// ===========================================================================

describe('documentsStore — reading', () => {
  it('opens every row it lists and exposes the decrypted name', async () => {
    listPages = [[await makeRow(ID_A, 'invoice.pdf')]];

    await useDocumentsStore.getState().fetchDocuments();

    const { documents, degradedCount, invalidCount } = useDocumentsStore.getState();
    expect(documents).toHaveLength(1);
    expect(documents[0]?.meta?.name).toBe('invoice.pdf');
    expect(degradedCount).toBe(0);
    expect(invalidCount).toBe(0);
    // The name never crossed the wire: the request carried no body at all, and the
    // row the server sent holds only ciphertext.
    expect(JSON.stringify(listPages)).not.toContain('invoice.pdf');
  });

  it('lists a row whose key belongs to another document as degraded rather than dropping it', async () => {
    // The DEK is wrapped under ID_B, so the unwrap under ID_A's derived key fails:
    // the wrap is authenticated over the document id precisely so a row cannot be
    // substituted across documents.
    listPages = [[await makeRow(ID_A, 'lost.txt', { wrapUnder: ID_B })]];

    await useDocumentsStore.getState().fetchDocuments();

    const { documents, degradedCount } = useDocumentsStore.getState();
    expect(documents).toHaveLength(1);
    expect(documents[0]?.meta).toBeNull();
    expect(degradedCount).toBe(1);
    // The negative that matters: it is still LISTED, because move, favorite, trash
    // and purge are exactly what a user needs in order to get rid of it.
    expect(documents[0]?.id).toBe(ID_A);
  });

  it('drops a row that does not satisfy the response schema, and counts it', async () => {
    const good = await makeRow(ID_A, 'kept.txt');
    const bad = { ...(await makeRow(ID_B, 'dropped.txt')), chunkCount: 99 };
    listPages = [[good, bad as DocumentResponse]];

    await useDocumentsStore.getState().fetchDocuments();

    const { documents, invalidCount, degradedCount } = useDocumentsStore.getState();
    // A row whose framing does not agree with itself is one this client cannot
    // derive a key from or compute a byte range with, so it is refused outright
    // rather than shown degraded.
    expect(documents.map((d) => d.id)).toEqual([ID_A]);
    expect(invalidCount).toBe(1);
    expect(degradedCount).toBe(0);
  });

  it('walks every page the server reports', async () => {
    listPages = [[await makeRow(ID_A, 'one.txt')], [await makeRow(ID_B, 'two.txt')]];

    await useDocumentsStore.getState().fetchDocuments();

    expect(useDocumentsStore.getState().documents.map((d) => d.meta?.name)).toEqual([
      'one.txt',
      'two.txt',
    ]);
    expect(requestsFor('GET', '/documents').filter((r) => r.url === '/documents')).toHaveLength(2);
  });

  it('deduplicates concurrent fetches into one round trip', async () => {
    listPages = [[await makeRow(ID_A, 'one.txt')]];
    const store = useDocumentsStore.getState();

    await Promise.all([store.fetchDocuments(), store.fetchDocuments(), store.fetchDocuments()]);

    expect(requests.filter((r) => r.url === '/documents')).toHaveLength(1);
  });

  it('does not let a superseded fetch overwrite the state a newer one wrote', async () => {
    listPages = [[await makeRow(ID_A, 'stale.txt')]];
    const store = useDocumentsStore.getState();

    // Start a fetch, then supersede it with `clearStore()` — the lock/logout path —
    // while its response is still in flight. The captured vault key would still
    // decrypt (clearing a key zeroes an exported copy, not the live handle), so
    // without the generation guard the just-emptied store is repopulated with
    // plaintext.
    const pending = store.fetchDocuments();
    store.clearStore();
    await pending;

    expect(useDocumentsStore.getState().documents).toEqual([]);
    expect(useDocumentsStore.getState().documentsLoading).toBe(false);
  });

  it('deduplicates concurrent trash and usage reads too', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt')];
    const store = useDocumentsStore.getState();

    await Promise.all([store.fetchTrash(), store.fetchTrash()]);
    await Promise.all([store.fetchUsage(), store.fetchUsage()]);

    expect(requests.filter((r) => r.url === '/documents/trash')).toHaveLength(1);
    expect(requests.filter((r) => r.url === '/documents/usage')).toHaveLength(1);
  });

  it('does not let a superseded trash or usage read write into a cleared store', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt')];
    const store = useDocumentsStore.getState();

    const trash = store.fetchTrash();
    const usage = store.fetchUsage();
    store.clearStore();
    await Promise.all([trash, usage]);

    // Same guard as the documents list, and it matters for the same reason: the
    // captured vault key still decrypts after a lock.
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(useDocumentsStore.getState().usage).toBeNull();
    expect(useDocumentsStore.getState().trashLoading).toBe(false);
    expect(useDocumentsStore.getState().usageLoading).toBe(false);
  });

  it('refuses a usage envelope that says success: false on a 200', async () => {
    listEnvelopeFails = true;

    await expect(useDocumentsStore.getState().fetchUsage()).rejects.toThrow(/document usage/i);
    expect(useDocumentsStore.getState().usage).toBeNull();
  });

  it('carries a trashed row folder, deletion date and pending purge through to the list', async () => {
    const row = await makeRow(ID_B, 'binned.txt');
    trashRows = [
      { ...row, folderId: ID_A, deletedAt: '2026-03-03T00:00:00.000Z', purgePending: true },
    ];

    await useDocumentsStore.getState().fetchTrash();

    const doc = useDocumentsStore.getState().trashDocuments[0];
    expect(doc?.folderId).toBe(ID_A);
    expect(doc?.deletedAt).toBe('2026-03-03T00:00:00.000Z');
    // A purge that has not finished still occupies storage, and a rotation still
    // has to name it — so the flag has to survive the read.
    expect(doc?.purgePending).toBe(true);
  });

  it('refuses a list envelope that says success: false on a 200', async () => {
    // It does not happen — this API's errors are FLAT and carry a non-2xx status,
    // so axios has already rejected — which is exactly why it must throw rather
    // than fall back: a 200 saying `success: false` means something is wrong that
    // nothing else would notice.
    listEnvelopeFails = true;

    await expect(useDocumentsStore.getState().fetchDocuments()).rejects.toThrow(/list documents/i);
    expect(useDocumentsStore.getState().documents).toEqual([]);
    expect(useDocumentsStore.getState().documentsLoading).toBe(false);
  });

  it('refuses to read anything while the vault is locked', async () => {
    useAuthStore.setState({ vaultKey: null });

    await expect(useDocumentsStore.getState().fetchDocuments()).rejects.toThrow(/locked/i);
    // The negative: no request was issued at all, so a locked vault cannot even
    // ask the server what it holds.
    expect(requests.filter((r) => r.url === '/documents')).toHaveLength(0);
  });

  it('reads the trash from its own route and the usage figures verbatim', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt')];

    await useDocumentsStore.getState().fetchTrash();
    await useDocumentsStore.getState().fetchUsage();

    expect(useDocumentsStore.getState().trashDocuments[0]?.meta?.name).toBe('binned.txt');
    expect(useDocumentsStore.getState().usage).toEqual({
      documentCount: 3,
      usedBytes: 1024,
      quotaBytes: 2_147_483_648,
      maxDocumentSizeBytes: 104_857_600,
    });
    // Trash is a separate route, not a flag: nothing here touched the active list.
    expect(useDocumentsStore.getState().documents).toEqual([]);
  });
});

// ===========================================================================
// Upload
// ===========================================================================

describe('documentsStore — uploading', () => {
  const CONTENT = bytes(104, 118, 97, 117, 108, 116); // "hvault"

  function source(content: DocumentBytes = CONTENT): Blob {
    return new Blob([content]);
  }

  async function primeCommittedRow(name = 'notes.txt'): Promise<void> {
    committedRow = await makeRow(ID_A, name, { plaintextBytes: CONTENT.length });
  }

  it('seals the file, sends one part per segment, and commits the document', async () => {
    await primeCommittedRow();
    const before = captured32.length;

    const id = await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'notes.txt',
      mime: 'text/plain',
    });

    expect(id).toBe(ID_A);
    // One crypto segment is one uploaded part: six bytes is one segment, so one
    // PUT, at part number 1 (part numbers are 1-based; segment indices are not).
    const parts = partRequests();
    expect(parts).toHaveLength(1);
    expect(parts[0]?.url).toBe(`/documents/uploads/${ID_A}/parts/1`);
    expect(parts[0]?.headers['Content-Type']).toBe('application/octet-stream');
    // The committed row is in the list and the transfer is out of the registry.
    expect(useDocumentsStore.getState().documents[0]?.id).toBe(ID_A);
    expect(useDocumentsStore.getState().uploads).toEqual({});
    // Exactly one of the two 32-byte buffers this upload drew — the DEK, not the
    // stream salt — was zeroed when the transfer ended.
    const drawn = captured32.slice(before);
    expect(drawn.filter(isAllZero)).toHaveLength(1);
    expect(drawn.filter((b) => !isAllZero(b)).length).toBeGreaterThan(0);
  });

  it('uploads a zero-byte file as one segment that is nothing but its tag', async () => {
    // The boundary the framing prototype measured, and the reason
    // `documentChunkCountFor` carries its `max(1, ...)`: `ceil(0 / P)` is 0, so an
    // empty file would otherwise claim no segments at all and no range would ever
    // be read for it.
    committedRow = await makeRow(ID_A, 'empty.txt', { plaintextBytes: 0 });

    await useDocumentsStore.getState().startUpload({
      source: new Blob([]),
      name: 'empty.txt',
      mime: 'text/plain',
    });

    expect(partRequests()).toHaveLength(1);
    expect((partRequests()[0]?.data as ArrayBuffer).byteLength).toBe(DOCUMENT_TAG_BYTES);
    expect(useDocumentsStore.getState().documents[0]?.meta?.plaintextBytes).toBe(0);
    expect(useDocumentsStore.getState().documents[0]?.meta?.chunkCount).toBe(1);
  });

  it('sends the SEALED segment, which opens back to the file under the declared framing', async () => {
    await primeCommittedRow();

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'notes.txt',
      mime: 'text/plain',
    });

    // Reconstruct the transfer's keys from what the client SENT, and open the part.
    // If the store framed the segment differently from the way it declared it, this
    // cannot decrypt — which is the whole reason the index and the last-segment
    // flag live inside the nonce.
    const init = JSON.parse(requestsFor('POST', '/documents/uploads')[0]?.data as string) as Record<
      string,
      string
    >;
    const complete = completeBodies[0] as unknown as Record<string, string>;
    const streamSalt = new Uint8Array(cryptoService.base64ToArrayBuffer(init.streamSalt ?? ''));
    const noncePrefix = new Uint8Array(cryptoService.base64ToArrayBuffer(init.noncePrefix ?? ''));
    const dek = await unwrapDek(
      {
        encryptedDek: complete.encryptedDek ?? '',
        dekIv: complete.dekIv ?? '',
        dekTag: complete.dekTag ?? '',
      },
      await deriveWrapKey(vaultKey, ID_A),
    );
    const opened = await decryptSegment(
      await deriveStreamKey(dek as DocumentBytes, streamSalt, ID_A),
      { noncePrefix, index: 0, isLast: true },
      new Uint8Array(partRequests()[0]?.data as ArrayBuffer) as DocumentBytes,
    );

    expect(Array.from(opened)).toEqual(Array.from(CONTENT));
  });

  it('walks a file across TWO segments, one part each, framed by index and last flag', async () => {
    // The only case in this file whose source is larger than one plaintext chunk,
    // and the arithmetic it reaches exists nowhere else. At `chunkCount === 1` the
    // loop runs once, so `partNumber` is always 1, `isLast` is always true and the
    // completed-prefix term of `sentBytes` is always zero — three values that
    // cannot be wrong in any single-segment test. The chunk size cannot be shrunk
    // to reach this cheaply either: the client refuses a server that advertises a
    // different `chunkPlaintextBytes`, deliberately, so the file has to be real.
    const bigLength = DOCUMENT_PLAINTEXT_CHUNK_BYTES + 5;
    const big = new Uint8Array(bigLength) as DocumentBytes;
    // Content that differs per position, so a segment opened at the wrong offset
    // decodes to the wrong bytes rather than to an accidentally-matching run.
    for (let index = 0; index < bigLength; index += 1) big[index] = (index * 31 + 7) & 0xff;
    committedRow = await makeRow(ID_A, 'big.bin', { plaintextBytes: bigLength });

    const seen: number[] = [];
    const unsubscribe = useDocumentsStore.subscribe((state) => {
      const bytes = state.uploads[ID_A]?.sentBytes;
      if (bytes !== undefined) seen.push(bytes);
    });
    await useDocumentsStore.getState().startUpload({
      source: source(big),
      name: 'big.bin',
      mime: 'application/octet-stream',
    });
    unsubscribe();

    // ONE part per segment, numbered from 1, and every non-final part exactly one
    // ciphertext chunk: a short middle part silently desynchronises every later
    // segment boundary, which is the failure the server also refuses.
    const parts = partRequests();
    expect(parts).toHaveLength(2);
    expect(parts.map((part) => part.url)).toEqual([
      `/documents/uploads/${ID_A}/parts/1`,
      `/documents/uploads/${ID_A}/parts/2`,
    ]);
    expect((parts[0]?.data as ArrayBuffer).byteLength).toBe(DOCUMENT_CIPHERTEXT_CHUNK_BYTES);
    expect((parts[1]?.data as ArrayBuffer).byteLength).toBe(5 + DOCUMENT_TAG_BYTES);

    // Both parts open at their OWN index with their own last-segment flag, and
    // concatenate back to the file. A store that marked every segment final, or
    // that re-read the first slice for the second part, cannot pass this.
    const init = JSON.parse(requestsFor('POST', '/documents/uploads')[0]?.data as string) as Record<
      string,
      string
    >;
    const complete = completeBodies[0] as unknown as Record<string, string>;
    const streamSalt = new Uint8Array(cryptoService.base64ToArrayBuffer(init.streamSalt ?? ''));
    const noncePrefix = new Uint8Array(cryptoService.base64ToArrayBuffer(init.noncePrefix ?? ''));
    const dek = await unwrapDek(
      {
        encryptedDek: complete.encryptedDek ?? '',
        dekIv: complete.dekIv ?? '',
        dekTag: complete.dekTag ?? '',
      },
      await deriveWrapKey(vaultKey, ID_A),
    );
    const streamKey = await deriveStreamKey(dek as DocumentBytes, streamSalt, ID_A);
    const first = await decryptSegment(
      streamKey,
      { noncePrefix, index: 0, isLast: false },
      new Uint8Array(parts[0]?.data as ArrayBuffer) as DocumentBytes,
    );
    const second = await decryptSegment(
      streamKey,
      { noncePrefix, index: 1, isLast: true },
      new Uint8Array(parts[1]?.data as ArrayBuffer) as DocumentBytes,
    );
    expect(first.length).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    expect(Array.from(second)).toEqual(Array.from(big.subarray(DOCUMENT_PLAINTEXT_CHUNK_BYTES)));
    const rejoined = new Uint8Array(bigLength) as DocumentBytes;
    rejoined.set(first, 0);
    rejoined.set(second, DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    // Compared by DIGEST rather than by `toEqual`: a deep-equality assertion over
    // eight million elements spends most of a minute inside the matcher's own diff
    // machinery, for a weaker statement than "these are the same bytes".
    expect(await sha256Hex(rejoined)).toBe(await sha256Hex(big));

    // `sentBytes` is ABSOLUTE, so the second part's progress starts from the first
    // part's total rather than from zero: it never goes backwards and never passes
    // the file's own size.
    expect(seen.some((value) => value >= DOCUMENT_PLAINTEXT_CHUNK_BYTES)).toBe(true);
    expect(Math.max(...seen)).toBe(bigLength);
    expect(seen.every((value, index) => index === 0 || value >= (seen[index - 1] ?? 0))).toBe(true);
  });

  it('does not list a committed row whose id is not the transfer it asked about', async () => {
    // The completion answered about a DIFFERENT document. The upload itself did
    // commit, so there is nothing to recover here — but a row inserted under an id
    // whose keys it was not sealed with would show as permanently undecodable, and
    // the next fetch reads the truth anyway.
    committedRow = await makeRow(ID_B, 'someone-elses.txt', { plaintextBytes: CONTENT.length });

    const id = await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'mine.txt',
      mime: 'text/plain',
    });

    expect(id).toBe(ID_A);
    expect(useDocumentsStore.getState().documents).toEqual([]);
    // And the transfer is still finished: no session, no key, no retry offered.
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('never puts the document name, its type or its bytes into any request', async () => {
    await primeCommittedRow('payroll-2026.csv');

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'payroll-2026.csv',
      mime: 'text/csv',
      tags: ['finance'],
      note: 'do not share',
    });

    // The zero-knowledge assertion, stated as a negative over everything that
    // crossed the wire: the name, the MIME type, the tag, the note and the
    // plaintext are all sealed, so none of them can appear in a body or a URL.
    const wire = requests
      .map((r) => `${r.url} ${typeof r.data === 'string' ? r.data : ''}`)
      .join('\n');
    expect(wire).not.toContain('payroll-2026.csv');
    expect(wire).not.toContain('text/csv');
    expect(wire).not.toContain('finance');
    expect(wire).not.toContain('do not share');
    expect(wire).not.toContain('hvault');
  });

  it('fetches a CSRF token before the part, and a fresh one after an invalidation', async () => {
    await primeCommittedRow();
    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });

    const csrfIndex = requests.findIndex((r) => r.url.includes('csrf-token'));
    const partIndex = requests.findIndex((r) => r.url.includes('/parts/'));
    expect(csrfIndex).toBeGreaterThanOrEqual(0);
    expect(csrfIndex).toBeLessThan(partIndex);

    // A refresh clears the cached token in every tab. The next part must resolve a
    // new one rather than send the dead one and be replayed.
    const before = requests.filter((r) => r.url.includes('csrf-token')).length;
    clearCsrfToken();
    partAttempt = 0;
    completeAttempt = 0;
    uploadId = ID_B;
    committedRow = await makeRow(ID_B, 'b.txt', { plaintextBytes: CONTENT.length });
    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'b.txt',
      mime: 'text/plain',
    });

    expect(requests.filter((r) => r.url.includes('csrf-token')).length).toBe(before + 1);
  });

  it('replays a part after the interceptor refreshes an expired access token', async () => {
    await primeCommittedRow();
    // Every part 401s until a refresh has happened — the shape of an access token
    // that expired mid-transfer.
    partsNeedFreshToken = true;

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });

    expect(refreshCount).toBe(1);
    // Two attempts at the SAME part: the 401 and the interceptor's replay. The
    // store's own backoff never ran — a 401 is absorbed below it.
    expect(partRequests()).toHaveLength(2);
    expect(partRequests()[0]?.url).toBe(partRequests()[1]?.url);
    // And the replay carried the new token, which is what made it succeed.
    expect(partRequests()[1]?.headers.Authorization).toBe('Bearer fresh-token');
  });

  it('retries a 5xx part with the 1s/2s/4s backoff and succeeds', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [503, 503, null];

    await settleWithBackoff(
      useDocumentsStore.getState().startUpload({
        source: source(),
        name: 'a.txt',
        mime: 'text/plain',
      }),
    );

    expect(partRequests()).toHaveLength(3);
    expect(useDocumentsStore.getState().documents[0]?.id).toBe(ID_A);
  });

  it('marks the upload failed after the initial attempt and all three retries fail offline', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    // -1 is the adapter's "no response at all": offline, DNS, a dropped socket.
    partOutcomes = [-1, -1, -1, -1];
    const before = captured32.length;

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    // Four attempts: the first, then one per backoff step.
    expect(partRequests()).toHaveLength(4);
    const entry = useDocumentsStore.getState().uploads[ID_A];
    expect(entry?.status).toBe('failed');
    expect(entry?.error).toBeTruthy();
    // RESUMABLE: the entry survives, so the UI can offer a retry, and the DEK is
    // deliberately NOT zeroed — a resume must re-send under the same key or every
    // part the server already holds becomes garbage.
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(0);
  });

  it('waits 1s, then 2s, then 4s between attempts and no longer', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [-1, -1, -1, -1];

    const pending = useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });
    const guarded = pending.catch(() => undefined);

    // Each step waits for the deadline to be ARMED before advancing, so the
    // measurement starts where the production code starts it — at the failure —
    // rather than at whatever moment the runner happened to record the request.
    await untilParts(1);
    await untilRetryArmed();
    // 999 ms is not a second, and the negative is the whole assertion: the retry
    // is on a deadline, not on the next tick of whatever the event loop does.
    await vi.advanceTimersByTimeAsync(999);
    await realTurn();
    expect(partRequests()).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(1);
    await untilParts(2);
    await untilRetryArmed();
    await vi.advanceTimersByTimeAsync(1_999);
    await realTurn();
    expect(partRequests()).toHaveLength(2);

    await vi.advanceTimersByTimeAsync(1);
    await untilParts(3);
    await untilRetryArmed();
    await vi.advanceTimersByTimeAsync(3_999);
    await realTurn();
    expect(partRequests()).toHaveLength(3);

    await vi.advanceTimersByTimeAsync(1);
    await untilParts(4);

    await guarded;
    await expect(pending).rejects.toThrow();
    // Bounded: a fourth failure ends the transfer rather than sleeping eight
    // seconds and trying again.
    await vi.advanceTimersByTimeAsync(30_000);
    await realTurn();
    expect(partRequests()).toHaveLength(4);
  });

  it('fails a rate-limited part at once rather than spending three more slots', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [429];

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    // The part budget's window is fifteen minutes; a seven-second backoff would
    // only burn three more slots out of a budget that is already empty.
    expect(partRequests()).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads[ID_A]?.status).toBe('failed');
  });

  it('fails a deterministically refused part at once and leaves it resumable', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    // A digest mismatch, a wrong length, a missing Content-Length: re-sending the
    // identical bytes cannot change any of them.
    partOutcomes = [400];

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    expect(partRequests()).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads[ID_A]?.status).toBe('failed');
  });

  it('abandons the transfer when the staging row is gone, zeroing the key', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [404];
    const before = captured32.length;

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    expect(partRequests()).toHaveLength(1);
    // No entry survives, so no Retry button can be offered for a transfer whose
    // every request — including the ledger read a retry starts with — would 404.
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
  });

  it('seals a metadata blob that describes the file exactly, and stores the name only there', async () => {
    await primeCommittedRow('quarterly report.txt');

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'quarterly report.txt',
      mime: 'text/plain',
      tags: ['reports'],
      note: 'internal',
    });

    const complete = completeBodies[0] as unknown as Record<string, string>;
    const init = JSON.parse(requestsFor('POST', '/documents/uploads')[0]?.data as string) as Record<
      string,
      string
    >;
    const dek = await unwrapDek(
      {
        encryptedDek: complete.encryptedDek ?? '',
        dekIv: complete.dekIv ?? '',
        dekTag: complete.dekTag ?? '',
      },
      await deriveWrapKey(vaultKey, ID_A),
    );
    const meta = await decryptMeta(
      await deriveMetaKey(
        dek as DocumentBytes,
        new Uint8Array(cryptoService.base64ToArrayBuffer(init.streamSalt ?? '')),
        ID_A,
      ),
      {
        encryptedMeta: complete.encryptedMeta ?? '',
        metaIv: complete.metaIv ?? '',
        metaTag: complete.metaTag ?? '',
      },
    );

    expect(meta.name).toBe('quarterly report.txt');
    expect(meta.mime).toBe('text/plain');
    // Derived through the shared rule, from the NAME rather than from the source
    // file, so a transformed upload is described by what it became.
    expect(meta.ext).toBe('txt');
    expect(meta.tags).toEqual(['reports']);
    expect(meta.note).toBe('internal');
    expect(meta.plaintextBytes).toBe(CONTENT.length);
    expect(meta.chunkCount).toBe(1);
    expect(meta.chunkPlaintextBytes).toBe(DOCUMENT_PLAINTEXT_CHUNK_BYTES);
    expect(meta.sha256).toBe(await sha256Hex(CONTENT));
    // And an ISO instant in UTC: an offset-bearing local time reads differently
    // depending on the reader's zone, which the DST gate exists to catch.
    expect(meta.capturedAt).toMatch(/Z$/);
  });

  it('reports progress in plaintext bytes and finishes at the file size', async () => {
    await primeCommittedRow();
    const seen: number[] = [];
    const unsubscribe = useDocumentsStore.subscribe((state) => {
      const entry = state.uploads[ID_A];
      if (entry) seen.push(entry.sentBytes);
    });

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });
    unsubscribe();

    // Monotonic and bounded by the file, never a running total that a replayed
    // part could push past the end — and it really does move WHILE the part is on
    // the wire, not only when it lands.
    expect(seen.length).toBeGreaterThan(0);
    expect(Math.max(...seen)).toBe(CONTENT.length);
    expect(seen.some((value) => value > 0 && value < CONTENT.length)).toBe(true);
    expect(seen.every((value, index) => index === 0 || value >= (seen[index - 1] ?? 0))).toBe(true);
  });

  it('resumes without re-sending a part the server already holds, and still digests it', async () => {
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [400];

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();
    expect(useDocumentsStore.getState().uploads[ID_A]?.status).toBe('failed');

    // The ledger now names part 1, so the retry must skip it.
    ledgerParts = [1];
    const partsBefore = partRequests().length;

    await useDocumentsStore.getState().retryUpload(ID_A);

    expect(partRequests()).toHaveLength(partsBefore);
    // But the slice was still READ and HASHED: the digest inside the metadata
    // covers the whole file, so a resume that skipped the hashing too would seal a
    // digest of nothing and every later download would report the file corrupt.
    const complete = completeBodies.at(-1) as unknown as Record<string, string>;
    const init = JSON.parse(requestsFor('POST', '/documents/uploads')[0]?.data as string) as Record<
      string,
      string
    >;
    const dek = await unwrapDek(
      {
        encryptedDek: complete.encryptedDek ?? '',
        dekIv: complete.dekIv ?? '',
        dekTag: complete.dekTag ?? '',
      },
      await deriveWrapKey(vaultKey, ID_A),
    );
    const meta = await decryptMeta(
      await deriveMetaKey(
        dek as DocumentBytes,
        new Uint8Array(cryptoService.base64ToArrayBuffer(init.streamSalt ?? '')),
        ID_A,
      ),
      {
        encryptedMeta: complete.encryptedMeta ?? '',
        metaIv: complete.metaIv ?? '',
        metaTag: complete.metaTag ?? '',
      },
    );
    expect(meta.sha256).toBe(await sha256Hex(CONTENT));
  });

  it('abandons a resume whose staging row has expired', async () => {
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    partOutcomes = [400];
    const before = captured32.length;

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    // The TTL fired, or another tab cancelled it: the ledger read itself 404s.
    api.defaults.adapter = (config) =>
      /^\/documents\/uploads\/[a-f0-9]{24}$/.test(config.url ?? '') &&
      config.method?.toUpperCase() === 'GET'
        ? fail(404, config)
        : adapter(config);

    await expect(useDocumentsStore.getState().retryUpload(ID_A)).rejects.toThrow();

    // Nothing to resume onto, so the key does not outlive the attempt.
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
  });

  it('carries the folder and the transform provenance through to the sealed metadata', async () => {
    await primeCommittedRow();
    const transform = {
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: '3.9.5',
      originalSha256: 'b'.repeat(64),
    } as const;

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.json',
      mime: 'application/json',
      folderId: ID_B,
      transform,
    });

    // The folder is a PLAINTEXT column the server files the document under, so it
    // travels on the init body.
    const init = JSON.parse(requestsFor('POST', '/documents/uploads')[0]?.data as string) as Record<
      string,
      unknown
    >;
    expect(init.folderId).toBe(ID_B);
    // The provenance is not: it says what was done to the user's bytes, so it is
    // sealed with the rest of the metadata.
    const complete = completeBodies[0] as unknown as Record<string, string>;
    const dek = await unwrapDek(
      {
        encryptedDek: complete.encryptedDek ?? '',
        dekIv: complete.dekIv ?? '',
        dekTag: complete.dekTag ?? '',
      },
      await deriveWrapKey(vaultKey, ID_A),
    );
    const meta = await decryptMeta(
      await deriveMetaKey(
        dek as DocumentBytes,
        new Uint8Array(cryptoService.base64ToArrayBuffer((init.streamSalt as string) ?? '')),
        ID_A,
      ),
      {
        encryptedMeta: complete.encryptedMeta ?? '',
        metaIv: complete.metaIv ?? '',
        metaTag: complete.metaTag ?? '',
      },
    );
    expect(meta.transform).toEqual(transform);
    expect(JSON.stringify(requests)).not.toContain('prettier');
  });

  it('reports progress even when the transport cannot say how long the part is', async () => {
    await primeCommittedRow();
    progressReportsTotal = false;
    const seen: number[] = [];
    const unsubscribe = useDocumentsStore.subscribe((state) => {
      const entry = state.uploads[ID_A];
      if (entry) seen.push(entry.sentBytes);
    });

    await useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });
    unsubscribe();

    // The fallback is the body's own length, so the bar still finishes rather than
    // dividing by an undefined total and sticking at zero.
    expect(Math.max(...seen)).toBe(CONTENT.length);
  });

  it('does not list a document whose completion landed after the vault locked', async () => {
    await primeCommittedRow();
    let releaseComplete = (): void => {};
    let completeCalls = 0;
    const gate = new Promise<void>((resolve) => {
      releaseComplete = resolve;
    });
    api.defaults.adapter = async (config) => {
      if ((config.url ?? '').endsWith('/complete')) {
        completeCalls += 1;
        await gate;
      }
      return adapter(config);
    };

    const pending = useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });
    await until(() => completeCalls === 1, 'the completion request');

    // The document IS committed, so this is not a failure and the call resolves —
    // but opening it for the list is a LOCAL write, and the captured vault key
    // would still decrypt after the lock (clearing a key zeroes an exported copy,
    // not the live handle). Without the guard the just-emptied store would be
    // repopulated with a decrypted name.
    useDocumentsStore.getState().clearStore();
    releaseComplete();
    await expect(pending).resolves.toBe(ID_A);

    expect(useDocumentsStore.getState().documents).toEqual([]);
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('does not list a document whose committed row was OPENED after the vault locked', async () => {
    await primeCommittedRow();

    // A DIFFERENT window from the case above, and the one nothing could reach.
    // `endSession` removes the transfer from the `sessions` map BEFORE the
    // committed row is opened, and that map is the only thing `clearStore()` and
    // `cancelUpload` iterate — so from that line on nothing in this codebase can
    // abort the signal, and the `isAborted` check that guards the write cannot
    // fire. A lock landing while the row is being DECRYPTED therefore put a fully
    // decrypted name, type, note and digest into a store the lock had just
    // emptied, where it survived until the next fetch, and across a logout into
    // the next account on the same tab.
    //
    // The lock is fired from a passthrough spy on Web Crypto's `decrypt` rather
    // than from a timer: `openDocumentRow` unwraps the DEK and then opens the
    // metadata blob, so the first `decrypt` after the completion response lands
    // exactly inside the window, deterministically and with the real crypto still
    // doing the work.
    let completeSeen = false;
    api.defaults.adapter = async (config) => {
      const response = await adapter(config);
      if ((config.url ?? '').endsWith('/complete')) completeSeen = true;
      return response;
    };

    const subtle = globalThis.crypto.subtle;
    const realDecrypt = subtle.decrypt.bind(subtle) as typeof subtle.decrypt;
    let locked = false;
    const decryptSpy = vi
      .spyOn(subtle, 'decrypt')
      .mockImplementation(async (algorithm, key, data) => {
        if (completeSeen && !locked) {
          locked = true;
          useDocumentsStore.getState().clearStore();
        }
        return realDecrypt(algorithm, key, data);
      });

    try {
      await expect(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ).resolves.toBe(ID_A);

      expect(locked).toBe(true);
      expect(useDocumentsStore.getState().documents).toEqual([]);
      expect(useDocumentsStore.getState().uploads).toEqual({});
    } finally {
      decryptSpy.mockRestore();
    }
  });

  it('abandons a part the server refuses on authorization grounds', async () => {
    installTestClock({ timers: 'timeouts' });
    await primeCommittedRow();
    // A 403 that is NOT a CSRF rejection: the interceptor has already done what it
    // can, and the session — not the part — is what failed.
    partOutcomes = [403];
    const before = captured32.length;

    await expect(
      settleWithBackoff(
        useDocumentsStore.getState().startUpload({
          source: source(),
          name: 'a.txt',
          mime: 'text/plain',
        }),
      ),
    ).rejects.toThrow();

    expect(partRequests()).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
  });

  it('does not register a transfer whose session was torn down while it opened', async () => {
    await primeCommittedRow();
    const before = captured32.length;
    let releaseInit = (): void => {};
    const gate = new Promise<void>((resolve) => {
      releaseInit = resolve;
    });
    api.defaults.adapter = async (config) => {
      if (config.url === '/documents/uploads' && config.method?.toUpperCase() === 'POST') {
        await gate;
      }
      return adapter(config);
    };

    const pending = useDocumentsStore.getState().startUpload({
      source: source(),
      name: 'a.txt',
      mime: 'text/plain',
    });
    // A lock lands while the transfer is still being opened. `clearStore()` has
    // already walked the session map, so registering afterwards would put a live
    // key and a progress row into a store that has just been emptied — and both
    // would then survive until the NEXT lock.
    useDocumentsStore.getState().clearStore();
    releaseInit();
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);

    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
    // No byte was ever sealed, and the server was told to release the transfer.
    expect(partRequests()).toHaveLength(0);
    expect(requestsFor('DELETE', `/documents/uploads/${ID_A}`)).toHaveLength(1);
  });

  it('refuses a document whose metadata is over its bounds BEFORE uploading anything', async () => {
    // The bounds are checked on what is known up front, so a name a byte too long
    // costs one refusal rather than a whole transfer that fails at its last step
    // and leaves a "resumable" entry whose retry re-reads and re-hashes the file
    // only to fail identically.
    await expect(
      useDocumentsStore.getState().startUpload({
        source: source(),
        name: 'x'.repeat(MAX_DOCUMENT_NAME_LENGTH + 1),
        mime: 'text/plain',
      }),
    ).rejects.toThrow();

    expect(requestsFor('POST', '/documents/uploads')).toHaveLength(0);
    expect(partRequests()).toHaveLength(0);
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('refuses to start when the server frames documents differently', async () => {
    advertisedChunkPlaintextBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES - 1;
    const before = captured32.length;

    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: source(), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow(/frames documents differently/);

    // Not one byte was sealed, the transfer was cancelled server-side, and the key
    // did not outlive the refusal.
    expect(partRequests()).toHaveLength(0);
    expect(requestsFor('DELETE', '/documents/uploads/')).toHaveLength(1);
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
  });

  it('zeroes the key when the transfer is refused before it is registered', async () => {
    advertisedChunkPlaintextBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES;
    const before = captured32.length;
    // The init itself fails: no upload id, so nothing to register and nothing to
    // abort — but a DEK was already generated.
    api.defaults.adapter = (config) =>
      config.url === '/documents/uploads' ? fail(400, config) : adapter(config);

    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: source(), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow();

    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });
});

// ===========================================================================
// The rotation refusal
// ===========================================================================

describe('documentsStore — a vault key rotated mid-upload', () => {
  it('rewraps the key and retries the completion ALONE, re-sending no part', async () => {
    const content = bytes(1, 2, 3);
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: content.length });
    // The account rotated to version 3 while the file was crossing the network.
    completeOutcomes = [
      { status: 409, data: { success: false, message: 'rotated', data: { vaultKeyVersion: 3 } } },
      'ok',
    ];
    // The profile then hands back the NEW vault key, wrapped under the same MEK.
    const rotatedRaw = cryptoService.generateVaultKey();
    const rotatedKey = await cryptoService.importVaultKey(rotatedRaw);
    const wrapped = await cryptoService.encryptVaultKey(rotatedKey, mek);
    profileBody = {
      encryptedVaultKey: wrapped.encrypted,
      vaultKeyIv: wrapped.iv,
      vaultKeyTag: wrapped.tag,
    };

    await useDocumentsStore.getState().startUpload({
      source: new Blob([content]),
      name: 'a.txt',
      mime: 'text/plain',
    });

    // ONE part, for TWO completions: the whole point of sending the wrapped key a
    // second time is that a rotation costs one request instead of the entire file.
    expect(partRequests()).toHaveLength(1);
    expect(completeBodies).toHaveLength(2);
    expect(completeBodies[0]?.vaultKeyVersion).toBe(0);
    expect(completeBodies[1]?.vaultKeyVersion).toBe(3);
    // The retry carried a DIFFERENT wrapped key — the same DEK under the new vault
    // key — which is what makes the document readable afterwards.
    expect(completeBodies[1]?.encryptedDek).not.toBe(completeBodies[0]?.encryptedDek);
    // And the sealed metadata was NOT re-sealed: it is under a DEK-derived key that
    // a vault rotation does not touch.
    expect(completeBodies[1]?.encryptedMeta).toBe(completeBodies[0]?.encryptedMeta);
    // The rewrapped key really is the DEK under the rotated vault key.
    const dek = await unwrapDek(
      {
        encryptedDek: completeBodies[1]?.encryptedDek as string,
        dekIv: completeBodies[1]?.dekIv as string,
        dekTag: completeBodies[1]?.dekTag as string,
      },
      await deriveWrapKey(rotatedKey, ID_A),
    );
    expect(dek).toHaveLength(32);
  });

  it('sends the version its OWN key is, not the one init echoed, and self-heals from the 409', async () => {
    // The S1 arrangement, which the case above does not reach: the rotation
    // happened BEFORE this transfer opened, from another session. A rotation
    // revokes nothing and refreshes no key already held here, so this session is
    // still holding the superseded vault key — and init, reading the server's own
    // counter, echoes the NEW generation back.
    //
    // Echoing that number onward is what committed a row wrapped under a key the
    // account no longer stores: the server would be comparing its own number with
    // itself and agreeing. The document then lists, charges the quota, never
    // opens, and — because the rotation screen aborts on the first row it cannot
    // unwrap — blocks every future rotation of the account.
    advertisedVaultKeyVersion = 1;
    useAuthStore.setState({ vaultKeyVersion: 0 });
    const content = bytes(9, 8, 7);
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: content.length });
    completeOutcomes = [
      { status: 409, data: { success: false, data: { vaultKeyVersion: 1 } } },
      'ok',
    ];
    const rotatedRaw = cryptoService.generateVaultKey();
    const rotatedKey = await cryptoService.importVaultKey(rotatedRaw);
    const wrapped = await cryptoService.encryptVaultKey(rotatedKey, mek);
    profileBody = {
      encryptedVaultKey: wrapped.encrypted,
      vaultKeyIv: wrapped.iv,
      vaultKeyTag: wrapped.tag,
    };

    await useDocumentsStore.getState().startUpload({
      source: new Blob([content]),
      name: 'a.txt',
      mime: 'text/plain',
    });

    // THE ASSERTION THIS TEST EXISTS FOR: the first completion carried 0 — what
    // this session's key IS — and not the 1 the init response advertised.
    expect(completeBodies[0]?.vaultKeyVersion).toBe(0);
    expect(advertisedVaultKeyVersion).toBe(1);
    // …so the server could refuse, and the existing recovery ran: one retry,
    // carrying the number the refusal handed back.
    expect(completeBodies).toHaveLength(2);
    expect(completeBodies[1]?.vaultKeyVersion).toBe(1);
    // One part for two completions — the recovery costs a request, not the file.
    expect(partRequests()).toHaveLength(1);
    // And the committed key really is the DEK under the account's CURRENT vault
    // key, which is the whole point of refusing the first attempt.
    const dek = await unwrapDek(
      {
        encryptedDek: completeBodies[1]?.encryptedDek as string,
        dekIv: completeBodies[1]?.dekIv as string,
        dekTag: completeBodies[1]?.dekTag as string,
      },
      await deriveWrapKey(rotatedKey, ID_A),
    );
    expect(dek).toHaveLength(32);

    // THE NEGATIVES, and the second is easy to get wrong. The session did not
    // adopt the rotated key — every item already decrypted in memory belongs to
    // the old one — and it must not adopt the rotated NUMBER either. A version
    // moved forward while the key stayed behind is the original defect rebuilt
    // from the client side: the next upload would send 1, the server would agree,
    // and the row would commit under a key nothing can unwrap.
    expect(useAuthStore.getState().vaultKey).toBe(vaultKey);
    expect(useAuthStore.getState().vaultKeyVersion).toBe(0);
  });

  it('does not adopt the rotated key into the auth store', async () => {
    const content = bytes(1);
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 1 });
    completeOutcomes = [
      { status: 409, data: { success: false, data: { vaultKeyVersion: 1 } } },
      'ok',
    ];
    const rotatedKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    const wrapped = await cryptoService.encryptVaultKey(rotatedKey, mek);
    profileBody = {
      encryptedVaultKey: wrapped.encrypted,
      vaultKeyIv: wrapped.iv,
      vaultKeyTag: wrapped.tag,
    };

    await useDocumentsStore.getState().startUpload({
      source: new Blob([content]),
      name: 'a.txt',
      mime: 'text/plain',
    });

    // Adopting a rotated vault key is a decision about the whole session — every
    // item already in memory was decrypted under the old one — and must not happen
    // as a side effect of finishing one upload.
    expect(useAuthStore.getState().vaultKey).toBe(vaultKey);
  });

  it('gives up rather than rewrapping when the vault locks during the profile read', async () => {
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 1 });
    completeOutcomes = [{ status: 409, data: { success: false, data: { vaultKeyVersion: 1 } } }];
    const rotatedKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    const wrapped = await cryptoService.encryptVaultKey(rotatedKey, mek);
    profileBody = {
      encryptedVaultKey: wrapped.encrypted,
      vaultKeyIv: wrapped.iv,
      vaultKeyTag: wrapped.tag,
    };
    let releaseProfile = (): void => {};
    let profileReads = 0;
    const gate = new Promise<void>((resolve) => {
      releaseProfile = resolve;
    });
    api.defaults.adapter = async (config) => {
      if (config.url === '/user/profile') {
        // Counted BEFORE the gate: a request held at the gate has been issued but
        // not yet recorded, so waiting on the recorded list would wait for ever.
        profileReads += 1;
        await gate;
      }
      return adapter(config);
    };

    const pending = useDocumentsStore
      .getState()
      .startUpload({ source: new Blob([bytes(1)]), name: 'a.txt', mime: 'text/plain' });
    const guarded = pending.catch(() => undefined);
    await until(() => profileReads === 1, 'the profile read');

    // An auto-lock is a wall-clock deadline and does not wait for a round trip.
    // What must NOT happen next is a second completion carrying a key wrapped from
    // a DEK that has just been filled with zeroes: the server commits the row from
    // that body, so the document's segments would be unopenable for ever.
    useDocumentsStore.getState().clearStore();
    releaseProfile();
    await guarded;
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);

    expect(completeBodies).toHaveLength(1);
    expect(useDocumentsStore.getState().documents).toEqual([]);
  });

  it('refuses to rewrap when the master key is gone, rather than deriving from nothing', async () => {
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 1 });
    completeOutcomes = [{ status: 409, data: { success: false, data: { vaultKeyVersion: 1 } } }];
    // The MEK is what decrypts the account's new vault key. Without it there is
    // nothing to rewrap under, and the refusal has to say so rather than proceed.
    useAuthStore.setState({ mek: null });

    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: new Blob([bytes(1)]), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow(/locked/i);

    expect(completeBodies).toHaveLength(1);
    // The negative: no profile was read, so nothing went looking for a key it
    // could not have opened anyway.
    expect(requestsFor('GET', '/user/profile')).toHaveLength(0);
  });

  it('surfaces a conflict that carries no version rather than treating it as a rotation', async () => {
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 1 });
    // The per-upload lock's own conflict: a number is exactly what it does not
    // carry, so there is nothing to rewrap under.
    completeOutcomes = [{ status: 409, data: { success: false, message: 'already completing' } }];

    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: new Blob([bytes(1)]), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow();

    expect(completeBodies).toHaveLength(1);
    // No profile was read, so nothing tried to rewrap under a key it could not name.
    expect(requestsFor('GET', '/user/profile')).toHaveLength(0);
  });
});

// ===========================================================================
// Cancel, teardown and resume
// ===========================================================================

describe('documentsStore — cancel and teardown', () => {
  /**
   * Starts an upload and pauses it inside its first part.
   *
   * `partAttempts` counts the part requests that REACHED the transport, recorded
   * before the gate rather than after it: a part held at the gate has already been
   * issued, so counting recorded requests alone could not tell "the in-flight one
   * finished" from "a second one was sent".
   *
   * `entropyBaseline` is sampled after the fixture row is built, because
   * `makeRow` generates and zeroes a DEK of its own.
   */
  async function startPausedUpload(): Promise<{
    pending: Promise<string>;
    releasePart: () => void;
    entropyBaseline: number;
    partAttempts: () => number;
  }> {
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 3 });
    const entropyBaseline = captured32.length;
    let attempts = 0;
    let releasePart = (): void => {};
    const gate = new Promise<void>((resolve) => {
      releasePart = resolve;
    });
    api.defaults.adapter = async (config) => {
      if ((config.url ?? '').includes('/parts/')) {
        attempts += 1;
        await gate;
      }
      return adapter(config);
    };
    const pending = useDocumentsStore.getState().startUpload({
      source: new Blob([bytes(1, 2, 3)]),
      name: 'a.txt',
      mime: 'text/plain',
    });
    // Let init settle and the part request reach the gate. `until` rather than
    // `vi.waitFor`: this file fakes `setTimeout`, and `vi.waitFor`'s own polling
    // budget is a timer — so it would be measured in a clock the test controls.
    await until(() => attempts === 1, 'the first part to reach the transport');
    return { pending, releasePart, entropyBaseline, partAttempts: () => attempts };
  }

  it('cancels an upload: the abort is sent, the key is zeroed and the entry is gone', async () => {
    const { pending, releasePart, entropyBaseline: before } = await startPausedUpload();

    useDocumentsStore.getState().cancelUpload(ID_A);
    releasePart();
    // The TYPE, not the wording: cancellation is the one outcome that must never
    // be retried and must never be reported as a failure of the file, and a caller
    // that cannot tell it apart from a network error will do both.
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);

    expect(requestsFor('DELETE', `/documents/uploads/${ID_A}`)).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);
    // The negative that matters most: cancellation must never be mistaken for
    // "offline" and retried, which would seal another segment under a zeroed key.
    expect(completeBodies).toHaveLength(0);
  });

  it('clearStore aborts every live transfer, zeroes every key and tells the server', async () => {
    const { pending, releasePart, entropyBaseline: before } = await startPausedUpload();

    useDocumentsStore.getState().clearStore();
    releasePart();
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);

    expect(requestsFor('DELETE', `/documents/uploads/${ID_A}`)).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(captured32.slice(before).filter(isAllZero)).toHaveLength(1);

    // A second teardown finds nothing left to abort — the session map and the
    // progress entry were removed together, which is what stops a live controller
    // outliving the entry the UI forgot about.
    const abortsSoFar = requestsFor('DELETE', `/documents/uploads/${ID_A}`).length;
    useDocumentsStore.getState().clearStore();
    expect(requestsFor('DELETE', `/documents/uploads/${ID_A}`)).toHaveLength(abortsSoFar);
  });

  it('does not send another part after a teardown', async () => {
    const { pending, releasePart, partAttempts } = await startPausedUpload();

    useDocumentsStore.getState().clearStore();
    releasePart();
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);
    await until(
      () => Object.keys(useDocumentsStore.getState().uploads).length === 0,
      'the teardown',
    );

    // An aborted request rejects with no `response`, which a classifier reading only
    // the status would call "offline" and answer with a sleep and a re-send — and
    // the re-send would seal another segment under a key that has just been zeroed.
    // ONE attempt, the one that was already in flight, and no second.
    expect(partAttempts()).toBe(1);
  });

  it('stops a transfer that is asleep on its backoff, without waiting the delay out', async () => {
    installTestClock({ timers: 'timeouts' });
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 3 });
    partOutcomes = [-1, -1, -1, -1];
    // The cancel endpoint refuses too, which must not stop the local teardown: it
    // is a courtesy to the server's quota, fired un-awaited and bounded.
    abortFails = true;

    const pending = useDocumentsStore.getState().startUpload({
      source: new Blob([bytes(1, 2, 3)]),
      name: 'a.txt',
      mime: 'text/plain',
    });
    const guarded = pending.catch(() => undefined);
    await untilParts(1);
    await untilRetryArmed();

    // Cancelled mid-sleep. The transfer must give up at once rather than serve out
    // a deadline that no longer means anything.
    useDocumentsStore.getState().cancelUpload(ID_A);
    await until(() => vi.getTimerCount() === 0, 'the retry deadline to be cleared');
    await guarded;
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);

    expect(partRequests()).toHaveLength(1);
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('refuses to resume when the source changed underneath the transfer', async () => {
    // `timers: 'timeouts'` and NOT `'all'`: these tests drive the backoff deadline
    // forward while awaiting a WebAssembly instantiation, Web Crypto and
    // `Blob.arrayBuffer()` in the same test, and a faked `setImmediate` /
    // `queueMicrotask` makes those awaits hang rather than run late.
    installTestClock({ timers: 'timeouts' });
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 3 });
    partOutcomes = [400];
    const file = new File([bytes(1, 2, 3)], 'a.txt', { lastModified: 1_000 });

    await expect(
      settleWithBackoff(
        useDocumentsStore
          .getState()
          .startUpload({ source: file, name: 'a.txt', mime: 'text/plain' }),
      ),
    ).rejects.toThrow();

    // The file on disk moved. Re-reading it would seal segment 0 over DIFFERENT
    // bytes under the same key and nonce, which is the catastrophic case rather
    // than the annoying one.
    Object.defineProperty(file, 'lastModified', { value: 2_000, configurable: true });
    await expect(useDocumentsStore.getState().retryUpload(ID_A)).rejects.toThrow(/changed/i);
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('refuses to retry a transfer it has never heard of', async () => {
    await expect(useDocumentsStore.getState().retryUpload(ID_A)).rejects.toThrow(
      /no longer available/i,
    );
  });

  it('refuses to retry a transfer that is still running', async () => {
    const { pending, releasePart } = await startPausedUpload();

    // A second run over the same parts would seal each `(index, isLast)` pair a
    // second time under the same stream key while the first run is still sending
    // them, which is the one thing the framing cannot survive.
    await expect(useDocumentsStore.getState().retryUpload(ID_A)).rejects.toThrow(
      /Only a failed upload/i,
    );

    useDocumentsStore.getState().cancelUpload(ID_A);
    releasePart();
    await expect(pending).rejects.toBeInstanceOf(UploadCancelledError);
  });

  /**
   * Two Retries taken inside the ledger round trip, and the wrap that must never
   * be sent.
   *
   * The status flip to `'uploading'` happens AFTER `GET /uploads/:id` returns, so
   * `status !== 'failed'` cannot refuse a second call taken while that request is
   * still on the wire. Both calls then reach `session.controller = new
   * AbortController()`, and the SECOND one overwrites the first's — which leaves
   * the first loop running with a controller nothing in this module can reach any
   * more.
   *
   * What that costs is not a duplicated request. `cancelUpload` aborts
   * `session.controller` — the surviving one — and zeroes the DEK, and the
   * orphaned loop, whose signal was never aborted, walks on to `wrapDek` and
   * commits a key made of 32 zero bytes. `completeTransfer`'s own abort check
   * cannot help: it reads the orphan's own signal. The metadata key is derived
   * from the same zeroes, so the row LISTS with its real name and its segments —
   * sealed under the stream key derived from the REAL DEK — can never be opened
   * again by anyone, including the account that stored them.
   *
   * The barrier below is deterministic rather than timed. Both calls await the
   * SAME gate promise, so their continuations run in registration order, and the
   * first thing each does on resuming is set its controller and enter
   * `runTransfer` synchronously up to `deriveStreamKey`. A part request costs
   * several more real awaits, so by the time ONE part has reached the transport,
   * a second call — if it was admitted at all — has already installed its
   * controller. Waiting on the part is therefore waiting on the exact state the
   * defect needs.
   */
  it('refuses a second resume taken inside the ledger read, and commits no key made of zeroes', async () => {
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 3 });
    // 400 is the `fail` verdict: no backoff, and the session is KEPT, which is
    // the only state a Retry is offered from.
    partOutcomes = [400];

    let ledgerReads = 0;
    let resumedParts = 0;
    let gatesArmed = false;
    let openLedger = (): void => {};
    let openPart = (): void => {};
    const ledgerGate = new Promise<void>((resolve) => {
      openLedger = resolve;
    });
    const partGate = new Promise<void>((resolve) => {
      openPart = resolve;
    });

    api.defaults.adapter = async (config) => {
      const url = config.url ?? '';
      const method = (config.method ?? 'get').toUpperCase();
      if (gatesArmed) {
        if (method === 'GET' && /^\/documents\/uploads\/[a-f0-9]{24}$/.test(url)) {
          ledgerReads += 1;
          await ledgerGate;
        } else if (method === 'PUT' && url.includes('/parts/')) {
          resumedParts += 1;
          await partGate;
        }
      }
      return adapter(config);
    };

    // The refusal is named, not merely counted: "something was raised" would pass
    // on a typo in the fixture and leave the row in a state this test then reads.
    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: new Blob([bytes(1, 2, 3)]), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow(/status code 400/);
    expect(useDocumentsStore.getState().uploads[ID_A]?.status).toBe('failed');

    gatesArmed = true;
    const first = useDocumentsStore.getState().retryUpload(ID_A);
    const firstOutcome = first.then(
      () => 'resolved' as unknown,
      (error: unknown) => error,
    );
    await until(() => ledgerReads === 1, 'the ledger read to reach the transport');

    // The second click, inside the window the status flip does not cover. It is
    // NOT awaited here: an unguarded second call parks on the same gate, so
    // awaiting it before the gate opens would hang instead of failing.
    const second = useDocumentsStore.getState().retryUpload(ID_A);
    const secondOutcome = second.then(
      () => 'resolved' as unknown,
      (error: unknown) => error,
    );

    openLedger();
    await until(() => resumedParts >= 1, 'the resumed part to reach the transport');

    useDocumentsStore.getState().cancelUpload(ID_A);
    openPart();

    const [firstResult, secondResult] = await Promise.all([firstOutcome, secondOutcome]);
    await until(
      () => Object.keys(useDocumentsStore.getState().uploads).length === 0,
      'the teardown',
    );

    // THE NEGATIVE THAT MATTERS, asserted FIRST because it is the one that costs a
    // user their file: no completion the server was ever given carries a DEK that
    // opens to zeroes. Stated as the shape rather than as a count, because the
    // count alone would not say WHICH body was wrong. With a second loop running,
    // this is the body that commits a permanently unopenable document and blocks
    // every future vault key rotation of the account.
    const wrapKey = await deriveWrapKey(vaultKey, ID_A);
    const zeroedWraps: number[] = [];
    for (const [index, body] of completeBodies.entries()) {
      const opened = await unwrapDek(
        {
          encryptedDek: String(body.encryptedDek),
          dekIv: String(body.dekIv),
          dekTag: String(body.dekTag),
        },
        wrapKey,
      ).catch(() => null);
      if (opened !== null && isAllZero(opened)) zeroedWraps.push(index);
    }
    expect(zeroedWraps).toEqual([]);
    // And nothing was committed at all: the transfer the user cancelled did not
    // quietly finish behind the cancellation.
    expect(completeBodies).toHaveLength(0);

    // The refusal is the second caller's answer, and it is not the cancellation
    // that came later: a caller that cannot tell them apart shows the user an
    // error about a vault they locked on purpose.
    expect(secondResult).toBeInstanceOf(Error);
    expect((secondResult as Error).message).toMatch(/already being retried/i);
    expect(secondResult).not.toBeInstanceOf(UploadCancelledError);
    // Only ONE transfer was ever prepared: the refused call never read the ledger.
    expect(ledgerReads).toBe(1);
    // The one that was admitted is the one the cancel reached.
    expect(firstResult).toBeInstanceOf(UploadCancelledError);
  });

  it('lets a resume that failed again be resumed once more', async () => {
    // The claim taken by a retry is RELEASED once the transfer is running, and
    // this is what says so: without the release the row goes back to `failed`,
    // offers its Retry button, and the button refuses for the rest of the
    // session. Two failures in a row, two accepted retries.
    committedRow = await makeRow(ID_A, 'a.txt', { plaintextBytes: 3 });
    partOutcomes = [400, 400, null];

    await expect(
      useDocumentsStore
        .getState()
        .startUpload({ source: new Blob([bytes(1, 2, 3)]), name: 'a.txt', mime: 'text/plain' }),
    ).rejects.toThrow(/status code 400/);

    // The FIRST retry is admitted — it is the part that fails again, not the
    // claim, which is what makes the second retry below a test of the release
    // rather than of a refusal that never happened.
    await expect(useDocumentsStore.getState().retryUpload(ID_A)).rejects.toThrow(/status code 400/);
    expect(useDocumentsStore.getState().uploads[ID_A]?.status).toBe('failed');

    // The second retry is admitted and this time the part lands, so the document
    // commits and leaves the registry.
    await expect(useDocumentsStore.getState().retryUpload(ID_A)).resolves.toBe(ID_A);
    expect(useDocumentsStore.getState().uploads).toEqual({});
    expect(useDocumentsStore.getState().documents[0]?.id).toBe(ID_A);
  });
});

// ===========================================================================
// Single-row writes
// ===========================================================================

describe('documentsStore — writes on a committed document', () => {
  beforeEach(async () => {
    listPages = [[await makeRow(ID_A, 'notes.txt')]];
    await useDocumentsStore.getState().fetchDocuments();
    requests = [];
  });

  it('re-seals the metadata under the SAME key with a FRESH iv on a rename', async () => {
    const before = useDocumentsStore.getState().documents[0];
    committedRow = {
      ...(before?._raw as DocumentResponse),
      updatedAt: '2026-02-02T00:00:00.000Z',
    };

    await useDocumentsStore.getState().updateDocumentMeta(ID_A, { name: 'renamed.txt' });

    const body = JSON.parse(requestsFor('PUT', `/documents/${ID_A}`)[0]?.data as string) as Record<
      string,
      string
    >;
    // A fresh IV on every seal is the one place in this design where a nonce could
    // repeat under a fixed key: the metadata key is deterministic for the
    // document's whole life, and the blob is deliberately mutable.
    expect(body.metaIv).not.toBe(before?._raw.metaIv);
    expect(body.encryptedMeta).not.toBe(before?._raw.encryptedMeta);
    // Nothing that frames the file crossed the wire: content is immutable, so a
    // rename cannot reach a framing field, the wrapped key or the object key.
    expect(Object.keys(body).sort()).toEqual(['encryptedMeta', 'metaIv', 'metaTag']);

    // And the row the server answered with IS adopted, because it names this
    // document. Without this the whole write could be dropped — by an over-eager
    // identity guard, or by losing the apply altogether — and every assertion
    // above would still pass, since they only describe the request.
    const after = useDocumentsStore.getState().documents[0];
    expect(after?.updatedAt).toBe('2026-02-02T00:00:00.000Z');
    expect(after?._raw).not.toBe(before?._raw);
    expect(after?.id).toBe(ID_A);
  });

  it('refuses to rename a document whose metadata will not open', async () => {
    listPages = [[await makeRow(ID_A, 'lost.txt', { wrapUnder: ID_B })]];
    await useDocumentsStore.getState().fetchDocuments();
    requests = [];

    await expect(
      useDocumentsStore.getState().updateDocumentMeta(ID_A, { name: 'x.txt' }),
    ).rejects.toThrow(/could not be opened/i);

    // The name lives inside the sealed blob, so there is nothing to rewrite and no
    // key to rewrite it with — and no request may be made pretending otherwise.
    expect(requestsFor('PUT', `/documents/${ID_A}`)).toHaveLength(0);
  });

  it('changes only plaintext columns for favorite and folder', async () => {
    committedRow = {
      ...(useDocumentsStore.getState().documents[0]?._raw as DocumentResponse),
      favorite: true,
    };

    await useDocumentsStore.getState().setFavorite(ID_A, true);

    const body = JSON.parse(requestsFor('PUT', `/documents/${ID_A}`)[0]?.data as string) as Record<
      string,
      unknown
    >;
    expect(body).toEqual({ favorite: true });
    expect(useDocumentsStore.getState().documents[0]?.favorite).toBe(true);
    // Its metadata is untouched, so a favorite toggle can never cost the name.
    expect(useDocumentsStore.getState().documents[0]?.meta?.name).toBe('notes.txt');
  });

  it('moves a document into a folder and back out to the root', async () => {
    const base = useDocumentsStore.getState().documents[0]?._raw as DocumentResponse;
    committedRow = { ...base, folderId: ID_B };

    await useDocumentsStore.getState().moveToFolder(ID_A, ID_B);
    expect(useDocumentsStore.getState().documents[0]?.folderId).toBe(ID_B);

    committedRow = base;
    await useDocumentsStore.getState().moveToFolder(ID_A, null);

    // `null` takes it OUT of the folder rather than leaving a stale id behind.
    expect(useDocumentsStore.getState().documents[0]?.folderId).toBeUndefined();
    const bodies = requestsFor('PUT', `/documents/${ID_A}`).map(
      (r) => JSON.parse(r.data as string) as Record<string, unknown>,
    );
    expect(bodies).toEqual([{ folderId: ID_B }, { folderId: null }]);
  });

  it('purges one trashed document without touching the active list', async () => {
    useDocumentsStore.setState({
      trashDocuments: [
        {
          id: ID_B,
          favorite: false,
          createdAt: 'x',
          updatedAt: 'x',
          meta: null,
          _raw: await makeRow(ID_B, 'gone.txt'),
        },
      ],
    });

    await useDocumentsStore.getState().purgeDocument(ID_B);

    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(requestsFor('DELETE', `/documents/${ID_B}/permanent`)).toHaveLength(1);
    // The negative: a purge is not a trash, and the active list is untouched.
    expect(useDocumentsStore.getState().documents).toHaveLength(1);
  });

  it('rewrites the tags and clears the note of a TRASHED document', async () => {
    // Reached through the trash list rather than the active one — a document in
    // the trash is still the user's, and its metadata is sealed under the same key.
    const row = await makeRow(ID_B, 'binned.txt');
    trashRows = [row];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    committedRow = row;

    await useDocumentsStore.getState().updateDocumentMeta(ID_B, {
      tags: ['archive'],
      note: null,
    });

    expect(requestsFor('PUT', `/documents/${ID_B}`)).toHaveLength(1);
    expect(useDocumentsStore.getState().documents).toHaveLength(1);
  });

  it('sets a note, and refuses to touch a document it does not hold', async () => {
    const base = useDocumentsStore.getState().documents[0]?._raw as DocumentResponse;
    committedRow = base;

    await useDocumentsStore.getState().updateDocumentMeta(ID_A, { note: 'renewal in March' });
    expect(requestsFor('PUT', `/documents/${ID_A}`)).toHaveLength(1);

    await expect(
      useDocumentsStore.getState().updateDocumentMeta(ID_B, { name: 'nope.txt' }),
    ).rejects.toThrow(/not found/i);
    // The negative: nothing was sent for a document this client cannot see, so it
    // cannot seal a blob under keys derived from an id it knows nothing about.
    expect(requestsFor('PUT', `/documents/${ID_B}`)).toHaveLength(0);
  });

  it('ignores a favorite response that describes a different document', async () => {
    const before = useDocumentsStore.getState().documents[0];
    committedRow = await makeRow(ID_B, 'someone-elses.txt');

    await useDocumentsStore.getState().setFavorite(ID_A, true);

    // `_raw` is what a later rename derives this document's metadata key from, so
    // adopting a foreign row here would seal the next rename under keys the row
    // was never sealed with. Nothing local changed.
    expect(useDocumentsStore.getState().documents[0]?.favorite).toBe(false);
    expect(useDocumentsStore.getState().documents[0]?._raw).toBe(before?._raw);
  });

  it('ignores a rename response that describes a different document', async () => {
    // The sibling check `patchDocument` has carried all along, and it is needed
    // here for a second reason on top of the shared one. The shared one: `_raw` is
    // what the NEXT rename derives this document's metadata key from, so adopting a
    // foreign row would seal that rename under keys the row was never sealed with.
    // The one that is particular to this path: the write lands by id, so a foreign
    // response does not even mis-apply the rename that was asked for — it rewrites
    // an entry nobody touched, with a row whose keys are derived from ITS id, which
    // this vault key may well fail to open. A healthy document then goes degraded,
    // and a degraded document is one this client refuses to rename at all.
    listPages = [[await makeRow(ID_A, 'notes.txt'), await makeRow(ID_B, 'contract.pdf')]];
    await useDocumentsStore.getState().fetchDocuments();
    requests = [];
    const [beforeA, beforeB] = useDocumentsStore.getState().documents;
    expect(beforeB?.meta?.name).toBe('contract.pdf');

    // A row about ID_B, and one this vault key cannot open: its DEK is wrapped
    // under a third document's key.
    committedRow = await makeRow(ID_B, 'someone-elses.txt', { wrapUnder: ID_C });

    await useDocumentsStore.getState().updateDocumentMeta(ID_A, { name: 'renamed.txt' });

    // The request was legitimate and was made; only the answer is refused.
    expect(requestsFor('PUT', `/documents/${ID_A}`)).toHaveLength(1);

    const [afterA, afterB] = useDocumentsStore.getState().documents;
    // The symptom first: the untouched document is neither degraded nor renamed.
    // Adopting the foreign row put a `meta: null` entry here — a document this
    // client then refuses to rename at all — for a file nobody asked about.
    expect(afterB?.meta).not.toBeNull();
    expect(afterB?.meta?.name).toBe('contract.pdf');
    expect(afterB?._raw).toBe(beforeB?._raw);
    // And the document that WAS renamed keeps the row it had. The server-side
    // rename may well have happened — this client simply will not adopt a row that
    // does not name it, and the next fetch reads the truth.
    expect(afterA?._raw).toBe(beforeA?._raw);
    expect(afterA?.meta?.name).toBe('notes.txt');
  });

  it('moves a document to the trash and back', async () => {
    await useDocumentsStore.getState().deleteDocument(ID_A);
    expect(useDocumentsStore.getState().documents).toEqual([]);

    committedRow = await makeRow(ID_A, 'notes.txt');
    useDocumentsStore.setState({
      trashDocuments: [
        {
          id: ID_A,
          favorite: false,
          createdAt: 'x',
          updatedAt: 'x',
          meta: null,
          _raw: committedRow,
        },
      ],
    });
    await useDocumentsStore.getState().restoreDocument(ID_A);

    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(useDocumentsStore.getState().documents[0]?.meta?.name).toBe('notes.txt');
  });

  it('empties the trash and drops every purged row', async () => {
    useDocumentsStore.setState({
      trashDocuments: [
        {
          id: ID_B,
          favorite: false,
          createdAt: 'x',
          updatedAt: 'x',
          meta: null,
          _raw: await makeRow(ID_B, 'gone.txt'),
        },
      ],
    });

    await useDocumentsStore.getState().emptyTrash();

    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
  });

  it('suppresses the local write of a trash, restore, purge or empty that lands after a teardown', async () => {
    // Every one of these is a server-side write that has ALREADY happened by the
    // time the guard fires. Only the local half is suppressed — which is what
    // stops a lock leaving one row, or one emptied list, behind.
    useDocumentsStore.setState({
      trashDocuments: [
        {
          id: ID_B,
          favorite: false,
          createdAt: 'x',
          updatedAt: 'x',
          meta: null,
          _raw: await makeRow(ID_B, 'binned.txt'),
        },
      ],
    });
    committedRow = await makeRow(ID_B, 'binned.txt');
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    api.defaults.adapter = async (config) => {
      const method = config.method?.toUpperCase();
      if (method === 'DELETE' || method === 'POST') await gate;
      return adapter(config);
    };
    const before = useDocumentsStore.getState();

    const pending = [
      useDocumentsStore.getState().deleteDocument(ID_A),
      useDocumentsStore.getState().restoreDocument(ID_B),
      useDocumentsStore.getState().purgeDocument(ID_B),
      useDocumentsStore.getState().emptyTrash(),
    ];
    useDocumentsStore.setState({
      documents: before.documents,
      trashDocuments: before.trashDocuments,
    });
    useDocumentsStore.getState().clearStore();
    useDocumentsStore.setState({
      documents: before.documents,
      trashDocuments: before.trashDocuments,
    });
    release();
    await Promise.all(pending);

    // The lists are exactly what they were put back to: no suppressed write
    // reached them afterwards.
    expect(useDocumentsStore.getState().documents).toHaveLength(1);
    expect(useDocumentsStore.getState().trashDocuments).toHaveLength(1);
  });

  it('drops a restored row it cannot vouch for rather than listing it', async () => {
    useDocumentsStore.setState({
      trashDocuments: [
        {
          id: ID_B,
          favorite: false,
          createdAt: 'x',
          updatedAt: 'x',
          meta: null,
          _raw: await makeRow(ID_B, 'binned.txt'),
        },
      ],
    });
    // A row whose framing does not agree with itself: the `_id` is HKDF material
    // and the framing decides byte ranges, so it must not be adopted.
    committedRow = { ...(await makeRow(ID_B, 'binned.txt')), chunkCount: 99 } as DocumentResponse;

    await useDocumentsStore.getState().restoreDocument(ID_B);

    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(useDocumentsStore.getState().documents).toHaveLength(1);
  });

  it('ignores a cancel for a transfer it does not hold', () => {
    useDocumentsStore.getState().cancelUpload(ID_B);

    // No request, no throw: cancelling twice, or cancelling after a lock already
    // ended the session, has to be a no-op rather than an error the UI must catch.
    expect(requestsFor('DELETE', `/documents/uploads/${ID_B}`)).toHaveLength(0);
  });

  it('does not repopulate the store with a write that resolves after a teardown', async () => {
    committedRow = {
      ...(useDocumentsStore.getState().documents[0]?._raw as DocumentResponse),
      favorite: true,
    };
    let release = (): void => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    api.defaults.adapter = async (config) => {
      if (config.method?.toUpperCase() === 'PUT') await gate;
      return adapter(config);
    };

    const pending = useDocumentsStore.getState().setFavorite(ID_A, true);
    useDocumentsStore.getState().clearStore();
    release();
    await pending;

    // The server-side write already happened; only the LOCAL write is suppressed,
    // which is what stops a lock leaving one decrypted row behind.
    expect(useDocumentsStore.getState().documents).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Filters, trash coherence and folder sweeps
//
// The three reported bugs — a favorite with nowhere to be used, a folder that
// changed nothing visible, a "moved to trash" with no trash — were all one
// missing surface over a store that already held the data. These cases pin the
// state that surface reads, and the two coherence rules it depends on: a trash
// list that knows whether it was ever read, and a listing that cannot resurrect
// a row deleted while it was in flight.
// ---------------------------------------------------------------------------

describe('documentsStore — filters, trash coherence and folder sweeps', () => {
  beforeEach(async () => {
    listPages = [[await makeRow(ID_A, 'notes.txt')]];
    await useDocumentsStore.getState().fetchDocuments();
    requests = [];
  });

  it('records that the trash was read on success, and does not on failure', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt')];
    await useDocumentsStore.getState().fetchTrash();
    expect(useDocumentsStore.getState().trashLoaded).toBe(true);

    useDocumentsStore.getState().clearStore();
    trashEnvelopeFails = true;
    await expect(useDocumentsStore.getState().fetchTrash()).rejects.toThrow();

    // The half that matters: a `finally` would set this on the failure path too,
    // and a trash "read" that loaded nothing is what makes the optimistic move
    // below render a trash holding exactly one row and hiding every other.
    expect(useDocumentsStore.getState().trashLoaded).toBe(false);
  });

  it('does not let a listing in flight resurrect a document deleted under it', async () => {
    // The list is still being read when the delete lands. Its pages predate the
    // delete, and its own generation is untouched — a single-row write must not
    // discard a listing the reader is waiting for — so without the in-flight set
    // the terminal write puts the row straight back.
    let releaseList: (() => void) | undefined;
    const held = new Promise<void>((resolve) => {
      releaseList = resolve;
    });
    listPages = [[await makeRow(ID_A, 'notes.txt'), await makeRow(ID_B, 'doomed.txt')]];
    useDocumentsStore.setState({ documents: [], trashLoaded: false });
    listGate = held;

    const listing = useDocumentsStore.getState().fetchDocuments();
    await useDocumentsStore.getState().deleteDocument(ID_B);
    releaseList?.();
    await listing;

    expect(useDocumentsStore.getState().documents.map((doc) => doc.id)).toEqual([ID_A]);
  });

  it('keeps a just-trashed row out of the ACTIVE listing and inside the trash listing', async () => {
    // The two id sets are bound ONE-TO-ONE to their own fetches, and that pairing
    // is the load-bearing part. Cross-filtering — the obvious "tidier"
    // implementation — means the id `deleteDocument` records is also filtered out
    // of the TRASH read, so a document is deleted and then simply absent from the
    // trash: the exact bug report this work exists to answer, reintroduced by its
    // own fix.
    listPages = [[await makeRow(ID_A, 'notes.txt')]];
    await useDocumentsStore.getState().fetchDocuments();
    trashRows = [];
    await useDocumentsStore.getState().fetchTrash();

    await useDocumentsStore.getState().deleteDocument(ID_A);
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([ID_A]);

    // The server now reports it as trashed, and the trash read must KEEP it — a
    // set that filtered both listings would drop it here.
    trashRows = [await makeRow(ID_A, 'notes.txt')];
    await useDocumentsStore.getState().fetchTrash();
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([ID_A]);

    // And the id does not haunt the ACTIVE listing for ever: each fetch clears
    // its own set on the way in, because from that point the server's own answer
    // already excludes what was deleted — which is what lets a restored document
    // be listed again at all.
    listPages = [[await makeRow(ID_A, 'notes.txt')]];
    await useDocumentsStore.getState().fetchDocuments();
    expect(useDocumentsStore.getState().documents.map((doc) => doc.id)).toEqual([ID_A]);
  });

  it('moves the deleted row into a trash that was read, stamped but never forged', async () => {
    trashRows = [];
    await useDocumentsStore.getState().fetchTrash();

    await useDocumentsStore.getState().deleteDocument(ID_A);

    const [trashed] = useDocumentsStore.getState().trashDocuments;
    expect(useDocumentsStore.getState().documents).toEqual([]);
    // An empty-but-READ trash still receives the row. A `trashDocuments.length > 0`
    // guard — the proxy `vaultStore` uses — loses exactly this case, and the first
    // delete on such an account vanishes from both lists.
    expect(trashed?.id).toBe(ID_A);
    expect(Number.isNaN(Date.parse(trashed?.deletedAt ?? ''))).toBe(false);
    // The stamp goes on the decrypted wrapper and NEVER on `_raw`: that is the
    // server's row, and a later metadata re-seal derives this document's key
    // material from it.
    expect(trashed?._raw.deletedAt).toBeUndefined();
  });

  it('leaves an unread trash alone, and prepends into a read one', async () => {
    // Unread: nothing is pushed, because one row in a list that was never loaded
    // is a trash that hides everything else in it.
    await useDocumentsStore.getState().deleteDocument(ID_A);
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(requestsFor('DELETE', `/documents/${ID_A}`)).toHaveLength(1);

    listPages = [[await makeRow(ID_A, 'notes.txt')]];
    await useDocumentsStore.getState().fetchDocuments();
    trashRows = [await makeRow(ID_B, 'older.txt')];
    await useDocumentsStore.getState().fetchTrash();

    await useDocumentsStore.getState().deleteDocument(ID_A);

    // Newest first, matching the order the trash endpoint itself returns. An
    // append would drop the document a reader just deleted to the bottom of a
    // list that virtualizes above fifty rows.
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([ID_A, ID_B]);
  });

  it('writes nothing locally when a lock lands between the delete and its response', async () => {
    trashRows = [];
    await useDocumentsStore.getState().fetchTrash();
    const before = useDocumentsStore.getState().documents;

    const pending = useDocumentsStore.getState().deleteDocument(ID_A);
    useDocumentsStore.getState().clearStore();
    await pending;

    // The server-side delete already happened; only the LOCAL write is suppressed,
    // and it must not repopulate a store that was just emptied.
    expect(useDocumentsStore.getState().documents).toEqual([]);
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    expect(before).toHaveLength(1);
  });

  it('empties the trash in one pass when nothing failed', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt')];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];

    const result = await useDocumentsStore.getState().emptyTrash();

    expect(result).toEqual({ deletedCount: 2, failedCount: 0 });
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    // The negative: a clean run needs no second read, and issuing one would
    // decrypt the whole trash again for nothing.
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(0);
  });

  it('does not let a listing in flight repopulate a trash that was emptied under it', async () => {
    // The reachable window, and the one no id set can close. A reader clicks
    // Trash — the listing starts, empties the local list and then spends seconds
    // unwrapping a key per row — and confirms Empty trash before it finishes.
    //
    // `emptyTrash` derives its suppression ids from the very list that listing has
    // already emptied, so it has nothing to add; and on a CLEAN purge there is no
    // re-read either. The listing then resolves and writes back the rows it read
    // before the purge: a trash full of documents that no longer exist, each of
    // which answers "not found" when opened, beside a quota bar reading zero.
    const doomedA = await makeRow(ID_A, 'gone-a.txt');
    const doomedB = await makeRow(ID_B, 'gone-b.txt');
    trashRows = [doomedA, doomedB];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    emptyTrashResult = { deletedCount: 2, failedCount: 0 };

    let releaseTrash: (() => void) | undefined;
    trashGate = new Promise<void>((resolve) => {
      releaseTrash = resolve;
    });
    const listing = useDocumentsStore.getState().fetchTrash();
    const result = await useDocumentsStore.getState().emptyTrash();
    releaseTrash?.();
    await listing;

    expect(result).toEqual({ deletedCount: 2, failedCount: 0 });
    expect(useDocumentsStore.getState().trashDocuments).toEqual([]);
    // And the listing that lost the race must not have stranded the spinner.
    expect(useDocumentsStore.getState().trashLoading).toBe(false);
  });

  it('reads the trash back when the engine could not delete every object', async () => {
    trashRows = [await makeRow(ID_B, 'stuck.txt')];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    emptyTrashResult = { deletedCount: 1, failedCount: 1 };

    const result = await useDocumentsStore.getState().emptyTrash();

    // A failed object delete leaves the row marked `purgePending` and still
    // listed, so reporting "all gone" would be this client inventing a state the
    // server never reached.
    expect(result.failedCount).toBe(1);
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(1);
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([ID_B]);
  });

  it('puts back the rows the server never reached when its walk stopped on a refusing engine', async () => {
    // The server's empty-trash walk shares the collector's circuit breaker: after
    // enough storage refusals in a row it STOPS, having attempted only some of the
    // set, and answers with the counts it actually accumulated. So the response can
    // report a handful of failures while the trash still holds rows nothing tried
    // to purge — rows that carry no `purgePending` marker at all and are simply
    // still there.
    //
    // This is the case that decides whether the server change needs a client
    // change, and it does NOT: the store already refetches whenever `failedCount`
    // is non-zero, and tripping the breaker costs several recorded failures, so
    // `failedCount` can never be zero on the path that stops early. The read is
    // what makes the list true again, and it returns MORE rows than the response
    // accounted for — which is exactly the state a client that trusted the counts
    // instead of re-reading would get wrong.
    const attempted = await makeRow(ID_A, 'attempted.txt');
    const neverReached = await makeRow(ID_B, 'never-reached.txt');
    const alsoNeverReached = await makeRow(ID_C, 'also-never-reached.txt');
    trashRows = [attempted, neverReached, alsoNeverReached];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    // Nothing was destroyed and the walk gave up part-way through.
    emptyTrashResult = { deletedCount: 0, failedCount: 5 };

    const result = await useDocumentsStore.getState().emptyTrash();

    expect(result).toEqual({ deletedCount: 0, failedCount: 5 });
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(1);
    // Every row is back, including the two the server never attempted. The
    // suppression set must stay EMPTY on this path — populating it would subtract
    // exactly these ids from the read that is meant to restore them.
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([
      ID_A,
      ID_B,
      ID_C,
    ]);
    expect(useDocumentsStore.getState().trashLoading).toBe(false);
  });

  it('reads the trash back for real when a listing was already in flight', async () => {
    // The window that made the partial path lie. A reader opens Trash — the
    // listing starts, empties the local list and then spends seconds unwrapping a
    // key per row — and confirms Empty trash before it finishes. `emptyTrash`
    // invalidates that listing, which is correct, and then asks for the list
    // again; if that request is answered by the very run it just invalidated, the
    // run's terminal write is suppressed and NOTHING is written. The trash then
    // renders empty while the row the engine refused is still on the server, still
    // listed, still charged to the quota — and the toast beside it points at this
    // list as the authoritative answer.
    const stuck = await makeRow(ID_A, 'stuck.txt');
    const destroyed = await makeRow(ID_B, 'destroyed.txt');
    trashRows = [stuck, destroyed];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    emptyTrashResult = { deletedCount: 1, failedCount: 1 };

    let releaseTrash: (() => void) | undefined;
    trashGate = new Promise<void>((resolve) => {
      releaseTrash = resolve;
    });
    // Parked in the adapter, so it cannot resolve until this test says so — and
    // waited for explicitly, because the premise of the whole test is that this
    // listing's body, BOTH rows, was fixed before the trash changed underneath it.
    // The adapter builds a response at request time, so gating on the request
    // itself makes that premise self-checking rather than a hope about turns.
    const listing = useDocumentsStore.getState().fetchTrash();
    await until(
      () => requestsFor('GET', '/documents/trash').length === 1,
      'the listing to reach the server',
    );

    // What the server still has once its walk is over: the row it could not delete,
    // marked and still listed. The listing parked above predates all of this and
    // would answer with both rows, so a store that let it win would put back a
    // document that really is gone.
    trashRows = [{ ...stuck, deletedAt: '2026-02-01T00:00:00.000Z', purgePending: true }];

    const emptied = useDocumentsStore.getState().emptyTrash();
    // One turn of the event loop, which drains the whole microtask queue: every
    // step between the DELETE going out and `emptyTrash` asking for the list again
    // is a promise continuation, so after this the re-read has been requested
    // whichever way the store chose to answer it. Nothing is being waited ON — the
    // listing is held by the gate, not by time — and turning too FEW times cannot
    // produce a false pass either: under the unfixed store the re-read is answered
    // by the suppressed run, so the assertions below fail however long this waits.
    await realTurn();
    releaseTrash?.();

    const result = await emptied;
    await listing;

    expect(result).toEqual({ deletedCount: 1, failedCount: 1 });
    // The row the engine refused is on screen — the symptom, stated first, because
    // an empty list here is what the reader was shown.
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([ID_A]);
    // And it is there because a genuinely fresh read fetched it, not because a
    // suppressed one happened to leave it behind.
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(2);
    expect(useDocumentsStore.getState().trashDocuments[0]?.purgePending).toBe(true);
    // The negatives: the destroyed row was not resurrected by the stale listing,
    // and no spinner was stranded by the run that lost.
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).not.toContain(ID_B);
    expect(useDocumentsStore.getState().trashLoading).toBe(false);
  });

  it('brings back every row a stopped-early walk never reached, even mid-listing', async () => {
    // Phase 10's breaker turned the partial path from the rare one into the
    // ORDINARY shape of a storage outage: after enough refusals in a row the
    // server's walk stops, so `failedCount` is non-zero on a run that attempted
    // only the first few rows and never touched the rest. Those untouched rows
    // carry no `purgePending` marker at all — the collector will never look at
    // them — so the re-read is the only thing that can tell the reader they are
    // still there. Combined with a listing in flight, this is the state that used
    // to render as an empty trash beside a warning saying the list had just been
    // refreshed to show what remained.
    const attempted = await makeRow(ID_A, 'attempted.txt');
    const neverReached = await makeRow(ID_B, 'never-reached.txt');
    const alsoNeverReached = await makeRow(ID_C, 'also-never-reached.txt');
    trashRows = [attempted, neverReached, alsoNeverReached];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];
    // Nothing was destroyed and the walk gave up part-way through.
    emptyTrashResult = { deletedCount: 0, failedCount: 5 };

    let releaseTrash: (() => void) | undefined;
    trashGate = new Promise<void>((resolve) => {
      releaseTrash = resolve;
    });
    const listing = useDocumentsStore.getState().fetchTrash();
    await until(
      () => requestsFor('GET', '/documents/trash').length === 1,
      'the listing to reach the server',
    );

    // The marker lands only on the row the walk actually attempted; the two it
    // never reached are simply still there, exactly as they were.
    trashRows = [
      { ...attempted, deletedAt: '2026-02-01T00:00:00.000Z', purgePending: true },
      neverReached,
      alsoNeverReached,
    ];

    const emptied = useDocumentsStore.getState().emptyTrash();
    await realTurn();
    releaseTrash?.();

    const result = await emptied;
    await listing;

    expect(result).toEqual({ deletedCount: 0, failedCount: 5 });
    // Every row is back, including the two the server never attempted, and only
    // the one it did attempt carries the marker.
    expect(useDocumentsStore.getState().trashDocuments.map((doc) => doc.id)).toEqual([
      ID_A,
      ID_B,
      ID_C,
    ]);
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(2);
    expect(
      useDocumentsStore.getState().trashDocuments.map((doc) => doc.purgePending ?? false),
    ).toEqual([true, false, false]);
    expect(useDocumentsStore.getState().trashLoading).toBe(false);
  });

  it('counts a trashed row whose key will not unwrap instead of dropping it silently', async () => {
    trashRows = [await makeRow(ID_B, 'lost.txt', { wrapUnder: ID_A })];
    await useDocumentsStore.getState().fetchTrash();

    const state = useDocumentsStore.getState();
    // Listed, with no metadata, and COUNTED. These numbers used to be computed
    // and thrown away, which was invisible only because nothing rendered the
    // trash: the row was simply absent with nothing said about it.
    expect(state.trashDocuments).toHaveLength(1);
    expect(state.trashDocuments[0]?.meta).toBeNull();
    expect(state.trashDegradedCount).toBe(1);
    // The active list's own counters are a different pair and stay where they were.
    expect(state.degradedCount).toBe(0);
  });

  it('re-parents on a folder move, to the PARENT when there was one', async () => {
    const foldered = await makeRow(ID_A, 'notes.txt');
    listPages = [[{ ...foldered, folderId: ID_B }]];
    await useDocumentsStore.getState().fetchDocuments();
    useDocumentsStore.getState().setSelectedFolder(ID_B);

    // The server's `move` update is `folder.parentId ? $set folderId=parentId :
    // $unset folderId` — so a nested folder's members move UP a level, not to the
    // root. A client that cleared the id would show them somewhere the server did
    // not put them, and would go on disagreeing until the next full reload.
    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'move', ID_C);
    expect(useDocumentsStore.getState().documents[0]?.folderId).toBe(ID_C);
    // A view scoped to a folder that no longer exists would show nothing and
    // explain nothing, so the selection goes with it.
    expect(useDocumentsStore.getState().selectedFolder).toBeNull();
  });

  it('clears folderId on a folder move only when the folder had no parent', async () => {
    const foldered = await makeRow(ID_A, 'notes.txt');
    listPages = [[{ ...foldered, folderId: ID_B }]];
    await useDocumentsStore.getState().fetchDocuments();

    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'move', undefined);
    expect(useDocumentsStore.getState().documents[0]?.folderId).toBeUndefined();
  });

  it('takes the rows away on a folder delete, and reads a trash that was read', async () => {
    const foldered = await makeRow(ID_A, 'notes.txt');
    listPages = [[{ ...foldered, folderId: ID_B }]];
    await useDocumentsStore.getState().fetchDocuments();
    trashRows = [];
    await useDocumentsStore.getState().fetchTrash();
    requests = [];

    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'delete', undefined);
    expect(useDocumentsStore.getState().documents).toEqual([]);
    // The swept rows are in the trash now, so a trash that WAS read is read again.
    await until(() => requestsFor('GET', '/documents/trash').length === 1, 'the trash re-read');
  });

  it('does not read the trash back after a folder delete when it was never read', async () => {
    const foldered = await makeRow(ID_A, 'notes.txt');
    listPages = [[{ ...foldered, folderId: ID_B }]];
    await useDocumentsStore.getState().fetchDocuments();
    requests = [];

    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'delete', undefined);
    await realTurn();
    await realTurn();

    // An unread trash is filled correctly by the next `fetchTrash`; reading it
    // here would decrypt the whole trash for a view nobody has opened.
    expect(requestsFor('GET', '/documents/trash')).toHaveLength(0);
  });

  it('follows the server into the trash on a MOVE, and stays out of it on a DELETE', async () => {
    // The two branches are not symmetrical and copying one onto the other is how
    // this goes wrong. `move` filters `{folderId, userId}` with NO `deletedAt`
    // clause, so it reaches trashed rows; `delete` filters `deletedAt: null`, so
    // a row already in the trash keeps the dead folder id and a restore lands it
    // wherever that id pointed.
    const binned = await makeRow(ID_B, 'binned.txt');
    trashRows = [{ ...binned, folderId: ID_B }];
    await useDocumentsStore.getState().fetchTrash();

    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'move', ID_C);
    expect(useDocumentsStore.getState().trashDocuments[0]?.folderId).toBe(ID_C);
  });

  it('leaves a trashed row on the dead folder when the folder was DELETED', async () => {
    // Read into the store WITHOUT marking the trash loaded, so the `delete`
    // branch's own re-read does not race this assertion — the point here is the
    // synchronous rule, not the refresh that follows it.
    const binned = await makeRow(ID_B, 'binned.txt');
    trashRows = [{ ...binned, folderId: ID_B }];
    await useDocumentsStore.getState().fetchTrash();
    // Read, then marked unread: the `delete` branch re-reads a trash it believes
    // was loaded, and that read would empty the list before this assertion runs.
    // The rule under test is the synchronous one, not the refresh after it.
    useDocumentsStore.setState({ trashLoaded: false });

    useDocumentsStore.getState().applyFolderDeleted(ID_B, 'delete', ID_C);

    // `delete` filters `deletedAt: null` server-side, so a row already in the
    // trash keeps the dead folder id — and a restore lands it wherever that id
    // pointed, which is what the detail view's Folder row then reports.
    expect(useDocumentsStore.getState().trashDocuments[0]?.folderId).toBe(ID_B);
  });

  it('keeps the four view modes mutually exclusive in every direction', () => {
    const store = () => useDocumentsStore.getState();

    store().toggleFavorites();
    store().setSelectedFolder(ID_B);
    expect(store().showFavorites).toBe(false);
    expect(store().selectedFolder).toBe(ID_B);

    store().toggleTrash();
    expect(store().showTrash).toBe(true);
    expect(store().showFavorites).toBe(false);
    expect(store().selectedFolder).toBeNull();

    store().toggleFavorites();
    expect(store().showFavorites).toBe(true);
    expect(store().showTrash).toBe(false);

    store().toggleFavorites();
    expect(store().showFavorites).toBe(false);

    store().setSelectedFolder(ID_A);
    store().clearFilters();
    expect(store().selectedFolder).toBeNull();
    expect(store().showFavorites).toBe(false);
    expect(store().showTrash).toBe(false);
  });

  it('takes every filter and every trash flag down with the vault key', async () => {
    trashRows = [await makeRow(ID_B, 'binned.txt', { wrapUnder: ID_A })];
    await useDocumentsStore.getState().fetchTrash();
    useDocumentsStore.getState().setSelectedFolder(ID_B);
    useDocumentsStore.getState().setSearchQuery('tax');

    useDocumentsStore.getState().clearStore();

    const state = useDocumentsStore.getState();
    // A folder id belonging to the account that just ended would drop the next
    // sign-in on this tab into an empty folder view with no explanation, and a
    // `showTrash` left true would open their unlock inside the trash.
    expect({
      selectedFolder: state.selectedFolder,
      showFavorites: state.showFavorites,
      showTrash: state.showTrash,
      searchQuery: state.searchQuery,
      trashLoaded: state.trashLoaded,
      trashDegradedCount: state.trashDegradedCount,
      trashInvalidCount: state.trashInvalidCount,
    }).toEqual({
      selectedFolder: null,
      showFavorites: false,
      showTrash: false,
      searchQuery: '',
      trashLoaded: false,
      trashDegradedCount: 0,
      trashInvalidCount: 0,
    });
  });
});
