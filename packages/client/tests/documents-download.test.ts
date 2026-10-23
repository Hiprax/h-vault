/**
 * Tests for `services/documents/download.ts` — reading a stored document back —
 * and for `services/documents/downloadAll.ts`, the one-archive bulk export
 * written on top of it, with the archive's save targets and its wait.
 *
 * The two share a suite because the bulk export's whole claim is that it is the
 * SAME read: a run over three documents has to perform the same four checks, in
 * the same order, that a download of one does. Testing it against a stubbed
 * `saveDocument` would have asserted that the loop calls the function it calls;
 * testing it here, against the real crypto and the same stub transport, asserts
 * the property anybody cares about — that three documents come back byte for
 * byte, and that a document which has been interfered with is refused BY NAME
 * without stopping the other two.
 *
 * ## How this suite is wired, and why
 *
 * Everything below the module under test is REAL. `documentCryptoService` runs
 * on Web Crypto, `cryptoService` is the shipped one, `documentsApi` builds the
 * shipped requests, and `services/api/client` keeps its interceptors. Only the
 * TRANSPORT is replaced, by a stub Axios adapter installed on both the shared
 * instance and the global one.
 *
 * That costs a bigger harness and buys the only thing that matters here: every
 * fixture is a document this client could really have uploaded, sealed by the
 * same functions that seal a real one. A test that mocked `decryptSegment` or
 * the hasher would be asserting that the code calls the functions it calls,
 * which is not a property anybody cares about — the property here is that a
 * document survives a round trip byte for byte, and that a document which has
 * been interfered with does not.
 *
 * ## Where the tampering comes from
 *
 * A hostile server is modelled as the ONLY thing it can be: something that
 * chooses which bytes to answer with. It never holds a key, so a fixture that
 * needs to be self-inconsistent (a metadata blob recording the digest of
 * different bytes, or framing that disagrees with the row) is BUILT with the
 * real sealing functions rather than faked, exactly as a corrupt upload or a
 * buggy older client would have produced it.
 *
 * ## Reading a DEK's lifetime without a seam
 *
 * The DEK never leaves the module. `crypto.subtle.decrypt` is wrapped in a
 * pass-through that records the 32-byte results it returns — `unwrapDek` builds
 * its `Uint8Array` as a VIEW over that exact buffer, so `zeroDek`'s `fill(0)` is
 * visible through the recorded reference. Every document below is sized so that
 * no segment and no metadata blob is 32 bytes, which is what keeps the recorded
 * set to exactly the document keys.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, {
  AxiosError,
  type AxiosAdapter,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';
import { DOCUMENT_TAG_BYTES, documentChunkCountFor } from '@hvault/shared';
import type { DocumentMeta, DocumentResponse } from '@hvault/shared';

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
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  encryptMeta,
  encryptSegment,
  generateDek,
  wrapDek,
  zeroDek,
  type DocumentBytes,
} from '../src/services/crypto/documentCryptoService.js';
import { api } from '../src/services/api/client.js';
import { useAuthStore } from '../src/stores/authStore.js';
import {
  DocumentDownloadCancelledError,
  DocumentIntegrityError,
  FALLBACK_DOWNLOAD_FILENAME,
  readDocumentPlaintext,
  sanitizeDownloadFilename,
  saveDocument,
  streamDocumentPlaintext,
} from '../src/services/documents/download.js';
import {
  archiveDocuments,
  waitAbortably,
  type ArchiveDocumentsOptions,
  type BulkDownloadCandidate,
} from '../src/services/documents/downloadAll.js';
import { UNOPENABLE_DOCUMENT_NAME } from '../src/services/documents/documentNames.js';
import { ArchivePathAllocator } from '../src/services/documents/archiveNames.js';
import {
  IN_MEMORY_ARCHIVE_LIMIT_BYTES,
  archiveFileName,
  openArchiveTarget,
  type ArchiveTarget,
} from '../src/services/documents/archiveTarget.js';
import { ZIP32_MAX_ARCHIVE_BYTES } from '../src/services/documents/zipArchive.js';
import { useDocumentsStore } from '../src/stores/documentsStore.js';
import { readArchive } from './support/zipOracle';

// ---------------------------------------------------------------------------
// The stub server
// ---------------------------------------------------------------------------

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';
const ID_C = '66c0f1a2b3c4d5e6f7a8b9c2';

interface RecordedRequest {
  method: string;
  url: string;
}

let requests: RecordedRequest[] = [];

/** What `GET /documents/:id` answers with. */
let rowEnvelope: unknown = null;

/** Sealed segments, indexed the way the route indexes them. */
let segmentBodies: DocumentBytes[] = [];

/** How each segment request is answered: `null` serves the body, a number fails with that status. */
let segmentOutcomes: (number | null)[] = [];

/** Runs when a request is recorded, so a test can abort mid-transfer. */
let onRequest: ((request: RecordedRequest) => void) | null = null;

/** How one segment request is refused: the status, and the sentence the server sends. */
interface SegmentRefusal {
  status: number;
  message: string;
  /** Response headers to send with it (a 429's `Retry-After`). */
  headers?: Record<string, string>;
  /** How many times it is served before the segment is answered normally; every time when absent. */
  remaining?: number;
}

/**
 * Documents the stub server holds BY ID, for the cases that read several.
 *
 * The three single-document globals above are left exactly as they are. They
 * carry the cases that make a row lie about itself — a malformed envelope, a
 * segment list that does not match the row it was served with — and those need
 * the envelope and the bodies settable independently of any coherent document.
 * A bulk run needs the opposite: several consistent documents, each answering
 * for its own id. So it gets its own register and the adapter reads it FIRST; an
 * id in the register wins, and anything else falls through unchanged.
 */
const library = new Map<string, { document: BuiltDocument; refusals: (SegmentRefusal | null)[] }>();

function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function fail(
  status: number,
  config: AxiosResponse['config'],
  message = 'nope',
  headers: Record<string, string> = {},
): Promise<never> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(status)}`,
      AxiosError.ERR_BAD_REQUEST,
      config as InternalAxiosRequestConfig,
      undefined,
      {
        status,
        statusText: 'Error',
        data: { success: false, message, statusCode: status },
        headers,
        config: config as InternalAxiosRequestConfig,
      },
    ),
  );
}

const adapter: AxiosAdapter = (config) => {
  const url = config.url ?? '';
  const method = (config.method ?? 'get').toUpperCase();
  const request: RecordedRequest = { method, url };
  requests.push(request);
  onRequest?.(request);

  const segment = /^\/documents\/([a-f0-9]{24})\/segments\/(\d+)$/.exec(url);
  if (segment) {
    const index = Number(segment[2]);
    const entry = library.get(segment[1] ?? '');
    if (entry) {
      const refusal = entry.refusals[index] ?? null;
      if (refusal !== null) {
        if (refusal.remaining !== undefined) {
          refusal.remaining -= 1;
          if (refusal.remaining === 0) entry.refusals[index] = null;
        }
        return fail(refusal.status, config, refusal.message, refusal.headers);
      }
      const held = entry.document.segments[index];
      if (!held) return fail(404, config);
      return Promise.resolve(ok(held.slice().buffer, config));
    }
    const outcome = segmentOutcomes[index] ?? null;
    if (outcome !== null) return fail(outcome, config);
    const body = segmentBodies[index];
    if (!body) return fail(404, config);
    // A real response body is an ArrayBuffer, because `responseType` is
    // `'arraybuffer'`. A copy, so a test cannot observe the module writing back
    // into the fixture it was handed.
    return Promise.resolve(ok(body.slice().buffer, config));
  }

  const row = /^\/documents\/([a-f0-9]{24})$/.exec(url);
  if (row && method === 'GET') {
    const entry = library.get(row[1] ?? '');
    if (entry) return Promise.resolve(ok({ success: true, data: entry.document.row }, config));
    return Promise.resolve(ok(rowEnvelope, config));
  }

  return fail(404, config);
};

// ---------------------------------------------------------------------------
// Capturing what the download helper does
// ---------------------------------------------------------------------------

interface SavedFile {
  blob: Blob;
  filename: string;
}

let savedFiles: SavedFile[] = [];
let createdAnchors: HTMLAnchorElement[] = [];

/**
 * Runs once a blob download has been handed to the browser, so a test can act
 * BETWEEN two documents of a bulk run. `onRequest` cannot reach that moment —
 * every hook it offers is inside a document's read.
 */
let onSaved: ((file: SavedFile) => void) | null = null;

/** The 32-byte plaintexts `crypto.subtle.decrypt` produced, i.e. the DEKs. */
let unwrappedKeys: Uint8Array[] = [];

function isAllZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

// ---------------------------------------------------------------------------
// The save dialog double
// ---------------------------------------------------------------------------

interface PickerDouble {
  picker: ReturnType<typeof vi.fn>;
  /** `write`, `truncate`, `close` and `abort`, in the order they were called. */
  calls: string[];
  /** Everything written, minus anything a `truncate(0)` erased. */
  written: number[];
  suggestedNames: string[];
  /**
   * How many requests had been made when the dialog opened.
   *
   * The dialog has to open on the click's own transient activation, which does
   * not survive a round trip to the server, so this is the observable that says
   * whether it did.
   */
  requestsWhenOpened: number[];
}

function installPicker(options: { name?: string; dismiss?: boolean } = {}): PickerDouble {
  const calls: string[] = [];
  const written: number[] = [];
  const suggestedNames: string[] = [];
  const requestsWhenOpened: number[] = [];

  const writable = {
    write: (chunk: Uint8Array) => {
      calls.push('write');
      written.push(...chunk);
      return Promise.resolve();
    },
    truncate: (size: number) => {
      calls.push(`truncate:${String(size)}`);
      written.length = size;
      return Promise.resolve();
    },
    close: () => {
      calls.push('close');
      return Promise.resolve();
    },
    abort: () => {
      calls.push('abort');
      return Promise.resolve();
    },
  };

  const handle = {
    name: options.name ?? 'saved.bin',
    createWritable: () => Promise.resolve(writable),
  };

  const picker = vi.fn((pickerOptions: { suggestedName: string }) => {
    suggestedNames.push(pickerOptions.suggestedName);
    requestsWhenOpened.push(requests.length);
    if (options.dismiss === true) {
      const error = new Error('The user aborted a request.');
      error.name = 'AbortError';
      return Promise.reject(error);
    }
    return Promise.resolve(handle);
  });

  vi.stubGlobal('showSaveFilePicker', picker);
  return { picker, calls, written, suggestedNames, requestsWhenOpened };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let vaultKey: CryptoKey;

function bytes(...values: number[]): DocumentBytes {
  return new Uint8Array(values);
}

/** `length` deterministic, non-repeating bytes, so a mis-ordered segment shows. */
function ramp(length: number): DocumentBytes {
  return new Uint8Array(Array.from({ length }, (_, index) => (index * 7 + 11) % 251));
}

async function sha256Hex(input: DocumentBytes): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

interface BuiltDocument {
  id: string;
  row: DocumentResponse;
  meta: DocumentMeta;
  plaintext: DocumentBytes;
  segments: DocumentBytes[];
}

interface BuildOptions {
  id?: string;
  name?: string;
  mime?: string;
  plaintext?: DocumentBytes;
  chunkPlaintextBytes?: number;
  /**
   * Replaces fields of the SEALED metadata, which is how a row and its
   * authenticated copy are made to disagree. The override still has to satisfy
   * `documentMetaSchema` — a document nobody could have sealed is not a threat
   * model, it is a broken fixture.
   */
  metaOverrides?: Partial<DocumentMeta>;
  /** Replaces fields of the plaintext row the server answers with. */
  rowOverrides?: Partial<DocumentResponse>;
}

/**
 * A document exactly as this client would have uploaded one.
 *
 * `chunkPlaintextBytes` defaults to 8 rather than the production 8 MiB: the
 * framing arithmetic is identical at any positive chunk size, and a small one
 * makes a three-segment document cost twenty-odd bytes instead of twenty-four
 * megabytes. Decryption reads the value from the ROW rather than from the
 * constant precisely so this is legitimate.
 */
async function buildDocument(options: BuildOptions = {}): Promise<BuiltDocument> {
  const id = options.id ?? ID_A;
  const plaintext = options.plaintext ?? ramp(20);
  const chunkPlaintextBytes = options.chunkPlaintextBytes ?? 8;
  const chunkCount = documentChunkCountFor(plaintext.length, chunkPlaintextBytes);

  const dek = generateDek();
  const streamSalt = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const noncePrefix = globalThis.crypto.getRandomValues(new Uint8Array(7));

  const wrapped = await wrapDek(dek, await deriveWrapKey(vaultKey, id));
  const streamKey = await deriveStreamKey(dek, streamSalt, id);

  const segments: DocumentBytes[] = [];
  for (let index = 0; index < chunkCount; index += 1) {
    const slice = plaintext.slice(
      index * chunkPlaintextBytes,
      (index + 1) * chunkPlaintextBytes,
    ) as DocumentBytes;
    segments.push(
      await encryptSegment(
        streamKey,
        { noncePrefix, index, isLast: index === chunkCount - 1 },
        slice,
      ),
    );
  }
  const ciphertextBytes = segments.reduce((total, segment) => total + segment.length, 0);

  const meta: DocumentMeta = {
    name: options.name ?? 'report.txt',
    mime: options.mime ?? 'text/plain',
    ext: 'txt',
    plaintextBytes: plaintext.length,
    sha256: await sha256Hex(plaintext),
    chunkPlaintextBytes,
    chunkCount,
    tags: [],
    capturedAt: '2026-01-01T00:00:00.000Z',
    ...options.metaOverrides,
  };
  const sealed = await encryptMeta(await deriveMetaKey(dek, streamSalt, id), meta);
  zeroDek(dek);

  const row: DocumentResponse = {
    _id: id,
    favorite: false,
    ...wrapped,
    streamSalt: cryptoService.arrayBufferToBase64(streamSalt.buffer),
    noncePrefix: cryptoService.arrayBufferToBase64(noncePrefix.buffer),
    ...sealed,
    chunkPlaintextBytes,
    chunkCount,
    ciphertextBytes,
    plaintextBytes: plaintext.length,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-02T00:00:00.000Z',
    ...options.rowOverrides,
  };

  return { id, row, meta, plaintext, segments };
}

/** Point the stub server at a built document. */
function serve(document: BuiltDocument): void {
  rowEnvelope = { success: true, data: document.row };
  segmentBodies = document.segments;
  segmentOutcomes = [];
}

/** Point the stub server at several documents at once, each answering for its own id. */
function serveMany(documents: BuiltDocument[]): void {
  for (const document of documents) {
    library.set(document.id, { document, refusals: [] });
  }
}

/** Make one document's segment `index` fail, with the sentence the server would send. */
function refuseSegment(id: string, index: number, refusal: SegmentRefusal): void {
  const entry = library.get(id);
  if (!entry) throw new Error(`no document ${id} is being served`);
  entry.refusals[index] = refusal;
}

function segmentRequests(): RecordedRequest[] {
  return requests.filter((request) => request.url.includes('/segments/'));
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

interface AdapterSlot {
  adapter?: typeof axios.defaults.adapter | undefined;
}
const axiosDefaults: AdapterSlot = axios.defaults;
const apiDefaults: AdapterSlot = api.defaults;
const originalGlobalAdapter = axios.defaults.adapter;
const originalApiAdapter = api.defaults.adapter;

let realDecrypt: typeof globalThis.crypto.subtle.decrypt;
let createElementSpy: ReturnType<typeof vi.spyOn>;

beforeEach(async () => {
  requests = [];
  rowEnvelope = null;
  segmentBodies = [];
  segmentOutcomes = [];
  library.clear();
  onRequest = null;
  savedFiles = [];
  onSaved = null;
  createdAnchors = [];
  unwrappedKeys = [];

  axios.defaults.adapter = adapter;
  api.defaults.adapter = adapter;

  // A PASS-THROUGH, never a stub: the real AES-GCM is what produces the value,
  // and what is recorded is the buffer itself, so a later `fill(0)` inside the
  // module is visible through this reference.
  realDecrypt = globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle);
  vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
    const result = await realDecrypt(...(args as Parameters<typeof realDecrypt>));
    if (result.byteLength === 32) unwrappedKeys.push(new Uint8Array(result));
    return result;
  });

  const createObjectURL = vi.fn((blob: Blob) => {
    savedFiles.push({ blob, filename: '' });
    return 'blob:document';
  });
  vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL: vi.fn() });

  const realCreateElement = document.createElement.bind(document);
  createElementSpy = vi
    .spyOn(document, 'createElement')
    .mockImplementation((tagName: string, elementOptions?: ElementCreationOptions) => {
      const element = realCreateElement(tagName, elementOptions);
      if (tagName === 'a') createdAnchors.push(element as HTMLAnchorElement);
      return element;
    });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    const saved = savedFiles[savedFiles.length - 1];
    if (saved) {
      saved.filename = this.download;
      onSaved?.(saved);
    }
  });

  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  useAuthStore.setState({ accessToken: 'access-token', vaultKey, isAuthenticated: true });
});

afterEach(() => {
  useAuthStore.setState({ vaultKey: null, mek: null, accessToken: null, isAuthenticated: false });
  axiosDefaults.adapter = originalGlobalAdapter;
  apiDefaults.adapter = originalApiAdapter;
  createElementSpy.mockRestore();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ===========================================================================
// Filenames
// ===========================================================================

describe('sanitizeDownloadFilename — a name a document carries is not a path', () => {
  it('replaces path separators so a traversal cannot survive into a save path', () => {
    expect(sanitizeDownloadFilename('../../etc/passwd')).toBe('.._.._etc_passwd');
    expect(sanitizeDownloadFilename('windows\\system32\\cmd.exe')).toBe('windows_system32_cmd.exe');
  });

  it('replaces a right-to-left override rather than deleting it, so the disguise shows', () => {
    // `report<U+202E>gnp.exe` displays as `reportexe.png`. Replaced, it reads as
    // what it is; deleted, it would read as the plausible `reportgnp.exe`.
    const disguised = `report${String.fromCharCode(0x202e)}gnp.exe`;
    expect(sanitizeDownloadFilename(disguised)).toBe('report_gnp.exe');
    expect(sanitizeDownloadFilename(disguised)).not.toContain(String.fromCharCode(0x202e));
  });

  it('replaces every bidirectional control, not only the override', () => {
    // Unicode's whole Bidi_Control set, U+061C included: the Arabic letter mark
    // reorders neutrals exactly as U+200F does and is the one a character class
    // assembled from memory leaves out.
    for (const code of [
      0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068,
      0x2069,
    ]) {
      expect(sanitizeDownloadFilename(`a${String.fromCharCode(code)}b.txt`)).toBe('a_b.txt');
    }
  });

  it('replaces C0 and C1 control characters', () => {
    expect(sanitizeDownloadFilename('two\nlines.txt')).toBe('two_lines.txt');
    expect(sanitizeDownloadFilename(`nul${String.fromCharCode(0)}.txt`)).toBe('nul_.txt');
    expect(sanitizeDownloadFilename(`del${String.fromCharCode(0x7f)}.txt`)).toBe('del_.txt');
    expect(sanitizeDownloadFilename(`c1${String.fromCharCode(0x9f)}.txt`)).toBe('c1_.txt');
  });

  it('trims trailing dots and spaces, which Windows would strip after the name was read', () => {
    expect(sanitizeDownloadFilename('evil.exe.')).toBe('evil.exe');
    expect(sanitizeDownloadFilename('notes.')).toBe('notes');
    expect(sanitizeDownloadFilename('spaced.txt   ')).toBe('spaced.txt');
  });

  it('keeps a leading dot, because a dotfile is an ordinary file', () => {
    expect(sanitizeDownloadFilename('.bashrc')).toBe('.bashrc');
    expect(sanitizeDownloadFilename('.env')).toBe('.env');
  });

  it('falls back to a constant only when nothing is left', () => {
    expect(sanitizeDownloadFilename('..')).toBe(FALLBACK_DOWNLOAD_FILENAME);
    expect(sanitizeDownloadFilename('   ')).toBe(FALLBACK_DOWNLOAD_FILENAME);
    // And not for a name that merely became underscores, which still tells the
    // user something about what they were handed.
    expect(sanitizeDownloadFilename('/')).toBe('_');
  });
});

// ===========================================================================
// The read path
// ===========================================================================

describe('readDocumentPlaintext — a document comes back byte for byte', () => {
  it('reassembles a multi-segment document exactly, one request per segment, in order', async () => {
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serve(built);

    const { meta, bytes: plaintext } = await readDocumentPlaintext(ID_A);

    expect(built.row.chunkCount).toBe(3);
    expect([...plaintext]).toEqual([...built.plaintext]);
    expect(meta.name).toBe('report.txt');
    expect(segmentRequests().map((request) => request.url)).toEqual([
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/2`,
    ]);
    // The plaintext was never sent anywhere: the only requests are the row read
    // and the three segment reads, and every one of them is a GET.
    expect(requests.every((request) => request.method === 'GET')).toBe(true);
  });

  it('reads a zero-byte document as one segment holding nothing but its tag', async () => {
    const built = await buildDocument({ plaintext: bytes(), chunkPlaintextBytes: 8 });
    serve(built);

    const { bytes: plaintext } = await readDocumentPlaintext(ID_A);

    expect(built.row.chunkCount).toBe(1);
    expect(built.row.ciphertextBytes).toBe(DOCUMENT_TAG_BYTES);
    expect(plaintext).toHaveLength(0);
    expect(segmentRequests()).toHaveLength(1);
  });

  it('accepts an id in upper case, because the row and the key derivation lower it', async () => {
    serve(await buildDocument());

    const { bytes: plaintext } = await readDocumentPlaintext(ID_A.toUpperCase());

    expect(plaintext).toHaveLength(20);
  });

  it('zeroes the document key when the read succeeds', async () => {
    serve(await buildDocument());

    await readDocumentPlaintext(ID_A);

    expect(unwrappedKeys).toHaveLength(1);
    expect(isAllZero(unwrappedKeys[0]!)).toBe(true);
  });

  it('zeroes the document key when the read fails part-way', async () => {
    serve(await buildDocument());
    segmentOutcomes = [null, 500];

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow();

    expect(unwrappedKeys).toHaveLength(1);
    expect(isAllZero(unwrappedKeys[0]!)).toBe(true);
  });

  it('refuses when the vault is locked, before it asks the server anything', async () => {
    useAuthStore.setState({ vaultKey: null });
    serve(await buildDocument());

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow(/Vault is locked/);

    expect(requests).toHaveLength(0);
  });

  it('refuses a 200 envelope that reports failure', async () => {
    rowEnvelope = { success: false, message: 'nope' };

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow(/Failed to read the document/);

    expect(segmentRequests()).toHaveLength(0);
  });

  it('refuses a row that does not satisfy the shared schema', async () => {
    const built = await buildDocument();
    // A salt one byte short is still valid base64 and still fits any generous
    // bound; the schema pins the byte count precisely so this is a 400-shaped
    // refusal rather than a decryption failure three requests later.
    rowEnvelope = {
      success: true,
      data: {
        ...built.row,
        streamSalt: cryptoService.arrayBufferToBase64(new Uint8Array(31).buffer),
      },
    };
    segmentBodies = built.segments;

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow();

    expect(segmentRequests()).toHaveLength(0);
  });
});

describe('readDocumentPlaintext — the four checks', () => {
  it('refuses a row describing a different document, and fetches no segment', async () => {
    // A COMPLETE, correctly sealed document — just not the one that was asked
    // for. Every later step would succeed on it: its key unwraps, its metadata
    // opens, its segments authenticate and its digest matches. Nothing but the
    // identity check stands between "right document" and "right request".
    const other = await buildDocument({ id: ID_B, name: 'someone-elses.txt' });
    serve(other);

    const error = await readDocumentPlaintext(ID_A).catch((raised: unknown) => raised);

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('identity');
    expect(segmentRequests()).toHaveLength(0);
  });

  it('refuses when the row framing disagrees with the authenticated copy, naming every field', async () => {
    // The sealed metadata says three segments of two plaintext bytes; the row
    // says one segment of eight. Both are internally consistent, so only the
    // comparison between them can catch it — and only the metadata copy is
    // authenticated.
    const built = await buildDocument({
      plaintext: ramp(6),
      chunkPlaintextBytes: 6,
      metaOverrides: { plaintextBytes: 6, chunkPlaintextBytes: 2, chunkCount: 3 },
    });
    serve(built);

    const error = await readDocumentPlaintext(ID_A).catch((raised: unknown) => raised);

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('framing');
    expect((error as DocumentIntegrityError).message).toContain('chunkPlaintextBytes');
    expect((error as DocumentIntegrityError).message).toContain('chunkCount');
    // Refused BEFORE a byte is fetched, which is the point of checking the row
    // against the blob rather than waiting for a segment not to open.
    expect(segmentRequests()).toHaveLength(0);
  });

  it('refuses a segment whose ciphertext was altered by a single bit', async () => {
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serve(built);
    const tampered = built.segments[1]!.slice() as DocumentBytes;
    tampered[0] = tampered[0]! ^ 0x01;
    segmentBodies = [built.segments[0]!, tampered, built.segments[2]!];

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow();

    // It stopped AT the bad segment rather than reading the rest first.
    expect(segmentRequests()).toHaveLength(2);
  });

  it('refuses a segment served at the wrong index, because the index is inside the nonce', async () => {
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serve(built);
    // Segment 0 and segment 1 swapped. Both are genuine ciphertext this client
    // sealed; neither opens at the other's position.
    segmentBodies = [built.segments[1]!, built.segments[0]!, built.segments[2]!];

    await expect(readDocumentPlaintext(ID_A)).rejects.toThrow();

    expect(segmentRequests()).toHaveLength(1);
  });

  it('refuses a document whose whole-file digest does not match the sealed one', async () => {
    // A self-inconsistent document: the segments are genuine and every one of
    // them authenticates, but the metadata records the digest of different
    // bytes. That is what a corrupt upload looks like, and the running hash is
    // the only check that spans segments and can see it.
    const built = await buildDocument({
      plaintext: ramp(20),
      chunkPlaintextBytes: 8,
      metaOverrides: { sha256: await sha256Hex(ramp(21)) },
    });
    serve(built);

    const error = await readDocumentPlaintext(ID_A).catch((raised: unknown) => raised);

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('digest');
    // Every segment WAS read and authenticated: the mismatch is not something a
    // per-segment check could have found.
    expect(segmentRequests()).toHaveLength(3);
  });
});

describe('streamDocumentPlaintext — the sink', () => {
  it('hands each verified segment over as it arrives and never buffers the file', async () => {
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serve(built);
    const seen: number[][] = [];

    const meta = await streamDocumentPlaintext(ID_A, {
      write: (segment) => {
        seen.push([...segment]);
        return Promise.resolve();
      },
      discard: () => Promise.resolve(),
    });

    expect(seen).toHaveLength(3);
    expect(seen.flat()).toEqual([...built.plaintext]);
    expect(meta.plaintextBytes).toBe(20);
  });

  it('asks the sink to discard when the digest fails, after it has already written', async () => {
    const built = await buildDocument({
      plaintext: ramp(20),
      chunkPlaintextBytes: 8,
      metaOverrides: { sha256: await sha256Hex(ramp(21)) },
    });
    serve(built);
    const order: string[] = [];

    await expect(
      streamDocumentPlaintext(ID_A, {
        write: () => {
          order.push('write');
          return Promise.resolve();
        },
        discard: () => {
          order.push('discard');
          return Promise.resolve();
        },
      }),
    ).rejects.toBeInstanceOf(DocumentIntegrityError);

    expect(order).toEqual(['write', 'write', 'write', 'discard']);
  });

  it('does not ask the sink to discard when nothing was written', async () => {
    const other = await buildDocument({ id: ID_B });
    serve(other);
    const discard = vi.fn(() => Promise.resolve());

    await expect(
      streamDocumentPlaintext(ID_A, { write: () => Promise.resolve(), discard }),
    ).rejects.toBeInstanceOf(DocumentIntegrityError);

    expect(discard).not.toHaveBeenCalled();
  });
});

describe('readDocumentPlaintext — cancellation', () => {
  it('stops before the first segment when the signal is aborted during the row read', async () => {
    serve(await buildDocument());
    const controller = new AbortController();
    onRequest = (request) => {
      if (!request.url.includes('/segments/')) controller.abort();
    };

    await expect(readDocumentPlaintext(ID_A, { signal: controller.signal })).rejects.toBeInstanceOf(
      DocumentDownloadCancelledError,
    );

    expect(segmentRequests()).toHaveLength(0);
  });

  it('stops between segments when the abort lands while a segment is being written', async () => {
    // The in-flight request is NOT what is cancelled here: segment 0 arrived and
    // was handed to the sink, and the lock landed while that write was running.
    // Only the loop's own re-check stands between that and sealing the next
    // segment under a key that is about to be zeroed.
    serve(await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 }));
    const controller = new AbortController();
    const written: number[] = [];

    await expect(
      streamDocumentPlaintext(
        ID_A,
        {
          write: (segment) => {
            written.push(...segment);
            controller.abort();
            return Promise.resolve();
          },
          discard: () => Promise.resolve(),
        },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(DocumentDownloadCancelledError);

    expect(written).toHaveLength(8);
    expect(segmentRequests()).toHaveLength(1);
  });

  it('stops between segments, leaving the rest of the document unread', async () => {
    serve(await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 }));
    const controller = new AbortController();
    onRequest = (request) => {
      if (request.url.endsWith('/segments/0')) controller.abort();
    };

    await expect(readDocumentPlaintext(ID_A, { signal: controller.signal })).rejects.toBeInstanceOf(
      DocumentDownloadCancelledError,
    );

    expect(segmentRequests()).toHaveLength(1);
  });
});

// ===========================================================================
// Saving
// ===========================================================================

describe('saveDocument — the in-memory path, where there is no save dialog', () => {
  it('saves the verified bytes under the freshly decrypted name', async () => {
    serve(await buildDocument({ name: 'quarterly report.txt', plaintext: ramp(20) }));

    const filename = await saveDocument({ id: ID_A, meta: (await buildDocument()).meta });

    expect(filename).toBe('quarterly report.txt');
    expect(savedFiles).toHaveLength(1);
    expect(savedFiles[0]!.filename).toBe('quarterly report.txt');
    expect(createdAnchors).toHaveLength(1);
    expect([...new Uint8Array(await savedFiles[0]!.blob.arrayBuffer())]).toEqual([...ramp(20)]);
    expect(savedFiles[0]!.blob.type).toBe('text/plain');
  });

  it('sanitises the name it saves under, not merely the one it suggested', async () => {
    serve(await buildDocument({ name: `..${'/'}invoice${String.fromCharCode(0x202e)}fdp.exe` }));

    const filename = await saveDocument({ id: ID_A, meta: (await buildDocument()).meta });

    expect(filename).toBe('.._invoice_fdp.exe');
    expect(savedFiles[0]!.filename).toBe('.._invoice_fdp.exe');
  });

  it('saves nothing at all when the document does not verify', async () => {
    serve(
      await buildDocument({
        plaintext: ramp(20),
        chunkPlaintextBytes: 8,
        metaOverrides: { sha256: await sha256Hex(ramp(21)) },
      }),
    );

    await expect(
      saveDocument({ id: ID_A, meta: (await buildDocument()).meta }),
    ).rejects.toBeInstanceOf(DocumentIntegrityError);

    expect(savedFiles).toHaveLength(0);
    expect(createdAnchors).toHaveLength(0);
  });
});

describe('saveDocument — the save-dialog path', () => {
  it('opens the dialog before the first request, with the sanitised name', async () => {
    const picker = installPicker({ name: 'chosen.txt' });
    const built = await buildDocument({ name: 'report/2026.txt', plaintext: ramp(20) });
    serve(built);

    const filename = await saveDocument({ id: ID_A, meta: built.meta });

    expect(filename).toBe('chosen.txt');
    expect(picker.suggestedNames).toEqual(['report_2026.txt']);
    // The dialog was opened before anything was fetched: `showSaveFilePicker`
    // needs transient activation, and a round trip to the server destroys it, so
    // a version of this that read the row first would throw a `SecurityError` in
    // a real browser and nowhere else.
    expect(picker.requestsWhenOpened).toEqual([0]);
    expect(requests.length).toBeGreaterThan(0);
    expect(picker.written).toEqual([...built.plaintext]);
    expect(picker.calls).toEqual(['write', 'write', 'write', 'close']);
    // Nothing was buffered into a Blob: the streaming path never touches the
    // anchor helper.
    expect(savedFiles).toHaveLength(0);
  });

  it('truncates the file to zero and commits it when the digest does not match', async () => {
    const picker = installPicker();
    const built = await buildDocument({
      plaintext: ramp(20),
      chunkPlaintextBytes: 8,
      metaOverrides: { sha256: await sha256Hex(ramp(21)) },
    });
    serve(built);

    const error = await saveDocument({ id: ID_A, meta: built.meta }).catch(
      (raised: unknown) => raised,
    );

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('digest');
    expect(picker.calls).toEqual(['write', 'write', 'write', 'truncate:0', 'close']);
    expect(picker.written).toEqual([]);
    // Not aborted: the file the user chose is committed EMPTY, so a path that
    // was written to says so instead of looking untouched.
    expect(picker.calls).not.toContain('abort');
  });

  it('aborts the stream, leaving the chosen file untouched, when the transfer fails', async () => {
    const picker = installPicker();
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serve(built);
    segmentOutcomes = [null, 500];

    await expect(saveDocument({ id: ID_A, meta: built.meta })).rejects.toThrow();

    expect(picker.calls).toEqual(['write', 'abort']);
    // Emptying a file the user already had, because a request failed, would be
    // destroying data in order to report an error.
    expect(picker.calls).not.toContain('truncate:0');
    expect(picker.calls).not.toContain('close');
  });

  it('reports a dismissed dialog as a cancellation and asks the server for nothing', async () => {
    installPicker({ dismiss: true });
    serve(await buildDocument());

    await expect(
      saveDocument({ id: ID_A, meta: (await buildDocument()).meta }),
    ).rejects.toBeInstanceOf(DocumentDownloadCancelledError);

    expect(requests).toHaveLength(0);
  });

  it('propagates a dialog failure that is not a dismissal', async () => {
    const picker = vi.fn(() => Promise.reject(new Error('Not allowed in this context')));
    vi.stubGlobal('showSaveFilePicker', picker);
    serve(await buildDocument());

    await expect(saveDocument({ id: ID_A, meta: (await buildDocument()).meta })).rejects.toThrow(
      /Not allowed/,
    );

    expect(requests).toHaveLength(0);
  });

  it('reports the read failure rather than a failure raised while tidying up', async () => {
    // A writable whose `abort` throws: the read's own failure is the one the
    // user needs, and a second one raised on the way out would hide it.
    vi.stubGlobal('showSaveFilePicker', () =>
      Promise.resolve({
        name: 'chosen.txt',
        createWritable: () =>
          Promise.resolve({
            write: () => Promise.resolve(),
            truncate: () => Promise.resolve(),
            close: () => Promise.resolve(),
            abort: () => Promise.reject(new Error('the stream is already broken')),
          }),
      }),
    );
    serve(await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 }));
    segmentOutcomes = [500];

    await expect(saveDocument({ id: ID_A, meta: (await buildDocument()).meta })).rejects.toThrow(
      /500/,
    );
  });
});

// ===========================================================================
// Saving all of them
// ===========================================================================

describe('streamDocumentPlaintext — a row the caller already holds', () => {
  /** A sink that keeps the verified segments. */
  function keeping(): { kept: number[]; sink: Parameters<typeof streamDocumentPlaintext>[1] } {
    const kept: number[] = [];
    return {
      kept,
      sink: {
        write: (segment) => {
          kept.push(...segment);
          return Promise.resolve();
        },
        discard: () => Promise.resolve(),
      },
    };
  }

  it('reads with the supplied row, asking the server only for the segments', async () => {
    const built = await buildDocument({ plaintext: ramp(20), chunkPlaintextBytes: 8 });
    serveMany([built]);
    const { kept, sink } = keeping();

    const meta = await streamDocumentPlaintext(ID_A, sink, { row: built.row });

    expect(meta).toEqual(built.meta);
    expect(kept).toEqual([...ramp(20)]);
    // NEGATIVE: the row was never fetched again.
    expect(requests.map((request) => request.url)).toEqual([
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/2`,
    ]);
  });

  it('refuses a supplied row that belongs to a different document, asking for nothing', async () => {
    const other = await buildDocument({ id: ID_B, name: 'someone-elses.txt' });
    serveMany([other]);
    const { kept, sink } = keeping();

    const error = await streamDocumentPlaintext(ID_A, sink, { row: other.row }).catch(
      (raised: unknown) => raised,
    );

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('identity');
    expect(requests).toEqual([]);
    expect(kept).toEqual([]);
  });

  it('refuses a supplied row whose framing disagrees with its sealed copy, before any segment', async () => {
    const built = await buildDocument({
      plaintext: ramp(6),
      chunkPlaintextBytes: 6,
      metaOverrides: { plaintextBytes: 6, chunkPlaintextBytes: 2, chunkCount: 3 },
    });
    serveMany([built]);
    const { sink } = keeping();

    const error = await streamDocumentPlaintext(ID_A, sink, { row: built.row }).catch(
      (raised: unknown) => raised,
    );

    expect(error).toBeInstanceOf(DocumentIntegrityError);
    expect((error as DocumentIntegrityError).failure).toBe('framing');
    expect(requests).toEqual([]);
  });
});

// ===========================================================================
// Where an archive goes
// ===========================================================================

/** A writable stream double that keeps the Blobs it is handed. */
function blobWritable(options: { failAbort?: boolean } = {}) {
  const calls: string[] = [];
  const parts: Blob[] = [];
  return {
    calls,
    parts,
    writable: {
      write: (chunk: Blob) => {
        calls.push('write');
        parts.push(chunk);
        return Promise.resolve();
      },
      close: () => {
        calls.push('close');
        return Promise.resolve();
      },
      abort: () => {
        calls.push('abort');
        return options.failAbort === true
          ? Promise.reject(new Error('the stream is already broken'))
          : Promise.resolve();
      },
    },
  };
}

describe('archiveFileName', () => {
  it('names the first archive by the UTC day, and each continuation by its part', () => {
    const moment = new Date('2026-10-23T23:30:00.000Z');
    expect(archiveFileName(moment, 1)).toBe('hvault-documents-2026-10-23.zip');
    expect(archiveFileName(moment, 2)).toBe('hvault-documents-2026-10-23-part-2.zip');
  });
});

describe('openArchiveTarget', () => {
  it('builds the archive in memory where there is no save dialog, and hands it over as ONE download', async () => {
    const target = await openArchiveTarget('archive.zip');

    expect(target).toMatchObject({
      kind: 'download',
      name: 'archive.zip',
      limitBytes: IN_MEMORY_ARCHIVE_LIMIT_BYTES,
    });
    await target!.write(new Blob([new Uint8Array([1, 2])]));
    await target!.write(new Blob([new Uint8Array([3])]));
    // Nothing reaches the browser until the archive is finished.
    expect(savedFiles).toEqual([]);

    await target!.commit();

    expect(savedFiles).toHaveLength(1);
    expect(savedFiles[0]!.filename).toBe('archive.zip');
    expect(savedFiles[0]!.blob.type).toBe('application/zip');
    expect([...new Uint8Array(await savedFiles[0]!.blob.arrayBuffer())]).toEqual([1, 2, 3]);
  });

  it('drops an abandoned in-memory archive without handing anything to the browser', async () => {
    const target = await openArchiveTarget('archive.zip');
    await target!.write(new Blob([new Uint8Array([1])]));

    await target!.discard();

    expect(savedFiles).toEqual([]);
  });

  it('opens the save dialog synchronously, before the first await, and writes into the chosen file', async () => {
    const double = blobWritable();
    const handle = { name: 'chosen.zip', createWritable: () => Promise.resolve(double.writable) };
    const picker = vi.fn(() => Promise.resolve(handle));
    vi.stubGlobal('showSaveFilePicker', picker);

    const opening = openArchiveTarget('hvault-documents-2026-10-23.zip');
    // Called inside the call itself, where the click's activation still holds.
    expect(picker).toHaveBeenCalledTimes(1);
    expect(picker).toHaveBeenCalledWith({
      suggestedName: 'hvault-documents-2026-10-23.zip',
      startIn: 'downloads',
      types: [{ description: 'ZIP archive', accept: { 'application/zip': ['.zip'] } }],
    });
    const target = await opening;

    expect(target).toMatchObject({
      kind: 'file',
      name: 'chosen.zip',
      limitBytes: ZIP32_MAX_ARCHIVE_BYTES,
    });
    const chunk = new Blob([new Uint8Array([9])]);
    await target!.write(chunk);
    await target!.commit();
    expect(double.parts).toEqual([chunk]);
    expect(double.calls).toEqual(['write', 'close']);
    // Nothing went through the in-memory download.
    expect(savedFiles).toEqual([]);
  });

  it('drops an abandoned file archive by aborting the stream, and never rejects doing so', async () => {
    for (const failAbort of [false, true]) {
      const double = blobWritable({ failAbort });
      vi.stubGlobal(
        'showSaveFilePicker',
        vi.fn(() =>
          Promise.resolve({
            name: 'x.zip',
            createWritable: () => Promise.resolve(double.writable),
          }),
        ),
      );
      const target = await openArchiveTarget('x.zip');

      await expect(target!.discard()).resolves.toBeUndefined();
      expect(double.calls).toEqual(['abort']);
    }
  });

  it('answers a dismissed dialog with null, and lets any other refusal through', async () => {
    const dismissal = new Error('The user aborted a request.');
    dismissal.name = 'AbortError';
    vi.stubGlobal(
      'showSaveFilePicker',
      vi.fn(() => Promise.reject(dismissal)),
    );
    await expect(openArchiveTarget('x.zip')).resolves.toBeNull();

    const refusal = new Error('Must be handling a user gesture to show a file picker.');
    refusal.name = 'SecurityError';
    vi.stubGlobal(
      'showSaveFilePicker',
      vi.fn(() => Promise.reject(refusal)),
    );
    await expect(openArchiveTarget('x.zip')).rejects.toBe(refusal);
  });
});

describe('waitAbortably', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('settles after the wait, and not a moment before', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const signal = new AbortController().signal;
    const removeListener = vi.spyOn(signal, 'removeEventListener');
    let settled = false;
    void waitAbortably(5_000, signal).then(() => {
      settled = true;
    });

    await vi.advanceTimersByTimeAsync(4_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    // It does not leave its listener behind on a signal that outlives it.
    expect(removeListener).toHaveBeenCalledWith('abort', expect.any(Function));
  });

  it('settles at once when the signal aborts, and leaves no timer behind', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const controller = new AbortController();
    let settled = false;
    void waitAbortably(5_000, controller.signal).then(() => {
      settled = true;
    });

    controller.abort();
    await Promise.resolve();

    expect(settled).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});

// ===========================================================================
// Archiving a library
// ===========================================================================

describe('archiveDocuments — every verified document an entry of one ZIP', () => {
  /** Three documents, each its own id, name and bytes, multi-segment on purpose. */
  async function threeDocuments(): Promise<BuiltDocument[]> {
    const built = [
      await buildDocument({ id: ID_A, name: 'alpha.txt', plaintext: ramp(20) }),
      await buildDocument({ id: ID_B, name: 'beta.txt', plaintext: ramp(12) }),
      await buildDocument({ id: ID_C, name: 'gamma.txt', plaintext: ramp(8) }),
    ];
    serveMany(built);
    return built;
  }

  /** The candidate the store hands in, for a document that opened. */
  function candidate(built: BuiltDocument, folderId?: string): BulkDownloadCandidate {
    return { id: built.id, meta: built.meta, _raw: built.row, ...(folderId ? { folderId } : {}) };
  }

  function urls(): string[] {
    return requests.map((request) => request.url);
  }

  /** The run's options, with a fresh signal and allocator unless given. */
  function options(overrides: Partial<ArchiveDocumentsOptions> = {}): ArchiveDocumentsOptions {
    return {
      signal: new AbortController().signal,
      allocator: new ArchivePathAllocator([]),
      ...overrides,
    };
  }

  /** The in-memory target, exactly as a browser without a save dialog gets it. */
  async function downloadTarget(): Promise<ArchiveTarget> {
    return (await openArchiveTarget('archive.zip'))!;
  }

  /** The one archive the run handed to the browser, read by the independent reader. */
  async function savedArchive() {
    expect(savedFiles).toHaveLength(1);
    return readArchive(new Uint8Array(await savedFiles[0]!.blob.arrayBuffer()));
  }

  /** A target that records what happens to it, and can be made to fail. */
  function recordingTarget(
    overrides: {
      limitBytes?: number;
      failWrite?: number;
      failCommit?: boolean;
      onWrite?: () => void;
    } = {},
  ) {
    const calls: string[] = [];
    const parts: Blob[] = [];
    let writes = 0;
    const target: ArchiveTarget = {
      kind: 'file',
      name: 'chosen.zip',
      limitBytes: overrides.limitBytes ?? ZIP32_MAX_ARCHIVE_BYTES,
      write: (chunk) => {
        writes += 1;
        calls.push('write');
        if (writes === overrides.failWrite) {
          return Promise.reject(new Error('There is not enough space on the disk.'));
        }
        parts.push(chunk);
        overrides.onWrite?.();
        return Promise.resolve();
      },
      commit: () => {
        calls.push('commit');
        return overrides.failCommit === true
          ? Promise.reject(new Error('The file could not be saved.'))
          : Promise.resolve();
      },
      discard: () => {
        calls.push('discard');
        return Promise.resolve();
      },
    };
    return { target, calls, parts };
  }

  it('archives every document in order, reading only segments, into ONE download read back byte for byte', async () => {
    const built = await threeDocuments();

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options(),
    );

    expect(result).toEqual({
      total: 3,
      savedCount: 3,
      failures: [],
      stopped: 'complete',
      archive: { name: 'archive.zip', kind: 'download' },
    });
    // One document strictly after the other, and no row request at all: the
    // list's own row is what each read used.
    expect(urls()).toEqual([
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/2`,
      `/documents/${ID_B}/segments/0`,
      `/documents/${ID_B}/segments/1`,
      `/documents/${ID_C}/segments/0`,
    ]);
    const entries = await savedArchive();
    expect(entries.map((entry) => entry.name)).toEqual(['alpha.txt', 'beta.txt', 'gamma.txt']);
    expect([...entries[0]!.bytes]).toEqual([...ramp(20)]);
    expect([...entries[1]!.bytes]).toEqual([...ramp(12)]);
    expect([...entries[2]!.bytes]).toEqual([...ramp(8)]);
    // Each entry carries the time sealed into the document's metadata.
    expect(
      entries[0]!.entry.getLastModDate({ timezone: 'local', forceDosFormat: true }).toISOString(),
    ).toBe('2026-01-01T00:00:00.000Z');
    expect(savedFiles[0]!.blob.type).toBe('application/zip');
  });

  it('leaves the vault unlocked and every document key zeroed', async () => {
    const built = await threeDocuments();

    await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options(),
    );

    expect(useAuthStore.getState().vaultKey).not.toBeNull();
    expect(unwrappedKeys).toHaveLength(3);
    expect(unwrappedKeys.every(isAllZero)).toBe(true);
  });

  it('files each document under its folders, and the rest at the archive root', async () => {
    const built = await threeDocuments();
    const folders = [
      {
        id: '66c0f1a2b3c4d5e6f7a8b901',
        name: 'Work',
        sortOrder: 0,
        createdAt: '',
        updatedAt: '',
        _raw: {},
      },
      {
        id: '66c0f1a2b3c4d5e6f7a8b902',
        name: 'Contracts',
        parentId: '66c0f1a2b3c4d5e6f7a8b901',
        sortOrder: 0,
        createdAt: '',
        updatedAt: '',
        _raw: {},
      },
    ] as unknown as ConstructorParameters<typeof ArchivePathAllocator>[0];

    await archiveDocuments(
      [
        candidate(built[0]!, '66c0f1a2b3c4d5e6f7a8b902'),
        candidate(built[1]!, '66c0f1a2b3c4d5e6f7a8b901'),
        candidate(built[2]!),
      ],
      await downloadTarget(),
      options({ allocator: new ArchivePathAllocator(folders) }),
    );

    expect((await savedArchive()).map((entry) => entry.name)).toEqual([
      'Work/Contracts/alpha.txt',
      'Work/beta.txt',
      'gamma.txt',
    ]);
  });

  it('keeps going when one stored file is missing, names it, and leaves it out of the archive', async () => {
    const built = await threeDocuments();
    refuseSegment(ID_B, 0, { status: 404, message: 'The stored file is no longer available.' });

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options(),
    );

    expect(result).toMatchObject({ total: 3, savedCount: 2, stopped: 'complete' });
    expect(result.failures).toEqual([
      { id: ID_B, name: 'beta.txt', reason: 'The stored file is no longer available.' },
    ]);
    expect((await savedArchive()).map((entry) => entry.name)).toEqual(['alpha.txt', 'gamma.txt']);
  });

  it('never puts a document that failed its checksum into the archive', async () => {
    const good = await buildDocument({ id: ID_A, name: 'alpha.txt', plaintext: ramp(20) });
    const tampered = await buildDocument({
      id: ID_B,
      name: 'beta.txt',
      plaintext: ramp(12),
      metaOverrides: { sha256: await sha256Hex(ramp(13)) },
    });
    serveMany([good, tampered]);

    const result = await archiveDocuments(
      [candidate(good), candidate(tampered)],
      await downloadTarget(),
      options(),
    );

    expect(result).toMatchObject({ total: 2, savedCount: 1, stopped: 'complete' });
    expect(result.failures[0]).toMatchObject({ id: ID_B, name: 'beta.txt' });
    expect(result.failures[0]?.reason).toMatch(/did not match the checksum/);
    // Every segment of it authenticated, and still not a byte of it is in the file.
    const entries = await savedArchive();
    expect(entries.map((entry) => entry.name)).toEqual(['alpha.txt']);
  });

  it('refuses a degraded row up front, by the name the list gives it, without a request', async () => {
    const built = await threeDocuments();

    const result = await archiveDocuments(
      [candidate(built[0]!), { id: ID_B, meta: null, _raw: built[1]!.row }, candidate(built[2]!)],
      await downloadTarget(),
      options(),
    );

    expect(result).toMatchObject({ total: 3, savedCount: 2, stopped: 'complete' });
    expect(result.failures).toEqual([
      {
        id: ID_B,
        name: UNOPENABLE_DOCUMENT_NAME,
        reason:
          'Its details could not be opened with this vault key, so there was nothing to download.',
      },
    ]);
    expect(urls().some((url) => url.includes(ID_B))).toBe(false);
  });

  it('refuses a row already claimed for permanent deletion, without a request', async () => {
    const built = await threeDocuments();

    const result = await archiveDocuments(
      [{ ...candidate(built[0]!), purgePending: true }, candidate(built[1]!)],
      await downloadTarget(),
      options(),
    );

    expect(result).toMatchObject({ total: 2, savedCount: 1, stopped: 'complete' });
    expect(result.failures[0]).toMatchObject({ id: ID_A, name: 'alpha.txt' });
    expect(result.failures[0]?.reason).toMatch(/being permanently deleted/);
    expect(urls().some((url) => url.includes(ID_A))).toBe(false);
  });

  it('waits out a short rate limit and reads the document again from its first segment, byte for byte', async () => {
    const built = await threeDocuments();
    refuseSegment(ID_A, 1, {
      status: 429,
      message: 'Too many requests',
      headers: { 'retry-after': '5' },
      remaining: 1,
    });
    const waits: number[] = [];

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options({
        wait: (ms) => {
          waits.push(ms);
          return Promise.resolve();
        },
      }),
    );

    expect(waits).toEqual([5_000]);
    expect(result).toMatchObject({ total: 3, savedCount: 3, failures: [], stopped: 'complete' });
    expect(urls().slice(0, 5)).toEqual([
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/2`,
    ]);
    // The refused attempt's first segment is NOT in front of the retried one's.
    const entries = await savedArchive();
    expect([...entries[0]!.bytes]).toEqual([...ramp(20)]);
  });

  it('stops as rate-limited after three short waits for one document, finishing the archive', async () => {
    const built = await threeDocuments();
    refuseSegment(ID_B, 0, {
      status: 429,
      message: 'Too many requests',
      headers: { 'retry-after': '5' },
    });
    const waits: number[] = [];

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options({
        wait: (ms) => {
          waits.push(ms);
          return Promise.resolve();
        },
      }),
    );

    expect(waits).toEqual([5_000, 5_000, 5_000]);
    expect(result).toMatchObject({
      total: 3,
      savedCount: 1,
      failures: [],
      stopped: 'rate-limited',
    });
    expect(result.stoppedDetail).toBe('Too many attempts. Please try again in 5 seconds.');
    expect((await savedArchive()).map((entry) => entry.name)).toEqual(['alpha.txt']);
    expect(urls().some((url) => url.includes(ID_C))).toBe(false);
  });

  it.each([
    [
      'a wait longer than it sits through',
      { 'retry-after': '900' },
      'Too many attempts. Please try again in 15 minutes.',
    ],
    ['no wait at all', {}, 'Too many attempts. Please wait a moment and try again.'],
  ])(
    'stops as rate-limited at once when the server asks for %s',
    async (_case, headers, detail) => {
      const built = await threeDocuments();
      refuseSegment(ID_B, 0, { status: 429, message: 'Too many requests', headers });
      const wait = vi.fn(() => Promise.resolve());

      const result = await archiveDocuments(
        built.map((b) => candidate(b)),
        await downloadTarget(),
        options({ wait }),
      );

      expect(wait).not.toHaveBeenCalled();
      expect(result).toMatchObject({
        savedCount: 1,
        failures: [],
        stopped: 'rate-limited',
        stoppedDetail: detail,
      });
      expect(result.archive).toEqual({ name: 'archive.zip', kind: 'download' });
    },
  );

  it('stops without reading again when Stop is pressed during a wait', async () => {
    const built = await threeDocuments();
    refuseSegment(ID_B, 0, {
      status: 429,
      message: 'Too many requests',
      headers: { 'retry-after': '5' },
    });
    const controller = new AbortController();

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options({
        signal: controller.signal,
        wait: () => {
          controller.abort();
          return Promise.resolve();
        },
      }),
    );

    expect(result).toMatchObject({ savedCount: 1, failures: [], stopped: 'stopped' });
    expect(urls().filter((url) => url.includes(ID_B))).toHaveLength(1);
    expect((await savedArchive()).map((entry) => entry.name)).toEqual(['alpha.txt']);
  });

  it('stops without reading again when the vault locks during a wait', async () => {
    const built = await threeDocuments();
    refuseSegment(ID_B, 0, {
      status: 429,
      message: 'Too many requests',
      headers: { 'retry-after': '5' },
    });

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options({
        wait: () => {
          useAuthStore.setState({ vaultKey: null });
          return Promise.resolve();
        },
      }),
    );

    expect(result).toMatchObject({ savedCount: 1, failures: [], stopped: 'vault-locked' });
    expect(urls().filter((url) => url.includes(ID_B))).toHaveLength(1);
  });

  it.each([
    [
      'a sign-out (the store cleared, the key not yet)',
      () => useDocumentsStore.getState().clearStore(),
    ],
    ['a lock', () => useAuthStore.setState({ vaultKey: null })],
  ])(
    'drops the document a %s lands in, and finishes the archive with the rest',
    async (_case, interrupt) => {
      const built = await threeDocuments();
      // Lands while beta's first segment is on the wire: the segment still
      // decrypts, and is refused at the write.
      onRequest = (request) => {
        if (request.url === `/documents/${ID_B}/segments/0`) interrupt();
      };

      const result = await archiveDocuments(
        built.map((b) => candidate(b)),
        await downloadTarget(),
        options(),
      );

      expect(result).toMatchObject({
        total: 3,
        savedCount: 1,
        failures: [],
        stopped: 'vault-locked',
      });
      expect((await savedArchive()).map((entry) => entry.name)).toEqual(['alpha.txt']);
      expect(urls().some((url) => url.includes(ID_C))).toBe(false);
      // Only the first segment of the interrupted document was ever asked for.
      expect(urls().filter((url) => url.includes(ID_B))).toEqual([`/documents/${ID_B}/segments/0`]);
    },
  );

  it.each([
    ['a sign-out', () => useDocumentsStore.getState().clearStore()],
    ['a lock', () => useAuthStore.setState({ vaultKey: null })],
  ])(
    'finishes the archive when %s lands between two documents, reading nothing more',
    async (_case, interrupt) => {
      const built = await threeDocuments();
      // Lands while alpha's entry is being written, after its read has finished,
      // so the check that catches it is the one at the top of the loop.
      const { target, parts, calls } = recordingTarget({ onWrite: interrupt });

      const result = await archiveDocuments(
        built.map((b) => candidate(b)),
        target,
        options(),
      );

      expect(result).toMatchObject({
        total: 3,
        savedCount: 1,
        failures: [],
        stopped: 'vault-locked',
      });
      expect(urls().some((url) => url.includes(ID_B))).toBe(false);
      expect(calls[calls.length - 1]).toBe('commit');
      const entries = await readArchive(new Uint8Array(await new Blob(parts).arrayBuffer()));
      expect(entries.map((entry) => entry.name)).toEqual(['alpha.txt']);
    },
  );

  it('finishes the archive when Stop lands between two documents, without asking for the rest', async () => {
    const built = await threeDocuments();
    const controller = new AbortController();
    // Pressed while alpha's entry is being written, so the stop lands between
    // documents: the ONLY path to the check at the top of the loop.
    const { target, parts, calls } = recordingTarget({
      onWrite: () => {
        controller.abort();
      },
    });

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      target,
      options({ signal: controller.signal }),
    );

    expect(result).toMatchObject({
      total: 3,
      savedCount: 1,
      failures: [],
      stopped: 'stopped',
      archive: { name: 'chosen.zip', kind: 'file' },
    });
    expect(urls().some((url) => url.includes(ID_B))).toBe(false);
    expect(calls[calls.length - 1]).toBe('commit');
    const entries = await readArchive(new Uint8Array(await new Blob(parts).arrayBuffer()));
    expect(entries.map((entry) => entry.name)).toEqual(['alpha.txt']);
  });

  it('stops at once, reading nothing more, when Stop lands inside a document', async () => {
    const built = await threeDocuments();
    const controller = new AbortController();
    onRequest = (request) => {
      if (request.url === `/documents/${ID_B}/segments/0`) controller.abort();
    };

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      await downloadTarget(),
      options({ signal: controller.signal }),
    );

    expect(result).toMatchObject({ savedCount: 1, failures: [], stopped: 'stopped' });
    expect((await savedArchive()).map((entry) => entry.name)).toEqual(['alpha.txt']);
    expect(urls().some((url) => url.includes(ID_C))).toBe(false);
  });

  it('stops as archive-full when the next document would pass the size limit, leaving it unread', async () => {
    const built = await threeDocuments();
    // Room for alpha's entry and the archive's tail, and not one byte more.
    const { target, parts } = recordingTarget({ limitBytes: 30 + 9 + 20 + 46 + 9 + 22 });

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      target,
      options(),
    );

    expect(result).toMatchObject({
      total: 3,
      savedCount: 1,
      failures: [],
      stopped: 'archive-full',
    });
    expect(urls().some((url) => url.includes(ID_B))).toBe(false);
    const archive = new Uint8Array(await new Blob(parts).arrayBuffer());
    expect(archive).toHaveLength(30 + 9 + 20 + 46 + 9 + 22);
    expect((await readArchive(archive)).map((entry) => entry.name)).toEqual(['alpha.txt']);
  });

  it.each([
    ['a write', { failWrite: 3 }, 'There is not enough space on the disk.'],
    ['the save', { failCommit: true }, 'The file could not be saved.'],
  ] as const)(
    'drops the archive, gives its names back, and counts nothing saved when %s fails',
    async (_case, failure, detail) => {
      const built = await threeDocuments();
      refuseSegment(ID_C, 0, { status: 404, message: 'The stored file is no longer available.' });
      const allocator = new ArchivePathAllocator([]);
      const { target, calls } = recordingTarget(failure);

      const result = await archiveDocuments(
        built.map((b) => candidate(b)),
        target,
        options({ allocator }),
      );

      expect(result).toEqual({
        total: 3,
        savedCount: 0,
        failures: [],
        stopped: 'save-failed',
        stoppedDetail: detail,
        archive: null,
      });
      expect(calls[calls.length - 1]).toBe('discard');
      // The names this archive had taken are free again for a retry.
      expect(allocator.place('alpha.txt', undefined).path).toBe('alpha.txt');
    },
  );

  it('keeps the names of a saved archive when a later archive of the run is thrown away', async () => {
    const built = await threeDocuments();
    const allocator = new ArchivePathAllocator([]);
    await archiveDocuments([candidate(built[0]!)], await downloadTarget(), options({ allocator }));

    const second = await archiveDocuments(
      [candidate(built[1]!)],
      recordingTarget({ failWrite: 1 }).target,
      options({ allocator }),
    );

    expect(second.stopped).toBe('save-failed');
    // alpha.txt went out in the saved archive and stays taken for the rest of the
    // run; beta.txt, from the archive that was dropped, is free again.
    expect(allocator.place('alpha.txt', undefined).path).toBe('alpha (2).txt');
    expect(allocator.place('beta.txt', undefined).path).toBe('beta.txt');
  });

  it('saves no archive at all when nothing verified, and still names every refusal', async () => {
    const built = await threeDocuments();
    for (const id of [ID_A, ID_B, ID_C]) {
      refuseSegment(id, 0, { status: 404, message: 'The stored file is no longer available.' });
    }
    const { target, calls } = recordingTarget();
    const finishing = vi.fn();

    const result = await archiveDocuments(
      built.map((b) => candidate(b)),
      target,
      options({ onFinishing: finishing }),
    );

    expect(result).toMatchObject({ total: 3, savedCount: 0, stopped: 'complete', archive: null });
    expect(result.failures.map((failure) => failure.id)).toEqual([ID_A, ID_B, ID_C]);
    expect(calls).toEqual(['discard']);
    expect(finishing).not.toHaveBeenCalled();
  });

  it('reports an empty list as a finished run that saved nothing and asked for nothing', async () => {
    const { target, calls } = recordingTarget();

    const result = await archiveDocuments([], target, options());

    expect(result).toEqual({
      total: 0,
      savedCount: 0,
      failures: [],
      stopped: 'complete',
      archive: null,
    });
    expect(requests).toEqual([]);
    expect(calls).toEqual(['discard']);
  });

  it('reports each document before it is read, and the finishing once before the save', async () => {
    const built = await threeDocuments();
    const seen: string[] = [];
    const { target, calls } = recordingTarget();

    await archiveDocuments(
      built.map((b) => candidate(b)),
      target,
      options({
        onProgress: (progress) => {
          seen.push(
            `${String(progress.index)}/${String(progress.total)} ${progress.name} after ${String(requests.length)}`,
          );
        },
        onFinishing: () => {
          seen.push(`finishing after ${String(calls.length)} writes`);
        },
      }),
    );

    expect(seen).toEqual([
      '1/3 alpha.txt after 0',
      '2/3 beta.txt after 3',
      '3/3 gamma.txt after 5',
      // Header plus one chunk per segment, per document: 4 + 3 + 2.
      'finishing after 9 writes',
    ]);
    expect(calls.slice(-2)).toEqual(['write', 'commit']);
  });

  it.each([
    ['complete', 3],
    ['stopped', 1],
    ['vault-locked', 1],
    ['rate-limited', 1],
    ['archive-full', 1],
    ['save-failed', 0],
  ] as const)(
    'consumes exactly savedCount + failures.length rows when it ends as %s',
    async (stopped, consumed) => {
      // THE identity the panel's Continue depends on: it resumes at
      // `targets.slice(savedCount + failures.length)`.
      const built = await threeDocuments();
      const controller = new AbortController();
      let target = await downloadTarget();
      if (stopped === 'stopped') {
        onRequest = (request) => {
          if (request.url === `/documents/${ID_B}/segments/0`) controller.abort();
        };
      }
      if (stopped === 'vault-locked') {
        onRequest = (request) => {
          if (request.url === `/documents/${ID_B}/segments/0`)
            useAuthStore.setState({ vaultKey: null });
        };
      }
      if (stopped === 'rate-limited')
        refuseSegment(ID_B, 0, { status: 429, message: 'Too many requests' });
      if (stopped === 'archive-full')
        target = recordingTarget({ limitBytes: 30 + 9 + 20 + 46 + 9 + 22 }).target;
      if (stopped === 'save-failed') target = recordingTarget({ failWrite: 3 }).target;

      const result = await archiveDocuments(
        built.map((b) => candidate(b)),
        target,
        options({ signal: controller.signal }),
      );

      expect(result.stopped).toBe(stopped);
      expect(result.savedCount + result.failures.length).toBe(consumed);
    },
  );
});
