/**
 * Tests for `services/documents/download.ts` — reading a stored document back.
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

// ---------------------------------------------------------------------------
// The stub server
// ---------------------------------------------------------------------------

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';

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

function ok(data: unknown, config: AxiosResponse['config']): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function fail(status: number, config: AxiosResponse['config']): Promise<never> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(status)}`,
      AxiosError.ERR_BAD_REQUEST,
      config as InternalAxiosRequestConfig,
      undefined,
      {
        status,
        statusText: 'Error',
        data: { success: false, message: 'nope', statusCode: status },
        headers: {},
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

  const segment = /^\/documents\/[a-f0-9]{24}\/segments\/(\d+)$/.exec(url);
  if (segment) {
    const index = Number(segment[1]);
    const outcome = segmentOutcomes[index] ?? null;
    if (outcome !== null) return fail(outcome, config);
    const body = segmentBodies[index];
    if (!body) return fail(404, config);
    // A real response body is an ArrayBuffer, because `responseType` is
    // `'arraybuffer'`. A copy, so a test cannot observe the module writing back
    // into the fixture it was handed.
    return Promise.resolve(ok(body.slice().buffer, config));
  }

  if (/^\/documents\/[a-f0-9]{24}$/.test(url) && method === 'GET') {
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
  onRequest = null;
  savedFiles = [];
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
    if (saved) saved.filename = this.download;
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
