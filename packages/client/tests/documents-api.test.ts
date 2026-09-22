/**
 * Tests for the document store's API service (`services/api/documentsApi.ts`).
 *
 * These wrappers hold no logic, and that is exactly why they are worth pinning:
 * the request each one builds IS the contract with the server, so a wrong verb, a
 * wrong path segment, a missing header or a body sent as JSON is a shippable bug
 * that no other test in this package would notice. The shared axios client is
 * mocked at its boundary so nothing here touches the network, and every assertion
 * is about what was handed to axios.
 *
 * Two request shapes carry more than a URL and get their own cases: the part
 * upload (binary body, an overridden content type, the digest header, an abort
 * signal and a progress callback) and the segment read (`responseType:
 * 'arraybuffer'`, because the default `'json'` would hand ciphertext to
 * `JSON.parse`).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockGet, mockPost, mockPut, mockDelete } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockPut: vi.fn(),
  mockDelete: vi.fn(),
}));

vi.mock('../src/services/api/client', () => ({
  api: {
    get: (...args: unknown[]) => mockGet(...args),
    post: (...args: unknown[]) => mockPost(...args),
    put: (...args: unknown[]) => mockPut(...args),
    delete: (...args: unknown[]) => mockDelete(...args),
  },
  clearCsrfToken: vi.fn(),
  ensureCsrfToken: vi.fn(),
}));

import { MAX_DOCUMENTS_PER_ROTATION } from '@hvault/shared';
import {
  DOCUMENT_PAGE_SIZE,
  MAX_DOCUMENT_PAGES,
  PART_DIGEST_HEADER,
  abortDocumentUploadApi,
  completeDocumentUploadApi,
  deleteDocumentApi,
  emptyDocumentTrashApi,
  getDocumentApi,
  getDocumentSegmentApi,
  getDocumentUploadApi,
  getDocumentUsageApi,
  initDocumentUploadApi,
  listDocumentTrashApi,
  listDocumentUploadsApi,
  listDocumentsApi,
  purgeDocumentApi,
  restoreDocumentApi,
  updateDocumentApi,
  uploadDocumentPartApi,
} from '../src/services/api/documentsApi.js';

const DOC_ID = '66c0f1a2b3c4d5e6f7a8b9c0';

beforeEach(() => {
  mockGet.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockPost.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockPut.mockReset().mockResolvedValue({ data: { success: true, data: null } });
  mockDelete.mockReset().mockResolvedValue({ data: { success: true, data: null } });
});

describe('the page ceiling both document walks clamp to', () => {
  it('reaches every row an account can actually hold', () => {
    // The ceiling exists to stop a walk following an inflated `totalPages`, and it
    // has to be derived from how many rows an account can ACTUALLY hold rather
    // than from the limit an upload is refused at. Those differ: the count is
    // checked only when a transfer is opened, so several concurrent transfers pass
    // the same reading and all commit. Derived from the advertised limit, this
    // ceiling stops one page short on exactly those accounts — silently, which
    // costs two separate things: the rotation walk drops rows it may never drop
    // and the account can never rotate its vault key again, and the list view
    // never shows those documents at all, so nobody can open, download or delete
    // them while their bytes keep counting against the quota.
    expect(MAX_DOCUMENT_PAGES * DOCUMENT_PAGE_SIZE).toBeGreaterThanOrEqual(
      MAX_DOCUMENTS_PER_ROTATION,
    );
    // And no more than one page of slack past it, so the ceiling stays a bound
    // rather than a number nobody derived.
    expect((MAX_DOCUMENT_PAGES - 1) * DOCUMENT_PAGE_SIZE).toBeLessThan(MAX_DOCUMENTS_PER_ROTATION);
  });
});

describe('documentsApi — collection routes', () => {
  it('lists documents with its query parameters passed through', async () => {
    await listDocumentsApi({ page: 2, limit: 200, favorite: true, sortBy: 'updatedAt' });

    expect(mockGet).toHaveBeenCalledWith('/documents', {
      params: { page: 2, limit: 200, favorite: true, sortBy: 'updatedAt' },
    });
  });

  it('lists documents with no parameters at all when none are given', async () => {
    await listDocumentsApi();

    expect(mockGet).toHaveBeenCalledWith('/documents', { params: undefined });
  });

  it('reads the trash from its OWN route rather than a flag on the list', async () => {
    await listDocumentTrashApi({ sortBy: 'deletedAt' });

    expect(mockGet).toHaveBeenCalledWith('/documents/trash', {
      params: { sortBy: 'deletedAt' },
    });
    // The negative that matters: trashed documents are a separate route, exactly
    // as trashed vault items are, so nothing here may reach the active list.
    expect(mockGet).not.toHaveBeenCalledWith('/documents', expect.anything());
  });

  it('reads usage', async () => {
    await getDocumentUsageApi();

    expect(mockGet).toHaveBeenCalledWith('/documents/usage');
  });

  it('empties the trash with DELETE on the two-segment literal path', async () => {
    await emptyDocumentTrashApi();

    expect(mockDelete).toHaveBeenCalledWith('/documents/trash/empty');
  });
});

describe('documentsApi — upload lifecycle', () => {
  it('lists the caller transfers', async () => {
    await listDocumentUploadsApi();

    expect(mockGet).toHaveBeenCalledWith('/documents/uploads');
  });

  it('initiates a transfer with the wrapped key, the framing and the declared size', async () => {
    const body = {
      encryptedDek: 'dek',
      dekIv: 'iv',
      dekTag: 'tag',
      streamSalt: 'c2FsdA==',
      noncePrefix: 'cHJlZml4',
      declaredPlaintextBytes: 1234,
      declaredChunkCount: 1,
    };

    await initDocumentUploadApi(body);

    expect(mockPost).toHaveBeenCalledWith('/documents/uploads', body);
  });

  it('reads one staging row', async () => {
    await getDocumentUploadApi(DOC_ID);

    expect(mockGet).toHaveBeenCalledWith(`/documents/uploads/${DOC_ID}`);
  });

  it('sends a part as binary, with the digest header and the 1-based part number', async () => {
    const body = new Uint8Array([1, 2, 3]).buffer;
    const controller = new AbortController();
    const onUploadProgress = vi.fn();
    const digest = 'a'.repeat(64);

    await uploadDocumentPartApi(DOC_ID, 3, body, {
      digest,
      signal: controller.signal,
      onUploadProgress,
    });

    // Part numbers are 1-based because S3 part numbers are; the URL carries the
    // number it was given and never an index derived from it.
    const [url, sent, config] = mockPut.mock.calls[0] as [
      string,
      ArrayBuffer,
      Record<string, unknown>,
    ];
    expect(url).toBe(`/documents/uploads/${DOC_ID}/parts/3`);
    // The BUFFER itself, not a copy and not JSON: the shared instance defaults to
    // `application/json`, and a serialized body would arrive as an object of
    // numbered keys.
    expect(sent).toBe(body);
    expect(config.headers).toEqual({
      'Content-Type': 'application/octet-stream',
      // Lower-case, because Node lower-cases every incoming header name and the
      // handler reads `req.headers['x-hv-part-sha256']`.
      'x-hv-part-sha256': digest,
    });
    expect(config.signal).toBe(controller.signal);
    expect(config.onUploadProgress).toBe(onUploadProgress);
  });

  it('omits the signal and the progress callback rather than sending them undefined', async () => {
    await uploadDocumentPartApi(DOC_ID, 1, new ArrayBuffer(8), { digest: 'b'.repeat(64) });

    const config = (mockPut.mock.calls[0] as [string, ArrayBuffer, Record<string, unknown>])[2];
    expect('signal' in config).toBe(false);
    expect('onUploadProgress' in config).toBe(false);
  });

  it('names the digest header through the exported constant, not a literal per call site', () => {
    // The constant is what the store and any later caller build their header from,
    // so its VALUE is part of the contract rather than an implementation detail.
    expect(PART_DIGEST_HEADER).toBe('x-hv-part-sha256');
  });

  it('completes a transfer with the sealed metadata AND the wrapped key again', async () => {
    const body = {
      encryptedMeta: 'meta',
      metaIv: 'iv',
      metaTag: 'tag',
      encryptedDek: 'dek',
      dekIv: 'dek-iv',
      dekTag: 'dek-tag',
      vaultKeyVersion: 2,
    };

    await completeDocumentUploadApi(DOC_ID, body);

    // The wrapped key crosses the wire a second time here on purpose: it is what
    // makes a rotation refusal cost one request instead of the whole file.
    expect(mockPost).toHaveBeenCalledWith(`/documents/uploads/${DOC_ID}/complete`, body);
  });

  it('aborts a transfer with a bounded per-call timeout when one is given', async () => {
    await abortDocumentUploadApi(DOC_ID, 5000);

    expect(mockDelete).toHaveBeenCalledWith(`/documents/uploads/${DOC_ID}`, { timeout: 5000 });
  });

  it('aborts without a timeout key at all when none is given', async () => {
    await abortDocumentUploadApi(DOC_ID);

    // An explicit `timeout: undefined` would be indistinguishable to axios but is
    // a different object; the negative pins that no timeout is imposed by default,
    // because this client deliberately has no global one.
    expect(mockDelete).toHaveBeenCalledWith(`/documents/uploads/${DOC_ID}`, {});
  });
});

describe('documentsApi — one document', () => {
  it('reads one row', async () => {
    await getDocumentApi(DOC_ID);

    expect(mockGet).toHaveBeenCalledWith(`/documents/${DOC_ID}`);
  });

  it('reads a segment as an ArrayBuffer at its 0-based index', async () => {
    await getDocumentSegmentApi(DOC_ID, 0);

    // `responseType` is mandatory rather than a preference: the default 'json'
    // hands the body to JSON.parse, and ciphertext is not text.
    expect(mockGet).toHaveBeenCalledWith(`/documents/${DOC_ID}/segments/0`, {
      responseType: 'arraybuffer',
    });
  });

  it('passes an abort signal to a segment read when one is given', async () => {
    const controller = new AbortController();

    await getDocumentSegmentApi(DOC_ID, 7, controller.signal);

    expect(mockGet).toHaveBeenCalledWith(`/documents/${DOC_ID}/segments/7`, {
      responseType: 'arraybuffer',
      signal: controller.signal,
    });
  });

  it('updates a document with the body it was given', async () => {
    await updateDocumentApi(DOC_ID, { favorite: true });

    expect(mockPut).toHaveBeenCalledWith(`/documents/${DOC_ID}`, { favorite: true });
  });

  it('trashes, restores and purges through three distinct routes', async () => {
    await deleteDocumentApi(DOC_ID);
    await restoreDocumentApi(DOC_ID);
    await purgeDocumentApi(DOC_ID);

    expect(mockDelete).toHaveBeenCalledWith(`/documents/${DOC_ID}`);
    expect(mockPost).toHaveBeenCalledWith(`/documents/${DOC_ID}/restore`);
    expect(mockDelete).toHaveBeenCalledWith(`/documents/${DOC_ID}/permanent`);
    // The negative: a trash is not a purge. Sending the plain DELETE for a
    // permanent delete would silently leave the object in the bucket.
    expect(mockDelete).toHaveBeenCalledTimes(2);
  });
});
