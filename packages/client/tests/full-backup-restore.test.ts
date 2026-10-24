/**
 * Restoring a full backup's documents (`services/backup/restoreFullBackupDocuments.ts`),
 * end to end against the REAL documents store, the real upload engine, the real
 * crypto and a stub transport that keeps documents the way the server does.
 *
 * The stub is a small document server: it lists live and trashed rows, mints an id
 * per upload, stores the parts, builds the committed row from the completion body
 * exactly as the server derives it, and applies metadata, folder, favorite and
 * trash changes. Every assertion about a restored document is made by OPENING what
 * the stub stored, under this account's key, with the real verified read: its
 * bytes, its sealed details and its provenance, never the calls the engine made.
 */
import { describe, it, expect, vi, beforeEach, afterEach, onTestFinished } from 'vitest';
import axios, {
  AxiosError,
  type AxiosAdapter,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENTS_PER_USER,
  type DocumentMeta,
  type DocumentResponse,
} from '@hvault/shared';

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

import { api } from '../src/services/api/client.js';
import { cryptoService } from '../src/services/crypto/cryptoService.js';
import { deriveFullBackupSigningKey } from '../src/services/crypto/fullBackupCrypto.js';
import {
  decryptMeta,
  deriveMetaKey,
  deriveWrapKey,
  unwrapDek,
  zeroDek,
} from '../src/services/crypto/documentCryptoService.js';
import { readDocumentPlaintext } from '../src/services/documents/download.js';
import {
  FullBackupWriter,
  openFullBackupFile,
  type OmittedReason,
  type OpenedFullBackup,
} from '../src/services/backup/fullBackupFormat.js';
import {
  restoreFullBackupDocuments,
  type DocumentRestoreProgress,
  type DocumentRestoreReport,
  type RestoreDocumentsOptions,
} from '../src/services/backup/restoreFullBackupDocuments.js';
import { UNOPENABLE_DOCUMENT_NAME } from '../src/services/documents/documentNames.js';
import { loadUploadRecovery } from '../src/lib/lazyUploadRecovery.js';
import { useAuthStore } from '../src/stores/authStore.js';
import { DocumentDetailsRefusedError, useDocumentsStore } from '../src/stores/documentsStore.js';
import {
  buildStoredDocument,
  memoryTarget,
  ramp,
  type StoredDocument,
} from './support/storedDocuments.js';

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';
const BACKUP_FOLDER = 'b0b0b0b0b0b0b0b0b0b0b0b0';
const LIVE_FOLDER = 'c0c0c0c0c0c0c0c0c0c0c0c0';
const MINTED = ['77c0f1a2b3c4d5e6f7a8b900', '77c0f1a2b3c4d5e6f7a8b901', '77c0f1a2b3c4d5e6f7a8b902'];

// ---------------------------------------------------------------------------
// The stub document server
// ---------------------------------------------------------------------------

interface Refusal {
  status: number | 'offline';
  message?: string;
  headers?: Record<string, string>;
  data?: Record<string, unknown>;
}

interface Staging {
  body: Record<string, unknown>;
  parts: Map<number, Uint8Array>;
}

let rows: Map<string, DocumentResponse>;
let storedSegments: Map<string, Uint8Array[]>;
let staging: Map<string, Staging>;
let minted: string[];
let documentsConfig: Record<string, unknown> | null;
let quotaBytes: number;
let documentCountOverride: number | null;
let requests: { method: string; url: string }[];
/** Runs on every request, before it is answered. */
let onRequest: ((method: string, url: string) => void) | null;
/** The chunk size upload start advertises; a different one is a server that frames differently. */
let advertisedChunkBytes: number;
/** Refusals queued per route, served first-in first-out before the route answers. */
let refusals: Record<'init' | 'part' | 'complete' | 'put' | 'restore' | 'list', Refusal[]>;

function ok(data: unknown, config: InternalAxiosRequestConfig, status = 200): AxiosResponse {
  return {
    data: { success: true, data },
    status,
    statusText: 'OK',
    headers: {},
    config,
  } as AxiosResponse;
}

function refuse(refusal: Refusal, config: InternalAxiosRequestConfig): Promise<never> {
  if (refusal.status === 'offline') {
    return Promise.reject(new AxiosError('Network Error', AxiosError.ERR_NETWORK, config));
  }
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(refusal.status)}`,
      AxiosError.ERR_BAD_REQUEST,
      config,
      undefined,
      {
        status: refusal.status,
        statusText: 'Error',
        data: {
          success: false,
          message: refusal.message ?? 'nope',
          statusCode: refusal.status,
          ...(refusal.data === undefined ? {} : { data: refusal.data }),
        },
        headers: refusal.headers ?? {},
        config,
      },
    ),
  );
}

function page(list: DocumentResponse[], config: InternalAxiosRequestConfig): AxiosResponse {
  return {
    data: {
      success: true,
      data: list,
      pagination: { page: 1, limit: 100, total: list.length, totalPages: 1 },
    },
    status: 200,
    statusText: 'OK',
    headers: {},
    config,
  } as AxiosResponse;
}

const adapter: AxiosAdapter = (config) => {
  const url = (config.url ?? '').replace(/^\/api\/v1/, '');
  const method = (config.method ?? 'get').toUpperCase();
  requests.push({ method, url });
  onRequest?.(method, url);

  if (url === '/csrf-token') {
    return Promise.resolve({
      data: { data: { csrfToken: 'csrf' } },
      status: 200,
      statusText: 'OK',
      headers: {},
      config,
    } as AxiosResponse);
  }
  if (url === '/config') {
    return Promise.resolve(
      ok(
        {
          fileEncryption: { maxSizeMB: 10 },
          ...(documentsConfig ? { documents: documentsConfig } : {}),
        },
        config,
      ),
    );
  }
  const live = [...rows.values()].filter((row) => row.deletedAt === undefined);
  if (url === '/documents' && method === 'GET') {
    const refusal = refusals.list.shift();
    if (refusal) return refuse(refusal, config);
    return Promise.resolve(page(live, config));
  }
  if (url === '/documents/trash') {
    return Promise.resolve(
      page(
        [...rows.values()].filter((row) => row.deletedAt !== undefined),
        config,
      ),
    );
  }
  if (url === '/documents/usage') {
    return Promise.resolve(
      ok(
        {
          documentCount: documentCountOverride ?? rows.size,
          usedBytes: [...rows.values()].reduce((total, row) => total + row.plaintextBytes, 0),
          quotaBytes,
          maxDocumentSizeBytes: 100 * 1024 * 1024,
        },
        config,
      ),
    );
  }
  if (url === '/user/profile') {
    return Promise.resolve(
      ok({ encryptedVaultKey: 'x', vaultKeyIv: 'x', vaultKeyTag: 'x' }, config),
    );
  }
  if (url === '/documents/uploads' && method === 'POST') {
    const refusal = refusals.init.shift();
    if (refusal) return refuse(refusal, config);
    const id = minted.shift()!;
    staging.set(id, {
      body: JSON.parse(config.data as string) as Record<string, unknown>,
      parts: new Map(),
    });
    return Promise.resolve(
      ok(
        { uploadId: id, vaultKeyVersion: 3, chunkPlaintextBytes: advertisedChunkBytes },
        config,
        201,
      ),
    );
  }
  const part = /^\/documents\/uploads\/([a-f0-9]{24})\/parts\/(\d+)$/.exec(url);
  if (part) {
    const refusal = refusals.part.shift();
    if (refusal) return refuse(refusal, config);
    const bytes = new Uint8Array(config.data as ArrayBuffer);
    staging.get(part[1]!)!.parts.set(Number(part[2]), bytes);
    config.onUploadProgress?.({ loaded: bytes.length, total: bytes.length } as never);
    return Promise.resolve(
      ok({ partNumber: Number(part[2]), bytes: bytes.length, receivedBytes: bytes.length }, config),
    );
  }
  const ledger = /^\/documents\/uploads\/([a-f0-9]{24})$/.exec(url);
  if (ledger && method === 'GET') {
    const held = staging.get(ledger[1]!);
    if (!held) return refuse({ status: 404, message: 'Upload not found' }, config);
    const parts = [...held.parts.entries()].map(([partNumber, bytes]) => ({
      partNumber,
      bytes: bytes.length,
    }));
    return Promise.resolve(
      ok(
        {
          _id: ledger[1],
          streamSalt: held.body['streamSalt'],
          noncePrefix: held.body['noncePrefix'],
          declaredPlaintextBytes: held.body['declaredPlaintextBytes'],
          declaredChunkCount: held.body['declaredChunkCount'],
          chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
          vaultKeyVersion: 3,
          parts,
          receivedBytes: parts.reduce((total, p) => total + p.bytes, 0),
          createdAt: '2026-10-23T10:00:00.000Z',
          expiresAt: '2026-10-24T10:00:00.000Z',
        },
        config,
      ),
    );
  }
  if (ledger && method === 'DELETE') {
    staging.delete(ledger[1]!);
    return Promise.resolve(ok(null, config));
  }
  const complete = /^\/documents\/uploads\/([a-f0-9]{24})\/complete$/.exec(url);
  if (complete) {
    const refusal = refusals.complete.shift();
    if (refusal) return refuse(refusal, config);
    const id = complete[1]!;
    const held = staging.get(id)!;
    const body = JSON.parse(config.data as string) as Record<string, string>;
    const segments = [...held.parts.entries()].sort(([a], [b]) => a - b).map(([, bytes]) => bytes);
    const ciphertextBytes = segments.reduce((total, segment) => total + segment.length, 0);
    const chunkCount = held.body['declaredChunkCount'] as number;
    const row: DocumentResponse = {
      _id: id,
      ...(held.body['folderId'] === undefined ? {} : { folderId: held.body['folderId'] as string }),
      favorite: false,
      encryptedDek: body['encryptedDek']!,
      dekIv: body['dekIv']!,
      dekTag: body['dekTag']!,
      streamSalt: held.body['streamSalt'] as string,
      noncePrefix: held.body['noncePrefix'] as string,
      encryptedMeta: body['encryptedMeta']!,
      metaIv: body['metaIv']!,
      metaTag: body['metaTag']!,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      chunkCount,
      ciphertextBytes,
      plaintextBytes: ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount,
      createdAt: '2026-10-23T11:00:00.000Z',
      updatedAt: '2026-10-23T11:00:00.000Z',
    };
    rows.set(id, row);
    storedSegments.set(id, segments);
    staging.delete(id);
    return Promise.resolve(ok(row, config, 201));
  }
  const one = /^\/documents\/([a-f0-9]{24})(\/restore)?$/.exec(url);
  if (one && method === 'PUT') {
    const refusal = refusals.put.shift();
    if (refusal) return refuse(refusal, config);
    const body = JSON.parse(config.data as string) as Record<string, unknown>;
    const current = rows.get(one[1]!)!;
    const next: DocumentResponse = { ...current };
    if (typeof body['encryptedMeta'] === 'string') {
      next.encryptedMeta = body['encryptedMeta'];
      next.metaIv = body['metaIv'] as string;
      next.metaTag = body['metaTag'] as string;
    }
    if (typeof body['favorite'] === 'boolean') next.favorite = body['favorite'];
    if (body['folderId'] === null) delete next.folderId;
    else if (typeof body['folderId'] === 'string') next.folderId = body['folderId'];
    rows.set(next._id, next);
    return Promise.resolve(ok(next, config));
  }
  if (one?.[2] === '/restore' && method === 'POST') {
    const refusal = refusals.restore.shift();
    if (refusal) return refuse(refusal, config);
    const { deletedAt: _deleted, ...restored } = rows.get(one[1]!)!;
    rows.set(restored._id, restored);
    return Promise.resolve(ok(restored, config));
  }
  if (one && method === 'GET') {
    const row = rows.get(one[1]!);
    return row
      ? Promise.resolve(ok(row, config))
      : refuse({ status: 404, message: 'Document not found' }, config);
  }
  return refuse({ status: 404 }, config);
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let sessionKey: CryptoKey;
let backupKey: CryptoKey;
let backupA: StoredDocument;
let backupB: StoredDocument;

/** The two adapter slots, typed so the original (possibly absent) adapter can be put back. */
interface AdapterSlot {
  adapter?: typeof axios.defaults.adapter | undefined;
}
const apiDefaults: AdapterSlot = api.defaults;
const axiosDefaults: AdapterSlot = axios.defaults;
const originalApiAdapter = api.defaults.adapter;
const originalGlobalAdapter = axios.defaults.adapter;

beforeEach(async () => {
  rows = new Map();
  storedSegments = new Map();
  staging = new Map();
  minted = [...MINTED];
  documentsConfig = { enabled: true, maxSizeMB: 10 };
  quotaBytes = 1024 * 1024 * 1024;
  documentCountOverride = null;
  requests = [];
  onRequest = null;
  advertisedChunkBytes = DOCUMENT_PLAINTEXT_CHUNK_BYTES;
  refusals = { init: [], part: [], complete: [], put: [], restore: [], list: [] };
  api.defaults.adapter = adapter;
  axios.defaults.adapter = adapter;

  sessionKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  backupKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  backupA = await buildStoredDocument({
    id: ID_A,
    vaultKey: backupKey,
    plaintext: ramp(20),
    name: 'passport.pdf',
    metaOverrides: {
      ext: 'pdf',
      mime: 'application/pdf',
      originalName: 'scan-0042.pdf',
      tags: ['travel', 'id'],
      note: 'Renew in 2031',
      capturedAt: '2025-05-06T07:08:09.000Z',
    },
    rowOverrides: { folderId: BACKUP_FOLDER, favorite: true },
  });
  backupB = await buildStoredDocument({
    id: ID_B,
    vaultKey: backupKey,
    plaintext: ramp(7, 5),
    name: 'notes.txt',
    metaOverrides: { capturedAt: '2024-01-02T03:04:05.000Z' },
  });

  useDocumentsStore.getState().clearStore();
  useAuthStore.setState({
    isAuthenticated: true,
    isLocked: false,
    accessToken: 'access-token',
    vaultKey: sessionKey,
    vaultKeyVersion: 3,
  });
});

afterEach(() => {
  useAuthStore.setState({ vaultKey: null, mek: null, accessToken: null, isAuthenticated: false });
  apiDefaults.adapter = originalApiAdapter;
  axiosDefaults.adapter = originalGlobalAdapter;
  vi.restoreAllMocks();
});

/** A real full backup file holding `documents`, opened by the real reader. */
async function backupOf(
  documents: StoredDocument[] = [backupA, backupB],
  vault: Record<string, unknown> = { documentSummary: { count: documents.length, totalBytes: 0 } },
  leftOut: { omitted: { id: string; reason: OmittedReason }[]; unlisted: number } = {
    omitted: [],
    unlisted: 0,
  },
): Promise<OpenedFullBackup> {
  const target = memoryTarget();
  const writer = new FullBackupWriter(target);
  await writer.begin();
  for (const doc of documents) {
    await writer.addDocument(
      doc.row,
      doc.segments.map((segment) => new Blob([segment])),
    );
  }
  await writer.finish(
    { createdAt: '2026-10-23T10:00:00.000Z', vault, ...leftOut },
    await deriveFullBackupSigningKey(cryptoService.generateBWK()),
  );
  return openFullBackupFile(new Blob([await target.bytes()]));
}

async function restore(
  overrides: Partial<RestoreDocumentsOptions> & { backup?: OpenedFullBackup } = {},
): Promise<{ report: DocumentRestoreReport; waits: number[] }> {
  const waits: number[] = [];
  const report = await restoreFullBackupDocuments({
    backup: overrides.backup ?? (await backupOf()),
    backupVaultKey: backupKey,
    folderIdMap: [{ backupId: BACKUP_FOLDER, folderId: LIVE_FOLDER }],
    conflictStrategy: 'skip',
    signal: new AbortController().signal,
    wait: (ms) => {
      waits.push(ms);
      return Promise.resolve();
    },
    ...overrides,
  });
  return { report, waits };
}

/** A stored document opened under the SESSION key: its sealed details and its bytes. */
async function openStored(
  id: string,
): Promise<{ meta: DocumentMeta; bytes: number[]; row: DocumentResponse }> {
  const row = rows.get(id)!;
  const dek = await unwrapDek(row, await deriveWrapKey(sessionKey, id));
  let meta: DocumentMeta;
  try {
    meta = await decryptMeta(
      await deriveMetaKey(
        dek,
        new Uint8Array(cryptoService.base64ToArrayBuffer(row.streamSalt)),
        id,
      ),
      row,
    );
  } finally {
    zeroDek(dek);
  }
  const { bytes } = await readDocumentPlaintext(id, {
    row,
    source: {
      vaultKey: sessionKey,
      readSegment: (index) => Promise.resolve(new Uint8Array(storedSegments.get(id)![index]!)),
    },
  });
  return { meta, bytes: [...bytes], row };
}

/** A document already in this account, sealed under the session key. */
async function holdHere(
  id: string,
  options: Partial<Parameters<typeof buildStoredDocument>[0]> = {},
): Promise<StoredDocument> {
  const doc = await buildStoredDocument({
    id,
    vaultKey: sessionKey,
    plaintext: ramp(20),
    ...options,
  });
  rows.set(id, doc.row);
  storedSegments.set(id, doc.segments);
  return doc;
}

function expectAccounted(report: DocumentRestoreReport): void {
  expect(
    report.uploaded +
      report.restoredFromTrash +
      report.updated +
      report.alreadyPresent +
      report.notRestored.length +
      report.notAttempted,
  ).toBe(report.total);
}

const uploadsStarted = (): number =>
  requests.filter((r) => r.method === 'POST' && r.url === '/documents/uploads').length;

// ---------------------------------------------------------------------------

describe('restoring into an account that holds none of the documents', () => {
  it('uploads each one with its bytes, details, folder, favorite and provenance', async () => {
    const { report } = await restore();

    expect(report).toMatchObject({
      total: 2,
      uploaded: 2,
      notRestored: [],
      notAttempted: 0,
      notes: [],
    });
    expect(report.stopped).toBeUndefined();
    expectAccounted(report);

    const [first, second] = MINTED;
    const a = await openStored(first!);
    expect(a.bytes).toEqual([...backupA.plaintext]);
    expect(a.meta).toMatchObject({
      name: 'passport.pdf',
      originalName: 'scan-0042.pdf',
      mime: 'application/pdf',
      tags: ['travel', 'id'],
      note: 'Renew in 2031',
      capturedAt: '2025-05-06T07:08:09.000Z',
      restoredFrom: ID_A,
      sha256: backupA.meta.sha256,
    });
    expect(a.row.folderId).toBe(LIVE_FOLDER);
    expect(a.row.favorite).toBe(true);

    const b = await openStored(second!);
    expect(b.bytes).toEqual([...backupB.plaintext]);
    expect(b.meta.restoredFrom).toBe(ID_B);
    expect(b.meta.capturedAt).toBe('2024-01-02T03:04:05.000Z');
    // The backup recorded no original name for it, and the restore invents none.
    expect('originalName' in b.meta).toBe(false);
    expect(b.row.folderId).toBeUndefined();
    expect(b.row.favorite).toBe(false);
    // Only the favorite needed a write after its upload.
    expect(
      requests.filter((r) => r.method === 'PUT' && /^\/documents\/[a-f0-9]{24}$/.test(r.url)),
    ).toHaveLength(1);
  });

  it('adds nothing on a second Skip run of the same backup: each document is recognised by its provenance', async () => {
    const backup = await backupOf();
    await restore({ backup });
    const started = uploadsStarted();

    const { report } = await restore({ backup });

    expect(report).toMatchObject({ uploaded: 0, alreadyPresent: 2 });
    expect(uploadsStarted()).toBe(started);
    expect(rows.size).toBe(2);
  });

  it('files documents outside any folder, and says so, when the server sent no folder map', async () => {
    const { report } = await restore({ folderIdMap: undefined });
    expect(report.uploaded).toBe(2);
    expect(report.notes).toEqual([expect.stringContaining('restored outside any folder')]);
    expect(rows.get(MINTED[0]!)?.folderId).toBeUndefined();
  });

  it('reports documents the account held that the backup does not carry', async () => {
    const { report } = await restore({
      backup: await backupOf([backupA], { documentSummary: { count: 4, totalBytes: 0 } }),
    });
    expect(report.missingFromBackup).toBe(3);
    expect(report.leftOutOfBackup).toBe(0);
  });

  it('reports the documents the backup itself could not include, apart from the ones it never listed', async () => {
    const { report } = await restore({
      backup: await backupOf(
        [backupA],
        { documentSummary: { count: 5, totalBytes: 0 } },
        {
          omitted: [
            { id: '88c0f1a2b3c4d5e6f7a8b900', reason: 'contents-missing' },
            { id: '88c0f1a2b3c4d5e6f7a8b901', reason: 'unreadable' },
          ],
          unlisted: 1,
        },
      ),
    });
    expect(report).toMatchObject({ uploaded: 1, leftOutOfBackup: 3, missingFromBackup: 1 });
    expectAccounted(report);
  });

  it('does nothing at all for a backup that carries no documents', async () => {
    const { report } = await restore({ backup: await backupOf([]) });
    expect(report).toMatchObject({ total: 0, uploaded: 0 });
    expect(requests).toEqual([]);
  });
});

describe('progress, for the restore card', () => {
  it('reports each document as it starts, then the transfer it registered', async () => {
    const seen: DocumentRestoreProgress[] = [];
    await restore({ onProgress: (progress) => seen.push({ ...progress }) });
    expect(seen).toEqual([
      { index: 1, total: 2, name: 'passport.pdf' },
      { index: 1, total: 2, name: 'passport.pdf', uploadId: MINTED[0] },
      { index: 2, total: 2, name: 'notes.txt' },
      { index: 2, total: 2, name: 'notes.txt', uploadId: MINTED[1] },
    ]);
  });

  it('announces no transfer for a document that needs no upload', async () => {
    await holdHere(ID_A, { name: 'passport.pdf', metaOverrides: { ext: 'pdf' } });
    const seen: DocumentRestoreProgress[] = [];
    await restore({ onProgress: (progress) => seen.push({ ...progress }) });
    expect(seen.filter((progress) => progress.name === 'passport.pdf')).toEqual([
      { index: 1, total: 2, name: 'passport.pdf' },
    ]);
  });
});

describe('a backup document this account already holds', () => {
  it('Skip leaves a live document exactly as it is', async () => {
    await holdHere(ID_A, { name: 'renamed.pdf' });
    const { report } = await restore({ backup: await backupOf([backupA]) });
    expect(report).toMatchObject({ alreadyPresent: 1, uploaded: 0 });
    expect(requests.some((r) => r.method === 'PUT')).toBe(false);
  });

  it('Overwrite gives it the backup’s name, tags, note, folder and favorite', async () => {
    await holdHere(ID_A, {
      name: 'renamed.pdf',
      metaOverrides: { ext: 'pdf', tags: ['old'], note: 'old note' },
    });

    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });

    expect(report).toMatchObject({ updated: 1, uploaded: 0 });
    const stored = await openStored(ID_A);
    expect(stored.meta).toMatchObject({
      name: 'passport.pdf',
      tags: ['travel', 'id'],
      note: 'Renew in 2031',
    });
    expect(stored.row.folderId).toBe(LIVE_FOLDER);
    expect(stored.row.favorite).toBe(true);
    expect(uploadsStarted()).toBe(0);
  });

  it('Overwrite writes nothing when every detail already matches', async () => {
    await holdHere(ID_B, {
      name: 'notes.txt',
      plaintext: ramp(7, 5),
      metaOverrides: { capturedAt: '2024-01-02T03:04:05.000Z' },
    });
    const { report } = await restore({
      backup: await backupOf([backupB]),
      conflictStrategy: 'overwrite',
    });
    expect(report).toMatchObject({ alreadyPresent: 1, updated: 0 });
    expect(requests.some((r) => r.method === 'PUT')).toBe(false);
  });

  it('Overwrite removes a note the backup did not have, and leaves an unmapped folder alone', async () => {
    await holdHere(ID_B, {
      name: 'notes.txt',
      metaOverrides: { note: 'added later' },
      rowOverrides: { folderId: LIVE_FOLDER },
    });
    const fromFolder = await buildStoredDocument({
      id: ID_B,
      vaultKey: backupKey,
      name: 'notes.txt',
      rowOverrides: { folderId: 'dddddddddddddddddddddddd' },
    });
    const { report } = await restore({
      backup: await backupOf([fromFolder]),
      conflictStrategy: 'overwrite',
    });
    expect(report.updated).toBe(1);
    const stored = await openStored(ID_B);
    expect('note' in stored.meta).toBe(false);
    expect(stored.row.folderId).toBe(LIVE_FOLDER);
  });

  it('Keep both uploads a copy beside it', async () => {
    await holdHere(ID_A, { name: 'passport.pdf', metaOverrides: { ext: 'pdf' } });
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'keep_both',
    });
    expect(report).toMatchObject({ uploaded: 1, alreadyPresent: 0 });
    expect(rows.size).toBe(2);
    expect((await openStored(MINTED[0]!)).meta.restoredFrom).toBe(ID_A);
  });

  it.each(['skip', 'overwrite', 'keep_both'] as const)(
    'takes a document in the trash back out of it under %s, with the backup’s details',
    async (strategy) => {
      await holdHere(ID_A, {
        name: 'old.pdf',
        metaOverrides: { ext: 'pdf' },
        rowOverrides: { deletedAt: '2026-10-01T00:00:00.000Z' },
      });
      const { report } = await restore({
        backup: await backupOf([backupA]),
        conflictStrategy: strategy,
      });
      expect(report).toMatchObject({ restoredFromTrash: 1, uploaded: 0 });
      const stored = await openStored(ID_A);
      expect(stored.row.deletedAt).toBeUndefined();
      expect(stored.meta.name).toBe('passport.pdf');
      expect(uploadsStarted()).toBe(0);
    },
  );

  it('uploads a fresh copy when the match is already being permanently deleted', async () => {
    await holdHere(ID_A, {
      rowOverrides: { deletedAt: '2026-10-01T00:00:00.000Z', purgePending: true },
    });
    const { report } = await restore({ backup: await backupOf([backupA]) });
    expect(report.uploaded).toBe(1);
  });

  it('records a match whose details here cannot be opened, and replaces nothing', async () => {
    const other = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    const degraded = await buildStoredDocument({ id: ID_A, vaultKey: other });
    rows.set(ID_A, degraded.row);
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.notes).toContain(
      'passport.pdf: its details here could not be opened, so they were not replaced.',
    );
    expect(report.updated).toBe(1);
  });
});

describe('documents it does not restore, with the run going on', () => {
  it('records a document whose details the backup’s key cannot open', async () => {
    const { report } = await restore({
      backupVaultKey: await cryptoService.importVaultKey(cryptoService.generateVaultKey()),
      backup: await backupOf([backupB]),
    });
    expect(report.notRestored).toEqual([
      {
        name: UNOPENABLE_DOCUMENT_NAME,
        reason: "Its details could not be opened with the backup's key, so it was not restored.",
      },
    ]);
    expect(uploadsStarted()).toBe(0);
  });

  it('records a document larger than this server accepts, without a request', async () => {
    documentsConfig = { enabled: true, maxSizeMB: 1 };
    const big = await buildStoredDocument({
      id: ID_B,
      vaultKey: backupKey,
      plaintext: new Uint8Array(1024 * 1024 + 1),
      chunkPlaintextBytes: 1024 * 1024,
    });
    const { report } = await restore({ backup: await backupOf([big]) });
    expect(report.notRestored).toEqual([
      { name: 'report.txt', reason: 'It is larger than this server accepts (1 MB).' },
    ]);
    expect(uploadsStarted()).toBe(0);
  });

  it('records a file type the server asks not to store, and one there is no room for', async () => {
    documentsConfig = { enabled: true, allowedExtensions: ['txt'] };
    // Room for less than the 7-byte notes.txt.
    quotaBytes = 5;
    const { report } = await restore();
    expect(report.notRestored).toEqual([
      { name: 'passport.pdf', reason: 'This server asks for these file types only: txt.' },
      { name: 'notes.txt', reason: 'There is not enough storage left for it.' },
    ]);
    expectAccounted(report);
  });

  it('records a document a 4xx refuses at upload start, cancelling nothing, and restores the next', async () => {
    refusals.init.push({ status: 422, message: 'Unprocessable' });
    const { report } = await restore();
    expect(report.notRestored).toEqual([{ name: 'passport.pdf', reason: 'Unprocessable' }]);
    expect(report.uploaded).toBe(1);
  });

  it('records a document whose bytes in the file were altered', async () => {
    const altered = { ...backupB, segments: [backupB.segments[0]!.slice()] };
    altered.segments[0]![0] = (altered.segments[0]![0] ?? 0) ^ 1;
    const { report } = await restore({ backup: await backupOf([altered]) });
    expect(report.notRestored).toEqual([
      {
        name: 'notes.txt',
        reason: 'It could not be read from the backup and verified, so it was not restored.',
      },
    ]);
    expect(uploadsStarted()).toBe(0);
  });

  it('notes a favorite the server refused, keeping the restored document', async () => {
    refusals.put.push({ status: 400, message: 'No' });
    const { report } = await restore({ backup: await backupOf([backupA]) });
    expect(report.uploaded).toBe(1);
    expect(report.notes).toEqual(['passport.pdf: No.']);
  });

  it('records a document that cannot be taken out of the trash', async () => {
    await holdHere(ID_A, { rowOverrides: { deletedAt: '2026-10-01T00:00:00.000Z' } });
    refusals.restore.push({ status: 404, message: 'Document not found' });
    const { report } = await restore({ backup: await backupOf([backupA]) });
    expect(report.notRestored).toEqual([
      {
        name: 'passport.pdf',
        reason: 'It could not be taken out of the trash: Document not found.',
      },
    ]);
  });
});

describe('refusals, decided by where they came from', () => {
  it('waits out a 429 at upload start and starts again', async () => {
    refusals.init.push({ status: 429, headers: { 'retry-after': '30' } });
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.uploaded).toBe(1);
    expect(waits).toEqual([20_000, 10_000]);
    expect(uploadsStarted()).toBe(2);
  });

  it.each(['part', 'complete'] as const)(
    'resumes the SAME transfer after a 429 at the %s, never starting a second one',
    async (route) => {
      refusals[route].push({ status: 429, headers: { 'retry-after': '5' } });
      const { report, waits } = await restore({ backup: await backupOf([backupB]) });
      expect(report.uploaded).toBe(1);
      expect(waits).toContain(5_000);
      expect(uploadsStarted()).toBe(1);
      expect((await openStored(MINTED[0]!)).bytes).toEqual([...backupB.plaintext]);
    },
  );

  it('re-sends the favorite after a 429 on it, uploading nothing twice', async () => {
    refusals.put.push({ status: 429, headers: { 'retry-after': '3' } });
    const { report, waits } = await restore({ backup: await backupOf([backupA]) });
    expect(report.uploaded).toBe(1);
    expect(waits).toEqual([3_000]);
    expect(uploadsStarted()).toBe(1);
    expect(rows.get(MINTED[0]!)?.favorite).toBe(true);
  });

  it('re-sends a details write after a 429 under Overwrite', async () => {
    await holdHere(ID_A, { name: 'renamed.pdf', metaOverrides: { ext: 'pdf' } });
    refusals.put.push({ status: 429, headers: { 'retry-after': '2' } });
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.updated).toBe(1);
    expect((await openStored(ID_A)).meta.name).toBe('passport.pdf');
  });

  it('waits and retries a start refused because another was being opened', async () => {
    refusals.init.push({
      status: 409,
      message:
        'Another transfer is already being opened for this account. Please wait a moment and retry.',
    });
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.uploaded).toBe(1);
    expect(waits).toEqual([2_000]);
  });

  it('restores outside any folder, once, when the mapped folder no longer exists', async () => {
    refusals.init.push({ status: 404, message: 'Target folder not found' });
    const { report } = await restore({ backup: await backupOf([backupA]) });
    expect(report.uploaded).toBe(1);
    expect(report.notes).toEqual([
      'passport.pdf: its folder no longer exists, so it was restored outside any folder.',
    ]);
    expect(rows.get(MINTED[0]!)?.folderId).toBeUndefined();
  });

  it('records a start refused for this one document, with nothing registered to cancel, and goes on', async () => {
    refusals.init.push({ status: 400, message: 'The upload request was not valid.' });
    const { report } = await restore({ backup: await backupOf([backupB, backupA]) });
    expect(report.notRestored).toEqual([
      { name: 'notes.txt', reason: 'The upload request was not valid.' },
    ]);
    expect(report).toMatchObject({ uploaded: 1, notAttempted: 0 });
    expect(report.stopped).toBeUndefined();
    expect(requests.some((r) => r.method === 'DELETE')).toBe(false);
    expectAccounted(report);
  });

  it('records a document whose details cannot be stored, and goes on with the rest', async () => {
    const realStart = useDocumentsStore.getState().startUpload;
    onTestFinished(() => useDocumentsStore.setState({ startUpload: realStart }));
    useDocumentsStore.setState({
      startUpload: vi
        .fn<typeof realStart>()
        .mockRejectedValueOnce(new DocumentDetailsRefusedError('Too many tags for one document.'))
        .mockImplementation(realStart),
    });
    const { report } = await restore({ backup: await backupOf([backupB, backupA]) });
    expect(report.notRestored).toEqual([
      { name: 'notes.txt', reason: 'Too many tags for one document.' },
    ]);
    expect(report).toMatchObject({ uploaded: 1, notAttempted: 0 });
    expect(report.stopped).toBeUndefined();
    expectAccounted(report);
  });

  it('stops on any other refusal made before a request was sent', async () => {
    const realStart = useDocumentsStore.getState().startUpload;
    onTestFinished(() => useDocumentsStore.setState({ startUpload: realStart }));
    useDocumentsStore.setState({
      startUpload: vi.fn().mockRejectedValue(new Error('Vault is locked')),
    });
    const { report } = await restore({ backup: await backupOf([backupB, backupA]) });
    expect(report.stopped).toEqual({ stop: 'failed', message: 'Vault is locked' });
    expect(report.uploaded).toBe(0);
    expectAccounted(report);
  });

  it('drops a registered transfer the server refused for this one document, and goes on', async () => {
    refusals.part.push({ status: 400, message: 'This part is not the size the upload expects.' });
    const { report } = await restore({ backup: await backupOf([backupB, backupA]) });
    expect(report.notRestored).toEqual([
      { name: 'notes.txt', reason: 'This part is not the size the upload expects.' },
    ]);
    expect(report).toMatchObject({ uploaded: 1, notAttempted: 0 });
    expect(report.stopped).toBeUndefined();
    // The refused transfer is gone from the store, and its staging row is aborted.
    expect(Object.keys(useDocumentsStore.getState().uploads)).toEqual([]);
    await vi.waitFor(() => {
      expect(
        requests.filter((r) => r.method === 'DELETE' && r.url.startsWith('/documents/uploads/')),
      ).toHaveLength(1);
    });
    expectAccounted(report);
  });

  it('notes a move refused because the folder is gone, leaving the document where it is', async () => {
    await holdHere(ID_A, {
      name: 'passport.pdf',
      metaOverrides: { ext: 'pdf', tags: ['travel', 'id'], note: 'Renew in 2031' },
      rowOverrides: { favorite: true },
    });
    refusals.put.push({ status: 404, message: 'Target folder not found' });
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.notes).toEqual([
      'passport.pdf: its folder no longer exists, so it was left where it is.',
    ]);
    expect(report.alreadyPresent).toBe(1);
  });

  it.each([
    [
      'a rotation in progress',
      { status: 409, message: 'Vault key rotation is in progress.' },
      'Vault key rotation is in progress.',
    ],
    [
      'a stale vault key',
      { status: 409, message: 'Your vault key changed.', data: { vaultKeyVersion: 4 } },
      'Your vault key changed. Reload the page.',
    ],
    [
      'too many uploads',
      { status: 400, message: 'Too many uploads in progress. You can run 3 at a time.' },
      'Too many uploads in progress. You can run 3 at a time.',
    ],
    ['a CSRF refusal', { status: 403, message: 'Invalid CSRF token' }, 'Invalid CSRF token'],
  ])('stops the whole run on %s at upload start', async (_label, refusal, message) => {
    refusals.init.push(refusal, refusal, refusal);
    const { report } = await restore();
    expect(report.stopped).toEqual({ stop: 'failed', message });
    expect(report.uploaded).toBe(0);
    expect(report.notAttempted).toBe(2);
    expectAccounted(report);
  });

  it('stops when the server stays unreachable at upload start for ten minutes', async () => {
    for (let i = 0; i < 40; i += 1) refusals.init.push({ status: 'offline' });
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.stopped?.stop).toBe('server-unavailable');
    expect(waits.reduce((total, ms) => total + ms, 0)).toBeLessThanOrEqual(10 * 60 * 1000);
  });

  it('stops when a start keeps failing with a server fault past the ladder', async () => {
    for (let i = 0; i < 4; i += 1) refusals.init.push({ status: 500, message: 'Boom' });
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.stopped).toEqual({ stop: 'server-unavailable', message: 'Boom' });
    expect(waits).toEqual([1_000, 2_000, 4_000]);
  });

  it('stops before uploading past the document limit', async () => {
    documentCountOverride = MAX_DOCUMENTS_PER_USER;
    const { report } = await restore();
    expect(report.stopped?.message).toBe(
      `Document limit reached: an account can hold ${String(MAX_DOCUMENTS_PER_USER)} documents.`,
    );
    expect(uploadsStarted()).toBe(0);
  });

  it('stops, saying so, when the server stores no documents or cannot say', async () => {
    documentsConfig = { enabled: false };
    expect((await restore()).report.stopped?.message).toContain('does not store documents');
    documentsConfig = null;
    api.defaults.adapter = (config) =>
      config.url === '/config'
        ? refuse({ status: 'offline' }, config as InternalAxiosRequestConfig)
        : adapter(config);
    expect((await restore()).report.stopped?.message).toContain(
      "Could not confirm this server's document storage",
    );
  });

  it('stops when the list cannot be read past its ladders', async () => {
    for (let i = 0; i < 7; i += 1) refusals.list.push({ status: 503 });
    const { report } = await restore();
    expect(report.stopped?.stop).toBe('server-unavailable');
    expect(report.notAttempted).toBe(2);
  });
});

describe('locks, sign-out and Stop', () => {
  it('stops at once when the vault locks during a wait, cancelling the transfer in flight', async () => {
    refusals.part.push({ status: 429, headers: { 'retry-after': '600' } });
    const { report } = await restore({
      backup: await backupOf([backupB]),
      wait: (_ms, signal) =>
        new Promise((resolve) => {
          signal.addEventListener('abort', () => resolve());
          useAuthStore.setState({ vaultKey: null });
        }),
    });
    expect(report.stopped).toEqual({
      stop: 'vault-locked',
      message: 'The vault locked or you signed out.',
    });
    expect(useDocumentsStore.getState().uploads).toEqual({});
    // The cancelled transfer's staging row is aborted on the server (a best-effort
    // request sent as the transfer is dropped).
    await vi.waitFor(() => {
      expect(staging.size).toBe(0);
    });
    expect(
      requests.some((r) => r.method === 'DELETE' && r.url.startsWith('/documents/uploads/')),
    ).toBe(true);
  });

  it('stops when sign-out clears the documents store, before the vault key is gone', async () => {
    let cleared = false;
    api.defaults.adapter = (config) => {
      if (!cleared && config.url?.endsWith('/complete')) {
        cleared = true;
        useDocumentsStore.getState().clearStore();
      }
      return adapter(config);
    };
    const { report } = await restore();
    expect(report.stopped?.stop).toBe('vault-locked');
  });

  it('reports the user’s own Stop as stopped, not as a lock', async () => {
    const controller = new AbortController();
    api.defaults.adapter = (config) => {
      if (config.url === '/documents/uploads' && config.method === 'post')
        controller.abort('stopped');
      return adapter(config);
    };
    const { report } = await restore({ signal: controller.signal });
    expect(report.stopped).toEqual({ stop: 'stopped', message: 'You stopped it.' });
    expectAccounted(report);
  });
});

describe('the rest of the paths', () => {
  it('reports nothing missing for a backup whose vault part names no document count', async () => {
    const { report } = await restore({ backup: await backupOf([backupB], {}) });
    expect(report).toMatchObject({ uploaded: 1, missingFromBackup: 0 });
  });

  it('does nothing for a page that already went away', async () => {
    const controller = new AbortController();
    controller.abort('left');
    const { report } = await restore({ signal: controller.signal });
    expect(report.stopped).toEqual({ stop: 'left', message: 'You left the page.' });
    expect(requests.filter((r) => r.url !== '/config')).toEqual([]);
  });

  it('waits on real timers when the caller gives no seam', async () => {
    const report = await restoreFullBackupDocuments({
      backup: await backupOf([backupB]),
      backupVaultKey: backupKey,
      folderIdMap: [],
      conflictStrategy: 'skip',
      signal: new AbortController().signal,
    });
    expect(report.uploaded).toBe(1);
  });

  it.each([
    [
      'after the account is read',
      (method: string, url: string) => method === 'GET' && url === '/documents/usage',
    ],
    [
      'between two documents',
      (method: string, url: string) => method === 'POST' && url.endsWith('/complete'),
    ],
  ])('stops on a Stop that lands %s', async (_label, when) => {
    const controller = new AbortController();
    onRequest = (method, url) => {
      if (when(method, url)) controller.abort('stopped');
    };
    const { report } = await restore({ signal: controller.signal });
    expect(report.stopped).toEqual({ stop: 'stopped', message: 'You stopped it.' });
    expectAccounted(report);
  });

  it('counts nothing more after a Stop, even for a document that needs no request', async () => {
    await holdHere(ID_B, { name: 'notes.txt' });
    // Not a favorite, so no write follows the upload that could notice the Stop first.
    const plainA = await buildStoredDocument({
      id: ID_A,
      vaultKey: backupKey,
      name: 'passport.pdf',
    });
    const controller = new AbortController();
    onRequest = (method, url) => {
      if (method === 'POST' && url.endsWith('/complete')) controller.abort('stopped');
    };
    const { report } = await restore({
      backup: await backupOf([plainA, backupB]),
      signal: controller.signal,
    });
    expect(report.stopped).toEqual({ stop: 'stopped', message: 'You stopped it.' });
    expect(report).toMatchObject({ uploaded: 1, alreadyPresent: 0, notAttempted: 1 });
    expectAccounted(report);
  });

  it('keeps the provenance of a transform the backup recorded', async () => {
    const transformed = await buildStoredDocument({
      id: ID_B,
      vaultKey: backupKey,
      name: 'data.json',
      metaOverrides: {
        transform: {
          formatted: true,
          repaired: false,
          tool: 'prettier',
          toolVersion: '3.0.0',
          originalSha256: 'a'.repeat(64),
        },
      },
    });
    await restore({ backup: await backupOf([transformed]) });
    expect((await openStored(MINTED[0]!)).meta.transform).toEqual({
      formatted: true,
      repaired: false,
      tool: 'prettier',
      toolVersion: '3.0.0',
      originalSha256: 'a'.repeat(64),
    });
  });

  it('records a document whose bytes in the file do not match the checksum sealed with it', async () => {
    const wrong = await buildStoredDocument({
      id: ID_B,
      vaultKey: backupKey,
      metaOverrides: { sha256: 'f'.repeat(64) },
    });
    const { report } = await restore({ backup: await backupOf([wrong]) });
    expect(report.notRestored).toEqual([
      {
        name: 'report.txt',
        reason: 'It could not be read from the backup and verified, so it was not restored.',
      },
    ]);
  });

  /** The backup, with its file reads replaced. */
  async function withReads(read: OpenedFullBackup['readSegment']): Promise<OpenedFullBackup> {
    return { ...(await backupOf([backupB])), readSegment: read };
  }

  it('stops when the backup file can no longer be read', async () => {
    const { report } = await restore({
      backup: await withReads(() => Promise.reject(new DOMException('gone', 'NotReadableError'))),
    });
    expect(report.stopped).toEqual({
      stop: 'failed',
      message: 'The backup file could not be read. Was it moved or changed?',
    });
  });

  it('stops on a Stop that lands while the file is read', async () => {
    const controller = new AbortController();
    const { report } = await restore({
      signal: controller.signal,
      backup: await withReads(() => {
        controller.abort('stopped');
        return Promise.reject(new Error('cut short'));
      }),
    });
    expect(report.stopped?.stop).toBe('stopped');
  });

  it('reports a fault it did not expect while reading the file as failed', async () => {
    const { report } = await restore({
      backup: await withReads(() => Promise.reject(new TypeError('Unexpected'))),
    });
    expect(report.stopped).toEqual({ stop: 'failed', message: 'Unexpected' });
  });

  it('stops when upload start answers that the session is gone', async () => {
    refusals.init.push({ status: 403, message: 'Forbidden' });
    const { report } = await restore();
    expect(report.stopped).toEqual({ stop: 'vault-locked', message: 'Your session ended.' });
  });

  it('waits a minute for a 429 at a part that names no wait', async () => {
    refusals.part.push({ status: 429 });
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.uploaded).toBe(1);
    expect(waits).toEqual([20_000, 20_000, 20_000]);
  });

  it.each([
    ['one pause longer than a window', [{ status: 429, headers: { 'retry-after': '901' } }]],
    [
      'seven pauses in a row',
      Array.from({ length: 7 }, () => ({ status: 429, headers: { 'retry-after': '1' } })),
    ],
  ])('stops a transfer the rate limit holds back for %s', async (_label, list) => {
    refusals.part.push(...(list as Refusal[]));
    const { report } = await restore({ backup: await backupOf([backupB]) });
    expect(report.stopped?.stop).toBe('rate-limited');
    expect(useDocumentsStore.getState().uploads).toEqual({});
  });

  it('stops after five starts refused because another was being opened', async () => {
    const busy = {
      status: 409,
      message:
        'Another transfer is already being opened for this account. Please wait a moment and retry.',
    };
    refusals.init.push(busy, busy, busy, busy, busy, busy);
    const { report, waits } = await restore({ backup: await backupOf([backupB]) });
    expect(report.stopped).toEqual({ stop: 'failed', message: busy.message });
    expect(waits).toEqual([2_000, 2_000, 2_000, 2_000, 2_000]);
  });

  it('stops when the server frames documents differently from this client', async () => {
    advertisedChunkBytes = 1024;
    const { report } = await restore({ backup: await backupOf([backupB]) });
    expect(report.stopped).toEqual({
      stop: 'failed',
      message:
        'This server frames documents differently from this client; the upload was not started.',
    });
  });

  describe('a transfer whose own ladders are spent', () => {
    beforeEach(async () => {
      // Loaded BEFORE the clock is faked: a dynamic import still to be fetched
      // does not settle under fake timers, so the run would wait for ever on it.
      await loadUploadRecovery();
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    async function settle<T>(promise: Promise<T>): Promise<T> {
      let done = false;
      const tracked = promise.finally(() => {
        done = true;
      });
      // Real asynchronous work (Web Crypto, Blob reads) completes on the REAL event
      // loop, so each step also yields one real macrotask before the fake clock
      // moves again; the engine's 1, 2 and 4 s waits are then advanced as they arm.
      for (let i = 0; i < 2_000 && !done; i += 1) {
        await new Promise<void>((resolve) => {
          setImmediate(resolve);
        });
        await vi.advanceTimersByTimeAsync(1_000);
      }
      return tracked;
    }

    it.each([
      [
        'a server fault on every part',
        () => Array.from({ length: 5 }, () => ({ status: 500, message: 'Boom' })),
      ],
      [
        'a 408 on every part',
        () => Array.from({ length: 5 }, () => ({ status: 408, message: 'Request Timeout' })),
      ],
    ])('stops on %s, cancelling the transfer', async (_label, list) => {
      refusals.part.push(...(list() as Refusal[]));
      const { report } = await settle(restore({ backup: await backupOf([backupB]) }));
      expect(report.stopped?.stop).toBe('server-unavailable');
      expect(useDocumentsStore.getState().uploads).toEqual({});
    });
  });

  it.each([
    [
      'a gone session',
      { status: 403, message: 'Forbidden' },
      { stop: 'vault-locked', message: 'Your session ended.' },
    ],
    [
      'a CSRF refusal',
      { status: 403, message: 'Invalid CSRF token' },
      { stop: 'failed', message: 'Invalid CSRF token' },
    ],
    [
      'a conflict',
      { status: 409, message: 'Changed meanwhile' },
      { stop: 'failed', message: 'Changed meanwhile' },
    ],
  ])('stops when a details write answers %s', async (_label, refusal, stopped) => {
    await holdHere(ID_A, { name: 'renamed.pdf', metaOverrides: { ext: 'pdf' } });
    refusals.put.push(refusal, refusal, refusal);
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.stopped).toEqual(stopped);
  });

  it('stops when a details write keeps failing with a server fault', async () => {
    await holdHere(ID_A, { name: 'renamed.pdf', metaOverrides: { ext: 'pdf' } });
    for (let i = 0; i < 4; i += 1) refusals.put.push({ status: 500, message: 'Boom' });
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.stopped).toEqual({ stop: 'server-unavailable', message: 'Boom' });
  });

  it('notes a rename the file type lock refuses, and still applies the rest', async () => {
    await holdHere(ID_A, { name: 'passport.txt', metaOverrides: { ext: 'txt' } });
    const { report } = await restore({
      backup: await backupOf([backupA]),
      conflictStrategy: 'overwrite',
    });
    expect(report.notes).toContain(
      'passport.pdf: its file type differs here, so its name, tags and note were not replaced.',
    );
    expect(report.updated).toBe(1);
    expect(rows.get(ID_A)?.favorite).toBe(true);
  });
});
