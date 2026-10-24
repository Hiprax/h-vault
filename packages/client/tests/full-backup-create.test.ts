/**
 * Making a full backup (`services/backup/createFullBackup.ts`), end to end against
 * the real documents store, the real crypto and a stub transport.
 *
 * Only the TRANSPORT is replaced: a stub Axios adapter answers the vault download,
 * the document list, each segment and the profile. Every document is sealed with
 * the real functions, and every file a run saves is read back with the real reader
 * (`openFullBackupFile`), so "the backup holds the document" is asserted as bytes
 * the restore would see, never as calls the engine made.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios, {
  AxiosError,
  type AxiosAdapter,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';

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
// Counted, not exercised: the pause itself is `auto-lock-progress.test.ts`'s
// subject. Here what matters is WHEN the run reports progress.
const progressNotes = vi.hoisted(() => ({ count: 0 }));
vi.mock('../src/hooks/useAutoLock', () => ({
  noteAutoLockProgress: () => {
    progressNotes.count += 1;
  },
}));

import { api } from '../src/services/api/client.js';
import { cryptoService } from '../src/services/crypto/cryptoService.js';
import {
  deriveFullBackupSigningKey,
  verifyFullBackupManifest,
} from '../src/services/crypto/fullBackupCrypto.js';
import {
  createFullBackup,
  type FullBackupProgress,
} from '../src/services/backup/createFullBackup.js';
import { openFullBackupFile } from '../src/services/backup/fullBackupFormat.js';
import { deriveWrapKey } from '../src/services/crypto/documentCryptoService.js';
import { UNOPENABLE_DOCUMENT_NAME } from '../src/services/documents/documentNames.js';
import { useAuthStore } from '../src/stores/authStore.js';
import { useDocumentsStore } from '../src/stores/documentsStore.js';
import {
  buildStoredDocument,
  memoryTarget,
  ramp,
  type MemoryTarget,
  type StoredDocument,
} from './support/storedDocuments.js';

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';
const ID_C = '66c0f1a2b3c4d5e6f7a8b9c2';
const FOLDER = 'f0f0f0f0f0f0f0f0f0f0f0f0';

// ---------------------------------------------------------------------------
// The stub server
// ---------------------------------------------------------------------------

interface Refusal {
  status: number;
  message?: string;
  headers?: Record<string, string>;
  /** Served this many times, then the request is answered normally; always when absent. */
  times?: number;
}

let vaultJson: string;
let listedRows: unknown[];
let segmentsById: Map<string, Uint8Array[]>;
let segmentRefusals: Map<string, Refusal>;
let profile: {
  encryptedVaultKey: string;
  vaultKeyIv?: string;
  vaultKeyTag?: string;
  vaultKeyVersion?: number;
};
let downloadRefusal: Refusal | null;
let requests: string[];
let onSegment: ((id: string, index: number) => void) | null;
/** Runs on every request, before it is answered. */
let onRequest: ((url: string) => void) | null;
/** The per-call deadline each segment request was sent with. */
let segmentTimeouts: (number | undefined)[];
/** Download progress events a segment answer reports, as `[loaded, total]` pairs; the real length when absent. */
let segmentProgress: ((expected: number) => [number, number][]) | null;

function ok(data: unknown, config: InternalAxiosRequestConfig): AxiosResponse {
  return { data, status: 200, statusText: 'OK', headers: {}, config } as AxiosResponse;
}

function refuse(refusal: Refusal, config: InternalAxiosRequestConfig): Promise<never> {
  return Promise.reject(
    new AxiosError(
      `Request failed with status code ${String(refusal.status)}`,
      AxiosError.ERR_BAD_RESPONSE,
      config,
      undefined,
      {
        status: refusal.status,
        statusText: 'Error',
        data: { success: false, message: refusal.message ?? 'nope', statusCode: refusal.status },
        headers: refusal.headers ?? {},
        config,
      },
    ),
  );
}

/** Serve `refusal` once more, if it still has servings left. */
function take(refusal: Refusal | null | undefined): Refusal | null {
  if (!refusal) return null;
  if (refusal.times === undefined) return refusal;
  if (refusal.times <= 0) return null;
  refusal.times -= 1;
  return refusal;
}

const adapter: AxiosAdapter = (config) => {
  const url = config.url ?? '';
  requests.push(url);
  onRequest?.(url);
  if (url === '/backup/download') {
    const refusal = take(downloadRefusal);
    if (refusal) return refuse(refusal, config);
    return Promise.resolve(ok(vaultJson, config));
  }
  if (url === '/documents') {
    const page = Number((config.params as { page?: number } | undefined)?.page ?? 1);
    return Promise.resolve(
      ok(
        {
          success: true,
          data: page === 1 ? listedRows : [],
          pagination: { page, limit: 100, total: listedRows.length, totalPages: 1 },
        },
        config,
      ),
    );
  }
  if (url === '/user/profile') {
    return Promise.resolve(ok({ success: true, data: profile }, config));
  }
  const segment = /^\/documents\/([a-f0-9]{24})\/segments\/(\d+)$/.exec(url);
  if (segment) {
    const id = segment[1]!;
    const index = Number(segment[2]);
    onSegment?.(id, index);
    segmentTimeouts.push(config.timeout);
    const refusal = take(segmentRefusals.get(`${id}/${String(index)}`) ?? segmentRefusals.get(id));
    if (refusal) return refuse(refusal, config);
    const body = segmentsById.get(id)?.[index];
    if (!body) return refuse({ status: 404, message: 'Document not found' }, config);
    for (const [loaded, total] of segmentProgress?.(body.length) ?? []) {
      config.onDownloadProgress?.({
        loaded,
        total,
        bytes: loaded,
        lengthComputable: true,
      } as never);
    }
    return Promise.resolve(ok(body.slice().buffer, config));
  }
  return refuse({ status: 404 }, config);
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let vaultKey: CryptoKey;
let mek: CryptoKey;
let bwk: ArrayBuffer;
let signingKey: CryptoKey;
let docA: StoredDocument;
let docB: StoredDocument;
let docC: StoredDocument;
/** The 32-byte plaintexts `crypto.subtle.decrypt` produced: the document keys. */
let unwrappedKeys: Uint8Array[];

/** The session key, wrapped ONCE per test: the server's stored wrapper does not change between reads. */
let sessionWrapper: { encrypted: string; iv: string; tag: string };

async function vaultFor(key: CryptoKey, extra: Record<string, unknown> = {}): Promise<string> {
  const wrapped = key === vaultKey ? sessionWrapper : await cryptoService.encryptVaultKey(key, mek);
  return JSON.stringify({
    version: '0.22.0',
    exportDate: '2026-10-23T10:00:00.000Z',
    items: [{ _id: 'a'.repeat(24), itemType: 'login' }],
    folders: [{ _id: FOLDER }],
    encryptedVaultKey: wrapped.encrypted,
    vaultKeyIv: wrapped.iv,
    vaultKeyTag: wrapped.tag,
    backupEncryption: { encryptedBWK: 'x' },
    metadata: { itemCount: 1, folderCount: 1 },
    documentSummary: { count: listedRows.length, totalBytes: 0 },
    ...extra,
  });
}

function serveDocuments(documents: StoredDocument[]): void {
  listedRows = documents.map((doc) => doc.row);
  for (const doc of documents) segmentsById.set(doc.id, doc.segments);
}

/** The two adapter slots, typed so the original (possibly absent) adapter can be put back. */
interface AdapterSlot {
  adapter?: typeof axios.defaults.adapter | undefined;
}
const apiDefaults: AdapterSlot = api.defaults;
const axiosDefaults: AdapterSlot = axios.defaults;
const originalApiAdapter = api.defaults.adapter;
const originalGlobalAdapter = axios.defaults.adapter;

beforeEach(async () => {
  requests = [];
  segmentsById = new Map();
  segmentRefusals = new Map();
  segmentTimeouts = [];
  downloadRefusal = null;
  onSegment = null;
  onRequest = null;
  segmentProgress = null;
  progressNotes.count = 0;
  unwrappedKeys = [];
  api.defaults.adapter = adapter;
  axios.defaults.adapter = adapter;

  const realDecrypt = globalThis.crypto.subtle.decrypt.bind(globalThis.crypto.subtle);
  vi.spyOn(globalThis.crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
    const result = await realDecrypt(...(args as Parameters<typeof realDecrypt>));
    if (result.byteLength === 32) unwrappedKeys.push(new Uint8Array(result));
    return result;
  });

  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  mek = await crypto.subtle.importKey(
    'raw',
    crypto.getRandomValues(new Uint8Array(32)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  sessionWrapper = await cryptoService.encryptVaultKey(vaultKey, mek);
  bwk = cryptoService.generateBWK();
  signingKey = await deriveFullBackupSigningKey(bwk);
  docA = await buildStoredDocument({
    id: ID_A,
    vaultKey,
    plaintext: ramp(20),
    rowOverrides: { folderId: FOLDER, favorite: true },
  });
  docB = await buildStoredDocument({ id: ID_B, vaultKey, plaintext: ramp(5, 3), name: 'b.pdf' });
  docC = await buildStoredDocument({ id: ID_C, vaultKey, plaintext: ramp(9, 5), name: 'c.txt' });
  serveDocuments([docA, docB]);
  vaultJson = await vaultFor(vaultKey);
  profile = {
    encryptedVaultKey: sessionWrapper.encrypted,
    vaultKeyIv: sessionWrapper.iv,
    vaultKeyTag: sessionWrapper.tag,
    vaultKeyVersion: 3,
  };

  useDocumentsStore.getState().clearStore();
  useAuthStore.setState({
    isAuthenticated: true,
    isLocked: false,
    accessToken: 'access-token',
    vaultKey,
    mek,
    vaultKeyVersion: 3,
  });
});

afterEach(() => {
  useAuthStore.setState({ vaultKey: null, mek: null, accessToken: null, isAuthenticated: false });
  apiDefaults.adapter = originalApiAdapter;
  axiosDefaults.adapter = originalGlobalAdapter;
  vi.restoreAllMocks();
});

/** Waits resolve at once, and are recorded. */
function instantWaits(): { waits: number[]; wait: (ms: number) => Promise<void> } {
  const waits: number[] = [];
  return {
    waits,
    wait: (ms) => {
      waits.push(ms);
      return Promise.resolve();
    },
  };
}

async function run(
  target: MemoryTarget = memoryTarget(),
  options: Partial<Parameters<typeof createFullBackup>[1]> = {},
) {
  const controller = new AbortController();
  const progress: FullBackupProgress[] = [];
  const result = await createFullBackup(target, {
    signal: controller.signal,
    signingKey,
    wait: instantWaits().wait,
    now: () => new Date('2026-10-23T10:00:00.000Z'),
    onProgress: (p) => progress.push(p),
    ...options,
  });
  return { result, target, progress };
}

// ---------------------------------------------------------------------------

describe('createFullBackup — a complete run', () => {
  it('saves the vault and every live document, verified, into one signed file the restore reads', async () => {
    const { result, target } = await run();

    expect(result).toEqual({
      saved: true,
      fileName: target.name,
      kind: 'file',
      bytes: (await target.bytes()).length,
      itemCount: 1,
      folderCount: 1,
      documentCount: 2,
      leftOut: [],
      unlisted: 0,
    });
    expect(target.calls.at(-1)).toBe('commit');
    expect(target.calls).not.toContain('discard');

    const opened = await openFullBackupFile(new Blob([await target.bytes()]));
    expect(opened.manifest.vault).toEqual(JSON.parse(vaultJson));
    expect(opened.manifest.documents.map((entry) => entry.row)).toEqual([docA.row, docB.row]);
    for (const [position, doc] of [docA, docB].entries()) {
      const entry = opened.manifest.documents[position]!;
      for (const [index, segment] of doc.segments.entries()) {
        expect([...(await opened.readSegment(entry, index))]).toEqual([...segment]);
      }
    }
    expect(await verifyFullBackupManifest(opened.signedPayload, opened.signature, bwk)).toBe(true);
    expect(opened.manifest.createdAt).toBe('2026-10-23T10:00:00.000Z');
    // Every document key unwrapped along the way was zeroed.
    expect(unwrappedKeys.length).toBeGreaterThan(0);
    expect(unwrappedKeys.every((key) => key.every((byte) => byte === 0))).toBe(true);
  });

  it('reads the vault before the list, and asks for every segment in order', async () => {
    await run();
    const order = requests.filter((url) => url !== '/user/profile');
    expect(order.slice(0, 2)).toEqual(['/backup/download', '/documents']);
    expect(order.slice(2)).toEqual([
      `/documents/${ID_A}/segments/0`,
      `/documents/${ID_A}/segments/1`,
      `/documents/${ID_A}/segments/2`,
      `/documents/${ID_B}/segments/0`,
    ]);
    expect(requests.at(-1)).toBe('/user/profile');
  });

  it('reports each document before it is read, then the finishing step', async () => {
    const { progress } = await run();
    expect(progress.map((p) => p.phase)).toEqual(['vault', 'documents', 'documents', 'finishing']);
    expect(progress[1]).toMatchObject({ index: 1, total: 2, name: 'report.txt', bytesRead: 0 });
    expect(progress[2]).toMatchObject({
      index: 2,
      name: 'b.pdf',
      bytesRead: docA.row.ciphertextBytes,
    });
  });

  it('saves a file with no document in it for an account holding none', async () => {
    serveDocuments([]);
    vaultJson = await vaultFor(vaultKey);
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 0 });
    expect((await openFullBackupFile(new Blob([await target.bytes()]))).manifest.documents).toEqual(
      [],
    );
  });
});

describe('createFullBackup — documents it leaves out, with the run going on', () => {
  it('leaves out a document whose key will not open, naming it as the list does', async () => {
    const other = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    const degraded = await buildStoredDocument({ id: ID_C, vaultKey: other });
    serveDocuments([docA, degraded]);
    vaultJson = await vaultFor(vaultKey);

    const { result, target } = await run();

    expect(result).toMatchObject({
      saved: true,
      documentCount: 1,
      leftOut: [
        { name: UNOPENABLE_DOCUMENT_NAME, reason: expect.stringContaining('could not be read') },
      ],
    });
    const opened = await openFullBackupFile(new Blob([await target.bytes()]));
    expect(opened.manifest.omitted).toEqual([{ id: ID_C, reason: 'unreadable' }]);
    // No segment of it was ever asked for.
    expect(requests.some((url) => url.startsWith(`/documents/${ID_C}/segments`))).toBe(false);
  });

  it("stops, saving nothing, when a degraded row shows the session's key was replaced (the vault locks)", async () => {
    const other = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    serveDocuments([docA, await buildStoredDocument({ id: ID_C, vaultKey: other })]);
    vaultJson = await vaultFor(vaultKey);
    // The account's live key is another one: the held-key check locks the vault.
    const live = await cryptoService.encryptVaultKey(other, mek);
    profile = {
      encryptedVaultKey: live.encrypted,
      vaultKeyIv: live.iv,
      vaultKeyTag: live.tag,
      vaultKeyVersion: 4,
    };
    const target = memoryTarget();
    useAuthStore.setState({
      lock: () => {
        useAuthStore.setState({ vaultKey: null, isLocked: true });
        return Promise.resolve();
      },
    });

    const { result } = await run(target);

    expect(result).toMatchObject({ saved: false });
    expect(target.calls).not.toContain('commit');
  });

  it.each([
    ['contents-missing', 'This document’s stored contents are missing from storage.'],
    ['deleted', 'Document not found'],
  ] as const)('records a 404 as %s, by the server’s sentence', async (reason, message) => {
    segmentRefusals.set(`${ID_B}/0`, { status: 404, message });
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1 });
    const opened = await openFullBackupFile(new Blob([await target.bytes()]));
    expect(opened.manifest.omitted).toEqual([{ id: ID_B, reason }]);
  });

  it('leaves out ONE document a server fault keeps refusing, after the short ladder, and saves the rest', async () => {
    serveDocuments([docA, docB, docC]);
    vaultJson = await vaultFor(vaultKey);
    segmentRefusals.set(ID_B, { status: 500, message: 'does not match its recorded size' });
    const { waits, wait } = instantWaits();

    const { result, target } = await run(memoryTarget(), { wait });

    expect(result).toMatchObject({
      saved: true,
      documentCount: 2,
      leftOut: [{ name: 'b.pdf', reason: 'does not match its recorded size' }],
    });
    expect(waits).toEqual([1_000, 2_000, 4_000]);
    const opened = await openFullBackupFile(new Blob([await target.bytes()]));
    expect(opened.manifest.documents.map((entry) => entry.row._id)).toEqual([ID_A, ID_C]);
  });

  it('leaves out a document the server sent a segment of the wrong length for', async () => {
    segmentsById.set(ID_B, [docB.segments[0]!.slice(0, 3)]);
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1 });
    expect((await openFullBackupFile(new Blob([await target.bytes()]))).manifest.omitted).toEqual([
      { id: ID_B, reason: 'unreadable' },
    ]);
  });

  it('leaves out a document whose segment was altered, and keeps nothing of it', async () => {
    const altered = docB.segments[0]!.slice();
    altered[0] = (altered[0] ?? 0) ^ 1;
    segmentsById.set(ID_B, [altered]);
    const { result } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1, leftOut: [{ name: 'b.pdf' }] });
  });

  it('counts the rows the server listed that failed the shared schema', async () => {
    listedRows = [docA.row, { _id: 'not-an-id' }];
    segmentsById.set(ID_A, docA.segments);
    vaultJson = await vaultFor(vaultKey, { documentSummary: { count: 2, totalBytes: 0 } });
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1, unlisted: 1 });
    expect((await openFullBackupFile(new Blob([await target.bytes()]))).manifest.unlisted).toBe(1);
  });
});

describe('createFullBackup — every early end saves nothing', () => {
  async function expectDiscarded(target: MemoryTarget): Promise<void> {
    expect(target.calls).toContain('discard');
    expect(target.calls).not.toContain('commit');
    expect(await target.bytes()).toHaveLength(0);
  }

  it('stops when three documents in a row fail on a server fault', async () => {
    serveDocuments([docA, docB, docC]);
    vaultJson = await vaultFor(vaultKey);
    for (const id of [ID_A, ID_B, ID_C]) segmentRefusals.set(id, { status: 500 });
    const { result, target } = await run();
    expect(result).toEqual({
      saved: false,
      stop: 'server-unavailable',
      message: 'The storage server failed on several documents in a row, so the backup stopped.',
    });
    await expectDiscarded(target);
  });

  it('counts server faults across a 404 between them, which neither counts nor resets the run', async () => {
    const docD = await buildStoredDocument({
      id: '66c0f1a2b3c4d5e6f7a8b9c3',
      vaultKey,
      plaintext: ramp(4, 9),
      name: 'd.txt',
    });
    serveDocuments([docA, docB, docC, docD]);
    vaultJson = await vaultFor(vaultKey);
    segmentRefusals.set(ID_A, { status: 500 });
    segmentRefusals.set(ID_B, { status: 404, message: 'Document not found' });
    segmentRefusals.set(ID_C, { status: 500 });
    segmentRefusals.set(docD.id, { status: 500 });
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: false, stop: 'server-unavailable' });
    await expectDiscarded(target);
  });

  it('starts the run of server faults again after a document is written', async () => {
    const docD = await buildStoredDocument({
      id: '66c0f1a2b3c4d5e6f7a8b9c3',
      vaultKey,
      plaintext: ramp(4, 9),
      name: 'd.txt',
    });
    serveDocuments([docA, docB, docC, docD]);
    vaultJson = await vaultFor(vaultKey);
    segmentRefusals.set(ID_A, { status: 500 });
    segmentRefusals.set(ID_B, { status: 500 });
    segmentRefusals.set(docD.id, { status: 500 });
    const { result } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1 });
  });

  it('never stops on documents the server says are gone, however many in a row', async () => {
    serveDocuments([docA, docB, docC]);
    vaultJson = await vaultFor(vaultKey);
    for (const id of [ID_A, ID_B, ID_C]) {
      segmentRefusals.set(id, { status: 404, message: 'Document not found' });
    }
    const { result } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 0 });
  });

  it('reports a document write the browser refused once as save-failed, never saving past it', async () => {
    const target = memoryTarget();
    const write = target.write;
    target.write = (chunk) => {
      // The header was written; the first document's bytes are refused once. A
      // DOMException is what a file write throws, and it says nothing a person reads.
      if (target.calls.length === 1) {
        target.calls.push('write');
        return Promise.reject(new DOMException('', 'QuotaExceededError'));
      }
      return write(chunk);
    };
    const { result } = await run(target);
    expect(result).toEqual({
      saved: false,
      stop: 'save-failed',
      message: 'Your browser could not write the backup file.',
    });
    expect(target.calls).toContain('discard');
    expect(target.calls).not.toContain('commit');
  });

  it('asks for every segment with a five-minute deadline of its own', async () => {
    await run();
    expect(segmentTimeouts.length).toBeGreaterThan(0);
    expect(new Set(segmentTimeouts)).toEqual(new Set([5 * 60 * 1000]));
  });

  it('leaves out a row a restore would refuse, reading none of it, and saves the rest', async () => {
    const purging = await buildStoredDocument({
      id: ID_C,
      vaultKey,
      rowOverrides: { purgePending: true } as never,
    });
    serveDocuments([docA, purging]);
    vaultJson = await vaultFor(vaultKey);
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: true, documentCount: 1 });
    expect(requests.some((url) => url.startsWith(`/documents/${ID_C}/segments`))).toBe(false);
    const opened = await openFullBackupFile(new Blob([await target.bytes()]));
    expect(opened.manifest.documents.map((entry) => entry.row._id)).toEqual([ID_A]);
    expect(opened.manifest.omitted).toEqual([{ id: ID_C, reason: 'unreadable' }]);
  });

  it('leaves out a row whose key opens to the wrong length without trying to read it', async () => {
    // Sealed correctly under this document's wrapping key, but sixteen bytes long: the
    // list cannot open it (so the row is degraded), and unwrapping it fails with a
    // plain error rather than a failed tag, which the read would treat as a fault.
    const doc = await buildStoredDocument({ id: ID_C, vaultKey });
    const wrapKey = await deriveWrapKey(vaultKey, ID_C);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        wrapKey,
        globalThis.crypto.getRandomValues(new Uint8Array(16)),
      ),
    );
    const short = {
      ...doc.row,
      encryptedDek: cryptoService.arrayBufferToBase64(sealed.slice(0, 16).buffer),
      dekIv: cryptoService.arrayBufferToBase64(iv.buffer),
      dekTag: cryptoService.arrayBufferToBase64(sealed.slice(16).buffer),
    };
    listedRows = [docA.row, short];
    segmentsById.set(ID_A, docA.segments);
    segmentsById.set(ID_C, doc.segments);
    vaultJson = await vaultFor(vaultKey);
    const { result } = await run();
    expect(result).toMatchObject({
      saved: true,
      documentCount: 1,
      leftOut: [
        { name: UNOPENABLE_DOCUMENT_NAME, reason: expect.stringContaining('could not be read') },
      ],
    });
  });

  it('refuses at once, reading no document, when the vault part does not hold the session’s key', async () => {
    vaultJson = await vaultFor(
      await cryptoService.importVaultKey(cryptoService.generateVaultKey()),
    );
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: false, stop: 'key-changed' });
    expect(requests).toEqual(['/backup/download']);
    await expectDiscarded(target);
  });

  it('refuses, before committing, when the account’s key changed during the run', async () => {
    profile = { ...profile, encryptedVaultKey: 'rotated' };
    const { result, target } = await run();
    expect(result).toEqual({
      saved: false,
      stop: 'key-changed',
      message: 'Your vault key or master password changed during the backup.',
    });
    await expectDiscarded(target);
  });

  it('refuses when the generation moved, and reads an absent one as 0', async () => {
    delete profile.vaultKeyVersion;
    expect((await run()).result).toMatchObject({ saved: false, stop: 'key-changed' });
    useAuthStore.setState({ vaultKeyVersion: 0 });
    expect((await run()).result).toMatchObject({ saved: true });
  });

  it('reads a short list once more, and refuses a list that is still short', async () => {
    vaultJson = await vaultFor(vaultKey, { documentSummary: { count: 3, totalBytes: 0 } });
    const { result, target } = await run();
    expect(result).toEqual({
      saved: false,
      stop: 'failed',
      message: 'Your documents changed while the backup was starting. Try again.',
    });
    expect(requests.filter((url) => url === '/documents')).toHaveLength(2);
    await expectDiscarded(target);
  });

  it('refuses a backup too large to build in memory, reading no document', async () => {
    const target = memoryTarget({ kind: 'download', limitBytes: 1_000 });
    const { result } = await run(target);
    expect(result).toMatchObject({ saved: false, stop: 'too-large' });
    expect((result as { message: string }).message).toContain('Desktop Chrome or Edge');
    expect(requests.some((url) => url.includes('/segments/'))).toBe(false);
    await expectDiscarded(target);
  });

  it('refuses a vault part a restore would refuse, before reading the list', async () => {
    vaultJson = await vaultFor(vaultKey, { padding: 'x'.repeat(26_214_400) });
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: false, stop: 'too-large' });
    expect(requests).toEqual(['/backup/download']);
    await expectDiscarded(target);
  });

  it.each(['not json', '[]', 'null'])(
    'refuses a vault download that is not an object: %s',
    async (body) => {
      vaultJson = body;
      const { result, target } = await run();
      expect(result).toEqual({
        saved: false,
        stop: 'failed',
        message: 'The server sent a vault backup this page could not read.',
      });
      await expectDiscarded(target);
    },
  );

  it('reports a write the browser refused as save-failed', async () => {
    const target = memoryTarget({ failWriteAt: 2 });
    const { result } = await run(target);
    expect(result).toEqual({ saved: false, stop: 'save-failed', message: 'The disk is full.' });
    await expectDiscarded(target);
  });

  it('stops on the user’s Stop, as stopped', async () => {
    const controller = new AbortController();
    onSegment = (id) => {
      if (id === ID_B) controller.abort('stopped');
    };
    const { result, target } = await run(memoryTarget(), { signal: controller.signal });
    expect(result).toEqual({ saved: false, stop: 'stopped', message: 'You stopped it.' });
    await expectDiscarded(target);
  });

  it('stops when the page goes away, as left', async () => {
    const controller = new AbortController();
    controller.abort('left');
    const { result } = await run(memoryTarget(), { signal: controller.signal });
    expect(result).toEqual({ saved: false, stop: 'left', message: 'You left the page.' });
  });

  it('stops when the server keeps asking for a pause longer than a window', async () => {
    segmentRefusals.set(`${ID_A}/0`, { status: 429, headers: { 'retry-after': '901' } });
    const { result, target } = await run();
    expect(result).toMatchObject({ saved: false, stop: 'rate-limited' });
    await expectDiscarded(target);
  });

  it('stops when the vault download keeps failing past the gateway ladder', async () => {
    downloadRefusal = { status: 503 };
    const { waits, wait } = instantWaits();
    const { result } = await run(memoryTarget(), { wait });
    expect(result).toMatchObject({ saved: false, stop: 'server-unavailable' });
    expect(waits).toEqual([1_000, 2_000, 4_000, 8_000, 16_000, 30_000]);
  });

  it('stops on a refusal that is not about one document', async () => {
    segmentRefusals.set(`${ID_A}/0`, { status: 410, message: 'Gone for good' });
    const { result } = await run();
    expect(result).toEqual({ saved: false, stop: 'failed', message: 'Gone for good' });
  });
});

describe('createFullBackup — waits, locks and sign-out', () => {
  it('waits out a short rate limit in steps that record progress, then carries on', async () => {
    segmentRefusals.set(`${ID_A}/1`, { status: 429, headers: { 'retry-after': '30' }, times: 1 });
    const { waits, wait } = instantWaits();
    const { result, progress } = await run(memoryTarget(), { wait });
    expect(result).toMatchObject({ saved: true, documentCount: 2 });
    expect(waits).toEqual([20_000, 10_000]);
    // The pause is shown against the document it interrupted.
    expect(progress.find((p) => p.waitUntil !== undefined)).toMatchObject({
      index: 1,
      name: 'report.txt',
    });
  });

  it('ends a wait the moment the vault locks, saves nothing and leaves every document key zeroed', async () => {
    segmentRefusals.set(`${ID_A}/1`, { status: 429, headers: { 'retry-after': '600' } });
    const target = memoryTarget();
    let waitEndedByAbort = false;
    const wait = (_ms: number, signal: AbortSignal): Promise<void> =>
      new Promise((resolve) => {
        signal.addEventListener('abort', () => {
          waitEndedByAbort = true;
          resolve();
        });
        // The lock lands DURING the wait.
        useAuthStore.setState({ vaultKey: null });
      });

    const { result } = await run(target, { wait });

    expect(waitEndedByAbort).toBe(true);
    expect(result).toEqual({
      saved: false,
      stop: 'vault-locked',
      message: 'The vault locked or you signed out.',
    });
    expect(target.calls).toContain('discard');
    expect(unwrappedKeys.length).toBeGreaterThan(0);
    expect(unwrappedKeys.every((key) => key.every((byte) => byte === 0))).toBe(true);
  });

  it('stops the moment sign-out clears the documents store, before the vault key is gone', async () => {
    // `logout()` clears the documents store first and the vault key only after its
    // awaited request: the run must stop on the first of the two.
    onSegment = (id) => {
      if (id === ID_B) useDocumentsStore.getState().clearStore();
    };
    const target = memoryTarget();
    const { result } = await run(target);
    expect(useAuthStore.getState().vaultKey).not.toBeNull();
    expect(result).toMatchObject({ saved: false, stop: 'vault-locked' });
    expect(target.calls).toContain('discard');
  });

  it('refuses to start without a vault key', async () => {
    useAuthStore.setState({ vaultKey: null });
    const target = memoryTarget();
    const { result } = await run(target);
    expect(result).toMatchObject({ saved: false, stop: 'vault-locked' });
    expect(requests).toEqual([]);
  });
});

describe('createFullBackup — the vault part, defensively', () => {
  it('counts nothing it cannot read, and skips the list check without a document count', async () => {
    vaultJson = JSON.stringify({
      ...JSON.parse(vaultJson),
      metadata: { itemCount: 1.5 },
      documentSummary: undefined,
    });
    const { result } = await run();
    expect(result).toMatchObject({ saved: true, itemCount: 0, folderCount: 0, documentCount: 2 });
    expect(requests.filter((url) => url === '/documents')).toHaveLength(1);
  });

  it.each([
    [
      'carries no initialisation vector',
      (vault: Record<string, unknown>) => delete vault.vaultKeyIv,
    ],
    [
      'was wrapped under another master key',
      (vault: Record<string, unknown>) => (vault.vaultKeyTag = 'AAAAAAAAAAAAAAAAAAAAAA=='),
    ],
  ])('refuses a vault part whose wrapped key %s', async (_label, damage) => {
    const vault = JSON.parse(vaultJson) as Record<string, unknown>;
    damage(vault);
    vaultJson = JSON.stringify(vault);
    const { result } = await run();
    expect(result).toMatchObject({ saved: false, stop: 'key-changed' });
  });

  it('dates the file now and waits on real timers when the caller gives no seam', async () => {
    const before = Date.now();
    const controller = new AbortController();
    const target = memoryTarget();
    const result = await createFullBackup(target, { signal: controller.signal, signingKey });
    expect(result).toMatchObject({ saved: true });
    const createdAt = Date.parse(
      (await openFullBackupFile(new Blob([await target.bytes()]))).manifest.createdAt,
    );
    expect(createdAt).toBeGreaterThanOrEqual(before);
    expect(createdAt).toBeLessThanOrEqual(Date.now());
  });
});

describe('createFullBackup — faults it did not expect, and the browser refusing the file', () => {
  it('reports an unexpected fault as failed, saving nothing', async () => {
    // Armed by the first segment request, so the fault lands in a document read
    // rather than in the vault check or the list, both of which handle their own.
    let armed = false;
    onRequest = (url) => {
      if (url.includes('/segments/')) armed = true;
    };
    const realDecrypt = vi.mocked(crypto.subtle.decrypt).getMockImplementation()!;
    vi.mocked(crypto.subtle.decrypt).mockImplementation((...args) => {
      if (armed) {
        armed = false;
        return Promise.reject(new TypeError('Something this page did not expect'));
      }
      return realDecrypt(...args);
    });
    const target = memoryTarget();
    const { result } = await run(target);
    expect(result).toEqual({
      saved: false,
      stop: 'failed',
      message: 'Something this page did not expect',
    });
    expect(target.calls).toContain('discard');
  });

  it.each([
    ['the header', 1],
    ['the table of contents', 4],
  ])('reports the browser refusing %s as save-failed', async (_label, failWriteAt) => {
    const target = memoryTarget({ failWriteAt });
    const { result } = await run(target);
    expect(result).toEqual({ saved: false, stop: 'save-failed', message: 'The disk is full.' });
    expect(target.calls).toContain('discard');
    expect(target.calls).not.toContain('commit');
  });

  it('leaves out a document whose bytes do not match the checksum sealed with it', async () => {
    const wrong = await buildStoredDocument({
      id: ID_C,
      vaultKey,
      metaOverrides: { sha256: 'f'.repeat(64) },
    });
    serveDocuments([docA, wrong]);
    vaultJson = await vaultFor(vaultKey);
    const { result } = await run();
    expect(result).toMatchObject({
      saved: true,
      documentCount: 1,
      leftOut: [{ name: 'report.txt' }],
    });
  });

  it('stops when a segment read answers that the session is gone', async () => {
    segmentRefusals.set(`${ID_A}/0`, { status: 403, message: 'Forbidden' });
    const target = memoryTarget();
    const { result } = await run(target);
    expect(result).toEqual({ saved: false, stop: 'vault-locked', message: 'Your session ended.' });
    expect(target.calls).toContain('discard');
  });
});

describe('createFullBackup — a Stop that lands between steps', () => {
  it.each([
    ['after the vault download', (url: string) => url === '/backup/download'],
    ['while the list is read', (url: string) => url === '/documents'],
    ["on a document's last segment", (url: string) => url === `/documents/${ID_A}/segments/2`],
    ["while the account's key is checked again", (url: string) => url === '/user/profile'],
  ])('ends the run %s, saving nothing', async (_label, when) => {
    const controller = new AbortController();
    onRequest = (url) => {
      if (when(url)) controller.abort('stopped');
    };
    const target = memoryTarget();
    const { result } = await run(target, { signal: controller.signal });
    expect(result).toEqual({ saved: false, stop: 'stopped', message: 'You stopped it.' });
    expect(target.calls).toContain('discard');
    expect(target.calls).not.toContain('commit');
  });

  it('ends the run while a document is being written to the file, before the next is read', async () => {
    const controller = new AbortController();
    const target = memoryTarget();
    const write = target.write;
    target.write = (chunk) => {
      // The first write after the header carries the first document.
      if (target.calls.length === 1) controller.abort('stopped');
      return write(chunk);
    };
    const { result } = await run(target, { signal: controller.signal });
    expect(result).toEqual({ saved: false, stop: 'stopped', message: 'You stopped it.' });
    expect(requests.some((url) => url.startsWith(`/documents/${ID_B}/`))).toBe(false);
    expect(target.calls).toContain('discard');
    expect(target.calls).not.toContain('commit');
  });

  it('ends the run while the file is being finished, before it is committed', async () => {
    const controller = new AbortController();
    const target = memoryTarget();
    const write = target.write;
    target.write = (chunk) => {
      // The fourth write is the table of contents.
      if (target.calls.length === 3) controller.abort('stopped');
      return write(chunk);
    };
    const { result } = await run(target, { signal: controller.signal });
    expect(result).toMatchObject({ saved: false, stop: 'stopped' });
    expect(target.calls).not.toContain('commit');
  });
});

describe('createFullBackup — progress for the auto-lock pause', () => {
  it('records progress per verified segment and per written document, never for an error body', async () => {
    serveDocuments([docB]);
    vaultJson = await vaultFor(vaultKey);
    // One event the length of the segment, one of some other length (an error body).
    segmentProgress = (expected) => [
      [expected, expected],
      [7, 999],
    ];
    await run();
    // docB: one download event that counts + one verified segment + one document written.
    expect(progressNotes.count).toBe(3);
  });

  it('records progress during a server-requested pause, and none while the server cannot be reached', async () => {
    serveDocuments([docB]);
    vaultJson = await vaultFor(vaultKey);
    segmentRefusals.set(`${ID_B}/0`, { status: 429, headers: { 'retry-after': '40' }, times: 1 });
    await run();
    const withPause = progressNotes.count;
    progressNotes.count = 0;
    downloadRefusal = null;
    segmentRefusals.clear();
    await run();
    // The 40-second pause recorded progress twice (every twenty seconds).
    expect(withPause - progressNotes.count).toBe(2);

    progressNotes.count = 0;
    let offline = 2;
    api.defaults.adapter = (config) => {
      if (config.url === `/documents/${ID_B}/segments/0` && offline > 0) {
        offline -= 1;
        return Promise.reject(
          new AxiosError(
            'Network Error',
            AxiosError.ERR_NETWORK,
            config as InternalAxiosRequestConfig,
          ),
        );
      }
      return adapter(config);
    };
    await run();
    expect(progressNotes.count).toBe(2);
  });
});
