/**
 * Documents exactly as this client stores them, for the full-backup suites: a row
 * the API would send and the sealed segments the storage engine holds, built with
 * the real sealing functions under a vault key the caller chooses.
 *
 * `chunkPlaintextBytes` defaults to 8 rather than the production 8 MiB: the framing
 * arithmetic is identical at any positive chunk size, and every reader takes the
 * value from the ROW, so a three-segment document costs twenty-odd bytes.
 */
import { documentChunkCountFor, type DocumentMeta, type DocumentResponse } from '@hvault/shared';
import { cryptoService } from '../../src/services/crypto/cryptoService.js';
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
} from '../../src/services/crypto/documentCryptoService.js';

export interface StoredDocument {
  id: string;
  row: DocumentResponse;
  meta: DocumentMeta;
  plaintext: DocumentBytes;
  segments: DocumentBytes[];
}

export interface StoredDocumentOptions {
  id: string;
  vaultKey: CryptoKey;
  name?: string;
  plaintext?: DocumentBytes;
  chunkPlaintextBytes?: number;
  metaOverrides?: Partial<DocumentMeta>;
  rowOverrides?: Partial<DocumentResponse>;
}

/** `length` deterministic bytes that differ from position to position. */
export function ramp(length: number, seed = 11): DocumentBytes {
  return new Uint8Array(Array.from({ length }, (_, index) => (index * 7 + seed) % 251));
}

async function sha256Hex(input: DocumentBytes): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', input);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** A document sealed under `options.vaultKey`, its row and its segments. */
export async function buildStoredDocument(options: StoredDocumentOptions): Promise<StoredDocument> {
  const { id, vaultKey } = options;
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
  const name = options.name ?? 'report.txt';
  const meta: DocumentMeta = {
    name,
    mime: 'text/plain',
    ext: name.includes('.') ? (name.split('.').pop() ?? '') : '',
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

/** An in-memory save target that keeps what is written and how it ended. */
export interface MemoryTarget {
  kind: 'file' | 'download';
  name: string;
  limitBytes: number;
  parts: Blob[];
  calls: string[];
  write: (chunk: Blob) => Promise<void>;
  commit: () => Promise<void>;
  discard: () => Promise<void>;
  /** Everything written, as one buffer. */
  bytes: () => Promise<Uint8Array<ArrayBuffer>>;
}

export function memoryTarget(
  options: { kind?: 'file' | 'download'; limitBytes?: number; failWriteAt?: number } = {},
): MemoryTarget {
  const parts: Blob[] = [];
  const calls: string[] = [];
  return {
    kind: options.kind ?? 'file',
    name: 'hvault-full-backup-2026-10-23.hvbackup',
    limitBytes: options.limitBytes ?? Number.MAX_SAFE_INTEGER,
    parts,
    calls,
    write: (chunk) => {
      calls.push('write');
      if (options.failWriteAt !== undefined && calls.length >= options.failWriteAt) {
        return Promise.reject(new Error('The disk is full.'));
      }
      parts.push(chunk);
      return Promise.resolve();
    },
    commit: () => {
      calls.push('commit');
      return Promise.resolve();
    },
    discard: () => {
      calls.push('discard');
      parts.length = 0;
      return Promise.resolve();
    },
    bytes: async () => new Uint8Array(await new Blob(parts).arrayBuffer()),
  };
}
