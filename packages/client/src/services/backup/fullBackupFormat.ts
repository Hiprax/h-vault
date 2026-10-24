/**
 * The full backup file: its layout, the ONE writer and the ONE reader.
 *
 * A full backup is the server's own vault backup (the `GET /backup/download`
 * document, exactly as the vault-only download carries it) together with every live
 * document as it is STORED: its row, and its sealed segments byte for byte. Nothing
 * in it is decrypted or re-encrypted. The document keys stay wrapped under the vault
 * key, and the file carries that key wrapped under the master key and under the
 * backup key, so the file is exactly as zero-knowledge as the server is.
 *
 * ```text
 * [0,16)          header: "HVFB" 0D 0A 1A 0A, u32be format version, 4 zero bytes
 * [16, M)         document region: each document's stored object, in manifest order
 * [M, size-16)    manifest: UTF-8 JSON, signed (see fullBackupCrypto.ts)
 * [size-16,size)  footer: "HVFBEND" 00, u64be manifest length in bytes
 * ```
 *
 * The manifest is written LAST, because the documents a run could not read are only
 * known once it has read them, and a writer that streams straight into a file
 * cannot go back and change what it already wrote.
 *
 * ## The reader is strict
 *
 * A full backup is a file someone hands the person restoring it, so it is untrusted
 * input in the origin holding the vault key. Only the CONTAINER is parsed here, and
 * every rule below refuses the whole file, before anything is restored, with one
 * sentence: the layout is fixed, every length is bounded before anything is read
 * whole, the document entries must tile the region exactly (no gap, no overlap, no
 * byte unaccounted for), and every row must pass the shared row schema. Document
 * bytes are never parsed at all: they are only decrypted, by the same verified read
 * every download uses (`download.ts`), under keys bound to the document's own id.
 */

import { z } from '@hvault/shared/zod';
import {
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENTS_PER_ROTATION,
  MAX_RESTORE_DATA_LENGTH,
  documentResponseSchema,
  type DocumentResponse,
} from '@hvault/shared';
import type { DocumentBytes } from '../crypto/documentCryptoService.js';
import { signFullBackupManifest } from '../crypto/fullBackupCrypto.js';
import {
  IN_MEMORY_ARCHIVE_LIMIT_BYTES,
  type ArchiveTarget,
  type SaveTargetSpec,
} from '../documents/archiveTarget.js';
import { FULL_BACKUP_MAGIC } from './fullBackupMagic.js';

/** The `format` every manifest names. */
const FULL_BACKUP_FORMAT = 'hvault-full-backup';

/** The one format version this release writes and reads. */
const FULL_BACKUP_FORMAT_VERSION = 1;

/** The header's length, which is also where the document region starts. */
export const FULL_BACKUP_HEADER_BYTES = 16;

/** The footer's length. */
export const FULL_BACKUP_FOOTER_BYTES = 16;

/** The footer's first eight bytes: "HVFBEND" and a zero. */
const FOOTER_MAGIC: readonly number[] = [0x48, 0x56, 0x46, 0x42, 0x45, 0x4e, 0x44, 0x00];

/**
 * The largest segment a full backup may frame, in plaintext bytes.
 *
 * Each segment is read whole into memory, and the row's `chunkPlaintextBytes` is a
 * number the file supplies, so it is bounded here (eight times today's segment). The
 * read still takes the value from the row rather than from today's constant.
 */
export const MAX_FULL_BACKUP_SEGMENT_PLAINTEXT_BYTES = 64 * 1024 * 1024;

/**
 * The largest manifest a full backup may carry, in bytes: the vault backup at the
 * most a restore accepts, plus every document row a rotation may name at the
 * largest a row can be (a sealed metadata blob of 51,200 characters and its fixed
 * fields, well under 56 KiB).
 */
const MAX_FULL_BACKUP_MANIFEST_BYTES =
  MAX_RESTORE_DATA_LENGTH + MAX_DOCUMENTS_PER_ROTATION * 56 * 1024;

/** The save dialog's description of the file, its type, and its size limits. */
export const FULL_BACKUP_FILE: SaveTargetSpec = {
  description: 'H-Vault full backup',
  mime: 'application/octet-stream',
  extension: '.hvbackup',
  fileLimitBytes: Number.MAX_SAFE_INTEGER,
  memoryLimitBytes: IN_MEMORY_ARCHIVE_LIMIT_BYTES,
};

/** The name a full backup is offered under: `hvault-full-backup-YYYY-MM-DD.hvbackup`, UTC. */
export function fullBackupFileName(now: Date): string {
  return `hvault-full-backup-${now.toISOString().slice(0, 10)}.hvbackup`;
}

/** Why a document is in a full backup's `omitted` list rather than its region. */
export type OmittedReason = 'unreadable' | 'deleted' | 'contents-missing';

/** A document the run could not include: its id and why. Never its name. */
export interface OmittedDocument {
  id: string;
  reason: OmittedReason;
}

/** One included document: its row, and where its stored object sits in the file. */
export interface FullBackupEntry {
  row: DocumentResponse;
  offset: number;
  length: number;
}

/** The signed manifest, as the writer builds it and the reader returns it. */
export interface FullBackupManifest {
  format: typeof FULL_BACKUP_FORMAT;
  formatVersion: typeof FULL_BACKUP_FORMAT_VERSION;
  createdAt: string;
  vault: Record<string, unknown>;
  documents: FullBackupEntry[];
  omitted: OmittedDocument[];
  /** Rows the server listed that did not satisfy the shared row schema. */
  unlisted: number;
}

/** A full backup file refused by the reader, with the one sentence that says why. */
export class FullBackupFormatError extends Error {
  constructor(reason: string) {
    super(
      `This file is not a full backup this version of H-Vault can read: ${reason}. Nothing was restored.`,
    );
    this.name = 'FullBackupFormatError';
  }
}

const DOCUMENT_ID = /^[a-f0-9]{24}$/;

const manifestSchema = z.object({
  format: z.literal(FULL_BACKUP_FORMAT),
  formatVersion: z.literal(FULL_BACKUP_FORMAT_VERSION),
  createdAt: z.iso.datetime(),
  vault: z.looseObject({}),
  documents: z.array(
    z.object({
      row: documentResponseSchema,
      offset: z.number().int().min(FULL_BACKUP_HEADER_BYTES),
      length: z.number().int().min(DOCUMENT_TAG_BYTES),
    }),
  ),
  omitted: z.array(
    z.object({
      id: z.string().regex(DOCUMENT_ID),
      reason: z.enum(['unreadable', 'deleted', 'contents-missing']),
    }),
  ),
  unlisted: z.number().int().min(0).max(MAX_DOCUMENTS_PER_ROTATION),
  integrity: z.string().regex(/^[0-9a-f]{64}$/),
});

/**
 * Why a document row cannot go into (or come out of) a full backup, or `null`.
 *
 * The ONE row rule, applied by the writer before it writes a row and by the reader
 * to every row it reads, so the writer can never produce a file its own reader
 * refuses. Only live documents are backed up; a segment over the bound would have
 * to be held whole in memory.
 */
export function unbackupableRow(row: DocumentResponse): string | null {
  if (row.deletedAt !== undefined || row.purgePending === true) {
    return 'it lists a document that is in the trash or being deleted';
  }
  if (row.chunkPlaintextBytes > MAX_FULL_BACKUP_SEGMENT_PLAINTEXT_BYTES) {
    return 'it lists a document framed in segments larger than this version reads';
  }
  return null;
}

/**
 * Whether a vault backup is larger than `POST /backup/restore` accepts.
 *
 * The ONE size rule for the vault part, applied by the reader and by the writer
 * right after the vault download, so a full backup the restore would refuse is
 * never written in the first place.
 */
export function vaultBackupTooLarge(vault: unknown): boolean {
  return JSON.stringify(vault).length > MAX_RESTORE_DATA_LENGTH;
}

/** The 16-byte header this release writes. */
export function fullBackupHeader(): DocumentBytes {
  const header = new Uint8Array(FULL_BACKUP_HEADER_BYTES);
  header.set(FULL_BACKUP_MAGIC);
  new DataView(header.buffer).setUint32(FULL_BACKUP_MAGIC.length, FULL_BACKUP_FORMAT_VERSION);
  return header;
}

/** The 16-byte footer naming a manifest of `manifestBytes` bytes. */
export function fullBackupFooter(manifestBytes: number): DocumentBytes {
  const footer = new Uint8Array(FULL_BACKUP_FOOTER_BYTES);
  footer.set(FOOTER_MAGIC);
  new DataView(footer.buffer).setBigUint64(FOOTER_MAGIC.length, BigInt(manifestBytes));
  return footer;
}

/**
 * The canonical JSON a manifest is signed over: everything but `integrity`, in the
 * order it was written. The same parse-and-re-serialise form the vault backup's own
 * signature uses, so the bytes on disk are not part of the contract.
 */
export function canonicalManifest(manifest: Record<string, unknown>): string {
  const { integrity: _integrity, ...signed } = manifest;
  return JSON.stringify(signed);
}

/** A full backup the reader accepted. */
export interface OpenedFullBackup {
  manifest: FullBackupManifest;
  /** The manifest's signature, to be judged by `resolveBackupSignature`. */
  signature: string;
  /** What the signature covers. */
  signedPayload: string;
  /** Read segment `index` of `entry`, sealed, straight from the file. */
  readSegment: (entry: FullBackupEntry, index: number) => Promise<DocumentBytes>;
}

async function bytesOf(file: Blob, start: number, end: number): Promise<DocumentBytes> {
  return new Uint8Array(await file.slice(start, end).arrayBuffer());
}

function startsWith(bytes: Uint8Array, prefix: readonly number[]): boolean {
  return prefix.every((byte, index) => bytes[index] === byte);
}

/**
 * Open `file` as a full backup, refusing it with a {@link FullBackupFormatError}
 * unless every rule in this module's header holds.
 *
 * Reads only the header, the footer and the manifest; the document region is read
 * later, one segment at a time, through `readSegment`.
 */
export async function openFullBackupFile(file: Blob): Promise<OpenedFullBackup> {
  const minimum = FULL_BACKUP_HEADER_BYTES + FULL_BACKUP_FOOTER_BYTES + 2;
  if (file.size < minimum) throw new FullBackupFormatError('it is too short');

  const header = await bytesOf(file, 0, FULL_BACKUP_HEADER_BYTES);
  if (!startsWith(header, FULL_BACKUP_MAGIC)) {
    throw new FullBackupFormatError('it does not start like one');
  }
  const headerView = new DataView(header.buffer);
  const version = headerView.getUint32(FULL_BACKUP_MAGIC.length);
  if (version > FULL_BACKUP_FORMAT_VERSION) {
    throw new FullBackupFormatError('it was made by a newer version of H-Vault');
  }
  if (version !== FULL_BACKUP_FORMAT_VERSION || headerView.getUint32(12) !== 0) {
    throw new FullBackupFormatError('its header is damaged');
  }

  const footer = await bytesOf(file, file.size - FULL_BACKUP_FOOTER_BYTES, file.size);
  if (!startsWith(footer, FOOTER_MAGIC)) {
    throw new FullBackupFormatError('its end is missing, so it is incomplete or damaged');
  }
  const declared = new DataView(footer.buffer).getBigUint64(FOOTER_MAGIC.length);
  const room = file.size - FULL_BACKUP_HEADER_BYTES - FULL_BACKUP_FOOTER_BYTES;
  if (declared > BigInt(Math.min(MAX_FULL_BACKUP_MANIFEST_BYTES, room))) {
    throw new FullBackupFormatError('its table of contents is larger than the file allows');
  }
  const manifestBytes = Number(declared);
  const manifestStart = file.size - FULL_BACKUP_FOOTER_BYTES - manifestBytes;

  let raw: unknown;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(
      await bytesOf(file, manifestStart, file.size - FULL_BACKUP_FOOTER_BYTES),
    );
    raw = JSON.parse(text);
  } catch {
    throw new FullBackupFormatError('its table of contents is not readable');
  }

  // The two list lengths FIRST, before any row is looked at: the schema below
  // walks every row, so a file of millions of junk entries is refused here.
  const lengthOf = (key: string): number => {
    const value = (raw as Partial<Record<string, unknown>> | null)?.[key];
    return Array.isArray(value) ? value.length : 0;
  };
  if (lengthOf('documents') + lengthOf('omitted') > MAX_DOCUMENTS_PER_ROTATION) {
    throw new FullBackupFormatError('it lists more documents than an account can hold');
  }

  const parsed = manifestSchema.safeParse(raw);
  if (!parsed.success) {
    const [issue] = parsed.error.issues;
    const where = issue && issue.path.length > 0 ? ` at ${issue.path.map(String).join('.')}` : '';
    throw new FullBackupFormatError(`its table of contents is invalid${where}`);
  }
  const { integrity, ...manifest } = parsed.data;

  if (vaultBackupTooLarge(manifest.vault)) {
    throw new FullBackupFormatError('its vault backup is larger than a restore accepts');
  }

  const seen = new Set<string>();
  let expectedOffset = FULL_BACKUP_HEADER_BYTES;
  for (const entry of manifest.documents) {
    const refusal = unbackupableRow(entry.row);
    if (refusal !== null) throw new FullBackupFormatError(refusal);
    if (seen.has(entry.row._id)) throw new FullBackupFormatError('it lists a document twice');
    seen.add(entry.row._id);
    if (entry.offset !== expectedOffset || entry.length !== entry.row.ciphertextBytes) {
      throw new FullBackupFormatError('its documents do not line up with its contents');
    }
    expectedOffset += entry.length;
  }
  if (expectedOffset !== manifestStart) {
    throw new FullBackupFormatError('its documents do not line up with its contents');
  }
  for (const omitted of manifest.omitted) {
    if (seen.has(omitted.id)) throw new FullBackupFormatError('it lists a document twice');
    seen.add(omitted.id);
  }

  return {
    manifest,
    signature: integrity,
    signedPayload: canonicalManifest(raw as Record<string, unknown>),
    readSegment: (entry, index) => {
      if (!Number.isInteger(index) || index < 0 || index >= entry.row.chunkCount) {
        return Promise.reject(
          new FullBackupFormatError('a document asked for a part it does not have'),
        );
      }
      const stride = entry.row.chunkPlaintextBytes + DOCUMENT_TAG_BYTES;
      const start = entry.offset + index * stride;
      return bytesOf(file, start, Math.min(entry.offset + entry.length, start + stride));
    },
  };
}

/** What a finished full backup holds, for the summary. */
export interface WrittenFullBackup {
  /** The whole file, in bytes. */
  bytes: number;
  documentCount: number;
}

/**
 * The ONE writer: the header, each document's verified stored object, then the
 * signed manifest and the footer, into `target`.
 *
 * It applies the reader's own rules as it writes (the row rule, the exact length of
 * every document, the manifest bound), so it cannot produce a file the reader
 * refuses. It commits nothing: the caller decides whether the target is committed
 * or discarded.
 */
export class FullBackupWriter {
  readonly #target: ArchiveTarget;
  readonly #maxManifestBytes: number;
  readonly #documents: FullBackupEntry[] = [];
  #offset = FULL_BACKUP_HEADER_BYTES;

  /** `maxManifestBytes` is a seam for tests; it is the reader's own bound otherwise. */
  constructor(target: ArchiveTarget, maxManifestBytes = MAX_FULL_BACKUP_MANIFEST_BYTES) {
    this.#target = target;
    this.#maxManifestBytes = maxManifestBytes;
  }

  /** Write the header. */
  begin(): Promise<void> {
    return this.#target.write(new Blob([fullBackupHeader()]));
  }

  /** Bytes the file would hold with nothing more written but a manifest of `manifestBytes`. */
  sizeWith(manifestBytes: number): number {
    return this.#offset + manifestBytes + FULL_BACKUP_FOOTER_BYTES;
  }

  /**
   * Append one document's stored object, given as the sealed segments the verified
   * read kept. Refuses a row the reader would refuse, and segments that do not add
   * up to the row's own size, before writing anything.
   */
  async addDocument(row: DocumentResponse, segments: readonly Blob[]): Promise<void> {
    const refusal = unbackupableRow(row);
    if (refusal !== null) throw new Error(`A full backup cannot hold this document: ${refusal}.`);
    if (this.#documents.some((entry) => entry.row._id === row._id)) {
      throw new Error('A full backup cannot hold the same document twice.');
    }
    const length = segments.reduce((total, segment) => total + segment.size, 0);
    if (length !== row.ciphertextBytes) {
      throw new Error('A document read for the full backup did not add up to its stored size.');
    }
    await this.#target.write(new Blob(segments as Blob[]));
    this.#documents.push({ row, offset: this.#offset, length });
    this.#offset += length;
  }

  /**
   * Sign and write the manifest, then the footer. Answers the file's size.
   *
   * The signature covers {@link canonicalManifest} of exactly the object written,
   * so the reader's re-serialisation of what it parses reproduces it.
   */
  async finish(
    fields: Pick<FullBackupManifest, 'createdAt' | 'vault' | 'omitted' | 'unlisted'>,
    signingKey: CryptoKey,
  ): Promise<WrittenFullBackup> {
    if (fields.omitted.some((left) => this.#documents.some((entry) => entry.row._id === left.id))) {
      throw new Error('A full backup cannot list a document both as included and as left out.');
    }
    const manifest: FullBackupManifest = {
      format: FULL_BACKUP_FORMAT,
      formatVersion: FULL_BACKUP_FORMAT_VERSION,
      createdAt: fields.createdAt,
      vault: fields.vault,
      documents: this.#documents,
      omitted: fields.omitted,
      unlisted: fields.unlisted,
    };
    const canonical = JSON.stringify(manifest);
    const integrity = await signFullBackupManifest(canonical, signingKey);
    const encoded = new TextEncoder().encode(JSON.stringify({ ...manifest, integrity }));
    if (encoded.byteLength > this.#maxManifestBytes) {
      throw new Error("The full backup's table of contents would be larger than a restore reads.");
    }
    await this.#target.write(new Blob([encoded]));
    await this.#target.write(new Blob([fullBackupFooter(encoded.byteLength)]));
    return { bytes: this.sizeWith(encoded.byteLength), documentCount: this.#documents.length };
  }
}
