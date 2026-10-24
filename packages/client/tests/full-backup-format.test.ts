/**
 * The full backup file (`services/backup/fullBackupFormat.ts`) and its signature
 * (`services/crypto/fullBackupCrypto.ts`).
 *
 * Every fixture is a real file: documents sealed with the real functions, written by
 * the real writer, signed with a key derived from a real BWK. A refusal test then
 * changes exactly one thing in such a file and asserts the reader's sentence for it,
 * so a rule that stopped being enforced turns its own test red.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MAX_RESTORE_DATA_LENGTH } from '@hvault/shared';

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
  deriveFullBackupSigningKey,
  signFullBackupManifest,
  verifyFullBackupManifest,
} from '../src/services/crypto/fullBackupCrypto.js';
import {
  FULL_BACKUP_FILE,
  FULL_BACKUP_FOOTER_BYTES,
  FULL_BACKUP_HEADER_BYTES,
  FullBackupFormatError,
  FullBackupWriter,
  MAX_FULL_BACKUP_SEGMENT_PLAINTEXT_BYTES,
  canonicalManifest,
  fullBackupFileName,
  fullBackupFooter,
  fullBackupHeader,
  openFullBackupFile,
  unbackupableRow,
  vaultBackupTooLarge,
} from '../src/services/backup/fullBackupFormat.js';
import { FULL_BACKUP_MAGIC, isFullBackupFile } from '../src/services/backup/fullBackupMagic.js';
import {
  buildStoredDocument,
  memoryTarget,
  ramp,
  type StoredDocument,
} from './support/storedDocuments.js';

const ID_A = '66c0f1a2b3c4d5e6f7a8b9c0';
const ID_B = '66c0f1a2b3c4d5e6f7a8b9c1';
const ID_C = '66c0f1a2b3c4d5e6f7a8b9c2';

const VAULT = {
  version: '0.22.0',
  exportDate: '2026-10-23T10:00:00.000Z',
  items: [{ _id: 'a'.repeat(24), itemType: 'login', encryptedName: 'n' }],
  folders: [],
  metadata: { itemCount: 1, folderCount: 0 },
  documentSummary: { count: 3, totalBytes: 40 },
};

let vaultKey: CryptoKey;
let bwk: ArrayBuffer;
let docA: StoredDocument;
let docB: StoredDocument;

beforeEach(async () => {
  vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
  bwk = cryptoService.generateBWK();
  docA = await buildStoredDocument({ id: ID_A, vaultKey, plaintext: ramp(20) });
  docB = await buildStoredDocument({ id: ID_B, vaultKey, plaintext: ramp(5, 3), name: 'b.pdf' });
});

/** A complete, valid file holding `documents`, as the writer makes it. */
async function writeFile(
  documents: StoredDocument[] = [docA, docB],
  fields: Partial<{ vault: Record<string, unknown>; unlisted: number }> = {},
): Promise<Uint8Array<ArrayBuffer>> {
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
    {
      createdAt: '2026-10-23T10:00:00.000Z',
      vault: fields.vault ?? VAULT,
      omitted: [{ id: ID_C, reason: 'unreadable' }],
      unlisted: fields.unlisted ?? 0,
    },
    await deriveFullBackupSigningKey(bwk),
  );
  return target.bytes();
}

/** The manifest of `file`, parsed, and a function that writes it back changed. */
function manifestOf(file: Uint8Array<ArrayBuffer>): Record<string, unknown> {
  const length = Number(
    new DataView(file.buffer, file.byteOffset + file.length - 8, 8).getBigUint64(0),
  );
  const start = file.length - FULL_BACKUP_FOOTER_BYTES - length;
  return JSON.parse(new TextDecoder().decode(file.slice(start, start + length))) as Record<
    string,
    unknown
  >;
}

/** `file` with its manifest replaced by `manifest`, footer recomputed. */
function withManifest(file: Uint8Array<ArrayBuffer>, manifest: unknown): Uint8Array<ArrayBuffer> {
  const length = Number(
    new DataView(file.buffer, file.byteOffset + file.length - 8, 8).getBigUint64(0),
  );
  const start = file.length - FULL_BACKUP_FOOTER_BYTES - length;
  const encoded = new TextEncoder().encode(JSON.stringify(manifest));
  return new Uint8Array([...file.slice(0, start), ...encoded, ...fullBackupFooter(encoded.length)]);
}

async function refusal(file: Uint8Array<ArrayBuffer>): Promise<string> {
  const error = await openFullBackupFile(new Blob([file])).catch((raised: unknown) => raised);
  expect(error).toBeInstanceOf(FullBackupFormatError);
  return (error as Error).message;
}

describe('the file layout', () => {
  it('starts with the 16-byte header and ends with the footer naming the manifest', async () => {
    const file = await writeFile();
    expect([...file.slice(0, 8)]).toEqual([...FULL_BACKUP_MAGIC]);
    expect(new DataView(file.buffer).getUint32(8)).toBe(1);
    expect(new DataView(file.buffer).getUint32(12)).toBe(0);
    expect(new TextDecoder().decode(file.slice(file.length - 16, file.length - 9))).toBe('HVFBEND');
    expect(file[file.length - 9]).toBe(0);
    // The documents sit verbatim, back to back, right after the header.
    const region = file.slice(
      FULL_BACKUP_HEADER_BYTES,
      FULL_BACKUP_HEADER_BYTES + docA.row.ciphertextBytes,
    );
    expect([...region]).toEqual(docA.segments.flatMap((segment) => [...segment]));
  });

  it('names the file by its UTC day and describes it for the save dialog', () => {
    expect(fullBackupFileName(new Date('2026-10-23T23:30:00.000Z'))).toBe(
      'hvault-full-backup-2026-10-23.hvbackup',
    );
    expect(FULL_BACKUP_FILE).toMatchObject({
      mime: 'application/octet-stream',
      extension: '.hvbackup',
      memoryLimitBytes: 512 * 1024 * 1024,
    });
  });

  it('writes the header and footer it is asked for, byte for byte', () => {
    expect([...fullBackupHeader()]).toEqual([...FULL_BACKUP_MAGIC, 0, 0, 0, 1, 0, 0, 0, 0]);
    expect([...fullBackupFooter(0x0102)]).toEqual([
      0x48, 0x56, 0x46, 0x42, 0x45, 0x4e, 0x44, 0x00, 0, 0, 0, 0, 0, 0, 0x01, 0x02,
    ]);
  });
});

describe('isFullBackupFile', () => {
  it('recognises a full backup by its first eight bytes only', async () => {
    const file = await writeFile();
    expect(await isFullBackupFile(new Blob([file]))).toBe(true);
    // A newer format version is still recognised as a full backup, so the reader
    // can refuse it in its own words instead of the vault-backup path guessing.
    const newer = file.slice();
    newer[11] = 2;
    expect(await isFullBackupFile(new Blob([newer]))).toBe(true);
  });

  it('does not take a vault backup, or anything shorter than the magic, for one', async () => {
    expect(await isFullBackupFile(new Blob(['{"version":"0.21.0","items":[]}']))).toBe(false);
    expect(await isFullBackupFile(new Blob([new Uint8Array(FULL_BACKUP_MAGIC.slice(0, 7))]))).toBe(
      false,
    );
    expect(await isFullBackupFile(new Blob([]))).toBe(false);
  });

  it('wants all eight bytes, not most of them', async () => {
    const nearly = [...FULL_BACKUP_MAGIC.slice(0, 7), 0x00, 0, 0, 0, 1];
    expect(await isFullBackupFile(new Blob([new Uint8Array(nearly)]))).toBe(false);
  });

  it('reads the first eight bytes only, however large the file', async () => {
    const slice = vi.fn(() => new Blob([new Uint8Array(FULL_BACKUP_MAGIC)]));
    // A file far too large to read whole: only its first bytes may be taken.
    const huge = { size: 1e12, slice } as unknown as Blob;
    expect(await isFullBackupFile(huge)).toBe(true);
    expect(slice).toHaveBeenCalledWith(0, 8);
  });
});

describe('openFullBackupFile — a valid file', () => {
  it('returns the manifest exactly as written, and every segment byte for byte', async () => {
    const opened = await openFullBackupFile(new Blob([await writeFile()]));

    expect(opened.manifest).toMatchObject({
      format: 'hvault-full-backup',
      formatVersion: 1,
      createdAt: '2026-10-23T10:00:00.000Z',
      vault: VAULT,
      omitted: [{ id: ID_C, reason: 'unreadable' }],
      unlisted: 0,
    });
    expect(opened.manifest.documents.map((entry) => entry.row)).toEqual([docA.row, docB.row]);
    expect(opened.manifest.documents.map((entry) => [entry.offset, entry.length])).toEqual([
      [16, docA.row.ciphertextBytes],
      [16 + docA.row.ciphertextBytes, docB.row.ciphertextBytes],
    ]);
    const [entryA, entryB] = opened.manifest.documents;
    for (const [index, segment] of docA.segments.entries()) {
      expect([...(await opened.readSegment(entryA!, index))]).toEqual([...segment]);
    }
    expect([...(await opened.readSegment(entryB!, 0))]).toEqual([...docB.segments[0]!]);
  });

  it('carries a signature that verifies under the BWK it was signed with, over the manifest', async () => {
    const opened = await openFullBackupFile(new Blob([await writeFile()]));
    expect(await verifyFullBackupManifest(opened.signedPayload, opened.signature, bwk)).toBe(true);
    // The signed payload is the manifest without its signature, in written order.
    expect(JSON.parse(opened.signedPayload)).not.toHaveProperty('integrity');
    expect(
      opened.signedPayload.startsWith('{"format":"hvault-full-backup","formatVersion":1,'),
    ).toBe(true);
  });

  it('accepts a file holding no document at all', async () => {
    const opened = await openFullBackupFile(new Blob([await writeFile([])]));
    expect(opened.manifest.documents).toEqual([]);
  });

  it('refuses to read a segment a document does not have', async () => {
    const opened = await openFullBackupFile(new Blob([await writeFile()]));
    const entry = opened.manifest.documents[0]!;
    for (const index of [-1, entry.row.chunkCount, 1.5]) {
      await expect(opened.readSegment(entry, index)).rejects.toBeInstanceOf(FullBackupFormatError);
    }
  });
});

describe('openFullBackupFile — every refusal names its reason and restores nothing', () => {
  it('refuses a file too short to be one', async () => {
    expect(await refusal(new Uint8Array(33))).toContain('it is too short');
  });

  it('refuses a file that does not start with the magic', async () => {
    const file = await writeFile();
    file[0] = 0x00;
    expect(await refusal(file)).toContain('it does not start like one');
  });

  it('refuses a newer format version in its own words', async () => {
    const file = await writeFile();
    new DataView(file.buffer).setUint32(8, 2);
    expect(await refusal(file)).toContain('it was made by a newer version of H-Vault');
  });

  it.each([
    ['version 0', (file: Uint8Array<ArrayBuffer>) => new DataView(file.buffer).setUint32(8, 0)],
    [
      'a non-zero reserved field',
      (file: Uint8Array<ArrayBuffer>) => new DataView(file.buffer).setUint32(12, 1),
    ],
  ])('refuses a header with %s as damaged', async (_label, damage) => {
    const file = await writeFile();
    damage(file);
    expect(await refusal(file)).toContain('its header is damaged');
  });

  it('refuses a file whose footer is missing, as a truncated one would be', async () => {
    const file = await writeFile();
    expect(await refusal(file.slice(0, file.length - 1))).toContain('its end is missing');
  });

  it('refuses a footer naming a manifest larger than the file', async () => {
    const file = await writeFile();
    new DataView(file.buffer).setBigUint64(file.length - 8, BigInt(file.length));
    expect(await refusal(file)).toContain('its table of contents is larger than the file allows');
  });

  it('refuses a manifest that is not UTF-8, or not JSON', async () => {
    const file = await writeFile();
    const bad = withManifest(file, 'x');
    // Replace the manifest bytes with an invalid UTF-8 sequence of the same length.
    const length = Number(new DataView(bad.buffer).getBigUint64(bad.length - 8));
    bad.set(new Uint8Array(length).fill(0xff), bad.length - 16 - length);
    expect(await refusal(bad)).toContain('its table of contents is not readable');

    const notJson = new TextEncoder().encode('{not json');
    const head = file.slice(0, 16 + docA.row.ciphertextBytes + docB.row.ciphertextBytes);
    expect(
      await refusal(new Uint8Array([...head, ...notJson, ...fullBackupFooter(notJson.length)])),
    ).toContain('its table of contents is not readable');
  });

  it('refuses a manifest listing more documents than an account can hold, before reading a row', async () => {
    const file = await writeFile();
    const manifest = manifestOf(file);
    manifest.omitted = Array.from({ length: 5_003 }, () => ({ id: ID_C, reason: 'deleted' }));
    expect(await refusal(withManifest(file, manifest))).toContain(
      'it lists more documents than an account can hold',
    );
  });

  it('refuses a manifest that fails its schema, naming where', async () => {
    const file = await writeFile();
    const manifest = manifestOf(file);
    manifest.format = 'something-else';
    expect(await refusal(withManifest(file, manifest))).toContain(
      'its table of contents is invalid at format',
    );
    const unsigned = manifestOf(file);
    delete unsigned.integrity;
    expect(await refusal(withManifest(file, unsigned))).toContain('invalid at integrity');
    expect(await refusal(withManifest(file, null))).toContain('its table of contents is invalid');
  });

  it('refuses a vault part larger than a restore accepts', async () => {
    const huge = { ...VAULT, padding: 'x'.repeat(MAX_RESTORE_DATA_LENGTH) };
    expect(vaultBackupTooLarge(huge)).toBe(true);
    expect(vaultBackupTooLarge(VAULT)).toBe(false);
    const file = await writeFile();
    const manifest = manifestOf(file);
    manifest.vault = huge;
    expect(await refusal(withManifest(file, manifest))).toContain(
      'its vault backup is larger than a restore accepts',
    );
  });

  it.each([
    ['in the trash', { deletedAt: '2026-10-01T00:00:00.000Z' }],
    ['being permanently deleted', { purgePending: true }],
  ])('refuses a document %s', async (_label, change) => {
    const file = await writeFile();
    const manifest = manifestOf(file);
    const documents = manifest.documents as { row: Record<string, unknown> }[];
    Object.assign(documents[0]!.row, change);
    expect(await refusal(withManifest(file, manifest))).toContain('in the trash or being deleted');
  });

  it('refuses a document framed in segments over the bound', async () => {
    const big = await buildStoredDocument({
      id: ID_A,
      vaultKey,
      plaintext: ramp(4),
      chunkPlaintextBytes: MAX_FULL_BACKUP_SEGMENT_PLAINTEXT_BYTES + 1,
    });
    expect(unbackupableRow(big.row)).toContain('segments larger');
    const file = await writeFile([docB]);
    const manifest = manifestOf(file);
    (manifest.documents as { row: unknown }[])[0]!.row = big.row;
    expect(await refusal(withManifest(file, manifest))).toContain(
      'segments larger than this version reads',
    );
  });

  it('refuses a document listed twice, or listed and omitted', async () => {
    // Built by hand: the writer itself refuses to write either (below).
    const single = await writeFile([docA]);
    const doubled = manifestOf(single);
    const [entry] = doubled.documents as { row: unknown; offset: number; length: number }[];
    doubled.documents = [entry, { ...entry!, offset: entry!.offset + entry!.length }];
    const region = single.slice(16, 16 + entry!.length);
    const twice = withManifest(
      new Uint8Array([
        ...single.slice(0, 16 + entry!.length),
        ...region,
        ...single.slice(16 + entry!.length),
      ]),
      doubled,
    );
    expect(await refusal(twice)).toContain('it lists a document twice');

    const file = await writeFile();
    const manifest = manifestOf(file);
    manifest.omitted = [{ id: ID_A, reason: 'deleted' }];
    expect(await refusal(withManifest(file, manifest))).toContain('it lists a document twice');
  });

  it.each([
    [
      'a gap before the first document',
      (entries: { offset: number }[]) => (entries[0]!.offset += 1),
    ],
    [
      'a length that is not the row’s size',
      (entries: { length: number }[]) => (entries[1]!.length -= 1),
    ],
  ])('refuses entries with %s', async (_label, change) => {
    const file = await writeFile();
    const manifest = manifestOf(file);
    change(manifest.documents as { offset: number; length: number }[]);
    expect(await refusal(withManifest(file, manifest))).toContain(
      'its documents do not line up with its contents',
    );
  });

  it('refuses a region holding bytes no entry accounts for', async () => {
    const file = await writeFile([docA]);
    const manifest = manifestOf(file);
    const length = Number(new DataView(file.buffer).getBigUint64(file.length - 8));
    const start = file.length - 16 - length;
    const encoded = new TextEncoder().encode(JSON.stringify(manifest));
    const padded = new Uint8Array([
      ...file.slice(0, start),
      0x00,
      ...encoded,
      ...fullBackupFooter(encoded.length),
    ]);
    expect(await refusal(padded)).toContain('its documents do not line up with its contents');
  });
});

describe('FullBackupWriter — it cannot write what the reader refuses', () => {
  it('refuses a row the reader would refuse, before writing a byte of it', async () => {
    const target = memoryTarget();
    const writer = new FullBackupWriter(target);
    await writer.begin();
    await expect(
      writer.addDocument({ ...docA.row, deletedAt: '2026-10-01T00:00:00.000Z' }, [
        new Blob([docA.segments[0]!]),
      ]),
    ).rejects.toThrow('A full backup cannot hold this document');
    expect(target.calls).toEqual(['write']);
  });

  it('refuses segments that do not add up to the row’s stored size', async () => {
    const target = memoryTarget();
    const writer = new FullBackupWriter(target);
    await writer.begin();
    await expect(writer.addDocument(docA.row, [new Blob([docA.segments[0]!])])).rejects.toThrow(
      'did not add up to its stored size',
    );
    expect(target.calls).toEqual(['write']);
  });

  it('refuses the same document twice, and a document both included and left out', async () => {
    const target = memoryTarget();
    const writer = new FullBackupWriter(target);
    await writer.begin();
    const segments = docA.segments.map((segment) => new Blob([segment]));
    await writer.addDocument(docA.row, segments);
    await expect(writer.addDocument(docA.row, segments)).rejects.toThrow('the same document twice');
    await expect(
      writer.finish(
        {
          createdAt: '2026-10-23T10:00:00.000Z',
          vault: VAULT,
          omitted: [{ id: ID_A, reason: 'deleted' }],
          unlisted: 0,
        },
        await deriveFullBackupSigningKey(bwk),
      ),
    ).rejects.toThrow('both as included and as left out');
    // Header and the one document; nothing after the refusals.
    expect(target.calls).toEqual(['write', 'write']);
  });

  it('refuses a manifest over its bound, writing neither it nor the footer', async () => {
    const target = memoryTarget();
    const writer = new FullBackupWriter(target, 64);
    await writer.begin();
    await expect(
      writer.finish(
        { createdAt: '2026-10-23T10:00:00.000Z', vault: VAULT, omitted: [], unlisted: 0 },
        await deriveFullBackupSigningKey(bwk),
      ),
    ).rejects.toThrow('larger than a restore reads');
    expect(target.calls).toEqual(['write']);
  });

  it('reports the size of the whole file it wrote', async () => {
    const target = memoryTarget();
    const writer = new FullBackupWriter(target);
    await writer.begin();
    await writer.addDocument(
      docA.row,
      docA.segments.map((segment) => new Blob([segment])),
    );
    const written = await writer.finish(
      { createdAt: '2026-10-23T10:00:00.000Z', vault: VAULT, omitted: [], unlisted: 2 },
      await deriveFullBackupSigningKey(bwk),
    );
    expect(written).toEqual({ bytes: (await target.bytes()).length, documentCount: 1 });
    // The writer never commits: that is the caller's decision.
    expect(target.calls).not.toContain('commit');
  });
});

describe('the full backup signature', () => {
  const PAYLOAD = '{"format":"hvault-full-backup"}';

  it('verifies only under the BWK that signed it, and only over the bytes it signed', async () => {
    const signature = await signFullBackupManifest(PAYLOAD, await deriveFullBackupSigningKey(bwk));
    expect(signature).toMatch(/^[0-9a-f]{64}$/);
    expect(await verifyFullBackupManifest(PAYLOAD, signature, bwk)).toBe(true);
    expect(await verifyFullBackupManifest(`${PAYLOAD} `, signature, bwk)).toBe(false);
    expect(await verifyFullBackupManifest(PAYLOAD, signature, cryptoService.generateBWK())).toBe(
      false,
    );
  });

  it('is the HMAC-SHA256 under HKDF(BWK, "hvault-full-backup-hmac-v1"), by an independent implementation', async () => {
    const { createHmac, hkdfSync } = await import('node:crypto');
    const key = Buffer.from(
      hkdfSync('sha256', Buffer.from(bwk), Buffer.alloc(0), 'hvault-full-backup-hmac-v1', 32),
    );
    const expected = createHmac('sha256', key).update(PAYLOAD).digest('hex');
    expect(await signFullBackupManifest(PAYLOAD, await deriveFullBackupSigningKey(bwk))).toBe(
      expected,
    );
  });

  it('refuses a signature with anything after its 64 hex characters, even more of the same', async () => {
    const signature = await signFullBackupManifest(PAYLOAD, await deriveFullBackupSigningKey(bwk));
    expect(await verifyFullBackupManifest(PAYLOAD, `${signature}${signature}`, bwk)).toBe(false);
    expect(await verifyFullBackupManifest(PAYLOAD, `${signature}0`, bwk)).toBe(false);
    expect(await verifyFullBackupManifest(PAYLOAD, `0${signature}`, bwk)).toBe(false);
    expect(await verifyFullBackupManifest(PAYLOAD, signature.toUpperCase(), bwk)).toBe(false);
  });

  it('is never satisfied by a vault backup’s signature, nor by an HMAC under the raw BWK', async () => {
    // Domain separation: the same BWK, the same bytes, the vault backup's label.
    const vaultBackupSignature = await cryptoService.computeBackupHmac(PAYLOAD, bwk);
    expect(await verifyFullBackupManifest(PAYLOAD, vaultBackupSignature, bwk)).toBe(false);
    // And no legacy fallback to the raw key, which the vault backup still accepts.
    const rawKey = await crypto.subtle.importKey(
      'raw',
      bwk,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const raw = new Uint8Array(
      await crypto.subtle.sign('HMAC', rawKey, new TextEncoder().encode(PAYLOAD)),
    );
    const rawHex = Array.from(raw, (byte) => byte.toString(16).padStart(2, '0')).join('');
    expect(await verifyFullBackupManifest(PAYLOAD, rawHex, bwk)).toBe(false);
    // The converse holds too: the vault backup's verifier refuses a full-backup signature.
    const full = await signFullBackupManifest(PAYLOAD, await deriveFullBackupSigningKey(bwk));
    expect(await cryptoService.verifyBackupHmac(PAYLOAD, full, bwk)).toBe(false);
  });

  it.each(['', 'A'.repeat(64), '0'.repeat(63), `${'0'.repeat(64)}0`, 'zz'.repeat(32)])(
    'answers a malformed signature %j with false, never a throw',
    async (signature) => {
      await expect(verifyFullBackupManifest(PAYLOAD, signature, bwk)).resolves.toBe(false);
    },
  );

  it('signs the manifest without its signature, in the order it was written', () => {
    expect(canonicalManifest({ b: 1, integrity: 'x', a: 2 })).toBe('{"b":1,"a":2}');
  });
});
