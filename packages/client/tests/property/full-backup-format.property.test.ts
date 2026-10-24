/**
 * The full backup file, as a property: for EVERY set of documents, left-out ids and
 * vault part a run could write, the reader accepts the file the writer produced,
 * hands back every row and every sealed segment byte for byte, and the signature
 * verifies over exactly the manifest it read.
 *
 * This is the writer/reader symmetry the format promises: the writer applies the
 * reader's own rules, so nothing it can write is a file the restore then refuses.
 */
import { describe, expect, it, vi } from 'vitest';
import fc from 'fast-check';

vi.mock('../../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));
vi.mock('../../src/lib/logger', () => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import { cryptoService } from '../../src/services/crypto/cryptoService';
import {
  deriveFullBackupSigningKey,
  verifyFullBackupManifest,
} from '../../src/services/crypto/fullBackupCrypto';
import {
  FullBackupWriter,
  openFullBackupFile,
  type OmittedReason,
} from '../../src/services/backup/fullBackupFormat';
import { buildStoredDocument, memoryTarget } from '../support/storedDocuments';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/** A distinct document id per position, so ids never collide within a sample. */
function idAt(position: number): string {
  return `66c0f1a2b3c4d5e6f7a8${position.toString(16).padStart(4, '0')}`;
}

const documentArbitrary = fc.record({
  plaintext: fc.uint8Array({ minLength: 0, maxLength: 40 }),
  chunkPlaintextBytes: fc.integer({ min: 1, max: 16 }),
  favorite: fc.boolean(),
});

const sampleArbitrary = fc.record({
  documents: fc.array(documentArbitrary, { maxLength: 3 }),
  omitted: fc.array(fc.constantFrom<OmittedReason>('unreadable', 'deleted', 'contents-missing'), {
    maxLength: 3,
  }),
  unlisted: fc.integer({ min: 0, max: 5 }),
  // The vault part is whatever JSON object the server sent; the restore reads it.
  vaultExtra: fc.dictionary(fc.string({ maxLength: 8 }), fc.jsonValue({ maxDepth: 2 })),
});

describe('the full backup file, as a property', () => {
  it('reads back exactly what was written, and verifies, for every sample', async () => {
    const vaultKey = await cryptoService.importVaultKey(cryptoService.generateVaultKey());
    const bwk = cryptoService.generateBWK();
    const signingKey = await deriveFullBackupSigningKey(bwk);

    await fc.assert(
      fc.asyncProperty(sampleArbitrary, async (sample) => {
        const built = await Promise.all(
          sample.documents.map((doc, position) =>
            buildStoredDocument({
              id: idAt(position),
              vaultKey,
              plaintext: new Uint8Array(doc.plaintext),
              chunkPlaintextBytes: doc.chunkPlaintextBytes,
              rowOverrides: { favorite: doc.favorite },
            }),
          ),
        );
        const omitted = sample.omitted.map((reason, position) => ({
          id: idAt(100 + position),
          reason,
        }));
        const vault = { version: '0.22.0', items: [], folders: [], extra: sample.vaultExtra };

        const target = memoryTarget();
        const writer = new FullBackupWriter(target);
        await writer.begin();
        for (const doc of built) {
          await writer.addDocument(
            doc.row,
            doc.segments.map((segment) => new Blob([segment])),
          );
        }
        const written = await writer.finish(
          { createdAt: '2026-10-23T10:00:00.000Z', vault, omitted, unlisted: sample.unlisted },
          signingKey,
        );
        const file = await target.bytes();
        expect(written.bytes, propertyBanner()).toBe(file.length);

        const opened = await openFullBackupFile(new Blob([file]));
        expect(
          opened.manifest.documents.map((entry) => entry.row),
          propertyBanner(),
        ).toEqual(built.map((doc) => doc.row));
        expect(opened.manifest.omitted, propertyBanner()).toEqual(omitted);
        expect(opened.manifest.unlisted, propertyBanner()).toBe(sample.unlisted);
        expect(JSON.stringify(opened.manifest.vault), propertyBanner()).toBe(JSON.stringify(vault));
        for (const [position, entry] of opened.manifest.documents.entries()) {
          for (let index = 0; index < entry.row.chunkCount; index += 1) {
            expect([...(await opened.readSegment(entry, index))], propertyBanner()).toEqual([
              ...built[position]!.segments[index]!,
            ]);
          }
        }
        expect(
          await verifyFullBackupManifest(opened.signedPayload, opened.signature, bwk),
          propertyBanner(),
        ).toBe(true);
      }),
      propertyRun({ numRuns: 40 }),
    );
  });
});
