/**
 * What the document store does when a step it already took cannot be undone, or
 * when the storage engine answers something other than "yes".
 *
 * ## Why these cases have their own file
 *
 * Every other document suite drives a handler that succeeds or refuses. These are
 * the paths that run AFTER something has already been written — an engine-side
 * upload opened, an object stored, a multipart transfer assembled — and whose only
 * job is to leave the account in a state a user can get out of. They are the least
 * exercised code in the feature and the most expensive to get wrong: the failure
 * mode is not an error message, it is bucket space a user pays for and cannot see,
 * a concurrency slot nothing can release, or an eight-hundred-megabyte upload the
 * server asks for a second time.
 *
 * Two of them exist because of an ORDERING that is deliberate and cannot be
 * swapped:
 *
 *   * `initUpload` opens the engine-side multipart upload BEFORE it writes the
 *     staging row, because the row must name the upload; if the write then fails,
 *     nothing in the database names that upload and only `initUpload` itself can
 *     abort it.
 *   * `completeUnderLock` calls `CompleteMultipartUpload` BEFORE it deletes the
 *     staging row, because a transient engine failure has to leave a finished
 *     transfer retryable; the engine invalidates the upload id on success, so a
 *     crash in that window leaves an assembled object and a row whose `ListParts`
 *     now answers `NoSuchUpload`.
 *
 * ## The two seams
 *
 * MONGO IS REAL. OBJECT STORAGE IS THE IN-MEMORY DOUBLE, which is an external
 * service in the same class as SMTP; the same contract suite runs it and a real
 * engine in the conformance gate. A storage FAILURE is injected by spying on the
 * double, which is the only honest way to reach a branch that exists for an engine
 * that is misbehaving. The two Mongo failures are injected the same way the
 * existing completion suite already does it, because a datastore that refuses a
 * write is not a state a passing test run can otherwise produce.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { httpErrors } from '@hiprax/errors';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
} from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return {
    ...actual,
    getStorage: () => {
      if (storageRef.current === undefined) {
        throw new Error('the in-memory storage double was not installed for this test');
      }
      return storageRef.current;
    },
  };
});

import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

const BYTES_PER_MB = 1024 * 1024;

/** Opaque framing columns; nothing here decrypts anything. */
const FRAMING = {
  streamSalt: Buffer.alloc(32, 7).toString('base64'),
  noncePrefix: Buffer.alloc(7, 3).toString('base64'),
};

const STAGED_DEK = {
  encryptedDek: 'staged-dek-ciphertext',
  dekIv: 'staged-dek-iv',
  dekTag: 'staged-dek-tag',
};

const COMPLETION_BODY = {
  encryptedMeta: 'document-metadata-ciphertext',
  metaIv: 'meta-iv',
  metaTag: 'meta-tag',
  encryptedDek: 'completion-dek-ciphertext',
  dekIv: 'completion-dek-iv',
  dekTag: 'completion-dek-tag',
  vaultKeyVersion: 0,
};

/**
 * Bytes that vary along their length, so a reordered or truncated object cannot
 * pass an assertion a run of identical bytes would survive.
 */
function pattern(bytes: number, seed = 0): Buffer {
  const buffer = Buffer.allocUnsafe(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = (i * 31 + (i >> 8) + seed) & 0xff;
  return buffer;
}

interface SeedOptions {
  partSizes?: number[];
  /** The ledger's part numbers, in the order the ledger stores them. Defaults to 1..n. */
  ledgerOrder?: number[];
  declaredChunkCount?: number;
  declaredPlaintextBytes?: number;
  multipart?: boolean;
}

interface Seeded {
  id: string;
  objectKey: string;
  s3UploadId: string | undefined;
  partSizes: number[];
}

/**
 * A finished transfer: the engine holding the parts, the ledger recording them.
 *
 * Seeded rather than driven through init and the part route, exactly as the
 * completion suite does: those handlers have their own suites, and routing every
 * case here through them would make each failure ambiguous between three handlers.
 */
async function seedTransfer(user: TestUser, options: SeedOptions = {}): Promise<Seeded> {
  const partSizes = options.partSizes ?? [1024 + DOCUMENT_TAG_BYTES];
  const declaredChunkCount = options.declaredChunkCount ?? Math.max(1, partSizes.length);
  const multipart = options.multipart ?? declaredChunkCount > 1;
  const storage = storageRef.current!;

  const uploadId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(user.id, uploadId.toHexString());
  const s3UploadId = multipart ? await storage.createMultipartUpload(objectKey) : undefined;

  for (const [index, bytes] of partSizes.entries()) {
    const body = pattern(bytes, index + 1);
    if (s3UploadId === undefined) {
      await storage.putObject(objectKey, body);
    } else {
      await storage.uploadPart(objectKey, s3UploadId, index + 1, body);
    }
  }

  const order = options.ledgerOrder ?? partSizes.map((_bytes, index) => index + 1);
  const ledger = order.map((partNumber) => ({
    partNumber,
    bytes: partSizes[partNumber - 1]!,
  }));

  await DocumentUpload.create({
    _id: uploadId,
    userId: user.id,
    objectKey,
    ...(s3UploadId === undefined ? {} : { s3UploadId }),
    ...STAGED_DEK,
    ...FRAMING,
    declaredPlaintextBytes:
      options.declaredPlaintextBytes ??
      partSizes.reduce((total, bytes) => total + bytes, 0) - DOCUMENT_TAG_BYTES * partSizes.length,
    declaredChunkCount,
    chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    vaultKeyVersion: 0,
    parts: ledger,
    receivedBytes: ledger.reduce((total, part) => total + part.bytes, 0),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  return { id: String(uploadId), objectKey, s3UploadId, partSizes };
}

/** One authenticated, CSRF-paired request through the real app. */
async function send(
  user: TestUser,
  method: 'post' | 'delete',
  path: string,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const pair = await getCsrf(agent);
  const pending = agent[method](path).set('Authorization', authHeader(user.accessToken));
  return pending
    .set('Cookie', pair.cookie)
    .set('x-csrf-token', pair.token)
    .send(body ?? {});
}

const completePath = (id: string): string => `/api/v1/documents/uploads/${id}/complete`;

describe('document store — compensation and recovery', () => {
  let user: TestUser;

  beforeEach(async () => {
    storageRef.current = createInMemoryStorage();
    user = await createTestUser({ email: 'documents-compensation@example.com' });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // initUpload: the engine-side upload is open and nothing names it
  // ---------------------------------------------------------------------------

  describe('POST /documents/uploads, when the staging row cannot be written', () => {
    const initBody = {
      encryptedDek: 'dek-ciphertext',
      dekIv: 'dek-iv',
      dekTag: 'dek-tag',
      ...FRAMING,
      declaredPlaintextBytes: (DOCUMENT_CIPHERTEXT_CHUNK_BYTES - DOCUMENT_TAG_BYTES) * 2,
      declaredChunkCount: 2,
    };

    it('aborts the multipart upload it had just opened, so nothing is left orphaned', async () => {
      // The engine-side upload is opened BEFORE the row, because the row names it.
      // A failed write therefore leaves an upload no row points at, and the staging
      // TTL that would eventually reclaim it never existed either — this handler is
      // the only thing that can still address it.
      vi.spyOn(DocumentUpload, 'create').mockRejectedValueOnce(new Error('write concern failed'));

      const res = await send(user, 'post', '/api/v1/documents/uploads', initBody);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(await DocumentUpload.countDocuments({})).toBe(0);
      // The negative that matters: nothing is left holding bucket space.
      expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
      expect(storageRef.current!.storedKeys()).toEqual([]);
    });

    it('still reports the original failure when the abort ALSO fails', async () => {
      // Best-effort by design: the caller needs to hear about the write that failed,
      // not about the cleanup of a resource it never knew existed. The abandoned
      // upload becomes an orphan, which is the case the collector's sweep is for.
      vi.spyOn(DocumentUpload, 'create').mockRejectedValueOnce(new Error('write concern failed'));
      const abort = vi
        .spyOn(storageRef.current!, 'abortMultipartUpload')
        .mockRejectedValueOnce(new Error('engine refused the abort'));

      const res = await send(user, 'post', '/api/v1/documents/uploads', initBody);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(abort).toHaveBeenCalledTimes(1);
      // The abort's failure must not become the answer: it would send a client
      // looking at object storage for a fault in the database.
      expect(String(res.body.message)).not.toContain('engine refused the abort');
      expect(await DocumentUpload.countDocuments({})).toBe(0);
    });

    it('opens no engine-side upload at all for a single-segment transfer', async () => {
      // The branch the two cases above skip: with `declaredChunkCount: 1` there is
      // no multipart handle, so a failed write has nothing to abort.
      vi.spyOn(DocumentUpload, 'create').mockRejectedValueOnce(new Error('write concern failed'));
      const abort = vi.spyOn(storageRef.current!, 'abortMultipartUpload');

      const res = await send(user, 'post', '/api/v1/documents/uploads', {
        ...initBody,
        declaredPlaintextBytes: 1024,
        declaredChunkCount: 1,
      });

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(abort).not.toHaveBeenCalled();
    });
  });

  // ---------------------------------------------------------------------------
  // abortUpload: the engine has already forgotten the upload
  // ---------------------------------------------------------------------------

  describe('DELETE /documents/uploads/:id', () => {
    it('cancels a transfer whose engine-side upload is already gone', async () => {
      // A 404 means the engine has ALREADY done what this request is asking for —
      // a lifecycle rule expired it, or a previous attempt of this very request
      // succeeded and its response was lost. Refusing here would make the row
      // permanently uncancellable, and it would hold a concurrency slot and a quota
      // reservation until the staging TTL fired, up to a week later.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 512 + DOCUMENT_TAG_BYTES],
      });
      await storageRef.current!.abortMultipartUpload(seeded.objectKey, seeded.s3UploadId!);

      const res = await send(user, 'delete', `/api/v1/documents/uploads/${seeded.id}`);

      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      // …and no document was invented on the way past.
      expect(await Document.countDocuments({})).toBe(0);
    });

    it('keeps the row when the engine could not be reached at all', async () => {
      // The other half of the same rule. A 503 means the engine may still be
      // holding parts, and deleting the row that names them would strand them: the
      // row IS the only thing that can address that upload.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 512 + DOCUMENT_TAG_BYTES],
      });
      // The provider's own 503, not a stand-in: `isStorageNotFound` narrows on
      // `ErrorHandler` AND the status, so a plain object carrying a `statusCode`
      // would take this branch for the wrong reason.
      vi.spyOn(storageRef.current!, 'abortMultipartUpload').mockRejectedValueOnce(
        httpErrors.serviceUnavailable('Object storage is unavailable'),
      );

      const res = await send(user, 'delete', `/api/v1/documents/uploads/${seeded.id}`);

      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
      expect(await storageRef.current!.listMultipartUploads()).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------------------
  // completeUpload: the engine assembled the object and the row survived
  // ---------------------------------------------------------------------------

  describe('POST /documents/uploads/:id/complete, after a crash mid-completion', () => {
    /** Puts the account in the exact state a crash between the two calls leaves. */
    async function assembleBehindTheHandlersBack(seeded: Seeded): Promise<void> {
      const parts = await storageRef.current!.listParts(seeded.objectKey, seeded.s3UploadId!);
      await storageRef.current!.completeMultipartUpload(
        seeded.objectKey,
        seeded.s3UploadId!,
        parts.map((part) => ({ partNumber: part.partNumber, etag: part.etag })),
      );
    }

    it('commits the document instead of asking for the whole file again', async () => {
      const partSizes = [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES];
      const seeded = await seedTransfer(user, { partSizes });
      await assembleBehindTheHandlersBack(seeded);
      // The state a retry actually finds: the object is whole, and `ListParts` on
      // the invalidated upload id is a 404.
      await expect(
        storageRef.current!.listParts(seeded.objectKey, seeded.s3UploadId!),
      ).rejects.toMatchObject({ statusCode: 404 });

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      const expectedCiphertext = partSizes.reduce((total, bytes) => total + bytes, 0);
      expect(res.body.data.chunkCount).toBe(2);
      expect(res.body.data.ciphertextBytes).toBe(expectedCiphertext);
      expect(res.body.data.plaintextBytes).toBe(
        expectedCiphertext - DOCUMENT_TAG_BYTES * partSizes.length,
      );
      // The staging row is gone and the object is the one the engine assembled.
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });

    it('recovers a transfer whose ledger records its parts out of order', async () => {
      // The ledger is written by a `$concatArrays` pipeline that APPENDS, so a
      // client that sent part 2 first — or the four-way parallel uploader finishing
      // out of order — stores them that way. `assertLedgerAgreesWithEngine` walks
      // its engine argument POSITIONALLY, so a recovery that handed it the raw
      // ledger would refuse a perfectly good transfer for a "missing part 1".
      const partSizes = [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES];
      const seeded = await seedTransfer(user, { partSizes, ledgerOrder: [2, 1] });
      const row = await DocumentUpload.findById(seeded.id).lean();
      expect(row?.parts.map((part) => part.partNumber)).toEqual([2, 1]);
      await assembleBehindTheHandlersBack(seeded);

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(res.body.data.chunkCount).toBe(2);
    });

    it('refuses when the assembled object is not the length the ledger claims', async () => {
      // The one cross-check this path has instead of `ListParts`. A length that
      // disagrees means the object is not the one this ledger describes, and the
      // honest answer is the 404 the engine already gave.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });
      await assembleBehindTheHandlersBack(seeded);
      // Someone else's bytes at this key: right key, wrong object.
      await storageRef.current!.putObject(seeded.objectKey, pattern(1024));

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(await Document.countDocuments({})).toBe(0);
      // Nothing was destroyed on the way to the refusal: the row is still there to
      // be cancelled.
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });

    it('refuses when the upload is gone and no object was ever assembled', async () => {
      // An abandoned transfer, which is what a 404 from `ListParts` USUALLY means.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });
      await storageRef.current!.abortMultipartUpload(seeded.objectKey, seeded.s3UploadId!);

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(404);
      expect(await Document.countDocuments({})).toBe(0);
    });

    it('passes on an engine that answers the upload but not the object', async () => {
      // The recovery has two engine calls and each may fail its own way. A 404 from
      // `ListParts` says the upload is gone; a 503 from `HeadObject` says nothing at
      // all, and answering "this transfer is gone" on the strength of it would tell
      // a user their finished upload had vanished because the engine was busy.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });
      await assembleBehindTheHandlersBack(seeded);
      vi.spyOn(storageRef.current!, 'headObject').mockRejectedValueOnce(
        httpErrors.serviceUnavailable('Object storage is unavailable'),
      );

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(await Document.countDocuments({})).toBe(0);
      // The transfer survives, so the retry that follows a 503 can still succeed.
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });

    it('passes on an engine that could not be reached, rather than guessing', async () => {
      // Only a 404 may be interpreted. Anything else is the engine failing to
      // answer, and treating that as "already assembled" would commit a document
      // against an object nobody verified.
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES],
      });
      vi.spyOn(storageRef.current!, 'listParts').mockRejectedValueOnce(
        httpErrors.serviceUnavailable('Object storage is unavailable'),
      );
      const head = vi.spyOn(storageRef.current!, 'headObject');

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(head).not.toHaveBeenCalled();
      expect(await Document.countDocuments({})).toBe(0);
    });
  });

  // ---------------------------------------------------------------------------
  // completeUpload: the ledger and the engine describe different part numbers
  // ---------------------------------------------------------------------------

  describe('POST /documents/uploads/:id/complete, ledger against engine', () => {
    it('refuses a part the engine holds that the server never accepted', async () => {
      // Contiguity passes on the engine's side and the counts match, so the only
      // thing that catches this is comparing the two ledgers entry by entry: the
      // server validated a part 3 and the engine is holding a part 2, and framing a
      // document from an unvalidated part is exactly what this refuses.
      const partSizes = [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, 4096 + DOCUMENT_TAG_BYTES];
      const seeded = await seedTransfer(user, { partSizes });
      await DocumentUpload.updateOne(
        { _id: seeded.id },
        { $set: { 'parts.1.partNumber': 3 } },
      ).exec();

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toContain('accepted no part 2');
      expect(await Document.countDocuments({})).toBe(0);
      // A refusal that leaves the transfer alone: it is not the bytes that are
      // wrong, it is the account of them.
      expect(await DocumentUpload.findById(seeded.id).lean()).not.toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // completeUpload: the per-document size cap, re-measured on real bytes
  // ---------------------------------------------------------------------------

  describe('POST /documents/uploads/:id/complete, the per-document size cap', () => {
    /**
     * Lowers the operator's cap for one test.
     *
     * `maxDocumentBytes()` reads `config.MAX_DOCUMENT_SIZE_MB` on every call, so
     * this is the same value a restart with a different `.env` would produce. It is
     * restored in `afterEach` below, because `config` is one object shared by the
     * whole process.
     */
    const originalCap = config.MAX_DOCUMENT_SIZE_MB;
    afterEach(() => {
      (config as { MAX_DOCUMENT_SIZE_MB: number }).MAX_DOCUMENT_SIZE_MB = originalCap;
    });

    it('refuses a transfer whose real bytes exceed the cap it declared under', async () => {
      // The exploit this closes. Init checks `declaredPlaintextBytes`, and only a
      // NON-final part must be a full chunk — so a transfer declaring one megabyte
      // gets a declaredChunkCount of 1 and may then legally deliver a whole 8 MiB
      // final part. Against a 1 MB cap that is an eightfold breach, and
      // `GET /documents/usage` would advertise a limit the stored row exceeds.
      (config as { MAX_DOCUMENT_SIZE_MB: number }).MAX_DOCUMENT_SIZE_MB = 1;
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredPlaintextBytes: BYTES_PER_MB,
        declaredChunkCount: 1,
      });

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(String(res.body.message)).toContain('Document is too large');
      expect(await Document.countDocuments({})).toBe(0);
      // Released, not left retryable: init would refuse the same declared size, so
      // a retained transfer could never be committed and would hold quota until the
      // staging TTL fired.
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
      expect(storageRef.current!.storedKeys()).toEqual([]);
    });

    it('commits a transfer sitting exactly on the cap', async () => {
      // n, beside the n+1 above: an off-by-one here refuses a legal document.
      (config as { MAX_DOCUMENT_SIZE_MB: number }).MAX_DOCUMENT_SIZE_MB = 1;
      const seeded = await seedTransfer(user, {
        partSizes: [BYTES_PER_MB + DOCUMENT_TAG_BYTES],
        declaredPlaintextBytes: BYTES_PER_MB,
        declaredChunkCount: 1,
      });

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(201);
      expect(res.body.data.plaintextBytes).toBe(BYTES_PER_MB);
    });

    it('deletes the row even when the engine will not release the bytes', async () => {
      // `releaseTransfer` is best-effort on the engine side and unconditional on the
      // row, because the row is the only thing that names the object: keeping it
      // because a delete failed would hold the user's quota hostage to an engine
      // fault. What is left behind is an orphan, which is the case the collector's
      // sweep exists for.
      (config as { MAX_DOCUMENT_SIZE_MB: number }).MAX_DOCUMENT_SIZE_MB = 1;
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredPlaintextBytes: BYTES_PER_MB,
        declaredChunkCount: 1,
      });
      const remove = vi
        .spyOn(storageRef.current!, 'deleteObject')
        .mockRejectedValueOnce(new Error('engine refused the delete'));

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(remove).toHaveBeenCalledTimes(1);
      // The refusal is still the size, not the cleanup.
      expect(String(res.body.message)).toContain('Document is too large');
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
    });

    it('aborts the multipart upload when a multi-part transfer is refused', async () => {
      // The other arm of `releaseTransfer`: an unassembled multipart transfer is
      // released by aborting it, never by deleting an object that does not exist
      // yet. Its failure is swallowed for the same reason.
      (config as { MAX_DOCUMENT_SIZE_MB: number }).MAX_DOCUMENT_SIZE_MB = 1;
      const seeded = await seedTransfer(user, {
        partSizes: [DOCUMENT_CIPHERTEXT_CHUNK_BYTES, DOCUMENT_CIPHERTEXT_CHUNK_BYTES],
        declaredPlaintextBytes: BYTES_PER_MB,
        declaredChunkCount: 2,
      });
      const abort = vi
        .spyOn(storageRef.current!, 'abortMultipartUpload')
        .mockRejectedValueOnce(new Error('engine refused the abort'));

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(abort).toHaveBeenCalledTimes(1);
      expect(String(res.body.message)).toContain('Document is too large');
      expect(await DocumentUpload.findById(seeded.id).lean()).toBeNull();
    });
  });

  // ---------------------------------------------------------------------------
  // completeUpload: the row could not be written and the object is already stored
  // ---------------------------------------------------------------------------

  describe('POST /documents/uploads/:id/complete, when the document row fails', () => {
    it('reports the write failure even when the object cannot be deleted', async () => {
      // The compensating delete is best-effort: the caller has to hear about the
      // write, and an object left behind is an orphan rather than a lie. What must
      // NOT happen is the delete's failure becoming the answer.
      const seeded = await seedTransfer(user);
      vi.spyOn(Document, 'create').mockRejectedValueOnce(new Error('write concern failed'));
      const remove = vi
        .spyOn(storageRef.current!, 'deleteObject')
        .mockRejectedValueOnce(new Error('engine refused the delete'));

      const res = await send(user, 'post', completePath(seeded.id), COMPLETION_BODY);

      expect(res.status, JSON.stringify(res.body)).toBe(500);
      expect(remove).toHaveBeenCalledTimes(1);
      expect(String(res.body.message)).not.toContain('engine refused the delete');
      expect(await Document.countDocuments({})).toBe(0);
      // The object survives as an orphan, which is the honest outcome: the row that
      // named it was already claimed before the insert was attempted.
      expect(storageRef.current!.storedKeys()).toEqual([seeded.objectKey]);
    });
  });
});
