import type { Request, Response } from 'express';
import mongoose from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import {
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_DOCUMENTS_PER_USER,
} from '@hvault/shared';
import type { InitDocumentUploadInput } from '@hvault/shared';
import { config } from '../config/index.js';
import { createModuleLogger } from '../utils/logger.js';
import { Document } from '../models/Document.js';
import { DocumentUpload } from '../models/DocumentUpload.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
import { getStorage } from '../services/storage/index.js';
import { buildObjectKey } from '../utils/documentObjects.js';
import {
  assertVaultNotRotating,
  getUserId,
  pickAllowedFields,
} from '../utils/controllerHelpers.js';

const logger = createModuleLogger('document-controller');

// ── Constants ────────────────────────────────────────────────────────

/** Bytes in one megabyte, so the two MB-denominated config values are read one way. */
const BYTES_PER_MB = 1024 * 1024;

/**
 * Defense-in-depth field allowlist for the staging row, on top of the Zod schema.
 *
 * What it keeps OUT is the point. `objectKey`, `chunkPlaintextBytes`,
 * `vaultKeyVersion`, `_id`, `parts`, `receivedBytes` and `expiresAt` are all
 * SERVER-assigned — a client that could set `objectKey` could address another
 * user's object, one that could set `chunkPlaintextBytes` could choose its own
 * framing, and one that could set `vaultKeyVersion` could defeat the rotation
 * check at completion. `z.object()` already strips an unknown key, so this is the
 * second of two independent filters rather than the only one.
 */
const ALLOWED_INIT_FIELDS = new Set([
  'encryptedDek',
  'dekIv',
  'dekTag',
  'streamSalt',
  'noncePrefix',
  'declaredPlaintextBytes',
  'declaredChunkCount',
  'folderId',
]);

/**
 * The staging-row fields a client is allowed to see.
 *
 * An EXCLUSION projection, matching `documentUploadResponseSchema` in
 * `@hvault/shared` field for field, and every entry is deliberate:
 *
 *   * `userId` is implied by the authenticated session;
 *   * `objectKey` is the one server-assigned address in the row, and a client
 *     that never learns it cannot form an expectation about it (the same argument
 *     `Document`'s `toJSON` records);
 *   * `s3UploadId` is an engine handle no client may present;
 *   * the wrapped DEK is not echoed back — the browser holds the DEK in memory for
 *     the life of the transfer, and the server's copy is wrapped under whatever
 *     vault key was current at init;
 *   * `parts.etag` is the engine's receipt, used only by the completion check.
 *
 * A `.lean()` read does NOT run a schema's `toJSON` transform, and every read here
 * is lean, so this projection is the control rather than a second line of defense.
 */
const UPLOAD_PROJECTION = '-userId -objectKey -s3UploadId -encryptedDek -dekIv -dekTag -parts.etag';

// ── Helpers ──────────────────────────────────────────────────────────

/** The operator's per-document size cap, in bytes. */
const maxDocumentBytes = (): number => config.MAX_DOCUMENT_SIZE_MB * BYTES_PER_MB;

/** The operator's per-user storage quota, in bytes. */
const storageQuotaBytes = (): number => config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER * BYTES_PER_MB;

/**
 * Bytes one user has already committed: every document row, TRASHED ONES
 * INCLUDED.
 *
 * A trashed document still occupies its object in the bucket, so it still costs
 * the operator storage and still counts against the quota. The UI says so, and
 * `GET /documents/usage` reports the same number, because a user who deletes a
 * file and sees no space returned would otherwise assume the deletion failed.
 */
async function committedBytesFor(userId: string): Promise<number> {
  const [row] = await Document.aggregate<{ total: number }>([
    { $match: { userId: new mongoose.Types.ObjectId(userId) } },
    { $group: { _id: null, total: { $sum: '$plaintextBytes' } } },
  ]);
  return row?.total ?? 0;
}

/**
 * Bytes one user has RESERVED: the declared size of every staging row that is
 * still live.
 *
 * Live only, and that is the whole reason this is not a bare count: an expired
 * row can never be completed, so reserving quota for it would lock a user out of
 * their own budget until the TTL index got round to it. The bytes such a transfer
 * did upload are reclaimed by the garbage collector, not charged here.
 */
async function inFlightBytesFor(userId: string, now: Date): Promise<number> {
  const [row] = await DocumentUpload.aggregate<{ total: number }>([
    { $match: { userId: new mongoose.Types.ObjectId(userId), expiresAt: { $gt: now } } },
    { $group: { _id: null, total: { $sum: '$declaredPlaintextBytes' } } },
  ]);
  return row?.total ?? 0;
}

// ── Handlers ─────────────────────────────────────────────────────────

/**
 * `POST /documents/uploads` — open a transfer.
 *
 * The response's `uploadId` is the FUTURE document id. It is minted here, before
 * a byte is sealed, because it is bound into the HKDF `info` of the DEK wrap, the
 * stream key and the metadata key (Section 1.4 of the design): the browser cannot
 * encrypt anything until it knows this value, and it can never be reassigned
 * without re-encrypting the whole file.
 *
 * Everything before that minting is a refusal that must leave NOTHING behind — no
 * staging row, and no engine-side multipart upload — because both consume a
 * budget the user can see (the concurrency cap) or the operator pays for (bucket
 * space the garbage collector then has to find).
 */
export const initUpload = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const body = req.body as InitDocumentUploadInput;

  // A wrapped DEK is ciphertext under the caller's vault key, so this is a
  // ciphertext-creating write and carries the same fence every other one does.
  // Both ends of an upload are fenced, and the two are not redundant: the
  // per-upload lock and the per-user rotation lock are disjoint, so a completion
  // that started before a rotation could otherwise commit a key nothing can
  // unwrap. See `assertVaultNotRotating`.
  await assertVaultNotRotating(userId);

  if (body.declaredPlaintextBytes > maxDocumentBytes()) {
    throw httpErrors.badRequest(
      `Document is too large. The maximum size is ${String(config.MAX_DOCUMENT_SIZE_MB)} MB.`,
    );
  }

  const documentCount = await Document.countDocuments({ userId });
  if (documentCount >= MAX_DOCUMENTS_PER_USER) {
    throw httpErrors.badRequest(
      `Document limit reached. You can have a maximum of ${String(MAX_DOCUMENTS_PER_USER)} documents.`,
    );
  }

  const now = new Date();
  const openUploads = await DocumentUpload.countDocuments({ userId, expiresAt: { $gt: now } });
  if (openUploads >= MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER) {
    throw httpErrors.badRequest(
      `Too many uploads in progress. You can run ${String(MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER)} at a time.`,
    );
  }

  const [committedBytes, inFlightBytes] = await Promise.all([
    committedBytesFor(userId),
    inFlightBytesFor(userId, now),
  ]);
  if (committedBytes + inFlightBytes + body.declaredPlaintextBytes > storageQuotaBytes()) {
    throw httpErrors.badRequest(
      `Storage quota exceeded. Your limit is ${String(config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER)} MB.`,
    );
  }

  if (body.folderId !== undefined) {
    const folderExists = await Folder.exists({ _id: body.folderId, userId });
    if (!folderExists) {
      throw httpErrors.notFound('Target folder not found');
    }
  }

  // Read as 0 when absent: an account created before this column existed, and the
  // `upgrade` gate's 0.7.0 fixture, both carry no value at all.
  const user = await User.findById(userId).select('vaultKeyVersion').lean();
  const vaultKeyVersion = user?.vaultKeyVersion ?? 0;

  const uploadId = new mongoose.Types.ObjectId();
  const objectKey = buildObjectKey(userId, uploadId.toHexString());

  // One segment is stored with `PutObject`, which has no multipart handle to keep
  // — so `s3UploadId` is ABSENT for a single-segment transfer rather than empty,
  // and three round trips are saved on the common case of a small file.
  const s3UploadId =
    body.declaredChunkCount > 1 ? await getStorage().createMultipartUpload(objectKey) : undefined;

  try {
    await DocumentUpload.create({
      _id: uploadId,
      userId,
      objectKey,
      ...(s3UploadId === undefined ? {} : { s3UploadId }),
      ...pickAllowedFields(body, ALLOWED_INIT_FIELDS),
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
      vaultKeyVersion,
      expiresAt: new Date(now.getTime() + config.DOCUMENT_UPLOAD_TTL_HOURS * 60 * 60 * 1000),
    });
  } catch (error) {
    // The engine-side upload is already open at this point and nothing names it
    // any more, so the garbage collector could only reclaim it an hour after the
    // staging TTL it never got — abort it here instead. The abort is best-effort:
    // the original failure is what the caller needs to hear.
    if (s3UploadId !== undefined) {
      try {
        await getStorage().abortMultipartUpload(objectKey, s3UploadId);
      } catch (abortError) {
        logger.error('Failed to abort a multipart upload after its staging row was not written', {
          userId,
          uploadId: uploadId.toHexString(),
          error: abortError instanceof Error ? abortError.message : String(abortError),
        });
      }
    }
    throw error;
  }

  logger.info('Document upload initiated', {
    userId,
    uploadId: uploadId.toHexString(),
    declaredChunkCount: body.declaredChunkCount,
  });

  res.status(201).json({
    success: true,
    data: {
      uploadId: uploadId.toHexString(),
      vaultKeyVersion,
      chunkPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES,
    },
  });
});

/**
 * `GET /documents/uploads` — the caller's transfers.
 *
 * UNFILTERED by expiry, deliberately, and the opposite of the caps above. A row
 * whose `expiresAt` has passed can no longer accept a part, but it is exactly
 * what a user needs to see in order to cancel it, and the response carries
 * `expiresAt` so the UI can say which is which. Hiding it would leave a row that
 * shows up in no list and holds an engine-side upload nobody can point at.
 *
 * Bounded by the concurrency cap, which is a ceiling this page cannot reach in
 * practice: init refuses a fourth LIVE transfer, and a row past its expiry is
 * removed by the TTL index within the minute.
 */
export const listUploads = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const uploads = await DocumentUpload.find({ userId })
    .select(UPLOAD_PROJECTION)
    .sort({ createdAt: -1 })
    .limit(MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER)
    .lean();

  res.json({ success: true, data: uploads });
});

/**
 * `GET /documents/uploads/:id` — one transfer, with the parts the server already
 * holds.
 *
 * This is what makes a same-session resume possible: the client compares the
 * ledger with the segments it has sealed and sends only what is missing. It is
 * scoped by `{ _id, userId }`, so a foreign id is indistinguishable from one that
 * never existed.
 */
export const getUpload = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const upload = await DocumentUpload.findOne({ _id: id, userId }).select(UPLOAD_PROJECTION).lean();
  if (!upload) {
    throw httpErrors.notFound('Upload not found');
  }

  res.json({ success: true, data: upload });
});

/**
 * `DELETE /documents/uploads/:id` — abandon a transfer.
 *
 * The engine-side upload is aborted FIRST and the row deleted second, never the
 * other way round: a crash between the two then leaves a staging row that still
 * names the upload, which the garbage collector can finish, rather than an open
 * multipart upload nothing in the database knows about.
 *
 * A single-segment transfer has no `s3UploadId` and nothing is aborted. If its
 * one part had already been stored, the object it wrote is reclaimed by the
 * collector's orphan sweep — a key that parses to a document id with no row.
 * Deleting it here instead would be one request cheaper and one race worse, since
 * this handler cannot yet tell an abandoned single-segment upload from one whose
 * completion is committing the very same key.
 */
export const abortUpload = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const upload = await DocumentUpload.findOne({ _id: id, userId })
    .select('objectKey s3UploadId')
    .lean();
  if (!upload) {
    throw httpErrors.notFound('Upload not found');
  }

  if (upload.s3UploadId !== undefined) {
    await getStorage().abortMultipartUpload(upload.objectKey, upload.s3UploadId);
  }

  await DocumentUpload.deleteOne({ _id: id, userId });

  logger.info('Document upload aborted', { userId, uploadId: id });

  res.json({ success: true, message: 'Upload cancelled' });
});
