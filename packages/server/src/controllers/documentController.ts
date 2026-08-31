import { createHash } from 'node:crypto';
import type { Request, Response } from 'express';
import mongoose from 'mongoose';
import { catchAsync, httpErrors } from '@hiprax/errors';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_DOCUMENTS_PER_USER,
} from '@hvault/shared';
import type { DocumentPartParams, InitDocumentUploadInput } from '@hvault/shared';
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

/**
 * The header carrying the client's SHA-256 of the sealed segment it is sending.
 *
 * Lower-case because Node lower-cases every incoming header name, and `req.headers`
 * is keyed by the lower-cased form.
 */
export const PART_DIGEST_HEADER = 'x-hv-part-sha256';

/**
 * 64 lowercase hexadecimal characters, the same shape `sha256Schema` pins for the
 * digests inside the encrypted metadata blob, so a client formats one digest one
 * way everywhere.
 */
const PART_DIGEST_PATTERN = /^[a-f0-9]{64}$/;

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

/**
 * `PUT /documents/uploads/:id/parts/:partNumber` — store one sealed segment.
 *
 * One crypto segment is one uploaded part is one downloaded range, so this handler
 * is the only place the server ever sees a document's bytes, and it sees them as
 * ciphertext it cannot read. What it CAN do is refuse a part that would make the
 * finished object undecryptable, and that is its whole job.
 *
 * The rule that matters most is the one the storage engine itself does not enforce:
 * **a non-final part must be exactly `DOCUMENT_CIPHERTEXT_CHUNK_BYTES`.** Garage was
 * measured accepting a short middle part, and S3's own contract only requires the
 * LAST part to be allowed to be short. A short middle part shifts every later
 * segment boundary by the shortfall, so segment `i` no longer starts at
 * `i * DOCUMENT_CIPHERTEXT_CHUNK_BYTES`, every subsequent ranged read returns the
 * wrong bytes, and the failure surfaces in the browser as a tag mismatch that looks
 * like corruption. The server is the only thing standing between that and a
 * document nobody can ever open.
 *
 * NOT rotation-fenced, unlike init and completion, and that is deliberate rather
 * than an omission. `assertVaultNotRotating` guards the writes that create
 * ciphertext under the caller's VAULT key; a part carries no wrapped key and no
 * vault-key-derived material at all. The DEK was wrapped at init (fenced there) and
 * is sent again at completion (fenced there, and version-checked), so a rotation
 * that runs mid-transfer is caught at the only two points where it can do harm.
 * Refusing parts as well would abort an 800 MB transfer for a rotation the
 * completion step can already recover from with a single retried request.
 *
 * The quota is not re-checked here either, and the honest reason is a BOUND rather
 * than an equality. A part number is bounded by `declaredChunkCount`, each part by
 * one segment, and a re-sent part replaces its ledger entry rather than adding one,
 * so the received total cannot exceed `declaredChunkCount` whole chunks. That is
 * not the same as the size init reserved: a transfer declaring one plaintext byte
 * gets a `declaredChunkCount` of 1 and may then legally send a full 8 MiB final
 * part. The overshoot is at most one chunk per transfer, times
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER`, and completion re-checks the quota
 * against the bytes actually received before anything is committed — so the
 * transient over-reservation is bounded and never becomes a stored document.
 */
export const uploadPart = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id, partNumber } = req.params as unknown as DocumentPartParams;
  const body: unknown = req.body;

  // `express.raw` only parses `application/octet-stream`; for anything else it
  // leaves whatever the global JSON parser produced, or nothing. A part is raw
  // bytes, and there is no second representation of one.
  //
  // `instanceof Buffer` rather than `Buffer.isBuffer`, and the difference is not
  // style: this is the TYPE TEST that everything below depends on. `.length` is
  // precisely the operation that behaves differently for a string, an array and a
  // Buffer, so a guard that a reader (or a static analyzer) cannot recognise as a
  // type test is a guard that does not obviously cover the comparisons it protects.
  // There is one realm in this process and `express.raw` builds the value with
  // `Buffer.concat`, so the cross-realm case `Buffer.isBuffer` additionally covers
  // cannot arise here.
  if (!(body instanceof Buffer)) {
    throw httpErrors.unsupportedMediaType(
      'A document part must be sent as application/octet-stream',
    );
  }

  // The size of this part, read ONCE, immediately behind that guard. Every rule
  // below is a statement about this number — the declared-length check, the
  // exact-size rule, the final-part window, the ledger entry and the response — and
  // reading `.length` off the buffer at each of them invites one of them to be read
  // off something else after an edit.
  const partBytes: number = body.length;

  // Projected, not the whole row: `parts` can hold one entry per segment, and this
  // handler needs none of them — the ledger is rewritten server-side by the pipeline
  // below rather than read, merged and written back.
  const upload = await DocumentUpload.findOne({ _id: id, userId })
    .select('objectKey s3UploadId declaredChunkCount expiresAt')
    .lean();
  // A foreign id and an id that never existed are the same answer, so neither
  // enumerates another account's transfers.
  if (!upload) {
    throw httpErrors.notFound('Upload not found');
  }
  // The TTL index deletes an expired row within the minute, not at the instant it
  // expires, so a part can still arrive against one. It is refused with the same
  // 404 the deleted row would have produced: a transfer past its deadline can never
  // be completed, and the two cases must be indistinguishable or the response
  // becomes a clock oracle.
  if (upload.expiresAt.getTime() <= Date.now()) {
    throw httpErrors.notFound('Upload not found');
  }

  if (partNumber > upload.declaredChunkCount) {
    throw httpErrors.badRequest(
      `This transfer has ${String(upload.declaredChunkCount)} part(s); part ${String(partNumber)} is outside it.`,
    );
  }

  // The bytes the parser handed over must be the bytes the client declared.
  //
  // Node's HTTP server enforces this today — it delivers exactly `Content-Length`
  // bytes and answers 400 itself when the client sends fewer or more — and
  // `raw-body` checks it a second time. This is the third check, and it is the one
  // that belongs to this handler, because the ledger entry, `receivedBytes` and the
  // quota are all computed from a length: if a future parser, a proxy or a
  // transfer coding ever broke that correspondence, everything downstream would be
  // wrong in a way nothing else would notice. `Number(undefined)` is `NaN`, which
  // is never equal to a length, so a missing header is refused here as well as by
  // the 411 guard ahead of the parser.
  const declaredBytes = Number(req.headers['content-length']);
  if (declaredBytes !== partBytes) {
    throw httpErrors.badRequest(
      `Part ${String(partNumber)} declared ${String(req.headers['content-length'])} byte(s) and delivered ${String(partBytes)}.`,
    );
  }

  const isFinalPart = partNumber === upload.declaredChunkCount;
  if (!isFinalPart && partBytes !== DOCUMENT_CIPHERTEXT_CHUNK_BYTES) {
    throw httpErrors.badRequest(
      `Part ${String(partNumber)} is not the last part of this transfer and must be exactly ` +
        `${String(DOCUMENT_CIPHERTEXT_CHUNK_BYTES)} bytes; it was ${String(partBytes)}.`,
    );
  }
  // The final part is the only one allowed to be short, and it still cannot be
  // empty: the smallest sealed segment is a bare authentication tag.
  if (
    isFinalPart &&
    (partBytes < DOCUMENT_TAG_BYTES || partBytes > DOCUMENT_CIPHERTEXT_CHUNK_BYTES)
  ) {
    throw httpErrors.badRequest(
      `The last part of this transfer must be between ${String(DOCUMENT_TAG_BYTES)} and ` +
        `${String(DOCUMENT_CIPHERTEXT_CHUNK_BYTES)} bytes; it was ${String(partBytes)}.`,
    );
  }

  // The digest the client computed over the sealed segment, checked against one the
  // server computes itself. It proves the bytes survived the network and every
  // middleware between the socket and here; it proves nothing about the plaintext,
  // which the server never sees. A plain comparison rather than a constant-time one
  // on purpose: both operands are the client's own values and neither is a secret,
  // so there is no secret for a timing side channel to leak.
  const declaredDigest = req.headers[PART_DIGEST_HEADER];
  if (typeof declaredDigest !== 'string' || !PART_DIGEST_PATTERN.test(declaredDigest)) {
    throw httpErrors.badRequest(
      `${PART_DIGEST_HEADER} must be 64 lowercase hexadecimal characters`,
    );
  }
  const actualDigest = createHash('sha256').update(body).digest('hex');
  if (actualDigest !== declaredDigest) {
    throw httpErrors.badRequest(`Part ${String(partNumber)} does not match its declared digest.`);
  }

  // Stored BEFORE the ledger is written. A part in the bucket that no ledger names
  // is reclaimed by the collector or overwritten by a retry; a ledger entry naming
  // bytes that were never stored would be counted at completion and produce a
  // document with a hole in it.
  let etag: string | undefined;
  if (upload.declaredChunkCount === 1) {
    // One segment is one whole object: `PutObject`, no multipart handle, no
    // engine receipt to record.
    await getStorage().putObject(upload.objectKey, body);
  } else if (upload.s3UploadId === undefined) {
    // A row claiming several segments while naming no engine-side upload cannot be
    // produced by `initUpload`, which opens one before it writes the row and aborts
    // it if the write fails. Reaching this means the row was corrupted or written
    // by something else, and falling through to `putObject` would store one part as
    // the WHOLE object and destroy every other part of the transfer.
    logger.error('A multi-segment staging row names no engine-side upload', {
      userId,
      uploadId: id,
      declaredChunkCount: upload.declaredChunkCount,
    });
    throw httpErrors.internalServerError('This transfer is no longer in a usable state');
  } else {
    ({ etag } = await getStorage().uploadPart(
      upload.objectKey,
      upload.s3UploadId,
      partNumber,
      body,
    ));
  }

  // One atomic update that REPLACES any existing entry for this part number and
  // recomputes `receivedBytes` from the array it just produced.
  //
  // An aggregation pipeline rather than `$push`, and that is what makes a re-sent
  // part idempotent by construction: `$push` plus a separate `$inc` would double
  // count the moment a client retried a part it had already delivered, and a
  // `$pull` followed by a `$push` is two updates with a window between them. Here
  // the filter drops the old entry, the concat appends the new one, and the second
  // stage sums the result, so `receivedBytes` is DERIVED from the ledger rather
  // than tracked alongside it and cannot drift from it.
  //
  // A pipeline update bypasses Mongoose's casting and validators, so the sub-schema's
  // bounds do NOT run on this write. That is safe because every one of them has
  // already been checked above by something stricter: `partNumber` by the param
  // schema and the declared-count check, `bytes` by the exact-size rules. The one
  // bound with no equivalent here is `etag`'s `maxlength`, which is therefore
  // ADVISORY on this path rather than enforced. That is acceptable, and only
  // because the value is engine-produced rather than caller-supplied:
  // `StorageProvider.uploadPart` returns it, the S3 provider throws before
  // returning if the SDK omits it, and nothing a client sends can reach it.
  const entry = {
    partNumber,
    bytes: partBytes,
    ...(etag === undefined ? {} : { etag }),
  };
  const updated = await DocumentUpload.findOneAndUpdate(
    { _id: id, userId },
    [
      {
        $set: {
          parts: {
            $concatArrays: [
              {
                $filter: {
                  input: '$parts',
                  as: 'part',
                  cond: { $ne: ['$$part.partNumber', partNumber] },
                },
              },
              // `$literal`, because everything inside a pipeline update is an
              // aggregation EXPRESSION: a string beginning with `$` would be
              // resolved as a field path and the value silently dropped or
              // substituted. No client-controlled string reaches this object and a
              // real S3 ETag is quoted hex, so it is not reachable today — but the
              // wrapper costs nothing and removes the class outright.
              [{ $literal: entry }],
            ],
          },
        },
      },
      { $set: { receivedBytes: { $sum: '$parts.bytes' } } },
    ],
    // `updatePipeline: true` is REQUIRED by Mongoose 9 to pass an aggregation
    // pipeline as the update: without it the array is refused outright rather
    // than being sent to the server as a pipeline, which is the failure mode a
    // reader would otherwise mistake for a MongoDB version problem.
    // `returnDocument: 'after'`, never the legacy `new: true`, which Mongoose 9
    // deprecates with a process warning — and this project's lint and gate surface
    // run at zero warnings.
    { returnDocument: 'after', projection: 'receivedBytes', updatePipeline: true },
  ).lean();

  if (!updated) {
    // The staging row was removed while this part was being stored — its TTL fired,
    // or the caller cancelled the transfer from another tab. The bytes are already
    // in the bucket and are left there for the collector's orphan sweep rather than
    // deleted here, because a completion committing the very same key may be in
    // flight; what must NOT happen is recreating the row this update would have
    // resurrected, which `findOneAndUpdate` without an upsert guarantees.
    throw httpErrors.notFound('Upload not found');
  }

  res.json({
    success: true,
    data: { partNumber, bytes: partBytes, receivedBytes: updated.receivedBytes },
  });
});
