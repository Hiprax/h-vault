import { createHash } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import type { Request, Response } from 'express';
import mongoose, { type HydratedDocument } from 'mongoose';
import { catchAsync, httpErrors, ErrorHandler } from '@hiprax/errors';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_FRAMING_MISMATCH_MESSAGE,
  DOCUMENT_PLAINTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER,
  MAX_DOCUMENTS_PER_USER,
  documentChunkCountFor,
  documentPlaintextBytesFor,
} from '@hvault/shared';
import type {
  CompleteDocumentUploadInput,
  DocumentPartParams,
  DocumentSegmentParams,
  InitDocumentUploadInput,
  ListDocumentTrashInput,
  ListDocumentsInput,
} from '@hvault/shared';
import { config } from '../config/index.js';
import { createModuleLogger } from '../utils/logger.js';
import { Document, type IDocument } from '../models/Document.js';
import { DocumentUpload, type IDocumentUpload } from '../models/DocumentUpload.js';
import { Folder } from '../models/Folder.js';
import { User } from '../models/User.js';
import { createAuditLog } from '../services/auditService.js';
import { getStorage } from '../services/storage/index.js';
import type { StoragePart, StorageRangeRead } from '../services/storage/types.js';
import { buildObjectKey, expectedPartSize, segmentRange } from '../utils/documentObjects.js';
import { acquireJobLock, releaseJobLock } from '../utils/jobLock.js';
import {
  assertVaultNotRotating,
  documentCompleteLockName,
  getRequestContext,
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
 * The committed-document fields a client is allowed to see.
 *
 * It reproduces `Document`'s own `toJSON` transform EXACTLY — `__v`, `userId` and
 * `objectKey` — and that exactness is the point twice over.
 *
 * First, because a `.lean()` read does not run `toJSON`, and every read on this
 * route file is lean. So this projection is the control, not a second line of
 * defense: `objectKey` is the one server-assigned address on the row, and a
 * client that never learns it cannot form an expectation about it.
 *
 * Second, because `POST /documents/uploads/:id/complete` answers with a HYDRATED
 * document and therefore goes through `toJSON`, while every read below is lean and
 * goes through this. The client parses both with the same
 * `documentResponseSchema`, so the two shapes have to be the same shape; a `__v`
 * present on one and absent on the other is exactly the kind of difference that
 * shows up as a validation failure on a code path nobody tested.
 */
const DOCUMENT_PROJECTION = '-__v -userId -objectKey';

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

/**
 * How long one completion may hold its per-upload lock.
 *
 * The same two minutes `toolsController` gives an import, and generously so: the
 * work under the lock is one `ListParts`, one `CompleteMultipartUpload` (which is
 * a metadata operation on every engine this stack targets — the parts are already
 * stored) and one insert. What the value really bounds is how long a completion
 * that died mid-flight blocks a retry of the SAME upload, and two minutes is short
 * enough that a user waits rather than gives up. It cannot block anything else: the
 * lock is keyed by upload id, so a second transfer of the same account is
 * untouched.
 */
const COMPLETE_LOCK_TTL_MS = 2 * 60 * 1000;

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

/**
 * The ENGINE's own account of a transfer — what it says it is holding, as opposed
 * to what the staging ledger says it accepted.
 *
 * The two are compared before either is believed, which is the whole point of
 * reading this at all: the ledger records what the part handler validated, and
 * the engine records what a download will actually read. A document is committed
 * only where they agree.
 *
 * A UNION rather than one array with an optional `etag`, because the difference
 * between the two shapes is real and only one of them can be completed. A
 * multipart transfer must hand every part's receipt back to the engine, and
 * `StoragePart.etag` is non-optional, so this shape carries that guarantee into
 * the completion call instead of leaving a fallback there for a value that cannot
 * be missing. The single-segment shape has no receipts BECAUSE there is nothing to
 * complete: its object is already whole.
 */
type EngineLedger =
  | { readonly mode: 'object'; readonly parts: readonly { partNumber: number; bytes: number }[] }
  | {
      readonly mode: 'multipart';
      readonly s3UploadId: string;
      readonly parts: readonly StoragePart[];
    };

/**
 * What the storage engine says it holds for this transfer.
 *
 * TWO PATHS, and the branch is not an optimisation. `ListParts` on an upload that
 * was never OPENED is a 404 (`NoSuchUpload` sits in the S3 provider's
 * not-found tokens, and the in-memory double raises the same thing), so a
 * single-segment transfer — which `initUpload` deliberately stores with
 * `PutObject` and gives no `s3UploadId` — cannot be verified that way at all. Its
 * one part IS the whole object, so `HeadObject` is the engine's account of it.
 *
 * The branch is on `declaredChunkCount`, mirroring `uploadPart` exactly, including
 * its refusal of the shape `initUpload` cannot produce: a row claiming several
 * segments while naming no engine-side upload. Reading such a row as a
 * single-segment transfer would commit one part as the whole document.
 */
async function readEngineLedger(
  upload: Pick<IDocumentUpload, 'objectKey' | 's3UploadId' | 'declaredChunkCount'>,
  context: { userId: string; uploadId: string },
): Promise<EngineLedger> {
  if (upload.declaredChunkCount === 1) {
    const stat = await getStorage().headObject(upload.objectKey);
    return { mode: 'object', parts: [{ partNumber: 1, bytes: stat.bytes }] };
  }

  if (upload.s3UploadId === undefined) {
    logger.error('A multi-segment staging row names no engine-side upload', {
      ...context,
      declaredChunkCount: upload.declaredChunkCount,
    });
    throw httpErrors.internalServerError('This transfer is no longer in a usable state');
  }

  return {
    mode: 'multipart',
    s3UploadId: upload.s3UploadId,
    parts: await getStorage().listParts(upload.objectKey, upload.s3UploadId),
  };
}

/**
 * Refuses unless the staging ledger and the engine describe the SAME set of parts.
 *
 * This is the "verify every part against `ListParts`" step, and it is a comparison
 * rather than a preference because each side knows something the other does not.
 * The ledger is the only record that a part passed the part handler's digest and
 * size checks; the engine is the only account of what a ranged read will actually
 * return. Committing from either alone would trust half the story: a part the
 * engine dropped would be counted, or a part nothing validated would be framed
 * into the document.
 *
 * Contiguity from 1 is checked here too, because part numbers index segments and
 * segment `i` is read from `i * chunkCiphertextBytes`: a gap does not produce a
 * short document, it produces one whose every later segment is at the wrong
 * offset.
 */
function assertLedgerAgreesWithEngine(
  staged: readonly { partNumber: number; bytes: number }[],
  engine: readonly { partNumber: number; bytes: number }[],
): void {
  if (staged.length !== engine.length) {
    throw httpErrors.badRequest(
      `The storage engine holds ${String(engine.length)} part(s) for this transfer and the server ` +
        `accepted ${String(staged.length)}.`,
    );
  }

  const stagedByNumber = [...staged].sort((left, right) => left.partNumber - right.partNumber);
  for (const [index, part] of engine.entries()) {
    // `engine` arrives in ascending part-number order from both the S3 provider
    // and the double, and `stagedByNumber` is sorted here, so a positional
    // comparison is a comparison of the same part on both sides.
    const expectedNumber = index + 1;
    const stagedPart = stagedByNumber[index];
    if (part.partNumber !== expectedNumber) {
      throw httpErrors.badRequest(
        `This transfer is missing part ${String(expectedNumber)}; the storage engine's next part ` +
          `is ${String(part.partNumber)}.`,
      );
    }
    // `noUncheckedIndexedAccess` makes the read optional and the two arrays are the
    // same length by the check above, so this narrows a value that is present.
    if (stagedPart?.partNumber !== part.partNumber) {
      throw httpErrors.badRequest(
        `The server accepted no part ${String(part.partNumber)} for this transfer.`,
      );
    }
    if (stagedPart.bytes !== part.bytes) {
      throw httpErrors.badRequest(
        `Part ${String(part.partNumber)} is ${String(part.bytes)} byte(s) in storage and ` +
          `${String(stagedPart.bytes)} byte(s) in this transfer's ledger.`,
      );
    }
  }
}

/**
 * The three sizes a committed document carries, DERIVED from the part ledger and
 * from nothing the client sent.
 *
 * A client that could declare these could under-report its own quota consumption
 * and mis-frame its own document; the request body is therefore not consulted for
 * any of them. `plaintextBytes` follows from the container format: every segment
 * is its plaintext plus exactly one authentication tag, so the tags are the whole
 * difference between the object and the file.
 */
function deriveFraming(engine: readonly { partNumber: number; bytes: number }[]): {
  chunkCount: number;
  ciphertextBytes: number;
  plaintextBytes: number;
} {
  const chunkCount = engine.length;
  const ciphertextBytes = engine.reduce((total, part) => total + part.bytes, 0);
  return {
    chunkCount,
    ciphertextBytes,
    // The shared identity, not a second spelling of it: `documentResponseSchema`
    // re-checks the same relationship on every row a client reads, and the two must
    // be one definition or a change to the framing gets applied to one of them.
    plaintextBytes: documentPlaintextBytesFor(ciphertextBytes, chunkCount),
  };
}

/**
 * Releases everything a transfer is holding: the engine-side parts (or the stored
 * object, for a single-segment transfer) and the staging row.
 *
 * Used by the one refusal at completion that can never become a success by being
 * retried with the same bytes — the quota. The received bytes ARE the bytes the
 * account cannot hold, so keeping them would bill the operator for storage that is
 * over budget until the staging TTL fired, and the reservation the transfer made
 * at init would keep the rest of the user's budget locked with it.
 *
 * Best-effort on the engine side, and deliberately so: the staging row is what
 * names these objects, so the row must go even if the engine call fails. What is
 * left behind then is an orphan the collector's sweep reclaims, which is the case
 * that sweep exists for.
 */
async function releaseTransfer(
  upload: Pick<IDocumentUpload, '_id' | 'userId' | 'objectKey'>,
  engine: EngineLedger,
): Promise<void> {
  try {
    if (engine.mode === 'object') {
      await getStorage().deleteObject(upload.objectKey);
    } else {
      await getStorage().abortMultipartUpload(upload.objectKey, engine.s3UploadId);
    }
  } catch (error) {
    logger.error('Failed to release the storage a refused completion was holding', {
      userId: String(upload.userId),
      uploadId: String(upload._id),
      error: error instanceof Error ? error.message : String(error),
    });
  }

  await DocumentUpload.deleteOne({ _id: upload._id, userId: upload.userId });
}

/**
 * What a completion decided, computed while its lock is held and rendered after it
 * is released.
 *
 * A return value rather than a response, because the lock must be released BEFORE
 * anything is written to the client — see `completeUpload`. Only two outcomes are
 * expressible: the document, and the one refusal that has to carry structured data
 * back. Every other refusal is a throw, which the surrounding `finally` releases
 * the lock on the way past.
 */
type CompletionOutcome =
  | { readonly kind: 'document'; readonly document: HydratedDocument<IDocument> }
  | { readonly kind: 'staleVaultKey'; readonly vaultKeyVersion: number };

/**
 * The committed row, as the completion endpoint reports it.
 *
 * 201 for a REPEAT completion too, deliberately: a client that retried after a
 * timeout must not be able to tell whether its first attempt landed, or it will try
 * to "fix" a document that is already correct.
 */
function sendDocument(res: Response, document: HydratedDocument<IDocument>): void {
  res.status(201).json({ success: true, data: document.toJSON() });
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

  // Checked HERE and not again at completion, deliberately. Init is where a
  // refusal is free — nothing has been uploaded yet — while a completion refused
  // for the count would throw away a transfer that has already crossed the network
  // in full, and the caps this project re-measures late are the ones a client can
  // move after the check (the quota, because the bytes that arrive may exceed the
  // bytes declared). The count cannot be moved that way: a transfer commits exactly
  // one document. The residual is bounded by the concurrency cap, so an account can
  // finish at most `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER - 1` documents past
  // the limit and cannot open another transfer until it is back under it.
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

/**
 * `POST /documents/uploads/:id/complete` — turn a finished transfer into a
 * document.
 *
 * This is the only place a `documents` row is ever created, and everything it
 * commits about the file's SHAPE it works out for itself. The request body carries
 * exactly two things: the sealed metadata blob, and the wrapped document key.
 *
 * ## Why the wrapped key is sent a second time
 *
 * It was already sent at init, and the staging row still holds that copy — wrapped
 * under whatever vault key was current then. It is sent AGAIN here, and the row is
 * built from the completion body rather than from the staging copy, because that is
 * the only thing that makes a mid-transfer vault-key rotation recoverable. A
 * rotation invalidates the init-time wrap; if that were the only copy, the client's
 * sole remedy would be to re-initiate, and a new upload id means new HKDF `info`,
 * which means re-encrypting and re-uploading every segment of the file. Instead the
 * 409 below hands back the current version, the browser rewraps the DEK it still
 * holds in memory, and retries THIS request alone — no byte crosses the wire twice.
 *
 * ## Why a lock AND a rotation fence AND a version check
 *
 * They are three different guards against three different races, and none
 * substitutes for another.
 *
 *   * The **per-upload JobLock** stops a completion racing ITSELF. The unique `_id`
 *     already makes a second row impossible, so the lock is not what guarantees
 *     that; what it prevents is a duplicate request getting half-way — aborting a
 *     multipart upload the first is completing, deleting the staging row out from
 *     under it — before the primary key stops it.
 *   * The **rotation fence** (`assertVaultNotRotating`) catches a rotation that is
 *     IN PROGRESS. Its flag is set before it enumerates, so a row inserted while it
 *     is true is a row the enumeration will not have seen and the new key will not
 *     cover.
 *   * The **`vaultKeyVersion` check** catches a rotation that has already
 *     COMMITTED, which the fence cannot see because the flag is cleared by then.
 *
 * The lock and the rotation lock are DISJOINT — one is keyed by upload, the other
 * by user — so holding this one says nothing whatever about whether a rotation is
 * running. That is precisely why the fence is here and not assumed.
 *
 * What the pair does NOT do is close the window between the version read and the
 * insert, and it is worth saying so rather than implying otherwise. A rotation that
 * begins and commits entirely inside that span enumerates an account this document
 * is not yet part of, so its own completeness check has nothing to catch, and the
 * row lands wrapped under a superseded key. The span is narrowed to as little as the
 * work allows and no further: for a multipart transfer it contains the engine's
 * completion call, because moving the version check after that call is what would
 * make the 409 unretryable — the engine invalidates the upload id on success, so a
 * client told to rewrap would find nothing left to complete. The same class of gap
 * is pre-existing for vault items and folders; it is wider here, and this is where
 * it is written down.
 *
 * ## Why the transfer is claimed before the row is inserted, and differently per mode
 *
 * A part upload takes neither this lock nor the fence. For a MULTIPART transfer that
 * is harmless — the engine ignores parts a completion does not name, and refuses one
 * that replaces a part it does — so its object is finalised FIRST and the staging row
 * is then deleted unconditionally. That ordering is deliberate: a transient failure
 * from the engine must leave a fully uploaded transfer retryable, and a row deleted
 * ahead of the call leaves nothing to retry against.
 *
 * For a SINGLE-SEGMENT transfer it is not harmless, because `PutObject` writes the
 * FINAL object key directly. A part 1 re-sent between this handler's size read and
 * its insert would leave a committed `ciphertextBytes` that no longer describes the
 * object — and the response schema's size identity then refuses that row on EVERY
 * read, so the document lists, counts against the quota and never opens. There the
 * claim is a conditional, atomic delete: it detects a ledger that moved and, once the
 * row is gone, stops a new part starting at all, because the part handler looks the
 * row up first. The residual window is a part upload already past its own row lookup
 * and inside its storage write; closing that too would mean fencing the part route,
 * which would abort a long transfer for something completion recovers from.
 */
export const completeUpload = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const body = req.body as CompleteDocumentUploadInput;

  // The cheap refusal, before a lock is taken or an engine is called. It is not
  // the guard that matters — see the late pair inside — but a rotation the caller
  // can already see running deserves an answer that costs nothing.
  await assertVaultNotRotating(userId);

  const lockName = documentCompleteLockName(userId, id);
  const lockId = await acquireJobLock(lockName, COMPLETE_LOCK_TTL_MS);
  if (lockId === null) {
    // Another completion of this upload holds the lock. It may already have
    // committed the row and simply not released yet, in which case this request's
    // work is done and the honest answer is that document — not a conflict.
    const committed = await Document.findOne({ _id: id, userId });
    if (committed !== null) {
      sendDocument(res, committed);
      return;
    }
    throw httpErrors.conflict(
      'This upload is already being completed. Please wait a moment and retry.',
    );
  }

  // The lock is released BEFORE the response is written, on EVERY path including a
  // refusal — the same ordering `toolsController.importVault` takes, and for the
  // same reason. A client that retried the moment its 400 landed would otherwise
  // race the release round trip and be told its own finished attempt was "already
  // being completed", which is a conflict it can do nothing about. Hence the
  // outcome is computed under the lock and rendered after it.
  let outcome: CompletionOutcome;
  try {
    outcome = await completeUnderLock(req, userId, id, body);
  } finally {
    await releaseJobLock(lockName, lockId);
  }

  if (outcome.kind === 'staleVaultKey') {
    // Answered directly rather than through `httpErrors`, because the client needs
    // the NUMBER and a flat error body has nowhere to put one. The single precedent
    // in this codebase (`authController`'s unverified-email 401) exists for the same
    // reason. Nothing was released: this is the recoverable refusal, and the whole
    // design of sending the wrapped key twice is so that the retry costs one request
    // instead of the entire file.
    res.status(409).json({
      success: false,
      message:
        `The vault key was rotated during this upload. Rewrap the document key under vault ` +
        `key version ${String(outcome.vaultKeyVersion)} and retry the completion.`,
      data: { vaultKeyVersion: outcome.vaultKeyVersion },
    });
    return;
  }

  sendDocument(res, outcome.document);
});

/**
 * Everything `completeUpload` does while it holds the per-upload lock.
 *
 * Split out so the lock can be released before the response is written rather than
 * after it. It therefore RETURNS its outcome instead of sending one: a refusal
 * still throws, because an `httpErrors` throw carries its own status and the
 * `finally` around the call releases the lock on the way past.
 */
async function completeUnderLock(
  req: Request,
  userId: string,
  id: string,
  body: CompleteDocumentUploadInput,
): Promise<CompletionOutcome> {
  // Checked INSIDE the lock as well as on the contention path above, and the two
  // are not the same check. Without this one a completed upload can answer 404: a
  // second request that found no row, then waited for the lock while the first
  // inserted the document and deleted the staging row, arrives here with nothing
  // left to find.
  const committed = await Document.findOne({ _id: id, userId });
  if (committed !== null) {
    return { kind: 'document', document: committed };
  }

  const upload = await DocumentUpload.findOne({ _id: id, userId }).lean();
  // A foreign id and an id that never existed are the same answer, so neither
  // enumerates another account's transfers.
  if (!upload) {
    throw httpErrors.notFound('Upload not found');
  }
  // An expired row is refused with the same 404 the TTL index will shortly make
  // literal, exactly as `uploadPart` refuses one: the transfer's last part could
  // not have been accepted either, and the quota it reserved has lapsed.
  if (upload.expiresAt.getTime() <= Date.now()) {
    throw httpErrors.notFound('Upload not found');
  }

  if (upload.parts.length === 0) {
    // Asked before the engine is, because the engine's answer for a transfer that
    // stored nothing is a 404 about a missing object, which reads as though the
    // upload itself had gone.
    throw httpErrors.badRequest('No parts have been received for this transfer.');
  }

  const engine = await readEngineLedger(upload, { userId, uploadId: id });
  assertLedgerAgreesWithEngine(upload.parts, engine.parts);
  if (engine.parts.length !== upload.declaredChunkCount) {
    throw httpErrors.badRequest(
      `This transfer declared ${String(upload.declaredChunkCount)} part(s) and ` +
        `${String(engine.parts.length)} arrived.`,
    );
  }

  const { chunkCount, ciphertextBytes, plaintextBytes } = deriveFraming(engine.parts);

  // Each of the three is derived independently, and that is NOT enough to make them
  // agree. A transfer of n >= 2 parts whose last part is exactly one authentication
  // tag — a sealed EMPTY final segment, which the part handler permits because only
  // a NON-final part must be a full chunk, and which the storage engine permits
  // because the last part may be short — yields a `plaintextBytes` of (n-1) whole
  // chunks against a `chunkCount` of n. Nothing downstream survives that:
  // `documentResponseSchema` refuses such a row on every read, so the document
  // would list, count against the quota, and never open. The client is supposed
  // never to send it; this is where the server stops believing that.
  if (
    plaintextBytes < 0 ||
    chunkCount !== documentChunkCountFor(plaintextBytes, upload.chunkPlaintextBytes)
  ) {
    throw httpErrors.badRequest(
      `The parts received cannot frame a document: ${DOCUMENT_FRAMING_MISMATCH_MESSAGE}.`,
    );
  }

  // Every part re-measured against the framing just derived, through the SAME
  // helper the download path computes its byte ranges with — so a part the download
  // would read from the wrong offset cannot be committed. The rule it enforces is
  // the one the storage engine does not: a non-final part must be a full ciphertext
  // chunk. The part handler already refused a short middle part on the way in; this
  // refuses one that reached the engine by any other route, and it is what keeps
  // `segmentRange` and this handler from ever disagreeing about where segment `i`
  // begins.
  //
  // `expectedPartSize` throws a `RangeError` for numbers that cannot describe an
  // object at all, and it cannot fire here: the two conditions it guards
  // (a `plaintextBytes` at or above zero, and a `chunkCount` consistent with it)
  // are exactly what the refusal above has just established.
  for (const part of engine.parts) {
    const required = expectedPartSize(
      part.partNumber,
      chunkCount,
      upload.chunkPlaintextBytes,
      ciphertextBytes,
    );
    if (part.bytes !== required) {
      throw httpErrors.badRequest(
        `Part ${String(part.partNumber)} is ${String(part.bytes)} byte(s) and must be ` +
          `${String(required)} to sit at the segment boundary the document is framed on.`,
      );
    }
  }

  // The quota, measured on the bytes that actually arrived rather than on the size
  // the transfer reserved at init — the two differ whenever a client sends a fuller
  // final segment than it declared. Other transfers still in flight are deliberately
  // NOT counted: their reservations exist to stop init from over-committing, and init
  // has already checked this transfer against them, so charging them again here would
  // refuse the last of three legitimate uploads.
  const committedBytes = await committedBytesFor(userId);
  if (committedBytes + plaintextBytes > storageQuotaBytes()) {
    // The ONE refusal here that releases the transfer instead of leaving it
    // retryable. See `releaseTransfer`: the bytes in the bucket are precisely the
    // bytes this account cannot hold.
    await releaseTransfer(upload, engine);
    throw httpErrors.badRequest(
      `Storage quota exceeded. Your limit is ${String(config.DOCUMENT_STORAGE_QUOTA_MB_PER_USER)} MB.`,
    );
  }

  // The late pair, as close to the insert as the work allows. Everything above this
  // point is arithmetic over bytes that are already stored; everything below commits
  // a key. The fence catches a rotation that is IN PROGRESS — its flag is raised
  // before it enumerates, so a row inserted now is one the new key will not cover —
  // and the version catches one that has already committed, which the fence cannot
  // see because the flag is cleared by then.
  await assertVaultNotRotating(userId);
  const user = await User.findById(userId).select('vaultKeyVersion').lean();
  const currentVaultKeyVersion = user?.vaultKeyVersion ?? 0;
  if (body.vaultKeyVersion !== currentVaultKeyVersion) {
    return { kind: 'staleVaultKey', vaultKeyVersion: currentVaultKeyVersion };
  }

  // Re-checked because the init-to-completion window is as long as the transfer. A
  // folder deleted in the meantime would leave the document filed under an id that
  // appears in no listing, which is worse than unfiled; stripping it mirrors what an
  // import does with a folder it cannot own, and refusing the completion instead
  // would destroy a finished upload over a folder.
  //
  // It runs HERE, before anything is finalised, because it is a pure read: below the
  // claim it would sit in the one span where a datastore fault leaves a stored object
  // with no row and no compensation.
  const folderId =
    upload.folderId !== undefined && (await Folder.exists({ _id: upload.folderId, userId }))
      ? upload.folderId
      : undefined;

  if (engine.mode === 'multipart') {
    // BEFORE the staging row is claimed, and that ordering is the difference between
    // a retry and a re-upload. If this call fails — a timeout, or a 5xx the SDK's own
    // attempts could not ride out — the transfer must still be completable: every part
    // is present and correct, and asking for eight hundred megabytes again because one
    // metadata call did not answer is not a recovery. With the row already deleted
    // there is nothing left to retry against, and the engine holds an upload nothing
    // in the database names.
    //
    // Nothing is at risk in the other direction, which is why the single-segment
    // ordering below does not apply here: the object is assembled from exactly the
    // parts listed above and named back by their etags, so it cannot disagree with the
    // framing already derived. A part re-sent in the meantime either carries a new
    // number this call does not name, or replaces one it does and the engine refuses
    // the whole completion.
    await getStorage().completeMultipartUpload(
      upload.objectKey,
      engine.s3UploadId,
      // From the ENGINE's ledger, never from the staging row: these etags are the
      // engine's own receipts and the staging copy is a record of them, not a
      // source.
      engine.parts.map((part) => ({ partNumber: part.partNumber, etag: part.etag })),
    );
  }

  // Claim the transfer, atomically, and the two modes claim it differently because
  // only one of them can still be undermined.
  //
  // A SINGLE-SEGMENT transfer is stored with `PutObject`, straight to the FINAL
  // object key, and the part route takes neither this lock nor the rotation fence. So
  // a part re-sent while this completion was doing its arithmetic would leave a
  // committed `ciphertextBytes` that no longer describes the object, and the response
  // schema's size identity then refuses that row on EVERY read: the document lists,
  // counts against the quota and never opens. Conditioning the delete on
  // `receivedBytes` — which the part handler recomputes as the sum of the ledger —
  // makes this a CHECK as well as a claim, and once the row is gone no new part can
  // start, because the part handler looks the row up first.
  //
  // A MULTIPART transfer has no such exposure: its object was assembled a few lines
  // above from the parts this completion named. Conditioning the claim there would
  // only invent a way to strand a finished object behind a 409 that no retry could
  // clear, since the engine has already invalidated the upload id.
  if (engine.mode === 'object') {
    const claimed = await DocumentUpload.findOneAndDelete({
      _id: id,
      userId,
      receivedBytes: ciphertextBytes,
    }).lean();
    if (!claimed) {
      throw httpErrors.conflict(
        'This transfer changed while it was being completed. Please retry the completion.',
      );
    }
  } else {
    await DocumentUpload.deleteOne({ _id: id, userId });
  }

  let document: HydratedDocument<IDocument>;
  try {
    document = await Document.create({
      // The staging row's id, because it is the id the browser bound its key
      // derivation to before it sealed the first byte.
      _id: upload._id,
      userId,
      ...(folderId === undefined ? {} : { folderId }),
      objectKey: upload.objectKey,
      // FROM THE COMPLETION BODY, not from the staging row. See the handler's note.
      encryptedDek: body.encryptedDek,
      dekIv: body.dekIv,
      dekTag: body.dekTag,
      // From the staging row: the framing parameters were chosen at init and are
      // baked into every segment already stored.
      streamSalt: upload.streamSalt,
      noncePrefix: upload.noncePrefix,
      encryptedMeta: body.encryptedMeta,
      metaIv: body.metaIv,
      metaTag: body.metaTag,
      chunkPlaintextBytes: upload.chunkPlaintextBytes,
      chunkCount,
      ciphertextBytes,
      plaintextBytes,
    });
  } catch (error) {
    // A repeat completion that got past both existence checks lands here on the
    // unique `_id`, and it is a success: the row the other attempt committed is the
    // answer.
    const duplicate =
      typeof error === 'object' && error !== null && 'code' in error && error.code === 11000;
    if (duplicate) {
      const existing = await Document.findOne({ _id: id, userId });
      if (existing !== null) {
        return { kind: 'document', document: existing };
      }
    }

    // Anything else and the object is now stored with no row naming it. Delete it
    // here rather than leaving the collector to find it an hour later: until it
    // does, the user is charged bucket space for a document that does not exist and
    // cannot be seen, let alone removed.
    try {
      await getStorage().deleteObject(upload.objectKey);
    } catch (deleteError) {
      logger.error('Failed to delete the object of a document row that was not written', {
        userId,
        uploadId: id,
        error: deleteError instanceof Error ? deleteError.message : String(deleteError),
      });
    }
    throw error;
  }

  const completeCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'document_create',
    { documentId: String(document._id), chunkCount, plaintextBytes },
    completeCtx.ip,
    completeCtx.userAgent,
  );

  logger.info('Document upload completed', { userId, uploadId: id, chunkCount, plaintextBytes });

  return { kind: 'document', document };
}

// ── Reads ────────────────────────────────────────────────────────────
//
// Four JSON reads and one byte stream. Every one of them scopes its query by
// `{ userId }` rather than by `_id` alone, so a foreign id and an id that never
// existed produce the same 404 and neither enumerates another account.
//
// None of them is rate-limited beyond `generalAuthLimiter`, except the segment
// stream, which carries `documentReadLimiter`: one download is one request per
// segment, so it is the only read whose volume scales with the operator's own
// size cap.

/**
 * `GET /documents` — the caller's active documents, paginated.
 *
 * The sort key is NOT re-checked against a second allowlist here, unlike
 * `vaultController.listItems`. `listDocumentsSchema` declares it as a
 * `z.enum([...])` and `validate(schema, 'query')` REPLACES `req.query` with the
 * parsed result, so the enum is the allowlist; a mirrored array beside it would
 * be a second copy of the same rule and a branch that can never be taken.
 *
 * `_id` is appended to the sort as a TIEBREAK, and that is a correctness fix
 * rather than tidiness. Pagination here is `skip`/`limit`, so the order has to be
 * TOTAL: two documents sharing an `updatedAt` (or, on `favorite`, the thousands
 * that share a boolean) may otherwise come back in a different order on each
 * request, and a row that moves across the page boundary between two requests is
 * one the client either sees twice or never sees at all.
 */
export const listDocuments = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { page, limit, folderId, favorite, sortBy, sortOrder } =
    req.query as unknown as ListDocumentsInput;

  // `deletedAt: null` matches a row whose field is ABSENT as well as one holding
  // an explicit null, which is what makes it the right predicate for a column
  // that defaults to `undefined` — and it is the same predicate
  // `vaultController.listItems` uses, so the two lists cannot come to mean
  // different things by "active".
  const filter: Record<string, unknown> = { userId, deletedAt: null };
  if (folderId !== undefined) filter.folderId = folderId;
  if (favorite !== undefined) filter.favorite = favorite;

  const sortDirection = sortOrder === 'asc' ? 1 : -1;

  const [documents, total] = await Promise.all([
    Document.find(filter)
      .select(DOCUMENT_PROJECTION)
      .sort({ [sortBy]: sortDirection, _id: sortDirection })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Document.countDocuments(filter),
  ]);

  res.status(200).json({
    success: true,
    data: documents,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
});

/**
 * `GET /documents/trash` — the caller's trashed documents.
 *
 * A separate route rather than a `?trash=true` flag on the list above, exactly as
 * trashed vault items have their own route: the two views have different sort
 * keys (`deletedAt` is meaningless on an active row) and different actions.
 *
 * A trashed document still occupies its object in the bucket, so it still counts
 * against `GET /documents/usage`. That is deliberate and the UI says so; a user
 * who deleted a file and saw no space returned would otherwise assume the
 * deletion failed.
 */
export const listDocumentTrash = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { page, limit, sortBy, sortOrder } = req.query as unknown as ListDocumentTrashInput;

  const filter = { userId, deletedAt: { $exists: true, $ne: null } };
  const sortDirection = sortOrder === 'asc' ? 1 : -1;

  const [documents, total] = await Promise.all([
    Document.find(filter)
      .select(DOCUMENT_PROJECTION)
      .sort({ [sortBy]: sortDirection, _id: sortDirection })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean(),
    Document.countDocuments(filter),
  ]);

  res.status(200).json({
    success: true,
    data: documents,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  });
});

/**
 * `GET /documents/usage` — what this account has stored and what it may store.
 *
 * The two limits are reported alongside the two measurements deliberately: the
 * operator can change either at any restart, so a client that cached them from
 * `GET /config` at sign-in would draw a quota bar against a number that has since
 * moved.
 *
 * `documentCount` counts TRASHED rows and `usedBytes` counts their bytes, because
 * both caps are enforced that way: `initUpload` measures the document count with
 * the same unfiltered query and the quota through the same `committedBytesFor`.
 * A usage endpoint that reported a smaller number than the endpoint that refuses
 * an upload would be an explanation for a refusal that the user cannot see.
 */
export const getUsage = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const [documentCount, usedBytes] = await Promise.all([
    Document.countDocuments({ userId }),
    committedBytesFor(userId),
  ]);

  res.status(200).json({
    success: true,
    data: {
      documentCount,
      usedBytes,
      quotaBytes: storageQuotaBytes(),
      maxDocumentSizeBytes: maxDocumentBytes(),
    },
  });
});

/**
 * `GET /documents/:id` — one document's row.
 *
 * Trashed rows are returned rather than hidden, which is what lets the trash view
 * open a document before restoring or purging it; `deletedAt` is on the row, so a
 * caller can always tell. `vaultController.getItem` behaves the same way.
 *
 * This is the response the client checks against `documentResponseSchema` before
 * it decrypts anything, and then against the AUTHENTICATED copy of the framing
 * inside the metadata blob. The second comparison is the mandatory one and it
 * belongs to the code that holds the DEK; this endpoint's job is only to hand
 * back the row it was asked for, which is why the client also asserts the
 * returned `_id` is the one it requested.
 */
export const getDocument = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const document = await Document.findOne({ _id: id, userId }).select(DOCUMENT_PROJECTION).lean();
  if (!document) {
    throw httpErrors.notFound('Document not found');
  }

  res.status(200).json({ success: true, data: document });
});

/**
 * `GET /documents/:id/segments/:index` — one sealed segment, streamed.
 *
 * ## The range is computed, never accepted
 *
 * There is no `Range` header on this route and there must never be one. The byte
 * window comes from `segmentRange`, out of the columns on the ROW — the same
 * function the completion endpoint measures every part with, so a segment can
 * only ever be read from the offset it was written to. A client-supplied range
 * would let a caller ask for a window that straddles two segments; those bytes
 * decrypt to nothing (the tag check fails), so the damage would be a confusing
 * corruption report rather than a disclosure, but the cure is the same and it is
 * free: the server already knows exactly which bytes segment `i` is.
 *
 * `chunkPlaintextBytes` and `ciphertextBytes` are read from the row rather than
 * from `DOCUMENT_PLAINTEXT_CHUNK_BYTES`, so changing that constant cannot
 * re-frame a document that already exists.
 *
 * ## Why the bytes are streamed rather than buffered
 *
 * A segment is up to 8 MiB. Buffering one per in-flight download would make this
 * process's memory a multiple of that times the number of concurrent readers, in
 * a container running under a fixed limit; piping bounds it by the socket
 * instead.
 *
 * ## The headers, and why each is there
 *
 *   * `Content-Type: application/octet-stream` — these are opaque sealed bytes.
 *     Anything else invites a browser to sniff them.
 *   * `Cache-Control: no-store` — a segment is user ciphertext, and it must not
 *     survive in a disk cache, a shared-computer profile or an intermediary. The
 *     service worker already pins `/api/` to `NetworkOnly`; this is the half that
 *     does not depend on the service worker being installed.
 *   * `Content-Length` — the EXACT segment length, taken from the framing rather
 *     than from whatever the engine chose to report, so a short read is a
 *     truncated response the client cannot mistake for a whole segment.
 *
 * ## A missing object is a 404
 *
 * There is deliberately no `objectMissing` column on the row: an object that has
 * gone is discovered here, and the provider's `NoSuchKey` becomes a 404 carrying
 * a message about the DOCUMENT rather than about a storage key, because that is
 * what the UI renders. A 404 is not redacted by the error middleware (only 5xx
 * is, and only in production), so the message really does reach the client.
 */
export const getSegment = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id, index } = req.params as unknown as DocumentSegmentParams;

  const document = await Document.findOne({ _id: id, userId })
    // `objectKey` is deliberately excluded from every other read on this route
    // file; it is selected here because this is the one handler that addresses
    // the object, and it never leaves the process.
    .select('objectKey chunkCount chunkPlaintextBytes ciphertextBytes')
    .lean();
  if (!document) {
    throw httpErrors.notFound('Document not found');
  }

  // The row is what bounds the index, and the check has to happen AFTER the
  // lookup for that reason. The param schema has already refused a negative, a
  // non-decimal and anything past the global chunk ceiling; this is the bound
  // that belongs to THIS document.
  if (index >= document.chunkCount) {
    throw httpErrors.badRequest(
      `This document has ${String(document.chunkCount)} segment(s); segment ${String(index)} is outside it.`,
    );
  }

  // Throws a `RangeError` for a row whose framing columns cannot describe an
  // object of the recorded length. That cannot happen for a row this application
  // committed — the completion endpoint establishes exactly those identities, and
  // the model's own minimums back them — so it is deliberately not caught: a row
  // written by a migration or a repair script that broke them should surface as a
  // server error rather than as a range that reads the wrong bytes.
  const range = segmentRange(
    index,
    document.chunkCount,
    document.chunkPlaintextBytes,
    document.ciphertextBytes,
  );

  let read: StorageRangeRead;
  try {
    read = await getStorage().getObjectRange(document.objectKey, range.start, range.end);
  } catch (error) {
    // The provider maps `NoSuchKey` and `NotFound` to a 404 and everything else
    // to 503 or 500, so this narrows to exactly the missing-object case and
    // re-words it. The original is kept on `cause` for the structured log.
    if (error instanceof ErrorHandler && error.statusCode === 404) {
      throw httpErrors.notFound(
        'The stored contents of this document are missing. It cannot be downloaded.',
        { cause: error },
      );
    }
    throw error;
  }

  if (read.bytes !== range.length) {
    // Refused BEFORE a byte is written, so the client never sees a partial
    // segment with a `Content-Length` that promised a whole one. Destroying the
    // body matters: an unread stream holds the engine's connection open.
    read.body.destroy();
    logger.error('The storage engine returned a segment of the wrong length', {
      userId,
      documentId: id,
      index,
      expected: range.length,
      received: read.bytes,
    });
    throw httpErrors.internalServerError('The stored document does not match its recorded size');
  }

  res.status(200);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Length', String(range.length));

  try {
    await pipeline(read.body, res);
  } catch (error) {
    // `pipeline` destroys both streams on failure, so by the time this runs the
    // client's connection has already been reset and there is no response left to
    // write: re-throwing would only ask the error middleware to serialise JSON
    // onto a socket that is gone. A reset is also the RIGHT outcome — the
    // declared `Content-Length` means a truncated body cannot be mistaken for a
    // whole segment, and the segment's authentication tag would refuse it even if
    // it were.
    logger.error('A document segment stream failed part-way through', {
      userId,
      documentId: id,
      index,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
