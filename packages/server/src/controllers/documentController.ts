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
  UpdateDocumentInput,
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
  assertFolderOwned,
  assertVaultNotRotating,
  buildFolderAwareUpdate,
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
 *   * `__v` is Mongoose's own bookkeeping and describes nothing a client can use.
 *     It is named for the same reason `DOCUMENT_PROJECTION` names it: `z.object()`
 *     strips an unknown key, so leaving it in would not break a client — it would
 *     simply put an internal column on the wire on two routes and not on the rest,
 *     which is the kind of difference that becomes an assertion somewhere later;
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
const UPLOAD_PROJECTION =
  '-__v -userId -objectKey -s3UploadId -encryptedDek -dekIv -dekTag -parts.etag';

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
 * Whether a storage failure is the engine saying "the thing you named is not
 * there", as opposed to saying nothing at all.
 *
 * `s3Provider.mapStorageError` is the single place that decision is made — it maps
 * `NoSuchKey`, `NotFound` and `NoSuchUpload` to a 404 and an unreachable engine to
 * a 503 — so this reads the status it produced rather than re-classifying an SDK
 * error shape a second time. `ErrorHandler` is checked before the status because a
 * bare object carrying a `statusCode` is not an error this codebase threw.
 */
function isStorageNotFound(error: unknown): boolean {
  return error instanceof ErrorHandler && error.statusCode === 404;
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
 * be missing. The `object` shape has no receipts BECAUSE there is nothing left to
 * complete, and TWO transfers reach it: a single-segment one, whose `PutObject`
 * wrote the whole object at once, and a multipart one whose
 * `CompleteMultipartUpload` already succeeded — see `readAssembledLedger`. Both
 * are finished objects, so both are claimed and released the same way.
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
  upload: Pick<IDocumentUpload, 'objectKey' | 's3UploadId' | 'declaredChunkCount' | 'parts'>,
  context: { userId: string; uploadId: string },
): Promise<EngineLedger> {
  if (upload.declaredChunkCount === 1) {
    const stat = await getStorage().headObject(upload.objectKey);
    return { mode: 'object', parts: [{ partNumber: 1, bytes: stat.bytes }] };
  }

  const s3UploadId = upload.s3UploadId;
  if (s3UploadId === undefined) {
    logger.error('A multi-segment staging row names no engine-side upload', {
      ...context,
      declaredChunkCount: upload.declaredChunkCount,
    });
    throw httpErrors.internalServerError('This transfer is no longer in a usable state');
  }

  try {
    return {
      mode: 'multipart',
      s3UploadId,
      parts: await getStorage().listParts(upload.objectKey, s3UploadId),
    };
  } catch (error) {
    // An upload id the engine does not know is the ONE failure that may still be a
    // finished transfer rather than a broken one. Everything else is passed on.
    if (!isStorageNotFound(error)) throw error;
    return readAssembledLedger(upload, context, error);
  }
}

/**
 * The engine's account of a multipart transfer whose upload id it no longer knows.
 *
 * WHY THIS EXISTS. `completeUnderLock` calls `CompleteMultipartUpload` and THEN
 * deletes the staging row, in that order and deliberately: a transient engine
 * failure must leave a fully uploaded transfer retryable, which a row deleted
 * first would not. The cost of that ordering is a window — a crash, or a Mongo
 * failure, between the two — in which the object is correctly assembled and the
 * staging row still exists. The engine invalidates the upload id on success, so a
 * retry's `ListParts` answers `NoSuchUpload`, and without this the user is told
 * their finished transfer is gone and asked to send the whole file again, while
 * the assembled object becomes an orphan for the collector.
 *
 * WHY IT IS SAFE TO BELIEVE. The check is `HeadObject`'s length against the sum of
 * the ledger's parts, and it is not a coincidence match:
 *
 *   * the object key is derived from a freshly minted, per-transfer upload id, so
 *     no other transfer can have written it, and a COMMITTED document at that id
 *     was already answered by the `Document.findOne` two checks earlier;
 *   * the ledger cannot have moved since the completion call. `uploadPart` reaches
 *     the engine BEFORE it writes its ledger entry, so once the upload id is
 *     invalid no further part can be recorded — which is also what makes the
 *     conditional claim on `receivedBytes` below still hold;
 *   * an object of the right total length whose parts were the wrong sizes is
 *     still refused, because the per-part `expectedPartSize` loop runs on this
 *     path exactly as it does on every other.
 *
 * A mismatch, or no object at all, re-throws the ORIGINAL 404: the transfer really
 * is unfinishable, and the honest answer is the one the engine gave.
 *
 * The ledger is SORTED before it is returned. `assertLedgerAgreesWithEngine`
 * documents that it may assume its `engine` argument is in ascending part-number
 * order — true of `ListParts`, and NOT true of `upload.parts`, which the
 * `$concatArrays` ledger update appends to, so a client that sent part 2 before
 * part 1 stores them in that order. Handing it unsorted would fail a valid
 * recovery with a "missing part" it does not have.
 */
async function readAssembledLedger(
  upload: Pick<IDocumentUpload, 'objectKey' | 'parts'>,
  context: { userId: string; uploadId: string },
  cause: unknown,
): Promise<EngineLedger> {
  const ledgerBytes = upload.parts.reduce((total, part) => total + part.bytes, 0);

  let stat;
  try {
    stat = await getStorage().headObject(upload.objectKey);
  } catch (error) {
    if (isStorageNotFound(error)) throw cause;
    throw error;
  }

  if (stat.bytes !== ledgerBytes) {
    logger.error('A transfer with no engine-side upload has an object of the wrong length', {
      ...context,
      objectBytes: stat.bytes,
      ledgerBytes,
    });
    throw cause;
  }

  logger.warn('Completing a transfer the storage engine had already assembled', {
    ...context,
    ledgerBytes,
  });

  return {
    mode: 'object',
    parts: [...upload.parts]
      .sort((left, right) => left.partNumber - right.partNumber)
      .map((part) => ({ partNumber: part.partNumber, bytes: part.bytes })),
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
 * One page of documents and the pagination envelope that describes it, for the
 * two list endpoints.
 *
 * Shared because the two lists differ in exactly two things and both are
 * arguments: the predicate that decides whose rows they are, and the column they
 * sort by. Everything else — the projection, the skip/limit arithmetic, the
 * `_id` tiebreak, the `totalPages` calculation and the envelope's shape — is one
 * decision, and a second copy of it is a second place for a page size or a sort
 * order to drift.
 *
 * `sortBy` is NOT re-checked against an allowlist here. Each route declares it as
 * a `z.enum([...])` and `validate(schema, 'query')` REPLACES `req.query` with the
 * parsed result, so the enum IS the allowlist and the two enums differ (`deletedAt`
 * is meaningless on an active row, `favorite` on a trashed one) — a mirrored array
 * here would have to be their union, which is wider than either route allows.
 *
 * The `_id` tiebreak is a correctness fix rather than tidiness. Pagination is
 * `skip`/`limit`, so the order has to be TOTAL: two documents sharing an
 * `updatedAt` — or, on `favorite`, the thousands sharing a boolean — may otherwise
 * come back in a different order on each request, and a row that moves across the
 * page boundary between two requests is one the client either sees twice or never
 * sees at all.
 */
async function sendDocumentPage(
  res: Response,
  filter: Record<string, unknown>,
  query: { page: number; limit: number; sortBy: string; sortOrder: string },
): Promise<void> {
  const { page, limit, sortBy, sortOrder } = query;
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
}

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
 * The limit is TWICE the concurrency cap, and the doubling is the whole reason
 * this list can do its job. Init refuses a fourth LIVE transfer, so the cap bounds
 * the live rows — but this page deliberately includes EXPIRED ones, and MongoDB's
 * TTL monitor sweeps on its own schedule (a minute's granularity, longer under
 * load). A cap of exactly `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` therefore
 * truncates the newest-first page at the wrong end: with three live transfers and
 * one expired row still awaiting the sweep, the row dropped off the page is the
 * OLDEST — which is precisely the expired one the user came here to cancel, the one
 * holding an engine-side upload nobody can point at. At most one generation of
 * rows can be awaiting the sweep at a time, so twice the cap is the real ceiling
 * and this limit is a safety valve rather than pagination.
 */
export const listUploads = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const uploads = await DocumentUpload.find({ userId })
    .select(UPLOAD_PROJECTION)
    .sort({ createdAt: -1 })
    .limit(MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER * 2)
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
 *
 * An engine that answers 404 has ALREADY done what this request asked, and the row
 * is deleted anyway. S3's abort is idempotent by contract, and the alternative is
 * strictly worse: an upload the engine has forgotten — expired by a bucket
 * lifecycle rule, or aborted by a previous attempt of this very request whose
 * response was lost — could then never be cancelled at all, and its row would hold
 * a concurrency slot and a quota reservation until the staging TTL fired, which is
 * up to `DOCUMENT_UPLOAD_TTL_HOURS` later. Every OTHER failure still propagates:
 * a 503 means the engine may still be holding parts, and deleting the row that
 * names them would strand them until the collector's sweep.
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
    try {
      await getStorage().abortMultipartUpload(upload.objectKey, upload.s3UploadId);
    } catch (error) {
      if (!isStorageNotFound(error)) throw error;
      logger.info('Cancelled a transfer the storage engine had already forgotten', {
        userId,
        uploadId: id,
      });
    }
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
 * Neither size cap is re-checked here, and the honest reason is a BOUND rather
 * than an equality. A part number is bounded by `declaredChunkCount`, each part by
 * one segment, and a re-sent part replaces its ledger entry rather than adding one,
 * so the received total cannot exceed `declaredChunkCount` whole chunks. That is
 * not the same as the size init reserved: a transfer declaring one plaintext byte
 * gets a `declaredChunkCount` of 1 and may then legally send a full 8 MiB final
 * part. The overshoot is at most one chunk per transfer, times
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER`, and completion re-checks BOTH the
 * per-document cap and the quota against the bytes actually received before
 * anything is committed — so the transient over-reservation is bounded and never
 * becomes a stored document. Re-checking here instead would mean refusing a part
 * mid-transfer for a total the client can still bring back under the cap by
 * finishing, and would not remove the need for the check at completion anyway.
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

  // The PER-DOCUMENT cap, re-measured on the bytes that actually arrived. Init
  // checked `declaredPlaintextBytes`, and a client is not held to that number: only
  // a NON-final part must be a full chunk, so a transfer that declared one byte gets
  // a `declaredChunkCount` of 1 and may then legally send a final part of a whole
  // 8 MiB chunk. That slack is one chunk in absolute terms and therefore harmless
  // against a large cap and an eight-fold breach against a small one — at
  // `MAX_DOCUMENT_SIZE_MB=1` the row committed would be eight times the limit
  // `GET /documents/usage` advertises to the very client that just wrote it.
  //
  // Refused the same way the quota is refused below, and for the same reason: the
  // bytes in the bucket are precisely the bytes this deployment will not store, so
  // a retry of the same transfer can only ever be refused again.
  if (plaintextBytes > maxDocumentBytes()) {
    await releaseTransfer(upload, engine);
    throw httpErrors.badRequest(
      `Document is too large. The maximum size is ${String(config.MAX_DOCUMENT_SIZE_MB)} MB.`,
    );
  }

  // The quota, measured on the bytes that actually arrived rather than on the size
  // the transfer reserved at init — the two differ whenever a client sends a fuller
  // final segment than it declared. Other transfers still in flight are deliberately
  // NOT counted: their reservations exist to stop init from over-committing, and init
  // has already checked this transfer against them, so charging them again here would
  // refuse the last of three legitimate uploads.
  const committedBytes = await committedBytesFor(userId);
  if (committedBytes + plaintextBytes > storageQuotaBytes()) {
    // The OTHER refusal here that releases the transfer instead of leaving it
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
 * The three filter columns are the only thing this adds to `sendDocumentPage`,
 * which owns the sort key, the tiebreak and the envelope for both lists.
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

  await sendDocumentPage(res, filter, { page, limit, sortBy, sortOrder });
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

  await sendDocumentPage(res, filter, { page, limit, sortBy, sortOrder });
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

// ── Mutations ────────────────────────────────────────────────────────
//
// One metadata write and four lifecycle transitions. Every one of them scopes
// its query by `{ userId }`, exactly as the reads above do, so a foreign id and
// an id that never existed are indistinguishable.
//
// CONTENT IS IMMUTABLE AFTER UPLOAD, and that is the rule the whole section is
// arranged around. A segment is never rewritten, which is what guarantees a nonce
// is never reused under a stream key: `iv(i, isLast)` is
// `noncePrefix || u32be(i) || lastFlag`, so rewriting segment `i` of a document
// would seal different plaintext under a key and nonce that had already been
// used, which hands an attacker holding both ciphertexts the XOR of the two
// plaintexts. Replacing a document's bytes therefore means a NEW document, and
// nothing below can reach a framing field, the wrapped key or the object key.
//
// NONE OF THESE FIVE IS ROTATION-FENCED. The reasoning is per handler and is
// written out at `updateDocument`, which is the only one that writes ciphertext
// at all.

/**
 * The fields `PUT /documents/:id` may write, and the ONLY ones.
 *
 * The wire schema (`updateDocumentSchema`) already strips everything else, so
 * this is the second of two independent filters rather than the only one — the
 * same belt-and-braces `ALLOWED_INIT_FIELDS` gives the staging row, and the same
 * one `vaultController`'s `ALLOWED_UPDATE_FIELDS` gives a vault item.
 *
 * **It cannot be exercised through the HTTP route, and that is expected rather
 * than a gap.** `validate()` runs first and `z.object()` strips by default, so by
 * the time the handler reads `req.body` there is nothing left for this to remove:
 * measured, replacing the call below with a plain spread of the body leaves the
 * cross-user and smuggling cases green, and removing the wire schema INSTEAD
 * leaves them green too. Only removing both turns them red. So each half holds
 * alone, which is the whole claim of defense in depth, and the wire half is
 * pinned separately by `packages/shared/tests/document-schema.test.ts` ("cannot
 * reach a framing field, the DEK or the object key"). What this half is for is a
 * future handler that reads a body `validate()` did not shape — a bulk endpoint,
 * a migration path, a route wired without its schema — and it is the cheapest
 * possible insurance against exactly the mistake nobody notices.
 *
 * What it keeps OUT is the entire point, and it is worth naming the three
 * classes:
 *
 *   * **The framing** — `streamSalt`, `noncePrefix`, `chunkPlaintextBytes`,
 *     `chunkCount`, `ciphertextBytes`, `plaintextBytes`. These describe how the
 *     stored object is cut into sealed segments. A client that could move one
 *     would re-frame a document that already exists: every later `Range` read
 *     would return the wrong window, every segment would fail its tag check, and
 *     the file would be unreadable with no error until the browser tried to open
 *     it. `plaintextBytes` additionally is what the quota is charged against.
 *   * **The wrapped key** — `encryptedDek`, `dekIv`, `dekTag`. The DEK is set at
 *     completion and rewrapped by exactly one other path, `bulkReEncrypt`, which
 *     holds the rotation lock while it does so. A second writer here would race
 *     that one and could store a key wrapped under a superseded vault key,
 *     which is a document nobody can ever open again.
 *   * **The object key** — server-assigned, unique, and the only value on the row
 *     that addresses storage. A client that could set it could point its own row
 *     at another user's object.
 *
 * `_id`, `userId`, `deletedAt`, `purgePending`, `createdAt` and `updatedAt` are
 * excluded for the ordinary reason: they are identity, ownership, lifecycle and
 * bookkeeping, and each has its own endpoint or its own writer.
 */
const ALLOWED_DOCUMENT_UPDATE_FIELDS = new Set([
  'encryptedMeta',
  'metaIv',
  'metaTag',
  'favorite',
  'folderId',
]);

/**
 * How many trashed rows `DELETE /documents/trash/empty` reads per page.
 *
 * The same 500 `jobs/trashCleanup.ts` uses, and for the same reason: it bounds
 * the memory one page of rows costs, not the work the request does. The work is
 * bounded by `MAX_DOCUMENTS_PER_USER`, because a user cannot have more rows in
 * the trash than they can have rows.
 */
const EMPTY_TRASH_PAGE_SIZE = 500;

/**
 * `PUT /documents/:id` — the sealed metadata blob, the favorite flag, the folder.
 *
 * ## Why this endpoint is deliberately NOT rotation-fenced
 *
 * Every other write in this codebase that creates ciphertext calls
 * `assertVaultNotRotating` first, and its absence here is a decision rather than
 * an omission. That fence exists for writes producing ciphertext under the
 * caller's VAULT key: a rotation rewrites every such value under a new key while
 * holding its lock, so a concurrent write of old-key ciphertext would survive the
 * rotation and be unreadable afterwards.
 *
 * The metadata blob is not such a value. It is sealed under `SK_meta`, an
 * HKDF-SHA256 subkey of the document's own DEK — the vault key is nowhere in its
 * derivation. A rotation rewraps the DEK (32 bytes per document) and never
 * touches the blob, so a metadata write landing in the middle of one is still
 * readable afterwards: it is sealed under a key the rotation did not change, and
 * the rewrapped DEK still unwraps to the same bytes. Rewriting the blob instead
 * of rewrapping the key is exactly what makes rotating a vault holding gigabytes
 * possible at all.
 *
 * Fencing anyway would not be free. `bulkReEncrypt` also runs a completeness
 * check over the account's document count, so a rotation can take a moment on a
 * large vault; refusing renames and favorites for its duration would buy nothing
 * and cost the user an unexplained 409.
 *
 * The three fields the fence WOULD protect are unreachable from here by
 * construction: `ALLOWED_DOCUMENT_UPDATE_FIELDS` cannot name the wrapped key.
 *
 * ## Why the server does not police IV reuse
 *
 * `SK_meta` is deterministic in (DEK, streamSalt, documentId) and therefore fixed
 * for a document's whole life, while the blob is deliberately mutable — so this
 * is the one place in the design where a nonce could repeat under a fixed key.
 * The guard lives in the browser, where `documentCryptoService.encryptMeta`
 * generates its own `metaIv` and accepts none, and it is asserted there and again
 * in the mutation suite.
 *
 * It is NOT enforced here, and the reason is worth writing down so it is not
 * "fixed" later: refusing a `metaIv` equal to the stored one would refuse an
 * IDEMPOTENT RETRY. A client whose first `PUT` timed out after the server
 * committed it retries the identical body, which carries the identical IV, and a
 * 400 there would turn a successful write into a permanent failure. The check
 * would also be worthless against the case it appears to cover, since a client
 * that reused a nonce could send any other value and still have reused it.
 */
export const updateDocument = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };
  const body = req.body as UpdateDocumentInput;

  // `null` means "clear it" and is handled below; only a real id is checked for
  // ownership, and an unowned one is a 404 rather than a 403 so a caller cannot
  // enumerate another account's folders. Shared with `vaultController.updateItem`.
  await assertFolderOwned(body.folderId, userId);

  const sanitizedUpdate = pickAllowedFields(body, ALLOWED_DOCUMENT_UPDATE_FIELDS);
  // Captured here, BEFORE the `folderId` handling below removes it from the
  // object: a clear-the-folder request must still be audited as having named
  // `folderId`. Taken from the sanitized copy rather than from `body`, so the
  // names that reach the audit collection are bounded by the allowlist even if a
  // future caller reaches this handler with a body `validate()` did not shape.
  const changedFields = Object.keys(sanitizedUpdate).sort();

  // An explicit `folderId: null` `$unset`s the field rather than storing a null.
  // `buildFolderAwareUpdate` owns that rule for `updateItem` and this handler
  // alike, and it MUTATES `sanitizedUpdate` — which is exactly why
  // `changedFields` above is read before this line and not after it.
  const updateOp = buildFolderAwareUpdate(sanitizedUpdate);

  // A body that named nothing this endpoint may write — `{}`, or one carrying
  // only fields the allowlist dropped — is answered with the row as it stands.
  //
  // A read rather than a write, deliberately. It keeps `PUT` idempotent for a
  // caller that has nothing to change, it writes no audit row for a request that
  // did nothing, and it does not depend on how the driver treats an update
  // document with no operators in it. A 400 was the alternative and buys nothing:
  // the caller receives exactly the state it asked the server to reach.
  if (Object.keys(updateOp).length === 0) {
    const current = await Document.findOne({ _id: id, userId }).select(DOCUMENT_PROJECTION).lean();
    if (!current) {
      throw httpErrors.notFound('Document not found');
    }
    res.status(200).json({ success: true, data: current });
    return;
  }

  const document = await Document.findOneAndUpdate({ _id: id, userId }, updateOp, {
    returnDocument: 'after',
    runValidators: true,
  })
    .select(DOCUMENT_PROJECTION)
    .lean();

  if (!document) {
    throw httpErrors.notFound('Document not found');
  }

  const updateCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'document_update',
    // The FIELD NAMES only. An audit row naming the ciphertext would put a copy
    // of the sealed blob in a second collection with a different retention, and
    // naming the plaintext is impossible because the server has never seen it.
    { documentId: id, fields: changedFields },
    updateCtx.ip,
    updateCtx.userAgent,
  );

  logger.info('Document updated', { userId, documentId: id });

  res.status(200).json({ success: true, data: document });
});

/**
 * `DELETE /documents/:id` — move a document to the trash.
 *
 * A soft delete: `deletedAt` is stamped and NOTHING ELSE HAPPENS. The object
 * stays in the bucket, the row keeps its wrapped key, and the document still
 * counts against both the document count and the storage quota — which is what
 * `GET /documents/usage` reports and what the UI has to say, because a user who
 * deleted a 90 MB file and saw no space returned would otherwise assume the
 * deletion failed. Space comes back at `DELETE /documents/:id/permanent`, or when
 * the trash-auto-purge cron reaches the row.
 *
 * Scoped by `{ _id, userId }` with no `deletedAt` predicate, exactly as
 * `vaultController.deleteItem` is, so trashing means one thing for a document and
 * for an item. The consequence, stated rather than discovered: a repeat delete of
 * an already-trashed document is a 200 that RE-STAMPS `deletedAt` and so restarts
 * its auto-purge clock. That is the right trade — a client retrying after a
 * timeout gets a 200 rather than a confusing 404 — and it cannot lose data, since
 * the only thing a later `deletedAt` delays is an automatic purge.
 *
 * Not rotation-fenced, and here there is nothing to argue about: it writes a
 * timestamp. No ciphertext of any kind is created.
 */
export const deleteDocument = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const document = await Document.findOneAndUpdate(
    { _id: id, userId },
    { $set: { deletedAt: new Date() } },
    { returnDocument: 'after' },
  )
    .select('_id')
    .lean();

  if (!document) {
    throw httpErrors.notFound('Document not found');
  }

  const deleteCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'document_delete',
    { documentId: id },
    deleteCtx.ip,
    deleteCtx.userAgent,
  );

  logger.info('Document moved to trash', { userId, documentId: id });

  res.status(200).json({ success: true, message: 'Document moved to trash' });
});

/**
 * `POST /documents/:id/restore` — bring a document back out of the trash.
 *
 * `$unset` rather than `$set: null`, for the reason the `deletedAt` index records
 * on the model: the sparse index over `deletedAt` is only small while the field
 * is genuinely ABSENT on the active majority, and a restore that wrote a null
 * would index every row that had ever been trashed.
 *
 * ## The one predicate that is not copied from `restoreItem`
 *
 * `purgePending: null` — that is, the field must be ABSENT.
 *
 * A `purgePending` row is one whose permanent deletion started and did not
 * finish: the marker goes up immediately BEFORE the object delete and comes down
 * only when the row itself is deleted, so a row still carrying it either has no
 * object left or is about to lose one, and the hourly collector will delete the
 * row. Restoring it would put a document back in the ACTIVE list that 404s on
 * every segment it is asked for and then disappears without explanation.
 *
 * This predicate is deliberately NOT added to `updateDocument` or to
 * `deleteDocument`. Those two write to a row that is going away, which is
 * pointless but harmless and costs the user nothing; restore is the one
 * transition that puts a dead document back in front of them.
 */
export const restoreDocument = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  const document = await Document.findOneAndUpdate(
    { _id: id, userId, deletedAt: { $exists: true, $ne: null }, purgePending: null },
    { $unset: { deletedAt: 1 } },
    { returnDocument: 'after' },
  )
    .select(DOCUMENT_PROJECTION)
    .lean();

  if (!document) {
    throw httpErrors.notFound('Document not found, not in trash, or already being deleted');
  }

  const restoreCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'document_restore',
    { documentId: id },
    restoreCtx.ip,
    restoreCtx.userAgent,
  );

  logger.info('Document restored from trash', { userId, documentId: id });

  res.status(200).json({
    success: true,
    data: document,
    message: 'Document restored from trash',
  });
});

/**
 * `DELETE /documents/:id/permanent` — destroy a trashed document for good.
 *
 * ## The order is the crash-safety argument, and it only works one way round
 *
 *   1. Set `purgePending` on the row.
 *   2. Delete the object.
 *   3. Delete the row.
 *
 * A crash after (1) leaves a marker the hourly collector finds and finishes. A
 * crash after (2) leaves the same marker on a row whose object is already gone,
 * and the collector's own delete is idempotent, so it finishes that too. The two
 * failure states converge on the same repair.
 *
 * Reversing (2) and (3) is what must never happen. Deleting the row first
 * destroys the only record of the object key — the key is derivable from the two
 * ids, but nothing would be left to derive it FROM — so the object would survive
 * as an orphan, charged to nobody, findable only by the collector's bounded
 * hourly sweep of the whole bucket.
 *
 * ## Deleting the row is what actually destroys the document
 *
 * The row holds the only wrapped copy of the DEK. Once it is gone, any object
 * that somehow survived is ciphertext under a key that no longer exists anywhere
 * — not on the server, not in the browser, not in a backup, because documents are
 * deliberately absent from the backup payload. SECURITY.md says so.
 *
 * ## Why `generalAuthLimiter` and not `heavyOpLimiter`
 *
 * `heavyOpLimiter` is IP-keyed at 10 per 15 minutes and is shared with export,
 * backup download, bulk delete, bulk move and empty-trash. On a PER-ROW route it
 * would 429 a user who purged eleven documents and then lock them out of emptying
 * their vault trash for a quarter of an hour. The per-item equivalent carries no
 * limiter at all; this one carries the ordinary authenticated budget.
 */
export const purgeDocument = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { id } = req.params as { id: string };

  // Trashed only, exactly as `permanentDelete` requires of a vault item: a
  // permanent delete is the second, deliberate half of a two-step destruction and
  // must not be reachable in one request from the active list.
  const document = await Document.findOneAndUpdate(
    { _id: id, userId, deletedAt: { $exists: true, $ne: null } },
    { $set: { purgePending: true } },
    { returnDocument: 'after' },
  )
    // `objectKey` is excluded from every response projection on this route file
    // and is selected here because this is a handler that addresses the object.
    // It never leaves the process.
    .select('objectKey')
    .lean();

  if (!document) {
    throw httpErrors.notFound('Document not found in trash');
  }

  // Deliberately NOT wrapped in a try/catch. A storage failure here must reach
  // the caller: the marker is already committed, so the collector will finish the
  // purge, and reporting success for work that has not happened would leave the
  // user believing their bytes are gone when the row is still there.
  await getStorage().deleteObject(document.objectKey);

  await Document.deleteOne({ _id: id, userId });

  const purgeCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    'document_purge',
    { documentId: id },
    purgeCtx.ip,
    purgeCtx.userAgent,
  );

  logger.info('Document permanently deleted', { userId, documentId: id });

  res.status(200).json({ success: true, message: 'Document permanently deleted' });
});

/**
 * `DELETE /documents/trash/empty` — destroy every trashed document.
 *
 * ## This is NOT the item implementation, and copying it would orphan the bucket
 *
 * `vaultController.emptyTrash` is a single `deleteMany`, which is correct there
 * because a vault item is only a row. Every document row owns an object, so a
 * `deleteMany` here would delete every row and leave every object behind, charged
 * to nobody and reachable only by the collector's bounded hourly sweep of the
 * whole bucket. So this walks the set instead and runs the same three ordered
 * steps `purgeDocument` does for each row.
 *
 * ## The set is bounded before the first delete
 *
 * `deletedAt <= startTime`, exactly as the item version bounds itself: a document
 * trashed by another tab WHILE this request runs is outside the set and survives,
 * so "empty the trash" means the trash the user was looking at.
 *
 * ## Why the pages are walked by `_id` and not by `skip`
 *
 * A failing row stays in the set — that is the whole point of leaving it to the
 * collector — so a query that re-read the same page would return it for ever and
 * this loop would not terminate. Paging on `_id > lastId` with an ascending sort
 * advances past a row whether it was deleted or skipped, so the walk is monotonic
 * and finishes in at most `MAX_DOCUMENTS_PER_USER / EMPTY_TRASH_PAGE_SIZE` pages.
 *
 * ## A failure is counted, not thrown
 *
 * One unreachable object must not abandon the rows after it, and it does not have
 * to: the row was marked `purgePending` before the delete was attempted, so the
 * collector will finish exactly this row. The response therefore carries both
 * counts and the request succeeds even when every delete failed, because in that
 * state nothing has been lost — the work is deferred, and the marker is what
 * defers it.
 */
export const emptyDocumentTrash = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);

  const startTime = new Date();
  const trashed = { userId, deletedAt: { $exists: true, $ne: null, $lte: startTime } };

  let deletedCount = 0;
  let failedCount = 0;
  let lastId: mongoose.Types.ObjectId | undefined;

  for (;;) {
    const page = await Document.find(
      lastId === undefined ? trashed : { ...trashed, _id: { $gt: lastId } },
    )
      .select('objectKey')
      .sort({ _id: 1 })
      .limit(EMPTY_TRASH_PAGE_SIZE)
      .lean();

    if (page.length === 0) {
      break;
    }

    for (const row of page) {
      // The cursor advances BEFORE the work, not after it, and that is what makes
      // the walk monotonic: a row whose purge throws is left behind for the
      // collector and must not be read again, or the loop that is supposed to
      // leave it alone would return to it for ever.
      lastId = row._id;
      try {
        await Document.updateOne({ _id: row._id, userId }, { $set: { purgePending: true } });
        await getStorage().deleteObject(row.objectKey);
        // The engine's own count, never a bare `+= 1`. A row purged by a
        // concurrent request between this page's read and this delete is removed
        // by that request and not by this one, so reporting it here would be a
        // number the caller cannot reconcile with anything. It is not a failure
        // either: the row is gone, which is what was asked for.
        const { deletedCount: removed } = await Document.deleteOne({ _id: row._id, userId });
        deletedCount += removed;
      } catch (error) {
        failedCount += 1;
        logger.error('Failed to purge a trashed document while emptying the trash', {
          userId,
          documentId: String(row._id),
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  const emptyCtx = getRequestContext(req);
  await createAuditLog(
    userId,
    // `document_purge` rather than a sixth action, exactly as the item version
    // reuses `item_delete` with an `action` discriminator: this is the same
    // destruction, in bulk.
    'document_purge',
    { action: 'empty_trash', deletedCount, failedCount },
    emptyCtx.ip,
    emptyCtx.userAgent,
  );

  logger.info('Document trash emptied', { userId, deletedCount, failedCount });

  res.status(200).json({
    success: true,
    data: { deletedCount, failedCount },
    message: `${String(deletedCount)} document(s) permanently deleted`,
  });
});
