import mongoose, { Schema, type Model, type Types } from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
} from '@hvault/shared';
import {
  streamFramingPaths,
  wrappedDekPaths,
  type IStreamFramingFields,
  type IWrappedDekFields,
} from './documentFields.js';

// ----- Sub-interfaces -----

/**
 * One accepted part of a transfer in progress, appended as the part is stored.
 *
 * The ledger is what completion is checked against: the handler compares it with
 * the engine's own `ListParts` (count, order and size) and DERIVES the committed
 * row's `chunkCount`, `ciphertextBytes` and `plaintextBytes` from it rather than
 * from anything the client sent.
 *
 * NOT exported: it is referenced only by `IDocumentUpload` and by the sub-schema
 * below, both in this file, and the dead-code gate reports an export nothing
 * outside its own module reads. The handler that consumes the ledger arrives with
 * the completion endpoint and will export it then, with an importer.
 */
interface IDocumentUploadPart {
  /** 1-based, because S3 part numbers are. Segment indices are 0-based; they differ by one. */
  partNumber: number;
  /** The engine's opaque receipt for the stored part, handed back verbatim at completion. */
  etag: string;
  /** The stored size of the part, which is one sealed segment. */
  bytes: number;
}

// ----- Main Interface -----

/**
 * The staging row for a transfer that has begun and not yet completed.
 *
 * It exists because the three sides of an upload are separate requests and the
 * server must remember what it agreed to between them: the wrapped key and the
 * framing chosen at init, the vault-key version that key was wrapped under, the
 * engine-side multipart upload, and every part accepted so far. The committed
 * `documents` row is built from the completion request and this row's `_id`,
 * never from a copy of this row's ciphertext columns.
 *
 * `_id` is the future document id, minted here and returned to the browser so it
 * can bind its HKDF `info` to it before sealing the first byte. That is what makes
 * a re-initiation expensive enough to design around: a new id would mean a new
 * stream key and a re-encryption of every segment, which is why a stale
 * vault-key version is answered with a 409 the client recovers from by rewrapping
 * the DEK it still holds and retrying the COMPLETION alone.
 */
export interface IDocumentUpload extends IWrappedDekFields, IStreamFramingFields {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  /** Server-assigned at init, identical to the key the committed row will carry. */
  objectKey: string;
  /**
   * The engine's multipart upload id, ABSENT for a single-segment transfer: one
   * segment is stored with `PutObject`, which has no multipart handle to keep.
   * Its absence is therefore meaningful and must not be defaulted to a string.
   */
  s3UploadId?: string | undefined;
  declaredPlaintextBytes: number;
  declaredChunkCount: number;
  /** Set by the SERVER at init from its own constant, and echoed to the client. */
  chunkPlaintextBytes: number;
  /**
   * The user's `vaultKeyVersion` at the moment the DEK above was wrapped.
   *
   * Completion refuses with 409 when it no longer matches, which is what stops a
   * rotation that ran mid-transfer from committing a DEK wrapped under the
   * superseded vault key — a row nothing could ever unwrap again.
   */
  vaultKeyVersion: number;
  parts: IDocumentUploadPart[];
  /** The sum of `parts[].bytes`, kept for the quota check against bytes actually received. */
  receivedBytes: number;
  folderId?: Types.ObjectId | undefined;
  createdAt: Date;
  /**
   * When the staging row stops being usable. Set once at init from
   * `DOCUMENT_UPLOAD_TTL_HOURS` and never slid forward, so a transfer cannot keep
   * itself alive indefinitely by dribbling parts, and the quota's in-flight
   * component is bounded in time. Required: see the TTL index below for what a
   * row without it would mean.
   */
  expiresAt: Date;
}

// ----- Sub-Schemas -----

const documentUploadPartSchema = new Schema<IDocumentUploadPart>(
  {
    partNumber: { type: Number, required: true, min: 1, max: MAX_DOCUMENT_CHUNK_COUNT },
    // Engine-assigned and opaque: an S3 ETag is a quoted MD5 (34 characters), or
    // that plus `-<partCount>` for a completed multipart object. The bound is a
    // sanity backstop an order of magnitude above anything a real engine emits,
    // deliberately NOT a tight fit — this value is not ours to shape, and a bound
    // narrow enough to bind would refuse a legitimate engine and break the
    // "any S3 service works through configuration alone" promise.
    etag: { type: String, required: true, maxlength: 256 },
    // One stored part is one sealed segment: at least a bare authentication tag
    // (a zero-byte final segment) and at most a full ciphertext chunk. Both ends
    // are the framing constants rather than round numbers, and they are the same
    // pair `documentUploadResponseSchema` states on the wire.
    bytes: {
      type: Number,
      required: true,
      min: DOCUMENT_TAG_BYTES,
      max: DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
    },
  },
  { _id: false },
);

// ----- Main Schema -----

const documentUploadSchema = new Schema<IDocumentUpload>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    objectKey: { type: String, required: true, maxlength: 200 },
    // No `maxlength` that could bind, for the same reason as `parts[].etag`: the
    // upload id is minted by whichever storage engine the operator configured.
    // AWS's is a few hundred characters of opaque base64; another engine's may be
    // longer. A generous ceiling keeps an unbounded write out of the collection
    // without deciding on an engine's behalf how long its handles may be.
    s3UploadId: { type: String, maxlength: 1024, default: undefined },
    ...wrappedDekPaths(),
    ...streamFramingPaths(),
    declaredPlaintextBytes: { type: Number, required: true, min: 0 },
    declaredChunkCount: { type: Number, required: true, min: 1, max: MAX_DOCUMENT_CHUNK_COUNT },
    chunkPlaintextBytes: { type: Number, required: true, min: 1 },
    vaultKeyVersion: { type: Number, required: true, min: 0 },
    parts: { type: [documentUploadPartSchema], default: [] },
    receivedBytes: { type: Number, required: true, default: 0, min: 0 },
    folderId: { type: Schema.Types.ObjectId, ref: 'Folder', default: undefined },
    expiresAt: { type: Date, required: true },
  },
  {
    // `createdAt` only. There is no `updatedAt` on purpose: the row's whole
    // lifetime is decided by `expiresAt`, which is set once and never slides, and
    // an `updatedAt` beside a TTL that ignores it is an invitation to believe the
    // deadline moves when a part arrives. It does not.
    timestamps: { createdAt: true, updatedAt: false },
    collection: 'document_uploads',
  },
);

// ----- Indexes -----

/**
 * One user's transfers, newest first: backs `GET /documents/uploads` (so the UI
 * can list and cancel an abandoned upload) and the
 * `MAX_CONCURRENT_DOCUMENT_UPLOADS_PER_USER` check at init.
 */
documentUploadSchema.index({ userId: 1, createdAt: -1 });
/**
 * TTL on `expiresAt` (`expireAfterSeconds: 0`): MongoDB deletes the row the
 * moment its expiry passes.
 *
 * READ THAT LITERALLY. **This index deletes the ROW, and ONLY the ROW. It does
 * not delete the stored object, and it does not abort the engine-side multipart
 * upload.** A TTL index looks like cleanup and is not: when it fires on an
 * abandoned transfer, the parts already written are still sitting in the bucket
 * and the engine still holds an open multipart upload, and nothing in MongoDB
 * knows either of them exists any more — the row that named them is gone.
 *
 * Reclaiming those two things is the garbage collector's work
 * (`jobs/documentCleanup.ts`, hourly): it aborts engine-side multipart uploads
 * older than `DOCUMENT_UPLOAD_TTL_HOURS + 1h` that no live staging row claims,
 * and sweeps orphaned objects whose key parses to a document id with no row. The
 * one-hour margin exists precisely because this index has already removed the
 * evidence by then, so the GC has to reason from the engine's own `Initiated`
 * dates instead. Removing or shortening that job does not make this index start
 * doing its work; it makes a bucket fill up with parts nobody can name.
 *
 * `expiresAt` is `required` for the same reason: a row without it is a row this
 * index cannot reap, and therefore a transfer that holds quota forever.
 */
documentUploadSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ----- Model -----

export const DocumentUpload: Model<IDocumentUpload> = mongoose.model<IDocumentUpload>(
  'DocumentUpload',
  documentUploadSchema,
);
