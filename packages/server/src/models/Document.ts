import mongoose, { Schema, type Model, type Types } from 'mongoose';
import {
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
} from '@hvault/shared';
import {
  streamFramingPaths,
  wrappedDekPaths,
  type IStreamFramingFields,
  type IWrappedDekFields,
} from './documentFields.js';

// ----- Main Interface -----

/**
 * A stored document: the row beside an object of ciphertext in the bucket.
 *
 * Every column here is something the SERVER needs and nothing else. It needs the
 * key to fetch (`objectKey`), the arithmetic to turn a segment index into a byte
 * range (`chunkPlaintextBytes`, `chunkCount`, `ciphertextBytes`), the sizes to
 * charge against a quota (`plaintextBytes`), and the lifecycle flags
 * (`deletedAt`, `purgePending`). The filename, the MIME type, the tags, the note
 * and the content digest live inside `encryptedMeta`, sealed under a key derived
 * from the document's own DEK, which is itself wrapped under a key derived from
 * the user's vault key. The server therefore holds no name signal at all: there
 * is deliberately no `searchHash` here (there is one on `VaultItem`), duplicate
 * names are legal, and `MAX_DOCUMENTS_PER_USER` plus the byte quota are the only
 * bounds on how many documents an account may hold.
 *
 * There is also deliberately no `objectMissing` column. An object that has gone
 * missing is discovered at download, where the storage provider's `NoSuchKey`
 * becomes a 404 the UI renders; a flag nothing acts on would be a column and a
 * code path in service of one string.
 *
 * `_id` is the UPLOAD id: it is minted when the transfer is initiated, handed to
 * the browser, and bound into the HKDF `info` of the DEK wrap, the stream key and
 * the metadata key before the first byte is sealed. That is why completion
 * inserts a row with a caller-supplied `_id` rather than letting Mongo mint one,
 * and why a repeat completion collides on the primary key instead of duplicating.
 */
export interface IDocument extends IWrappedDekFields, IStreamFramingFields {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  folderId?: Types.ObjectId | undefined;
  favorite: boolean;
  /**
   * `u/<userId>/d/<documentId>`, built by `utils/documentObjects.ts` and ALWAYS
   * server-assigned. Nothing accepts a client-supplied key, so a key that reaches
   * the storage engine can never contain a path segment, a traversal or a name.
   */
  objectKey: string;
  encryptedMeta: string;
  metaIv: string;
  metaTag: string;
  /**
   * The plaintext one segment holds, written by the SERVER at upload init from
   * its own `DOCUMENT_PLAINTEXT_CHUNK_BYTES` and never taken from a request.
   *
   * Decryption reads this value from the ROW rather than from the constant, which
   * is the whole reason it is a column: changing the constant later cannot
   * mis-frame a document that already exists.
   */
  chunkPlaintextBytes: number;
  /**
   * All three sizes are DERIVED SERVER-SIDE from the part ledger at completion
   * and never taken from the request body: `ciphertextBytes` is the sum of the
   * part sizes, `chunkCount` is their count, and `plaintextBytes` is
   * `ciphertextBytes - DOCUMENT_TAG_BYTES * chunkCount`. A client that could
   * declare them could under-report its own quota consumption.
   */
  chunkCount: number;
  ciphertextBytes: number;
  plaintextBytes: number;
  /**
   * Set immediately BEFORE the object delete of a permanent purge and cleared by
   * the row delete that follows it, so a crash between the two leaves a marker
   * the hourly garbage collector finishes rather than an object nobody owns.
   */
  purgePending?: boolean | undefined;
  deletedAt?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

// ----- Main Schema -----

const documentSchema = new Schema<IDocument>(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    folderId: { type: Schema.Types.ObjectId, ref: 'Folder', default: undefined },
    favorite: { type: Boolean, default: false },
    // `buildObjectKey` emits a FIXED 53 characters (`u/` + 24 + `/d/` + 24), so
    // this bound can never bind on a key this application wrote. It is here as a
    // backstop against one it did not.
    objectKey: { type: String, required: true, maxlength: 200 },
    ...wrappedDekPaths(),
    ...streamFramingPaths(),
    encryptedMeta: { type: String, required: true, maxlength: MAX_ENCRYPTED_DOCUMENT_META_LENGTH },
    metaIv: { type: String, required: true, maxlength: 24 },
    metaTag: { type: String, required: true, maxlength: 32 },
    // The numeric guards below mirror the identities `documentResponseSchema`
    // already states on the wire. They are not a second source of truth for the
    // framing — the derivation lives in `documentChunkCountFor` and the sizes are
    // computed from the part ledger — they are the floor under a row that reached
    // the database by any other route (a migration, a repair script, a future
    // handler). A negative `plaintextBytes` or a zero `chunkCount` turns segment
    // range arithmetic into nonsense, and refusing it here costs one validator.
    chunkPlaintextBytes: { type: Number, required: true, min: 1 },
    chunkCount: { type: Number, required: true, min: 1, max: MAX_DOCUMENT_CHUNK_COUNT },
    // A zero-byte document is still one segment, so the smallest object that can
    // exist is exactly one authentication tag.
    ciphertextBytes: { type: Number, required: true, min: DOCUMENT_TAG_BYTES },
    plaintextBytes: { type: Number, required: true, min: 0 },
    purgePending: { type: Boolean, default: undefined },
    deletedAt: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'documents',
    toJSON: {
      transform(_doc, ret) {
        // `userId` is implied by the authenticated session and would only widen
        // the leak surface (logs, error reports, shared-browser caches), exactly
        // as on `VaultItem`.
        //
        // `objectKey` is stripped for a stronger reason than tidiness: it is the
        // one server-assigned value in this row, and a client that never learns it
        // cannot form an expectation about it. Every storage address the server
        // uses is derived from ids the server already holds
        // (`buildObjectKey(userId, documentId)`), so nothing downstream needs it,
        // and a key echoed back into a response is a key that can appear in a
        // browser cache, a URL a user pastes into a bug report, or an error
        // payload — for an object the client has no business addressing directly.
        //
        // This transform does NOT run on a `.lean()` read, and every read path in
        // this feature is lean. So it is defense-in-depth for the hydrated path,
        // not the control: a lean handler must carry
        // `.select('-userId -objectKey')` of its own, exactly as every lean read of
        // `VaultItem` carries `.select('-sourceRefId')` for the same reason.
        const { __v: _v, userId: _userId, objectKey: _objectKey, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

/**
 * The document list, in the order the UI asks for it: one user's active
 * documents, newest change first. `deletedAt` sits in the middle because every
 * listing predicate names it (active rows ask for absent, the trash view asks for
 * present), so it must precede the sort key for the index to serve both.
 *
 * It serves the PREDICATE of both listings, and the LEADING SORT KEY of each only
 * at that listing's DEFAULT `sortBy`: `updatedAt` for the active list (this
 * index's third key, under a point bound on `deletedAt`) and `deletedAt` for the
 * trash list (its second key, scanned as a range). Ask either listing for one of
 * its other permitted keys — `createdAt` or `favorite` active, `createdAt` or
 * `updatedAt` in the trash, where the range bound on `deletedAt` leaves the third
 * key with no global order — and this index contributes nothing to the sort at
 * all.
 *
 * And a blocking SORT is added in EVERY case regardless, because the listing
 * orders by `{ <sortBy>: dir, _id: dir }` — the `_id` tiebreak that makes a paged
 * walk a total order — and `_id` is in no index here. So the tiebreak is what
 * costs the two default sorts their index-provided ordering; the other four paid
 * for a blocking SORT with or without it. That is the deliberate trade:
 * bounded by the per-user document ceiling, and spilling to temporary files
 * rather than failing on MongoDB 6.0 and later. `vaultController`'s `listItems`
 * carries the same tiebreak and the same note.
 */
documentSchema.index({ userId: 1, deletedAt: 1, updatedAt: -1 });
/** Folder contents, and the orphan sweep `deleteFolder` runs after re-parenting. */
documentSchema.index({ userId: 1, folderId: 1 });
/** The favorites filter, mirroring `VaultItem`'s. */
documentSchema.index({ userId: 1, favorite: 1 });
/**
 * UNIQUE on `objectKey`. The key is `u/<userId>/d/<documentId>` and `_id` is
 * already unique, so two rows cannot legitimately collide here — which is exactly
 * why the constraint is worth declaring: it makes "two rows point at one object"
 * unrepresentable rather than merely unlikely. Without it, a bug that reused an id
 * would end with one purge deleting the object another live row still needs, and
 * the only symptom would be a document that stops opening.
 */
documentSchema.index({ objectKey: 1 }, { unique: true });
/**
 * Supports the trash auto-purge cron, which scans `{ deletedAt: { $lte: cutoff } }`
 * across ALL users with no `userId` predicate, so none of the `userId`-prefixed
 * indexes above can seek it.
 *
 * The cron pages that scan on `_id` (`{ deletedAt: { $lte: cutoff }, _id: { $gt:
 * lastId } }` sorted by `_id` ascending), because a document whose stored object
 * cannot be deleted is deliberately LEFT in the expired set and a loop re-reading
 * its own predicate would return it for ever. The planner therefore has two
 * candidates per page — this index with a sort stage, or `_id_` with `deletedAt`
 * as a residual filter — and it is this one that keeps the work proportional to
 * the TRASHED rows rather than to the collection, which is exactly what the
 * sparseness below buys.
 *
 * `sparse` rather than a `{ deletedAt: { $exists: true } }` partial filter, for the
 * reason spelled out at the same index on `VaultItem`: MongoDB will not use such a
 * partial index for a `$lte` RANGE predicate, so it would be built and never
 * chosen. A sparse index has no such restriction. It also stays small only while
 * the field is genuinely ABSENT on active rows, which is why `deletedAt` defaults
 * to `undefined` here and must never be given a `null` default — that would index
 * every row in the collection and dissolve the whole point of it.
 */
documentSchema.index({ deletedAt: 1 }, { sparse: true });
/**
 * Supports the garbage collector's second pass, `{ purgePending: true }`, also a
 * cross-user scan. Sparse for the same reason and with the same requirement: the
 * flag defaults to `undefined`, is set only for the instant between the object
 * delete and the row delete, and so indexes a handful of rows at most. Either a
 * sparse index or a `{ purgePending: true }` partial one is planner-eligible for
 * this EQUALITY predicate; sparse is chosen so both lifecycle flags in this file
 * are treated the same way and a reader does not have to work out why they differ.
 */
documentSchema.index({ purgePending: 1 }, { sparse: true });

// ----- Model -----

export const Document: Model<IDocument> = mongoose.model<IDocument>('Document', documentSchema);
