import { describe, it, expect } from 'vitest';
import mongoose, { Types } from 'mongoose';
import {
  completeDocumentUploadSchema,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
  MAX_ENCRYPTED_DOCUMENT_META_LENGTH,
} from '@hvault/shared';
import { Document } from '../src/models/Document.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';

/**
 * The `documents` row is the only server-side record of a stored document, and
 * every guarantee the feature makes rests on four properties of it, each asserted
 * here:
 *
 *   1. `toJSON` strips `userId` and `objectKey`. The storage address is the one
 *      server-assigned value in the row, and a client that never learns it cannot
 *      form an expectation about it.
 *   2. Every stored ciphertext and framing column is bounded, so no write can put
 *      an unbounded string in the collection.
 *   3. `objectKey` is UNIQUE, which makes "two rows point at one object"
 *      unrepresentable — the shape in which a purge would delete an object a live
 *      row still needs.
 *   4. `deletedAt` is genuinely ABSENT on an active row, which is the entire
 *      premise of the sparse index the trash cron seeks on.
 */
describe('Document model', () => {
  const userId = new Types.ObjectId();

  /**
   * A row exactly as `complete` writes one: a single-segment, 12-byte document.
   * Sizes satisfy the identity the wire schema states
   * (`ciphertextBytes === plaintextBytes + DOCUMENT_TAG_BYTES * chunkCount`), so a
   * case that fails does so for the reason it names and not for a stale fixture.
   */
  const makeDoc = (overrides: Record<string, unknown> = {}) => {
    const documentId = new Types.ObjectId();
    return {
      _id: documentId,
      userId,
      objectKey: buildObjectKey(userId.toString(), documentId.toString()),
      encryptedDek: 'ZGVr',
      dekIv: 'aXY=',
      dekTag: 'dGFn',
      streamSalt: 'c2FsdA==',
      noncePrefix: 'cHJlZg==',
      encryptedMeta: 'bWV0YQ==',
      metaIv: 'bWV0YWl2',
      metaTag: 'bWV0YXRhZw==',
      chunkPlaintextBytes: 1024,
      chunkCount: 1,
      plaintextBytes: 12,
      ciphertextBytes: 12 + DOCUMENT_TAG_BYTES,
      ...overrides,
    };
  };

  /**
   * The validation error a candidate row produces, or `undefined` when it is
   * valid.
   *
   * Built on the async `validate()` rather than `validateSync()`, which Mongoose 9
   * deprecates and Mongoose 10 removes — the same adaptation, for the same reason,
   * as `getValidationError` in `user-model-validation.test.ts`. There are no
   * `pre('validate')` hooks on this schema, so `validate()` fires exactly the
   * synchronous `required` / `maxlength` / `min` / `max` validators these cases
   * exercise.
   */
  const validationErrorFor = async (
    overrides: Record<string, unknown>,
  ): Promise<mongoose.Error.ValidationError | undefined> => {
    try {
      await new Document(makeDoc(overrides)).validate();
      return undefined;
    } catch (error: unknown) {
      return error as mongoose.Error.ValidationError;
    }
  };

  // ── toJSON ────────────────────────────────────────────────────────────

  describe('toJSON', () => {
    it('never emits userId, objectKey or __v', () => {
      const json = new Document(makeDoc()).toJSON();

      // The three negatives. `objectKey` is the load-bearing one: it is the row's
      // only server-assigned value, it addresses an object in the bucket, and
      // nothing downstream needs it because every storage address is rebuilt from
      // ids the server already holds.
      expect(Object.hasOwn(json, 'userId')).toBe(false);
      expect(Object.hasOwn(json, 'objectKey')).toBe(false);
      expect(Object.hasOwn(json, '__v')).toBe(false);

      // ...and the strip is not achieved by emitting nothing: everything the
      // client needs in order to unwrap the DEK and frame a download survives.
      expect(json).toMatchObject({
        encryptedDek: 'ZGVr',
        dekIv: 'aXY=',
        dekTag: 'dGFn',
        streamSalt: 'c2FsdA==',
        noncePrefix: 'cHJlZg==',
        encryptedMeta: 'bWV0YQ==',
        chunkPlaintextBytes: 1024,
        chunkCount: 1,
        ciphertextBytes: 12 + DOCUMENT_TAG_BYTES,
        plaintextBytes: 12,
        favorite: false,
      });
      expect(json['_id']).toBeDefined();
    });

    it('emits no deletedAt or purgePending key for an active document', () => {
      const json = new Document(makeDoc()).toJSON();

      // Both lifecycle flags default to `undefined` rather than to a value, and
      // `documentResponseSchema` declares both optional. A `null` here would parse
      // as a malformed row on the client and, far worse for `deletedAt`, would mean
      // the sparse index covers every row in the collection.
      expect(Object.hasOwn(json, 'deletedAt')).toBe(false);
      expect(Object.hasOwn(json, 'purgePending')).toBe(false);
    });
  });

  // ── Stored bounds ─────────────────────────────────────────────────────

  describe('string bounds', () => {
    it.each([
      ['objectKey', 200],
      ['encryptedDek', 200],
      ['dekIv', 24],
      ['dekTag', 32],
      ['streamSalt', 64],
      ['noncePrefix', 16],
      ['encryptedMeta', MAX_ENCRYPTED_DOCUMENT_META_LENGTH],
      ['metaIv', 24],
      ['metaTag', 32],
    ])('accepts %s at its bound and rejects it one character over', async (field, max) => {
      expect(await validationErrorFor({ [field]: 'a'.repeat(max) })).toBeUndefined();

      const error = await validationErrorFor({ [field]: 'a'.repeat(max + 1) });
      expect(error?.errors[field]?.kind).toBe('maxlength');
      // NEGATIVE: exactly one field is at fault, so an over-long value cannot pass
      // by tripping some unrelated validator that happens to fire first.
      expect(Object.keys(error?.errors ?? {})).toEqual([field]);
    });

    it.each([
      // `userId` first, and it is not a formality: a row with no owner is
      // un-listable, is never reached by `cascadeDeleteUser`'s `{ userId }` sweep,
      // and is counted against nobody's quota while still occupying an object.
      'userId',
      'objectKey',
      'encryptedDek',
      'dekIv',
      'dekTag',
      'streamSalt',
      'noncePrefix',
      'encryptedMeta',
      'metaIv',
      'metaTag',
    ])('rejects a row with no %s', async (field) => {
      const error = await validationErrorFor({ [field]: undefined });
      expect(error?.errors[field]?.kind).toBe('required');
    });
  });

  describe('numeric bounds', () => {
    it('requires chunkPlaintextBytes to be at least 1', async () => {
      // Zero would make `ceil(plaintextBytes / chunkPlaintextBytes)` infinite and
      // every segment range meaningless.
      expect(
        (await validationErrorFor({ chunkPlaintextBytes: 0 }))?.errors['chunkPlaintextBytes']?.kind,
      ).toBe('min');
      expect(await validationErrorFor({ chunkPlaintextBytes: 1 })).toBeUndefined();
    });

    it('requires at least one chunk and refuses more than MAX_DOCUMENT_CHUNK_COUNT', async () => {
      // A zero-byte document is still ONE segment holding a bare tag, so there is
      // no such thing as a document with no segments.
      expect((await validationErrorFor({ chunkCount: 0 }))?.errors['chunkCount']?.kind).toBe('min');
      expect(
        (await validationErrorFor({ chunkCount: MAX_DOCUMENT_CHUNK_COUNT + 1 }))?.errors[
          'chunkCount'
        ]?.kind,
      ).toBe('max');
      expect(await validationErrorFor({ chunkCount: MAX_DOCUMENT_CHUNK_COUNT })).toBeUndefined();
    });

    it('requires ciphertextBytes to be at least one authentication tag', async () => {
      expect(
        (await validationErrorFor({ ciphertextBytes: DOCUMENT_TAG_BYTES - 1 }))?.errors[
          'ciphertextBytes'
        ]?.kind,
      ).toBe('min');
      // The floor is the empty document: zero plaintext bytes and one tag.
      expect(
        await validationErrorFor({ ciphertextBytes: DOCUMENT_TAG_BYTES, plaintextBytes: 0 }),
      ).toBeUndefined();
    });

    it('refuses a negative plaintextBytes', async () => {
      expect(
        (await validationErrorFor({ plaintextBytes: -1 }))?.errors['plaintextBytes']?.kind,
      ).toBe('min');
      expect(await validationErrorFor({ plaintextBytes: 0 })).toBeUndefined();
    });

    it.each(['chunkPlaintextBytes', 'chunkCount', 'ciphertextBytes', 'plaintextBytes'])(
      'rejects a row with no %s',
      async (field) => {
        expect((await validationErrorFor({ [field]: undefined }))?.errors[field]?.kind).toBe(
          'required',
        );
      },
    );
  });

  // ── Persistence-level guarantees ──────────────────────────────────────

  describe('indexes', () => {
    it('declares a UNIQUE index on objectKey', async () => {
      await Document.ensureIndexes();
      const indexes = (await Document.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        sparse?: boolean;
        partialFilterExpression?: Record<string, unknown>;
      }[];

      const index = indexes.find((idx) => idx.key['objectKey'] === 1);
      expect(index).toBeDefined();
      expect(index!.unique).toBe(true);
    });

    it('declares deletedAt SPARSE rather than partial, so the trash cron can seek a range on it', async () => {
      await Document.ensureIndexes();
      const indexes = (await Document.collection.indexes()) as {
        key: Record<string, number>;
        sparse?: boolean;
        partialFilterExpression?: Record<string, unknown>;
      }[];

      const index = indexes.find(
        (idx) => idx.key['deletedAt'] === 1 && Object.keys(idx.key).length === 1,
      );
      expect(index).toBeDefined();
      expect(index!.sparse).toBe(true);
      // NEGATIVE, and this is the whole point of the assertion: MongoDB will not
      // use a `{ deletedAt: { $exists: true } }` partial index for the `$lte`
      // RANGE predicate the cross-user purge scan issues, so a partial index here
      // would be built and never chosen — a COLLSCAN wearing an index's costume.
      expect(index!.partialFilterExpression).toBeUndefined();
    });

    it('declares purgePending sparse for the garbage collector"s cross-user scan', async () => {
      await Document.ensureIndexes();
      const indexes = (await Document.collection.indexes()) as {
        key: Record<string, number>;
        sparse?: boolean;
      }[];

      const index = indexes.find((idx) => idx.key['purgePending'] === 1);
      expect(index).toBeDefined();
      expect(index!.sparse).toBe(true);
    });

    it.each([
      [
        'userId + deletedAt + updatedAt desc (the list query)',
        { userId: 1, deletedAt: 1, updatedAt: -1 },
      ],
      ['userId + folderId (folder contents and the orphan sweep)', { userId: 1, folderId: 1 }],
      ['userId + favorite (the favorites filter)', { userId: 1, favorite: 1 }],
    ])('declares a compound index on %s', async (_label, key) => {
      await Document.ensureIndexes();
      const indexes = (await Document.collection.indexes()) as { key: Record<string, number> }[];

      expect(indexes.some((idx) => JSON.stringify(idx.key) === JSON.stringify(key))).toBe(true);
    });
  });

  describe('stored rows', () => {
    it('lives in the `documents` collection', () => {
      // Pinned because it is invisible from inside the model: with the explicit
      // `collection` option removed, Mongoose pluralises the model name to
      // `documents` here by luck, but `DocumentUpload` would silently become
      // `documentuploads`. Both names are fixed by PLAN Section 1.5, and every
      // test in this repository goes through the model, so a rename would show up
      // only as an empty collection on a deployed database after an upgrade.
      expect(Document.collection.collectionName).toBe('documents');
    });

    it('stores no deletedAt key at all on a freshly created document', async () => {
      const created = await Document.create(makeDoc());

      // Read through the RAW collection, not through Mongoose: a hydrated read
      // would apply schema defaults on the way out and could not tell an absent
      // field from a defaulted one. The sparse index only stays small — and only
      // stays correct — while this key is genuinely missing, so a `default: null`
      // slipped into the schema must fail here.
      const raw = await Document.collection.findOne({ _id: created._id });
      expect(raw).not.toBeNull();
      expect(Object.hasOwn(raw!, 'deletedAt')).toBe(false);
      expect(Object.hasOwn(raw!, 'purgePending')).toBe(false);
      // ...and the row really was written, so the two negatives above are not
      // passing on an empty document.
      expect(raw!['favorite']).toBe(false);
      expect(raw!['objectKey']).toBe(created.objectKey);
    });

    it('rejects a second row claiming the same objectKey', async () => {
      await Document.ensureIndexes();
      const collidingKey = buildObjectKey(userId.toString(), new Types.ObjectId().toString());
      await Document.create(makeDoc({ objectKey: collidingKey }));

      let error: unknown;
      try {
        // A DIFFERENT `_id` and a different owner: only the object key collides,
        // so nothing but the unique index can refuse this.
        await Document.create(makeDoc({ objectKey: collidingKey, userId: new Types.ObjectId() }));
      } catch (err: unknown) {
        error = err;
      }

      expect((error as { code?: number } | undefined)?.code).toBe(11000);
      expect(await Document.countDocuments({ objectKey: collidingKey })).toBe(1);
    });

    it('accepts every wrapped-DEK value the wire schema does, so no request dies at the database', async () => {
      // The one failure this closes: a stored bound TIGHTER than the wire bound.
      // `completeDocumentUploadSchema` would accept the request, the handler would
      // build the row, and the insert would fail with a Mongoose ValidationError
      // that names a column no client has ever heard of — after the ciphertext is
      // already in the bucket. The two bounds are written in two packages
      // (`documentFields.ts` and `schemas/document.ts`) and neither derives from
      // the other, so nothing but this test notices when one of them moves.
      const atWireBound = {
        encryptedMeta: 'a'.repeat(MAX_ENCRYPTED_DOCUMENT_META_LENGTH),
        metaIv: 'a'.repeat(24),
        metaTag: 'a'.repeat(32),
        encryptedDek: 'a'.repeat(200),
        dekIv: 'a'.repeat(24),
        dekTag: 'a'.repeat(32),
        vaultKeyVersion: 0,
      };
      // The wire accepts it...
      expect(completeDocumentUploadSchema.safeParse(atWireBound).success).toBe(true);
      // ...and so does the row it becomes.
      const { vaultKeyVersion: _version, ...rowFields } = atWireBound;
      expect(await validationErrorFor(rowFields)).toBeUndefined();

      // NEGATIVE: one character past the shared bound is refused on BOTH sides, so
      // this is an agreement about a real ceiling rather than two absent bounds.
      expect(
        completeDocumentUploadSchema.safeParse({ ...atWireBound, dekIv: 'a'.repeat(25) }).success,
      ).toBe(false);
      expect((await validationErrorFor({ dekIv: 'a'.repeat(25) }))?.errors['dekIv']?.kind).toBe(
        'maxlength',
      );
    });

    it('accepts a caller-supplied _id and refuses a repeat completion of the same upload', async () => {
      // The row's `_id` IS the upload id, bound into the HKDF `info` of every key
      // the document uses, so completion cannot let Mongo mint a fresh one. The
      // primary key is therefore what makes a retried completion a no-op rather
      // than a duplicate.
      const uploadId = new Types.ObjectId();
      const created = await Document.create(makeDoc({ _id: uploadId }));
      expect(created._id.toString()).toBe(uploadId.toString());

      let error: unknown;
      try {
        await Document.create(
          makeDoc({
            _id: uploadId,
            objectKey: buildObjectKey(userId.toString(), new Types.ObjectId().toString()),
          }),
        );
      } catch (err: unknown) {
        error = err;
      }

      expect((error as { code?: number } | undefined)?.code).toBe(11000);
      expect(await Document.countDocuments({ _id: uploadId })).toBe(1);
    });
  });
});
