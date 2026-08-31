import { describe, it, expect } from 'vitest';
import mongoose, { Types } from 'mongoose';
import {
  DOCUMENT_CIPHERTEXT_CHUNK_BYTES,
  DOCUMENT_TAG_BYTES,
  MAX_DOCUMENT_CHUNK_COUNT,
} from '@hvault/shared';
import { Document } from '../src/models/Document.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { User } from '../src/models/User.js';
import { streamFramingPaths, wrappedDekPaths } from '../src/models/documentFields.js';
import { buildObjectKey } from '../src/utils/documentObjects.js';

/**
 * The `document_uploads` staging row, and the `User.vaultKeyVersion` counter it
 * exists to compare against.
 *
 * The two are tested together because they are one mechanism: the staging row
 * records the vault-key version its wrapped DEK was sealed under, and completion
 * refuses with 409 when the user's current version no longer matches. Without
 * that pair, a rotation running mid-transfer commits a DEK wrapped under the
 * superseded vault key — a document row that nothing, ever, can unwrap again.
 */
describe('DocumentUpload model', () => {
  const userId = new Types.ObjectId();

  const makeUpload = (overrides: Record<string, unknown> = {}) => {
    const uploadId = new Types.ObjectId();
    return {
      _id: uploadId,
      userId,
      objectKey: buildObjectKey(userId.toString(), uploadId.toString()),
      encryptedDek: 'ZGVr',
      dekIv: 'aXY=',
      dekTag: 'dGFn',
      streamSalt: 'c2FsdA==',
      noncePrefix: 'cHJlZg==',
      declaredPlaintextBytes: 12,
      declaredChunkCount: 1,
      chunkPlaintextBytes: 1024,
      vaultKeyVersion: 0,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      ...overrides,
    };
  };

  /**
   * As in `document-model.test.ts`: the async `validate()` rather than the
   * deprecated `validateSync()`, adapted back to `ValidationError | undefined`.
   */
  const validationErrorFor = async (
    overrides: Record<string, unknown>,
  ): Promise<mongoose.Error.ValidationError | undefined> => {
    try {
      await new DocumentUpload(makeUpload(overrides)).validate();
      return undefined;
    } catch (error: unknown) {
      return error as mongoose.Error.ValidationError;
    }
  };

  // ── Indexes ───────────────────────────────────────────────────────────

  describe('indexes', () => {
    it('has a TTL index on expiresAt with expireAfterSeconds 0', async () => {
      await DocumentUpload.ensureIndexes();
      const indexes = (await DocumentUpload.collection.indexes()) as {
        key: Record<string, number>;
        expireAfterSeconds?: number;
      }[];

      const ttlIndex = indexes.find((idx) => idx.key['expiresAt'] === 1);
      expect(ttlIndex).toBeDefined();
      // Zero, not a window. Unlike `RefreshToken`, whose TTL deliberately holds a
      // consumed token for the reuse-detection period, there is nothing to learn
      // from an expired staging row: it is dead the instant its deadline passes.
      expect(ttlIndex!.expireAfterSeconds).toBe(0);
    });

    it('has a (userId, createdAt desc) index for listing and the concurrency cap', async () => {
      await DocumentUpload.ensureIndexes();
      const indexes = (await DocumentUpload.collection.indexes()) as {
        key: Record<string, number>;
      }[];

      expect(indexes.some((idx) => idx.key['userId'] === 1 && idx.key['createdAt'] === -1)).toBe(
        true,
      );
    });
  });

  // ── Required fields and bounds ────────────────────────────────────────

  describe('validation', () => {
    it('rejects a staging row with no expiresAt', async () => {
      // A row the TTL index cannot reap is a transfer that holds bucket space and
      // quota forever, and one the garbage collector's "no live staging row claims
      // this object" test would keep treating as live.
      const error = await validationErrorFor({ expiresAt: undefined });
      expect(error?.errors['expiresAt']?.kind).toBe('required');
      expect(Object.keys(error?.errors ?? {})).toEqual(['expiresAt']);
    });

    it.each([
      'userId',
      'objectKey',
      'encryptedDek',
      'dekIv',
      'dekTag',
      'streamSalt',
      'noncePrefix',
      'declaredPlaintextBytes',
      'declaredChunkCount',
      'chunkPlaintextBytes',
      'vaultKeyVersion',
    ])('rejects a staging row with no %s', async (field) => {
      expect((await validationErrorFor({ [field]: undefined }))?.errors[field]?.kind).toBe(
        'required',
      );
    });

    it.each([
      ['objectKey', 200],
      ['encryptedDek', 200],
      ['streamSalt', 64],
      ['s3UploadId', 1024],
    ])('accepts %s at its bound and rejects it one character over', async (field, max) => {
      expect(await validationErrorFor({ [field]: 'a'.repeat(max) })).toBeUndefined();
      expect(
        (await validationErrorFor({ [field]: 'a'.repeat(max + 1) }))?.errors[field]?.kind,
      ).toBe('maxlength');
    });

    it('refuses a negative declaredPlaintextBytes and accepts an empty document', async () => {
      expect(
        (await validationErrorFor({ declaredPlaintextBytes: -1 }))?.errors['declaredPlaintextBytes']
          ?.kind,
      ).toBe('min');
      // Zero bytes is a legal upload: one segment holding a bare tag.
      expect(await validationErrorFor({ declaredPlaintextBytes: 0 })).toBeUndefined();
    });

    it('bounds declaredChunkCount between 1 and MAX_DOCUMENT_CHUNK_COUNT', async () => {
      expect(
        (await validationErrorFor({ declaredChunkCount: 0 }))?.errors['declaredChunkCount']?.kind,
      ).toBe('min');
      expect(
        (await validationErrorFor({ declaredChunkCount: MAX_DOCUMENT_CHUNK_COUNT + 1 }))?.errors[
          'declaredChunkCount'
        ]?.kind,
      ).toBe('max');
      expect(
        await validationErrorFor({ declaredChunkCount: MAX_DOCUMENT_CHUNK_COUNT }),
      ).toBeUndefined();
    });

    it('refuses a chunkPlaintextBytes of zero and a negative vaultKeyVersion or receivedBytes', async () => {
      expect(
        (await validationErrorFor({ chunkPlaintextBytes: 0 }))?.errors['chunkPlaintextBytes']?.kind,
      ).toBe('min');
      expect(
        (await validationErrorFor({ vaultKeyVersion: -1 }))?.errors['vaultKeyVersion']?.kind,
      ).toBe('min');
      expect((await validationErrorFor({ receivedBytes: -1 }))?.errors['receivedBytes']?.kind).toBe(
        'min',
      );
    });
  });

  describe('the part ledger', () => {
    const part = (overrides: Record<string, unknown> = {}) => ({
      partNumber: 1,
      etag: '"d41d8cd98f00b204e9800998ecf8427e"',
      bytes: DOCUMENT_TAG_BYTES,
      ...overrides,
    });

    it('accepts a part at both size extremes: a bare tag and a full ciphertext chunk', async () => {
      expect(
        await validationErrorFor({ parts: [part({ bytes: DOCUMENT_TAG_BYTES })] }),
      ).toBeUndefined();
      expect(
        await validationErrorFor({ parts: [part({ bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES })] }),
      ).toBeUndefined();
    });

    it.each([
      ['one byte under a bare tag', DOCUMENT_TAG_BYTES - 1, 'min'],
      ['one byte over a full ciphertext chunk', DOCUMENT_CIPHERTEXT_CHUNK_BYTES + 1, 'max'],
    ])('refuses a part of %s', async (_label, bytes, kind) => {
      // A part smaller than one tag cannot be a sealed segment at all, and one
      // larger than a ciphertext chunk means the framing has already diverged —
      // which is exactly the desynchronisation the server exists to catch, since
      // the storage engine will happily accept it.
      const error = await validationErrorFor({ parts: [part({ bytes })] });
      expect(error?.errors['parts.0.bytes']?.kind).toBe(kind);
    });

    it('bounds partNumber between 1 and MAX_DOCUMENT_CHUNK_COUNT, and requires an etag', async () => {
      // S3 part numbers are 1-based while segment indices are 0-based, so a part
      // numbered 0 is a caller that has confused the two.
      expect(
        (await validationErrorFor({ parts: [part({ partNumber: 0 })] }))?.errors[
          'parts.0.partNumber'
        ]?.kind,
      ).toBe('min');
      expect(
        (await validationErrorFor({ parts: [part({ partNumber: MAX_DOCUMENT_CHUNK_COUNT + 1 })] }))
          ?.errors['parts.0.partNumber']?.kind,
      ).toBe('max');
      expect(
        (await validationErrorFor({ parts: [part({ etag: undefined })] }))?.errors['parts.0.etag']
          ?.kind,
      ).toBe('required');
    });
  });

  // ── Stored shape ──────────────────────────────────────────────────────

  describe('stored rows', () => {
    it('lives in the `document_uploads` collection', () => {
      // Load-bearing, and invisible without this assertion: Mongoose's default
      // pluralisation of `DocumentUpload` is `documentuploads`, so dropping the
      // explicit `collection` option renames the collection while every test in
      // this repository — all of which go through the model — stays green. The
      // name is fixed by PLAN Section 1.5, and a rename would surface only as an
      // empty collection on a deployed database after an upgrade.
      expect(DocumentUpload.collection.collectionName).toBe('document_uploads');
    });

    it('starts with an empty ledger, no received bytes and no multipart handle', async () => {
      const created = await DocumentUpload.create(makeUpload());

      expect(created.parts).toEqual([]);
      expect(created.receivedBytes).toBe(0);

      // Read raw, because a hydrated read cannot tell an absent field from a
      // defaulted one. `s3UploadId` must be genuinely ABSENT for a single-segment
      // transfer: its absence is what tells completion to expect a `PutObject`
      // rather than a multipart complete, so a `default: ''` would silently route
      // an empty-string handle into the engine.
      const raw = await DocumentUpload.collection.findOne({ _id: created._id });
      expect(raw).not.toBeNull();
      expect(Object.hasOwn(raw!, 's3UploadId')).toBe(false);
      expect(raw!['receivedBytes']).toBe(0);
    });

    it('stores each part as a bare {partNumber, etag, bytes} with no _id of its own', async () => {
      const created = await DocumentUpload.create(
        makeUpload({
          parts: [{ partNumber: 1, etag: '"abc"', bytes: DOCUMENT_TAG_BYTES }],
          receivedBytes: DOCUMENT_TAG_BYTES,
        }),
      );

      // The sub-schema sets `_id: false`. Without it Mongoose mints an ObjectId
      // per part, which inflates a 10,000-entry ledger and changes the stored
      // shape — and `documentUploadResponseSchema`'s STRIP mode would hide the
      // extra key on the wire, so nothing else in the system would ever say so.
      const raw = (await DocumentUpload.collection.findOne({ _id: created._id })) as {
        parts: Record<string, unknown>[];
      } | null;
      expect(raw).not.toBeNull();
      expect(raw!.parts).toHaveLength(1);
      expect(Object.keys(raw!.parts[0]!).sort()).toEqual(['bytes', 'etag', 'partNumber']);
    });

    it('stamps createdAt and deliberately no updatedAt', async () => {
      const created = await DocumentUpload.create(makeUpload());
      const raw = await DocumentUpload.collection.findOne({ _id: created._id });

      expect(raw!['createdAt']).toBeInstanceOf(Date);
      // NEGATIVE, and it is a decision rather than an omission: the row's lifetime
      // is decided solely by `expiresAt`, which is set once at init and never
      // slides. An `updatedAt` stamped when a part arrives, beside a TTL that
      // ignores it, invites the belief that sending parts keeps a transfer alive.
      expect(Object.hasOwn(raw!, 'updatedAt')).toBe(false);
    });
  });

  // ── The shared field group ────────────────────────────────────────────

  describe('shared field definitions', () => {
    it.each([
      ['wrappedDekPaths', wrappedDekPaths],
      ['streamFramingPaths', streamFramingPaths],
    ])('%s returns a fresh object each call rather than one shared literal', (_label, factory) => {
      // The contract `documentFields.ts` states in prose, pinned. Mongoose keeps a
      // reference to the options object it is handed (`SchemaType.prototype.options`),
      // so exporting these as shared `const`s would give the staging schema and the
      // committed schema one object with two owners. Converting either factory to a
      // shared literal leaves every other test in this phase green.
      expect(factory()).not.toBe(factory());
      expect(factory()).toStrictEqual(factory());
    });

    it.each(['encryptedDek', 'dekIv', 'dekTag', 'streamSalt', 'noncePrefix'])(
      'declares the same bound for %s as the committed document row does',
      (field) => {
        // `models/documentFields.ts` exists so these five paths are written once.
        // This is what fails if a future edit re-inlines one copy and changes it:
        // the staging row and the committed row would then disagree about how long
        // a wrapped DEK may be, and the disagreement would first appear as an
        // upload that completes and a document that will not open.
        const staging = DocumentUpload.schema.path(field).options as { maxlength?: number };
        const committed = Document.schema.path(field).options as { maxlength?: number };

        expect(staging.maxlength).toBeTypeOf('number');
        expect(staging.maxlength).toBe(committed.maxlength);
      },
    );
  });
});

/**
 * `User.vaultKeyVersion` lives in this file rather than in a user-model suite
 * because it has exactly one purpose: to be compared with the version recorded on
 * a staging row above. It is incremented ONLY by a successful vault-key rotation,
 * and a password change must never touch it — that flow re-wraps the same vault
 * key under a new MEK, so an upload spanning it is still valid.
 */
describe('User.vaultKeyVersion', () => {
  const validUser = (email: string) => ({
    email,
    authHash: 'hash',
    encryptedVaultKey: 'key',
    vaultKeyIv: 'iv',
    vaultKeyTag: 'tag',
  });

  it('starts at 0 for a newly created account', async () => {
    const user = await User.create(validUser('vkv-new@example.com'));
    expect(user.vaultKeyVersion).toBe(0);
  });

  it('is ABSENT, not 0, on an account that predates the field — through a lean read', async () => {
    // Inserted through the raw driver precisely because that is how an account
    // created by an earlier release exists: no Mongoose default was ever applied
    // to it, and there is no backfill migration.
    const { insertedId } = await User.collection.insertOne(validUser('vkv-legacy@example.com'));

    const raw = await User.collection.findOne({ _id: insertedId });
    expect(Object.hasOwn(raw!, 'vaultKeyVersion')).toBe(false);

    const lean = await User.findById(insertedId).lean();
    expect(lean).not.toBeNull();
    expect(lean?.vaultKeyVersion).toBeUndefined();
  });

  it('reads as 0 through a HYDRATED read of that same legacy account, which is why the lean case above exists', async () => {
    const { insertedId } = await User.collection.insertOne(validUser('vkv-hydrated@example.com'));

    // Mongoose applies the schema default on the way out, so a hydrated read
    // CANNOT distinguish a stored 0 from a missing field. Every hot path here
    // (`getProfile`, the upload-init read, the completion check) uses `.lean()`,
    // so a test written against this read alone would prove nothing at all about
    // the value those paths actually see.
    const hydrated = await User.findById(insertedId);
    expect(hydrated?.vaultKeyVersion).toBe(0);

    // NEGATIVE: reading it hydrated did not write it back.
    const raw = await User.collection.findOne({ _id: insertedId });
    expect(Object.hasOwn(raw!, 'vaultKeyVersion')).toBe(false);
  });

  it('treats the missing field as 0 under $inc, which is what the rotation increment relies on', async () => {
    const { insertedId } = await User.collection.insertOne(validUser('vkv-inc@example.com'));

    // The rotation applies `$inc: { vaultKeyVersion: 1 }` in the SAME update
    // document that `$set`s the new vault key, rather than a value computed from a
    // prior read (which would be racy: the handler's read happens before it takes
    // the rotation lock). MongoDB creates a missing field at 0 and then increments
    // it, so a legacy account needs no backfill to take part.
    await User.updateOne({ _id: insertedId }, { $inc: { vaultKeyVersion: 1 } });

    const lean = await User.findById(insertedId).lean();
    expect(lean?.vaultKeyVersion).toBe(1);
  });

  it('is not backfilled by an unrelated write, so consumers must keep reading it as `?? 0`', async () => {
    const { insertedId } = await User.collection.insertOne(validUser('vkv-untouched@example.com'));

    await User.updateOne({ _id: insertedId }, { $set: { emailVerified: true } });

    // The absence survives every write that is not the rotation's own `$inc`.
    // Anything that assumed a `number` here would be doing arithmetic on
    // `undefined` the first time it met an account older than this release.
    const raw = await User.collection.findOne({ _id: insertedId });
    expect(raw!['emailVerified']).toBe(true);
    expect(Object.hasOwn(raw!, 'vaultKeyVersion')).toBe(false);
  });
});
