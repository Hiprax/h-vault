/**
 * F-24: the JavaScript measure of a row agrees with the database, byte for byte.
 *
 * The vault byte counter is moved by deltas computed in JavaScript
 * (`BSON.serialize` of what was written) and corrected by totals the DATABASE
 * computes (`$bsonSize`). If the two ever disagreed on one row, every write of
 * that row would drift the counter by the difference, and the hourly recount would
 * pull it back each time: a counter that is wrong between recounts, by an amount
 * the account chooses. These properties draw rows of every shape the API can store
 * (any code point, lone surrogates, NUL, `-0`, empty and maximal arrays) and hold
 * three measures to the database's:
 *
 * 1. a stored row's counted size;
 * 2. the size a create PREDICTS (what it reserves) for that row;
 * 3. the change a pinned update PREDICTS against the change it actually makes.
 *
 * `calculateObjectSize` failed (1) on `-0` (12 bytes against the 16 stored), which
 * is why the module measures with `serialize`.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import mongoose from 'mongoose';
import { ITEM_TYPES } from '@hvault/shared';
import { VaultItem } from '../../src/models/VaultItem.js';
import { Folder } from '../../src/models/Folder.js';
import {
  countedBytes,
  countedBytesExpression,
  countedBytesOfNew,
  deltaOfPinnedUpdate,
  measureStoredRows,
  storedImage,
  versionPin,
  type CountedKind,
} from '../../src/utils/vaultQuota.js';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/**
 * Cases per property. Each case is two to four round trips to the in-memory
 * database (a create, a measure, an update): measured at about 5 ms a case here,
 * so 40 cases cost ~0.25 s per property (measured: 0.99 s for all four), in each of the three
 * gates that run this file.
 */
const MEASURE_RUNS = 40;

/** Any string at all, and half the time one built from the awkward characters. */
const AWKWARD = fc.constantFrom('\u0000', '\ud800', '\udfff', '\u{1f600}', 'é', '"', '\\', '\n');
const anyText = (minLength: number, maxLength: number) =>
  fc.oneof(
    fc.string({ unit: 'binary', minLength, maxLength }),
    fc.string({ unit: AWKWARD, minLength, maxLength }),
  );

const owner = new mongoose.Types.ObjectId();

/** Up to ten retained passwords, as an item stores them. */
const passwordHistory = fc.array(
  fc.record({
    encryptedPassword: anyText(1, 200),
    iv: anyText(1, 24),
    tag: anyText(1, 32),
    changedAt: fc.date({
      min: new Date('2000-01-01T00:00:00Z'),
      max: new Date('2100-01-01T00:00:00Z'),
      noInvalidDate: true,
    }),
  }),
  { maxLength: 10 },
);
const searchHash = fc.stringMatching(/^[a-f0-9]{64}$/);

const itemFields = fc.record(
  {
    itemType: fc.constantFrom(...ITEM_TYPES),
    encryptedData: anyText(1, 600),
    dataIv: anyText(1, 24),
    dataTag: anyText(1, 32),
    encryptedName: anyText(1, 120),
    nameIv: anyText(1, 24),
    nameTag: anyText(1, 32),
    searchHash,
    tags: fc.array(anyText(1, 50), { maxLength: 20 }),
    favorite: fc.boolean(),
    passwordHistory,
    folderId: fc.constant(new mongoose.Types.ObjectId()),
    deletedAt: fc.date({ noInvalidDate: true }),
  },
  {
    requiredKeys: [
      'itemType',
      'encryptedData',
      'dataIv',
      'dataTag',
      'encryptedName',
      'nameIv',
      'nameTag',
    ],
  },
);

const folderFields = fc.record(
  {
    encryptedName: anyText(1, 200),
    nameIv: anyText(1, 24),
    nameTag: anyText(1, 32),
    searchHash,
    // `-0` included on purpose: the API normalises it now, but a row stored
    // before that (or written by anything else) can hold it.
    sortOrder: fc.oneof(fc.constant(-0), fc.integer({ min: 0, max: 10_000 })),
    icon: anyText(0, 50),
    color: anyText(0, 20),
    parentId: fc.constant(new mongoose.Types.ObjectId()),
  },
  { requiredKeys: ['encryptedName', 'nameIv', 'nameTag'] },
);

/** The database's own counted size of one stored row. */
async function databaseCounted(kind: CountedKind, id: mongoose.Types.ObjectId): Promise<number> {
  const model = kind === 'item' ? VaultItem : Folder;
  const [row] = await model.collection
    .find({ _id: id }, { projection: { counted: countedBytesExpression(kind) } })
    .toArray();
  return Number(row?.['counted']);
}

async function createRow(kind: CountedKind, fields: Record<string, unknown>) {
  const data = { userId: owner, ...fields };
  return kind === 'item' ? VaultItem.create(data) : Folder.create(data);
}

describe("the JavaScript measure of a row equals the database's", () => {
  for (const [kind, arbitrary] of [
    ['item', itemFields],
    ['folder', folderFields],
  ] as const) {
    it(`a stored ${kind}, and what its create predicted`, async () => {
      await fc.assert(
        fc.asyncProperty(arbitrary, async (fields) => {
          const data = { userId: owner, ...fields } as Record<string, unknown>;
          const predicted = countedBytesOfNew(kind, data);
          const doc = await createRow(kind, fields as Record<string, unknown>);
          const stored = await databaseCounted(kind, doc._id);

          expect(countedBytes(kind, storedImage(doc)), propertyBanner()).toBe(stored);
          expect(predicted, propertyBanner()).toBe(stored);
        }),
        propertyRun({ numRuns: MEASURE_RUNS }),
      );
    });
  }

  it('a pinned update of an item changes the stored size by exactly what was predicted', async () => {
    await fc.assert(
      fc.asyncProperty(
        itemFields,
        fc.record(
          {
            // Every field a counted item write sets: the per-request update, the
            // import overwrite and the rotation (and the rotation's rollback).
            encryptedData: anyText(1, 600),
            dataIv: anyText(1, 24),
            dataTag: anyText(1, 32),
            encryptedName: anyText(1, 120),
            nameIv: anyText(1, 24),
            nameTag: anyText(1, 32),
            searchHash,
            passwordHistory,
            tags: fc.array(anyText(1, 50), { maxLength: 20 }),
            favorite: fc.boolean(),
          },
          { requiredKeys: [] },
        ),
        fc.subarray(['searchHash', 'passwordHistory', 'tags'] as const),
        async (fields, set, unsetFields) => {
          const doc = await createRow('item', fields as Record<string, unknown>);
          const update = {
            $set: set as Record<string, unknown>,
            ...(unsetFields.length > 0
              ? {
                  $unset: Object.fromEntries(
                    unsetFields.filter((f) => !(f in set)).map((f) => [f, 1]),
                  ),
                }
              : {}),
          };
          const [measure] = await measureStoredRows('item', { _id: doc._id }, update);
          const before = await databaseCounted('item', doc._id);
          // Through the model, as every counted write is: its casting and its
          // `updatedAt` are part of what the prediction must account for.
          const result = await VaultItem.updateOne(
            { _id: doc._id, ...versionPin(measure!) },
            { ...update, $inc: { __v: 1 } },
            { runValidators: true },
          );
          const after = await databaseCounted('item', doc._id);

          expect(result.matchedCount, propertyBanner()).toBe(1);
          expect(measure!.counted, propertyBanner()).toBe(before);
          expect(deltaOfPinnedUpdate('item', measure!, update), propertyBanner()).toBe(
            after - before,
          );
        },
      ),
      propertyRun({ numRuns: MEASURE_RUNS }),
    );
  });

  it('a pinned update of a folder changes the stored size by exactly what was predicted', async () => {
    await fc.assert(
      fc.asyncProperty(
        folderFields,
        fc.record(
          {
            // What a rename, a reorder, a rotation and its rollback set.
            encryptedName: anyText(1, 200),
            nameIv: anyText(1, 24),
            nameTag: anyText(1, 32),
            searchHash,
            sortOrder: fc.oneof(fc.constant(-0), fc.integer({ min: 0, max: 10_000 })),
            icon: anyText(0, 50),
            color: anyText(0, 20),
          },
          { requiredKeys: [] },
        ),
        fc.subarray(['searchHash', 'icon', 'color'] as const),
        async (fields, set, unsetFields) => {
          const doc = await createRow('folder', fields as Record<string, unknown>);
          const update = {
            $set: set as Record<string, unknown>,
            ...(unsetFields.length > 0
              ? {
                  $unset: Object.fromEntries(
                    unsetFields.filter((f) => !(f in set)).map((f) => [f, 1]),
                  ),
                }
              : {}),
          };
          const [measure] = await measureStoredRows('folder', { _id: doc._id }, update);
          const before = await databaseCounted('folder', doc._id);
          const result = await Folder.updateOne(
            { _id: doc._id, ...versionPin(measure!) },
            { ...update, $inc: { __v: 1 } },
            { runValidators: true },
          );
          const after = await databaseCounted('folder', doc._id);

          expect(result.matchedCount, propertyBanner()).toBe(1);
          expect(deltaOfPinnedUpdate('folder', measure!, update), propertyBanner()).toBe(
            after - before,
          );
        },
      ),
      propertyRun({ numRuns: MEASURE_RUNS }),
    );
  });
});
