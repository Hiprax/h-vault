/**
 * F-24 on a replica set: the transactional branches keep the vault byte counter
 * exact. A rotation, a re-seal, an import and a folder delete each commit their
 * rows and their count together (or count only after the commit), and an update
 * that measured a row before a rotation rewrote it measures it again.
 *
 * The ground truth is the database's own total (`support/vaultBytes.ts`).
 */
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { User } from '../src/models/User.js';
import { supportsTransactions } from '../src/utils/transactionSupport.js';
import { useReplicaSetConnection } from './mongoHarness.js';
import { createTestUser, sampleFolder, type TestUser } from './helpers.js';
import {
  apiCall,
  createQuotaItem,
  expectCounterExact,
  quotaItemBody,
} from './support/vaultQuotaApi.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** The stored vault-key generation, which a re-seal must name. */
async function vaultKeyVersionOf(userId: string): Promise<number> {
  const row = await mongoose.connection
    .collection('users')
    .findOne({ _id: new mongoose.Types.ObjectId(userId) }, { projection: { vaultKeyVersion: 1 } });
  return (row?.['vaultKeyVersion'] as number | undefined) ?? 0;
}

function rotationBody(
  user: TestUser,
  items: Record<string, unknown>[],
  folders: Record<string, unknown>[],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    authHash: user.rawPassword,
    newEncryptedVaultKey: 'rotated-key',
    newVaultKeyIv: 'rotated-iv',
    newVaultKeyTag: 'rotated-tag',
    items,
    folders,
    documents: [],
    vaultFieldFormat: 2,
    ...extra,
  };
}

function rotatedItem(id: string, dataBytes: number, ivPrefix = ''): Record<string, unknown> {
  return {
    id,
    encryptedName: 'rotated-item-name',
    nameIv: `${ivPrefix}rot-name-iv`,
    nameTag: 'rot-name-tag',
    encryptedData: 'r'.repeat(dataBytes),
    dataIv: `${ivPrefix}rot-data-iv`,
    dataTag: 'rot-data-tag',
  };
}

describe('the vault byte counter on a replica set (transactional branches)', () => {
  useReplicaSetConnection();

  beforeAll(() => {
    // Without this the block would silently test the sequential fallback.
    expect(supportsTransactions()).toBe(true);
  });

  it('a rotation and then a re-seal move the counter with their rows, in their transactions', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 1_000);
    const b = await createQuotaItem(user, 2_000);
    const folder = await apiCall(user, 'post', '/folders', sampleFolder());
    expect(folder.status).toBe(201);
    const folderId = String(folder.body.data._id);
    const before = await expectCounterExact(user);

    // The rotation grows one row and shrinks the other.
    const rotated = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationBody(
        user,
        [rotatedItem(a, 4_000), rotatedItem(b, 100)],
        [{ id: folderId, encryptedName: 'rotated-folder', nameIv: 'rf-iv', nameTag: 'rf-tag' }],
      ),
    );
    expect(rotated.status).toBe(200);
    const afterRotation = await expectCounterExact(user);
    expect(afterRotation).not.toBe(before);

    // The re-seal: same key, rows rewritten with `v2:` IVs (longer), so its own
    // change is not zero.
    const resealed = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationBody(
        user,
        [rotatedItem(a, 4_000, 'v2:'), rotatedItem(b, 100, 'v2:')],
        [
          {
            id: folderId,
            encryptedName: 'rotated-folder',
            nameIv: 'v2:rf-iv',
            nameTag: 'rf-tag',
          },
        ],
        {
          reseal: true,
          idempotencyKey: '0f8fad5b-d9cb-469f-a165-70867728950e',
          vaultKeyVersion: await vaultKeyVersionOf(user.id),
        },
      ),
    );
    expect(resealed.status).toBe(200);
    expect(await expectCounterExact(user)).toBeGreaterThan(afterRotation);
  });

  it('a rotation whose transaction is retried counts its change once', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    // The first attempt fails at its last write with a transient error, so
    // `withTransaction` aborts it and runs the whole callback again: the counter
    // write of the first attempt must have been rolled back with its rows.
    const real = User.updateOne.bind(User) as (...args: unknown[]) => unknown;
    let keyWrites = 0;
    vi.spyOn(User, 'updateOne').mockImplementation(((...args: unknown[]) => {
      const update = args[1] as { $inc?: { vaultKeyVersion?: unknown } };
      if (update.$inc?.vaultKeyVersion === 1) {
        keyWrites += 1;
        if (keyWrites === 1) {
          return Promise.reject(
            new mongoose.mongo.MongoServerError({
              message: 'simulated write conflict',
              code: 112,
              errorLabels: ['TransientTransactionError'],
            }),
          );
        }
      }
      return real(...args);
    }) as never);

    const rotated = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationBody(user, [rotatedItem(a, 6_000)], []),
    );

    expect(rotated.status).toBe(200);
    expect(keyWrites).toBe(2);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe('r'.repeat(6_000));
    await expectCounterExact(user);
  });

  it('a rotation the coverage check refuses rolls its rows AND its count back', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 1_000);
    await createQuotaItem(user, 1_000); // not named by the rotation below
    const before = await expectCounterExact(user);

    const refused = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationBody(user, [rotatedItem(a, 9_000)], []),
    );

    expect(refused.status).toBe(409);
    expect((await VaultItem.findById(a).lean())?.encryptedData).toBe('d'.repeat(1_000));
    expect(await expectCounterExact(user)).toBe(before);
  });

  it('an update that measured a row before a re-seal rewrote it measures it again', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 1_000);
    await expectCounterExact(user);

    // Between the update's measure and its pinned write, a RE-SEAL rewrites the
    // row under the same key (and only bumps `__v` to tell it so). A re-seal and
    // not a rotation: after a rotation the update's re-check refuses it, because
    // its ciphertext is sealed under the key the rotation retired
    // (save-rotation-race.test.ts holds that); the same key leaves it valid, and
    // what this case pins is that its second measure is counted exactly once.
    const real = mongoose.mongo.Collection.prototype.findOneAndUpdate;
    let reseal: Awaited<ReturnType<typeof apiCall>> | undefined;
    let updateWrites = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'findOneAndUpdate').mockImplementation(
      async function (this: mongoose.mongo.Collection, ...args: Parameters<typeof real>) {
        const update = args[1] as { $set?: { encryptedData?: unknown } };
        if (
          this.collectionName === 'vault_items' &&
          update.$set?.encryptedData === 'u'.repeat(3_000)
        ) {
          updateWrites += 1;
          if (updateWrites === 1) {
            const stored = await User.findById(user.id)
              .select('encryptedVaultKey vaultKeyIv vaultKeyTag')
              .lean();
            reseal = await apiCall(
              user,
              'post',
              '/vault/items/bulk-reencrypt',
              rotationBody(user, [rotatedItem(id, 7_000, 'v2:')], [], {
                newEncryptedVaultKey: stored?.encryptedVaultKey,
                newVaultKeyIv: stored?.vaultKeyIv,
                newVaultKeyTag: stored?.vaultKeyTag,
                reseal: true,
                idempotencyKey: '00000000-0000-4000-8000-000000000017',
                vaultKeyVersion: await vaultKeyVersionOf(user.id),
              }),
            );
          }
        }
        return real.apply(this, args);
      } as never,
    );

    const updated = await apiCall(user, 'put', `/vault/items/${id}`, {
      encryptedData: 'u'.repeat(3_000),
      dataIv: 'test-data-iv',
      dataTag: 'test-data-tag',
    });

    expect(reseal?.status).toBe(200);
    expect(updated.status).toBe(200);
    expect(updateWrites).toBe(2);
    expect((await VaultItem.findById(id).lean())?.encryptedData).toBe('u'.repeat(3_000));
    await expectCounterExact(user);
  });

  it('an import (inserts and an overwrite) commits its rows and is counted once', async () => {
    const user = await createTestUser();
    const target = await createQuotaItem(user, 900);
    await expectCounterExact(user);

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [
          quotaItemBody(2_000, { searchHash: 'e'.repeat(64) }),
          quotaItemBody(30, { searchHash: 'e'.repeat(64) }),
        ],
        updates: [
          {
            id: target,
            encryptedName: 'overwritten',
            nameIv: 'o-iv',
            nameTag: 'o-tag',
            encryptedData: 'o'.repeat(5_000),
            dataIv: 'o-data-iv',
            dataTag: 'o-data-tag',
            searchHash: 'e'.repeat(64),
          },
        ],
      },
    });

    expect(res.status).toBe(201);
    expect(res.body.data).toMatchObject({ insertedCount: 2, updatedCount: 1 });
    await expectCounterExact(user);
  });

  it('an import whose transaction aborts hands its whole reservation back', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    const before = await expectCounterExact(user);

    vi.spyOn(VaultItem, 'insertMany').mockRejectedValue(
      new Error('simulated failure inside the transaction'),
    );

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [quotaItemBody(4_000, { searchHash: 'f'.repeat(64) })],
        updates: [],
      },
    });

    expect(res.status).toBe(500);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await expectCounterExact(user)).toBe(before);
  });

  it('an import whose session cannot be opened hands its whole reservation back', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    const before = await expectCounterExact(user);
    vi.spyOn(mongoose, 'startSession').mockRejectedValueOnce(new Error('no session available'));

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [quotaItemBody(4_000, { searchHash: 'f'.repeat(64) })],
        updates: [],
      },
    });

    expect(res.status).toBe(500);
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(1);
    expect(await expectCounterExact(user)).toBe(before);
  });

  it('an import whose commit outcome is unknown keeps its reservation (it did commit)', async () => {
    const user = await createTestUser();
    await createQuotaItem(user, 900);
    await expectCounterExact(user);

    // The transaction commits, then the answer is lost: the driver reports the
    // commit's outcome as unknown.
    const realWithTransaction = mongoose.mongo.ClientSession.prototype.withTransaction;
    vi.spyOn(mongoose.mongo.ClientSession.prototype, 'withTransaction').mockImplementationOnce(
      async function (this: mongoose.mongo.ClientSession, ...args: unknown[]) {
        await (realWithTransaction as (...a: unknown[]) => Promise<unknown>).apply(this, args);
        throw new mongoose.mongo.MongoServerError({
          message: 'commit outcome unknown',
          code: 50,
          errorLabels: ['UnknownTransactionCommitResult'],
        });
      } as never,
    );

    const res = await apiCall(user, 'post', '/tools/import', {
      format: 'json',
      operations: {
        inserts: [quotaItemBody(4_000, { searchHash: 'f'.repeat(64) })],
        updates: [],
      },
    });

    expect(res.status).toBe(500);
    // The rows landed, and the reservation made for them stayed: exact.
    expect(await VaultItem.countDocuments({ userId: user.id })).toBe(2);
    await expectCounterExact(user);
  });

  it('deleting a folder (its items trashed, or moved to its parent) keeps the counter exact', async () => {
    const user = await createTestUser();
    const parent = await apiCall(user, 'post', '/folders', sampleFolder());
    const parentId = String(parent.body.data._id);
    const first = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'first-child', parentId }),
    );
    const second = await apiCall(
      user,
      'post',
      '/folders',
      sampleFolder({ encryptedName: 'second-child', parentId }),
    );
    const inFirst = await createQuotaItem(user, 1_200, { folderId: String(first.body.data._id) });
    await createQuotaItem(user, 1_400, { folderId: String(second.body.data._id) });
    await expectCounterExact(user);

    const deleted = await apiCall(
      user,
      'delete',
      `/folders/${String(first.body.data._id)}?action=delete`,
    );
    expect(deleted.status).toBe(200);
    expect((await VaultItem.findById(inFirst).lean())?.deletedAt).toBeInstanceOf(Date);
    await expectCounterExact(user);

    const moved = await apiCall(
      user,
      'delete',
      `/folders/${String(second.body.data._id)}?action=move`,
    );
    expect(moved.status).toBe(200);
    expect(await Folder.countDocuments({ userId: user.id })).toBe(1);
    await expectCounterExact(user);
  });
});
