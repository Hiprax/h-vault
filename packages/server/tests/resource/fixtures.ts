/**
 * Full-vault fixtures for the `test:resource` suite.
 *
 * Every scenario here needs a vault at or near `MAX_ITEMS_PER_USER`, which is
 * 10,000 rows — far past what a `create` per item can build in a test. These
 * helpers write the rows the way a loaded account looks, straight through the
 * model, and they are shared so the scenarios cannot drift into measuring several
 * differently-shaped vaults.
 *
 * The ciphertext is filler, and deliberately so: not one assertion in this
 * directory decrypts anything. What the scenarios measure is BYTES and ROWS
 * moving through cursors, parsers and update loops, and the server treats every
 * `encryptedData` as an opaque string, so a real AES-GCM payload would cost
 * seconds of key derivation to produce a value nothing reads.
 */
import mongoose from 'mongoose';
import { VaultItem } from '../../src/models/VaultItem.js';
import { User } from '../../src/models/User.js';

/** How many rows are written per `insertMany`. */
const INSERT_CHUNK = 500;

/** Fixed-width filler for the fields whose LENGTH is what a scenario varies. */
const IV = 'i'.repeat(16);
const TAG = 't'.repeat(22);

export interface VaultShape {
  /** How many items to write. */
  count: number;
  /** Length of each item's `encryptedData`, which dominates every size estimate. */
  dataBytes: number;
  /** Password-history entries per item. Quote-dense: 4 keys and 4 values each. */
  historyEntries?: number;
  /** Tags per item. Quote-dense: two quotes and a comma per entry. */
  tags?: number;
}

/** One item document, shaped by {@link VaultShape}. */
function buildItemDoc(userId: string, index: number, shape: VaultShape): Record<string, unknown> {
  const history = Array.from({ length: shape.historyEntries ?? 0 }, (_unused, h) => ({
    encryptedPassword: `h${String(index)}-${String(h)}`.padEnd(24, 'p'),
    iv: IV,
    tag: TAG,
    changedAt: new Date(Date.UTC(2026, 0, 1 + (h % 27))),
  }));
  return {
    userId,
    itemType: 'login',
    encryptedData: 'd'.repeat(shape.dataBytes),
    dataIv: IV,
    dataTag: TAG,
    encryptedName: `name-${String(index)}`.padEnd(40, 'n'),
    nameIv: IV,
    nameTag: TAG,
    // A 64-hex string, which is what the model's `match` validator accepts and
    // what the restore path's SEARCH_HASH_RE checks. Derived from the index so
    // every row differs, because a shared value would collide on the unique
    // partial index the folder model carries and would make items indistinguishable.
    searchHash: index.toString(16).padStart(64, '0'),
    tags: Array.from({ length: shape.tags ?? 0 }, (_unused, t) => `t${String(t)}`),
    favorite: false,
    ...(history.length > 0 ? { passwordHistory: history } : {}),
  };
}

/**
 * Writes `shape.count` items for `userId` and returns how long it took plus the
 * measured BSON footprint, so a scenario can report the volume it actually
 * exercised rather than the volume it intended to.
 */
export async function seedVault(
  userId: string,
  shape: VaultShape,
): Promise<{ count: number; seedMs: number; collectionBytes: number }> {
  const startedAt = Date.now();
  for (let base = 0; base < shape.count; base += INSERT_CHUNK) {
    const docs: Record<string, unknown>[] = [];
    for (let i = base; i < Math.min(base + INSERT_CHUNK, shape.count); i++) {
      docs.push(buildItemDoc(userId, i, shape));
    }
    await VaultItem.insertMany(docs, { ordered: false });
  }
  const db = mongoose.connection.db;
  if (!db) throw new Error('seedVault() called without a live mongoose connection');
  const stats = (await db.command({ collStats: VaultItem.collection.collectionName })) as {
    size?: number;
  };
  return {
    count: shape.count,
    seedMs: Date.now() - startedAt,
    collectionBytes: stats.size ?? 0,
  };
}

/**
 * Marks backup encryption as configured for a user.
 *
 * Written straight to the document rather than driven through `POST
 * /backup/setup`, because that endpoint costs a bcrypt compare and a CSRF round
 * trip to establish a precondition none of these scenarios is measuring. The
 * fields are the ones `triggerBackup` and `downloadBackup` read before they
 * reach `collectBackupData`.
 */
export async function configureBackupEncryption(userId: string): Promise<void> {
  await User.updateOne(
    { _id: userId },
    {
      $set: {
        'settings.backup.isConfigured': true,
        'settings.backup.encryptedBWK': 'resource-suite-bwk',
        'settings.backup.bwkIv': IV,
        'settings.backup.bwkTag': TAG,
        'settings.backup.bwkSalt': 's'.repeat(32),
      },
    },
  );
}
