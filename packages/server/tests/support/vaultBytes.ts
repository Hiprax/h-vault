/**
 * The ground truth the vault byte quota is held to, measured by the DATABASE.
 *
 * What an account stores, as the quota counts it: for every vault item and folder
 * row it owns (trashed rows included), the BSON size of the stored document minus
 * its placement fields — an item's `deletedAt` and `folderId`, a folder's
 * `parentId`. Those are fixed-size (a Date, an ObjectId), carry nothing a user can
 * fill, and are exactly what trash, restore and move change, which is why those
 * operations are byte-neutral.
 *
 * Measured with `$bsonSize` in an aggregation, never with the application's own
 * JavaScript measure: a test that compared the counter with the code's own
 * arithmetic would agree with any bug in that arithmetic.
 */
import mongoose from 'mongoose';

const withoutFields = (fields: readonly string[]): unknown =>
  fields.reduce<unknown>((input, field) => ({ $unsetField: { field, input } }), '$$ROOT');

async function sumBytes(
  collection: string,
  userId: string,
  placementFields: readonly string[],
): Promise<number> {
  const [row] = await mongoose.connection
    .collection(collection)
    .aggregate<{ bytes: number }>([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      { $group: { _id: null, bytes: { $sum: { $bsonSize: withoutFields(placementFields) } } } },
    ])
    .toArray();
  return row?.bytes ?? 0;
}

/** The counted bytes of every item and folder row `userId` owns, per the database. */
export async function storedVaultBytes(userId: string): Promise<number> {
  const items = await sumBytes('vault_items', userId, ['deletedAt', 'folderId']);
  const folders = await sumBytes('folders', userId, ['parentId']);
  return items + folders;
}

/** The account's counter as stored, or `undefined` when it has none. */
export async function vaultBytesCounter(userId: string): Promise<number | undefined> {
  const user = await mongoose.connection
    .collection('users')
    .findOne({ _id: new mongoose.Types.ObjectId(userId) }, { projection: { vaultBytes: 1 } });
  const value = (user as { vaultBytes?: unknown } | null)?.vaultBytes;
  return typeof value === 'number' ? value : undefined;
}

/**
 * The rows `userId` owns, counted by the database: items (trashed included) and
 * folders, which is what the per-user caps count (F-15).
 */
export async function storedRowCounts(userId: string): Promise<{ items: number; folders: number }> {
  const owner = new mongoose.Types.ObjectId(userId);
  return {
    items: await mongoose.connection.collection('vault_items').countDocuments({ userId: owner }),
    folders: await mongoose.connection.collection('folders').countDocuments({ userId: owner }),
  };
}

/** The account's row counters as stored, each `undefined` when absent. */
export async function rowCounters(
  userId: string,
): Promise<{ items: number | undefined; folders: number | undefined }> {
  const user = await mongoose.connection
    .collection('users')
    .findOne({ _id: new mongoose.Types.ObjectId(userId) }, { projection: { counters: 1 } });
  const counters = (user as { counters?: { items?: unknown; folders?: unknown } } | null)?.counters;
  return {
    items: typeof counters?.items === 'number' ? counters.items : undefined,
    folders: typeof counters?.folders === 'number' ? counters.folders : undefined,
  };
}
