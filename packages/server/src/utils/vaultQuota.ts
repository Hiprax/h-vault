import mongoose, { type ClientSession, type Model } from 'mongoose';
import { ErrorHandler, httpErrors } from '@hiprax/errors';
import { MAX_FOLDERS_PER_USER, MAX_ITEMS_PER_USER } from '@hvault/shared';
import { config } from '../config/index.js';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { createModuleLogger, errorMessage } from './logger.js';

const logger = createModuleLogger('vault-quota');

/**
 * The per-account vault byte quota (F-24): ONE module reads and writes the counter.
 *
 * `User.vaultBytes` is a denormalised count of the bytes an account's vault items
 * and folders occupy, TRASHED ROWS INCLUDED (their bytes stay stored until they are
 * purged), bounded by `VAULT_STORAGE_QUOTA_MB_PER_USER`.
 *
 * WHAT IS COUNTED: for every item and folder row, the BSON size of the stored
 * document minus its PLACEMENT fields (an item's `deletedAt` and `folderId`, a
 * folder's `parentId`). Those are fixed-size, hold nothing a user fills, and are
 * exactly what trash, restore and move change, so those operations are
 * byte-neutral and never counter sites.
 *
 * HOW, for every operation that writes a counted row:
 *
 * 1. RESERVE ({@link reserveVaultWrite}) the predicted growth, never less than zero,
 *    with ONE conditional update refused past the quota, BEFORE the first row is
 *    touched. A zero reservation is made too ("touch first"): it installs a missing
 *    counter and marks the account busy (`quotaEpoch`, `vaultBytesWrittenAt`), which
 *    is what keeps the hourly recount away while the operation runs.
 * 2. Write the rows. A write that changes an EXISTING row's counted bytes is pinned
 *    on that row's `{__v, createdAt}` ({@link versionPin}) and bumps `__v`, so its
 *    change is measured against the exact image it replaced: a delta taken from a stale read is an undercount the account
 *    could repeat. A many-row delete goes row by row, so every row's bytes are
 *    subtracted by the one call that removed it.
 * 3. SETTLE ({@link settleVaultWrite}) the exact difference. Released whole only when
 *    the write certainly did not apply ({@link isDefiniteWriteFailure}); an
 *    ambiguous failure keeps the reservation (an overcount refuses early and the
 *    recount corrects it, while releasing a write that landed would be an undercount).
 *
 * Absolute totals (the inline install, the recount, the migration) are measured BY
 * THE DATABASE (`$bsonSize`), never transferred. Deltas are measured in JS on
 * documents the database returned, with `BSON.serialize`, which is byte-for-byte
 * what the driver stores (`calculateObjectSize` is not: it sizes `-0` as an int32).
 *
 * A write that cannot grow the vault is never refused, however far over the quota
 * the account is: deletes, purges, shrinking updates, rotations and re-seals.
 *
 * THE ROW CAPS (F-15) ride the same machinery. `User.counters.items` and
 * `User.counters.folders` count the account's item and folder rows, trashed rows
 * included (that is what `MAX_ITEMS_PER_USER` and `MAX_FOLDERS_PER_USER` count),
 * and a reservation names the rows it will add beside the bytes, so the bytes and
 * both caps are decided by ONE conditional update before the first insert. A cap
 * read with `countDocuments` and then trusted by an insert let every one of N
 * concurrent requests through. Only an insert adds a row and only a HARD delete
 * removes one (a permanent delete, emptying the trash, the nightly purge, a
 * folder delete); trash, restore and move change neither counter. An absent
 * counter is installed exactly like `vaultBytes`, from the rows, by the first
 * operation that needs it, and never refused for being absent.
 */

export type CountedKind = 'item' | 'folder';

/** The fields of each kind of row that the quota does not count. */
const PLACEMENT_FIELDS: Readonly<Record<CountedKind, readonly string[]>> = {
  item: ['deletedAt', 'folderId'],
  folder: ['parentId'],
};

/** The two counted collections, typed loosely: this module reads and writes them generically. */
type CountedModel = Model<Record<string, unknown>>;

const MODEL_OF: Readonly<Record<CountedKind, CountedModel>> = {
  item: VaultItem as unknown as CountedModel,
  folder: Folder as unknown as CountedModel,
};

/**
 * What a refused growing write is told. Under 200 characters with the remedy
 * first, because the client slices a 4xx message there.
 */
export const VAULT_STORAGE_QUOTA_MESSAGE =
  'Storage limit reached: delete items or empty the trash to make room, then try again. ' +
  'This change would take the vault past its storage quota.';

/** What an update that lost its row to other requests on every attempt is told. */
const VAULT_ROW_CHANGED_MESSAGE =
  'This entry was changed by another request while this one was saving it. Reload and try again.';

/** The refusal of a growing write the quota has no room for: always a 400. */
export class VaultQuotaExceededError extends ErrorHandler {
  constructor() {
    super(VAULT_STORAGE_QUOTA_MESSAGE, 400);
    this.name = 'VaultQuotaExceededError';
  }
}

/** The per-account row cap of each counted kind. */
const ROW_CAP: Readonly<Record<CountedKind, number>> = {
  item: MAX_ITEMS_PER_USER,
  folder: MAX_FOLDERS_PER_USER,
};

/** The text of a refused row: the wording the item and folder creates have always used. */
export function rowLimitMessage(kind: CountedKind): string {
  return kind === 'item'
    ? `Item limit reached. You can have a maximum of ${String(MAX_ITEMS_PER_USER)} items.`
    : `Folder limit reached. You can have a maximum of ${String(MAX_FOLDERS_PER_USER)} folders.`;
}

/**
 * The refusal of a write that would take the account past a row cap (F-15):
 * always a 400. `stored` is the account's row count of that kind when it was
 * refused, for a caller whose message names it (the import's).
 */
export class VaultRowLimitError extends ErrorHandler {
  readonly kind: CountedKind;
  readonly stored: number;

  constructor(kind: CountedKind, stored: number) {
    super(rowLimitMessage(kind), 400);
    this.name = 'VaultRowLimitError';
    this.kind = kind;
    this.stored = stored;
  }
}

/**
 * Matches a stored NUMBER of any numeric BSON type, and nothing else: a comparison
 * only matches values in its own type bracket, so a missing counter, a null and a
 * string all fail it. (The server's `$type: 'number'` alias says the same, but the
 * driver's filter typings do not accept it.)
 */
const IS_NUMBER = { $gte: Number.NEGATIVE_INFINITY } as const;

/** The quota in bytes, read on every call so a changed configuration applies at once. */
export function vaultQuotaBytes(): number {
  return Math.floor(config.VAULT_STORAGE_QUOTA_MB_PER_USER * 1024 * 1024);
}

/**
 * The counted size of a stored row, as an aggregation expression over `$$ROOT`:
 * the database's own measure, the one the install and the recount use.
 */
export function countedBytesExpression(kind: CountedKind): Record<string, unknown> {
  return {
    $bsonSize: PLACEMENT_FIELDS[kind].reduce<unknown>(
      (input, field) => ({ $unsetField: { field, input } }),
      '$$ROOT',
    ),
  };
}

/** A BSON document with no fields: its length prefix and its terminator. */
const EMPTY_DOCUMENT_BYTES = 5;

/**
 * The counted size of a row from a document the database returned (lean, or a
 * Mongoose document's stored image): exactly the bytes the driver serialises.
 */
export function countedBytes(kind: CountedKind, doc: object): number {
  const placement = PLACEMENT_FIELDS[kind];
  const counted = Object.fromEntries(
    Object.entries(doc).filter(([field]) => !placement.includes(field)),
  );
  return mongoose.mongo.BSON.serialize(counted).byteLength;
}

/** The bytes one field adds to a BSON document: type, name and value. Absent is zero. */
function entryBytes(field: string, value: unknown): number {
  if (value === undefined) return 0;
  return mongoose.mongo.BSON.serialize({ [field]: value }).byteLength - EMPTY_DOCUMENT_BYTES;
}

/** `toObject` options that reproduce the stored document: no virtuals, getters or transforms. */
const STORED_IMAGE = {
  depopulate: true,
  versionKey: true,
  virtuals: false,
  getters: false,
  transform: false,
  flattenMaps: false,
} as const;

/** What a pinned update needs to know about the row it replaces. */
export interface RowMeasure {
  readonly _id: unknown;
  /** The row's `__v`, which a pinned write requires and bumps; absent on a legacy row. */
  readonly __v?: unknown;
  /**
   * The row's `createdAt`, which a pinned write also requires: a row id can be
   * used again (it is derived from a client nonce, so a permanent delete followed
   * by a create with the same nonce stores the same `_id` at `__v` 0), and only
   * the creation time tells two incarnations of one id apart.
   */
  readonly createdAt?: unknown;
  /** The row's counted size. */
  readonly counted: number;
  readonly hasUpdatedAt: boolean;
  /** For each counted field the update writes, the bytes it occupies in the row now (0 when absent). */
  readonly fieldBytes: Readonly<Record<string, number>>;
}

/** An update of top-level fields, the only kind a counted write makes. */
export interface CountedUpdate {
  $set?: Record<string, unknown>;
  $unset?: Record<string, unknown>;
}

/** The counted (non-placement) fields `update` writes. */
function countedFieldsOf(kind: CountedKind, update: CountedUpdate): string[] {
  const placement = PLACEMENT_FIELDS[kind];
  return [
    ...new Set([...Object.keys(update.$set ?? {}), ...Object.keys(update.$unset ?? {})]),
  ].filter((field) => !placement.includes(field));
}

/** True when `update` writes at least one counted field (a placement-only update is not counted). */
function writesCountedField(kind: CountedKind, update: CountedUpdate): boolean {
  return countedFieldsOf(kind, update).length > 0;
}

/** Measures a row the caller already holds in full (a lean document). */
export function measureImage(kind: CountedKind, doc: object, update: CountedUpdate): RowMeasure {
  const row = doc as Record<string, unknown>;
  return {
    _id: row._id,
    __v: row.__v,
    createdAt: row.createdAt,
    counted: countedBytes(kind, row),
    hasUpdatedAt: row.updatedAt !== undefined,
    fieldBytes: Object.fromEntries(
      countedFieldsOf(kind, update).map((field) => [field, entryBytes(field, row[field])]),
    ),
  };
}

/**
 * Measures the rows `filter` matches, IN THE DATABASE and from the PRIMARY, for an
 * update that writes the fields of `update`: no row is transferred, so a batch of
 * large rows costs a few bytes each. `filter` goes to the driver as it is (cast
 * ids first).
 */
export async function measureStoredRows(
  kind: CountedKind,
  filter: Record<string, unknown>,
  update: CountedUpdate,
  session?: ClientSession,
): Promise<RowMeasure[]> {
  const fields = countedFieldsOf(kind, update);
  const projection: Record<string, unknown> = {
    __v: 1,
    createdAt: 1,
    hasUpdatedAt: { $ne: [{ $type: '$updatedAt' }, 'missing'] },
    counted: countedBytesExpression(kind),
  };
  fields.forEach((field, index) => {
    projection[`f${String(index)}`] = { $bsonSize: { [field]: `$${field}` } };
  });
  const rows = await MODEL_OF[kind].collection
    .find(filter, session ? { projection, session } : { projection, readPreference: 'primary' })
    .toArray();
  return rows.map((row) => ({
    _id: row._id,
    __v: row.__v as unknown,
    createdAt: row.createdAt as unknown,
    counted: Number(row.counted),
    hasUpdatedAt: row.hasUpdatedAt === true,
    fieldBytes: Object.fromEntries(
      fields.map((field, index) => [
        field,
        Number(row[`f${String(index)}`]) - EMPTY_DOCUMENT_BYTES,
      ]),
    ),
  }));
}

/** `values` cast as Mongoose stores them (strings to ObjectIds and Dates, sub-document defaults). */
function castForStorage(
  kind: CountedKind,
  values: Record<string, unknown>,
): Record<string, unknown> {
  const defined = Object.fromEntries(
    Object.entries(values).filter(([, value]) => value !== undefined),
  );
  const Constructor = MODEL_OF[kind];
  const image = new Constructor(defined).toObject(STORED_IMAGE) as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(defined)
      .filter((field) => image[field] !== undefined)
      .map((field) => [field, image[field]]),
  );
}

/**
 * The change in counted bytes a write of `update`, PINNED on the image `measure`
 * describes, makes: each written field's new entry less its old one, an unset
 * field's old entry, plus the `__v` and `updatedAt` the write adds to a legacy row
 * that had neither. Exact when the pin holds; also the prediction a reservation is
 * made from.
 */
export function deltaOfPinnedUpdate(
  kind: CountedKind,
  measure: RowMeasure,
  update: CountedUpdate,
): number {
  const cast = castForStorage(kind, update.$set ?? {});
  const unset = update.$unset ?? {};
  let delta = 0;
  for (const field of countedFieldsOf(kind, update)) {
    if (Object.hasOwn(cast, field)) {
      delta += entryBytes(field, cast[field]) - (measure.fieldBytes[field] ?? 0);
    } else if (Object.hasOwn(unset, field)) {
      delta -= measure.fieldBytes[field] ?? 0;
    }
  }
  if (measure.__v === undefined) delta += entryBytes('__v', 1);
  if (!measure.hasUpdatedAt) delta += entryBytes('updatedAt', new Date(0));
  return delta;
}

/**
 * The measure of the row a pinned write of `update` leaves behind, for a second
 * pinned write of `next` to the same row (a rotation's rollback).
 */
export function measureAfter(
  kind: CountedKind,
  measure: RowMeasure,
  update: CountedUpdate,
  next: CountedUpdate,
): RowMeasure {
  const cast = castForStorage(kind, update.$set ?? {});
  const fieldBytes: Record<string, number> = {};
  for (const field of countedFieldsOf(kind, next)) {
    if (Object.hasOwn(cast, field)) fieldBytes[field] = entryBytes(field, cast[field]);
    else if (Object.hasOwn(update.$unset ?? {}, field)) fieldBytes[field] = 0;
    else fieldBytes[field] = measure.fieldBytes[field] ?? 0;
  }
  return {
    _id: measure._id,
    __v: (typeof measure.__v === 'number' ? measure.__v : 0) + 1,
    createdAt: measure.createdAt,
    counted: measure.counted + deltaOfPinnedUpdate(kind, measure, update),
    hasUpdatedAt: true,
    fieldBytes,
  };
}

/**
 * What a pinned write requires of the row: the measured image's `__v` and its
 * `createdAt` (see {@link RowMeasure.createdAt}), each `{$exists: false}` when the
 * image had none.
 */
export function versionPin(measure: {
  __v?: unknown;
  createdAt?: unknown;
}): Record<string, unknown> {
  return {
    __v: measure.__v === undefined ? { $exists: false } : measure.__v,
    createdAt: measure.createdAt === undefined ? { $exists: false } : measure.createdAt,
  };
}

/**
 * True when `next` measures the same row as `first`: the same id AND the same
 * creation (see {@link RowMeasure.createdAt}). A retry after a pin miss re-measures
 * the row, and only continues while this holds: a row deleted and created again
 * under its id is a different row, which the operation never addressed.
 */
export function sameIncarnation(
  next: RowMeasure | undefined,
  first: RowMeasure,
): next is RowMeasure {
  if (next === undefined) return false;
  const a = next.createdAt;
  const b = first.createdAt;
  return a instanceof Date && b instanceof Date ? a.getTime() === b.getTime() : a === b;
}

/** The counted size a row created from `data` will have once it is saved. */
export function countedBytesOfNew(kind: CountedKind, data: Record<string, unknown>): number {
  const Constructor = MODEL_OF[kind];
  const image = new Constructor(data).toObject(STORED_IMAGE) as Record<string, unknown>;
  const now = new Date(0);
  image.createdAt ??= now;
  image.updatedAt ??= now;
  image.__v ??= 0;
  return countedBytes(kind, image);
}

/** The stored image of a saved Mongoose document, for {@link countedBytes}. */
export function storedImage(doc: { toObject(options: typeof STORED_IMAGE): unknown }): object {
  return doc.toObject(STORED_IMAGE) as object;
}

/** What an account stores, as the quota and the row caps count it. */
interface VaultTotals {
  /** The counted bytes of every item and folder row. */
  bytes: number;
  /** Item rows, trashed rows included. */
  items: number;
  /** Folder rows. */
  folders: number;
}

/**
 * The counted bytes and the number of every item and folder row `userId` owns,
 * measured by the database in one aggregate per collection. From the primary,
 * or inside `session` when one is given (a transaction then sees its own
 * snapshot plus its own writes).
 *
 * `maxTimeMS` bounds EACH of the two aggregates of a BACKGROUND total (the recount,
 * the boot migration) and nothing else. The
 * request-path install is never capped: a total that timed out there would make
 * the zero reservation every delete takes fail, and an account over its quota
 * would be unable to delete anything.
 */
async function storedVaultTotals(
  userId: string,
  options: { session?: ClientSession; maxTimeMS?: number } = {},
): Promise<VaultTotals> {
  const owner = new mongoose.Types.ObjectId(userId);
  const totals: VaultTotals = { bytes: 0, items: 0, folders: 0 };
  for (const kind of ['item', 'folder'] as const) {
    const query = MODEL_OF[kind].aggregate<{ bytes: number; rows: number }>([
      { $match: { userId: owner } },
      {
        $group: {
          _id: null,
          bytes: { $sum: countedBytesExpression(kind) },
          rows: { $sum: 1 },
        },
      },
    ]);
    if (options.maxTimeMS !== undefined) query.option({ maxTimeMS: options.maxTimeMS });
    const [row] = await (options.session ? query.session(options.session) : query.read('primary'));
    totals.bytes += row?.bytes ?? 0;
    totals[kind === 'item' ? 'items' : 'folders'] = row?.rows ?? 0;
  }
  return totals;
}

/** The counted bytes alone of {@link storedVaultTotals}, for a byte-only caller (a rotation). */
export async function storedVaultBytes(
  userId: string,
  options: { session?: ClientSession; maxTimeMS?: number } = {},
): Promise<number> {
  return (await storedVaultTotals(userId, options)).bytes;
}

/** The three counters an account carries, by stored path. */
const COUNTER_PATHS = ['vaultBytes', 'counters.items', 'counters.folders'] as const;

/** Keeps a stored number at `path`, else takes `value`: an install never overwrites a counter. */
function keepCounter(path: string, value: number): Record<string, unknown> {
  return { $cond: [{ $isNumber: `$${path}` }, `$${path}`, value] };
}

/**
 * Installs whichever of the account's three counters (`vaultBytes`,
 * `counters.items`, `counters.folders`) is missing, with the database's own
 * totals, and leaves an installed one as it is. Uncapped on the request path;
 * `maxTimeMS` is for a caller that must not wait (a boot migration). One
 * compare-and-set: losing it means another request installed first, which is
 * just as good.
 *
 * Safe against an install racing a write because every write path reserves (and
 * so installs ALL THREE) before it touches a row: no row is created or removed
 * while any counter is absent, so totals measured before the install are still
 * the totals when it lands.
 */
export async function installVaultCounters(
  userId: string,
  options: { maxTimeMS?: number } = {},
): Promise<void> {
  const totals = await storedVaultTotals(userId, options);
  const now = new Date();
  await User.collection.updateOne(
    {
      _id: new mongoose.Types.ObjectId(userId),
      $or: COUNTER_PATHS.map((path) => ({ [path]: { $not: IS_NUMBER } })),
    },
    [
      {
        $set: {
          vaultBytes: keepCounter('vaultBytes', totals.bytes),
          counters: {
            items: keepCounter('counters.items', totals.items),
            folders: keepCounter('counters.folders', totals.folders),
          },
          quotaRecountedAt: now,
          vaultBytesWrittenAt: now,
          quotaEpoch: { $add: [{ $ifNull: ['$quotaEpoch', 0] }, 1] },
        },
      },
    ],
  );
}

/** Rows of each kind an operation adds or removes. An omitted kind is zero. */
export interface RowCounts {
  readonly items?: number;
  readonly folders?: number;
}

/** One reservation, to be settled or released by the operation that made it. */
export interface VaultWriteReservation {
  readonly userId: string;
  readonly bytes: number;
  readonly items: number;
  readonly folders: number;
}

/** Attempts a reservation makes before deciding: an install, and an install race. */
const RESERVE_ATTEMPTS = 3;

/** Refuses anything a reservation cannot be made of: a negative, fractional or unsafe amount. */
function assertReservable(name: string, amount: number): void {
  if (!Number.isSafeInteger(amount) || amount < 0) {
    throw new RangeError(
      `A vault reservation's ${name} must be a non-negative integer, not ${String(amount)}`,
    );
  }
}

/** The filter on one counter: installed, and with room for `amount` below `ceiling` when it grows. */
function counterRoom(amount: number, ceiling: number): Record<string, number> {
  return amount === 0 ? IS_NUMBER : { ...IS_NUMBER, $lte: ceiling - amount };
}

/** The three counters as the driver returns them, each a number or not installed. */
interface StoredCounters {
  vaultBytes?: unknown;
  counters?: { items?: unknown; folders?: unknown } | null;
}

/**
 * Reserves `bytes` (a non-negative integer) of growth and `items`/`folders` new
 * rows (non-negative integers, zero when omitted) for `userId` BEFORE the
 * operation writes its first row, in ONE conditional update: the bytes and both
 * row caps are decided together, so no two requests can each see room for the
 * same last row. Installs any missing counter first. A reservation that grows
 * nothing is never refused. A growing one is refused with
 * {@link VaultRowLimitError} when a row cap has no room (checked first: it is
 * the refusal an account at its item limit has always been given), else with
 * {@link VaultQuotaExceededError} when the stored total plus `bytes` exceeds the
 * quota. 404 when the account no longer exists.
 */
export async function reserveVaultWrite(
  userId: string,
  { bytes, items = 0, folders = 0 }: { bytes: number } & RowCounts,
): Promise<VaultWriteReservation> {
  assertReservable('bytes', bytes);
  assertReservable('items', items);
  assertReservable('folders', folders);
  const quota = vaultQuotaBytes();
  const filter = {
    _id: userId,
    vaultBytes: counterRoom(bytes, quota),
    'counters.items': counterRoom(items, ROW_CAP.item),
    'counters.folders': counterRoom(folders, ROW_CAP.folder),
  };
  // Every counter is named, a zero included: an `$inc` of zero changes nothing,
  // and one shape for every reservation is one shape to recognise.
  const increments = {
    vaultBytes: bytes,
    'counters.items': items,
    'counters.folders': folders,
    quotaEpoch: 1,
  };
  let lastRefusal: Error | null = null;
  for (let attempt = 0; attempt < RESERVE_ATTEMPTS; attempt += 1) {
    const result = await User.updateOne(
      filter,
      { $inc: increments, $set: { vaultBytesWrittenAt: new Date() } },
      { timestamps: false },
    );
    if (result.matchedCount === 1) return { userId, bytes, items, folders };
    const stored = await User.collection.findOne<StoredCounters>(
      { _id: new mongoose.Types.ObjectId(userId) },
      { projection: { vaultBytes: 1, counters: 1 }, readPreference: 'primary' },
    );
    if (!stored) throw httpErrors.notFound('User not found');
    const storedItems = stored.counters?.items;
    const storedFolders = stored.counters?.folders;
    if (
      typeof stored.vaultBytes !== 'number' ||
      typeof storedItems !== 'number' ||
      typeof storedFolders !== 'number'
    ) {
      await installVaultCounters(userId);
      continue;
    }
    if (items > 0 && storedItems + items > ROW_CAP.item) {
      throw new VaultRowLimitError('item', storedItems);
    }
    if (folders > 0 && storedFolders + folders > ROW_CAP.folder) {
      throw new VaultRowLimitError('folder', storedFolders);
    }
    if (bytes > 0 && stored.vaultBytes + bytes > quota) throw new VaultQuotaExceededError();
    // Otherwise the update missed in the moment another request installed a
    // counter or released room: try again, which now matches. Should every
    // attempt miss that way, the refusal is the one for the first thing the
    // reservation grows.
    lastRefusal =
      items > 0
        ? new VaultRowLimitError('item', storedItems)
        : folders > 0
          ? new VaultRowLimitError('folder', storedFolders)
          : bytes > 0
            ? new VaultQuotaExceededError()
            : null;
  }
  throw lastRefusal ?? new Error(`The vault counter of ${userId} could not be touched`);
}

/** The signed change of each counter one write applies. An omitted one is zero. */
export interface VaultCountDelta extends RowCounts {
  readonly bytes?: number;
}

/**
 * Adds `delta` to INSTALLED counters, inside `session` when one is given, and
 * throws on failure. For a transaction that commits its rows and its count
 * together (a rotation), and for {@link settleVaultWrite}: the filter requires
 * every counter it moves to exist, so a missing one can never be installed as a
 * delta (the zero reservation every operation takes first has installed it).
 * Resolves to whether the counters were written.
 */
export async function addVaultCounts(
  userId: string,
  delta: VaultCountDelta,
  session?: ClientSession,
): Promise<boolean> {
  const moves: [string, number][] = [
    ['vaultBytes', delta.bytes ?? 0],
    ['counters.items', delta.items ?? 0],
    ['counters.folders', delta.folders ?? 0],
  ];
  for (const [path, amount] of moves) {
    // `$inc` with NaN or an infinity would store it, and no comparison matches
    // NaN, so the counter would be stuck until a recount: refuse the arithmetic.
    if (!Number.isFinite(amount)) {
      throw new RangeError(`A vault ${path} delta must be finite, not ${String(amount)}`);
    }
  }
  const moved = moves.filter(([, amount]) => amount !== 0);
  if (moved.length === 0) return true;
  const result = await User.updateOne(
    { _id: userId, ...Object.fromEntries(moved.map(([path]) => [path, IS_NUMBER])) },
    {
      $inc: { ...Object.fromEntries(moved), quotaEpoch: 1 },
      $set: { vaultBytesWrittenAt: new Date() },
    },
    session ? { timestamps: false, session } : { timestamps: false },
  );
  return result.matchedCount === 1;
}

/** {@link addVaultCounts} for a change in bytes alone. */
export async function addVaultBytes(
  userId: string,
  delta: number,
  session?: ClientSession,
): Promise<boolean> {
  return addVaultCounts(userId, { bytes: delta }, session);
}

/**
 * Applies what the operation actually wrote: `actualBytes` (the signed change in
 * counted bytes) and `actualRows` (the signed change in rows of each kind, zero
 * when omitted), each less what it reserved. Never refused, and never fails the
 * operation it closes: by now its rows are written, so a failure here is logged
 * (the recount corrects it) rather than turned into an error that invites a
 * duplicate retry. A zero correction writes nothing.
 *
 * An operation that RESERVED rows must say how many it added, since an omitted
 * kind reads as zero and so hands the reservation back.
 */
export async function settleVaultWrite(
  reservation: VaultWriteReservation,
  actualBytes: number,
  actualRows: RowCounts = {},
): Promise<void> {
  const correction = {
    bytes: actualBytes - reservation.bytes,
    items: (actualRows.items ?? 0) - reservation.items,
    folders: (actualRows.folders ?? 0) - reservation.folders,
  };
  try {
    await addVaultCounts(reservation.userId, correction);
  } catch (error: unknown) {
    logger.error('Could not settle a vault reservation; the hourly recount corrects it', {
      userId: reservation.userId,
      ...correction,
      error: errorMessage(error),
    });
  }
}

/** Hands a reservation back whole: the operation wrote nothing. */
export async function releaseVaultWrite(reservation: VaultWriteReservation): Promise<void> {
  await settleVaultWrite(reservation, 0);
}

/** Server codes that mean the write was refused and nothing was stored. */
const REFUSED_WRITE_CODES: ReadonlySet<number> = new Set([
  11000, // duplicate key
  121, // document failed validation
]);

/**
 * True when a failed write is known NOT to have applied: refused by Mongoose's
 * validation or casting before it was sent, or a single write the server refused
 * outright (a duplicate key, a failed document validation). Everything else is
 * ambiguous and keeps the reservation: a network failure or a timeout (the write
 * may have landed), a write-concern error (it did land), an error carrying a
 * retry or commit-result label, and a bulk write error (some rows may have landed).
 */
export function isDefiniteWriteFailure(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  if (
    error.name === 'ValidationError' ||
    error.name === 'CastError' ||
    error.name === 'StrictModeError'
  ) {
    return true;
  }
  if (!(error instanceof mongoose.mongo.MongoServerError)) return false;
  if (error instanceof mongoose.mongo.MongoBulkWriteError) return false;
  if (error instanceof mongoose.mongo.MongoWriteConcernError) return false;
  if (error.errorLabels.length > 0) return false;
  return typeof error.code === 'number' && REFUSED_WRITE_CODES.has(error.code);
}

/** Releases `reservation` when `error` is a definite failure, then rethrows `error` itself. */
async function releaseOnDefiniteFailure(
  reservation: VaultWriteReservation,
  error: unknown,
): Promise<never> {
  if (isDefiniteWriteFailure(error)) await releaseVaultWrite(reservation);
  throw error;
}

/** How often a pinned update re-reads and retries a row another request changed under it. */
const PINNED_UPDATE_ATTEMPTS = 3;

/**
 * Updates ONE existing counted row and keeps the counter exact: measures the row in
 * the database, reserves the predicted growth, writes pinned on the measured
 * `{__v, createdAt}` (bumping `__v`), and settles the difference between the
 * measured image and the written one. A row another request changed in between misses the pin; the
 * reservation is handed back and the cycle runs again, at most
 * {@link PINNED_UPDATE_ATTEMPTS} times, then 409. An update that writes no counted
 * field is applied as it always was: no accounting, no pin, no `__v` bump.
 *
 * Resolves to the updated row (lean, every field) or `null` when no row of
 * `userId` with id `id` (and `extraFilter`) exists, which includes the row this
 * call first measured having been deleted and created again under its id: the
 * edit was made to the row that went, and is not applied to its successor. An error from the write
 * propagates, after the reservation is handed back when the write certainly did
 * not apply.
 */
export async function updateCountedRow(options: {
  kind: CountedKind;
  userId: string;
  id: string;
  update: CountedUpdate;
  extraFilter?: Record<string, unknown>;
}): Promise<Record<string, unknown> | null> {
  const { kind, userId, id, update, extraFilter = {} } = options;
  if (!mongoose.isObjectIdOrHexString(id)) return null;
  const rowId = new mongoose.Types.ObjectId(id);
  const owner = new mongoose.Types.ObjectId(userId);
  const model = MODEL_OF[kind];
  if (!writesCountedField(kind, update)) {
    const placed = await model
      .findOneAndUpdate({ ...extraFilter, _id: rowId, userId: owner }, update, {
        returnDocument: 'after',
        runValidators: true,
      })
      .lean();
    return placed;
  }
  let first: RowMeasure | undefined;
  for (let attempt = 0; attempt < PINNED_UPDATE_ATTEMPTS; attempt += 1) {
    const [measure] = await measureStoredRows(
      kind,
      { ...extraFilter, _id: rowId, userId: owner },
      update,
    );
    if (!measure) return null;
    first ??= measure;
    if (!sameIncarnation(measure, first)) return null;
    const reservation = await reserveVaultWrite(userId, {
      bytes: Math.max(0, deltaOfPinnedUpdate(kind, measure, update)),
    });
    let after: Record<string, unknown> | null;
    try {
      after = await model
        .findOneAndUpdate(
          { ...extraFilter, _id: rowId, userId: owner, ...versionPin(measure) },
          { ...update, $inc: { __v: 1 } },
          { returnDocument: 'after', runValidators: true },
        )
        .lean();
    } catch (error: unknown) {
      return releaseOnDefiniteFailure(reservation, error);
    }
    if (!after) {
      await releaseVaultWrite(reservation);
      continue;
    }
    await settleVaultWrite(reservation, countedBytes(kind, after) - measure.counted);
    return after;
  }
  throw httpErrors.conflict(VAULT_ROW_CHANGED_MESSAGE);
}

/** One row of `kind`, as a {@link RowCounts}. */
function oneRowOf(kind: CountedKind): RowCounts {
  return kind === 'item' ? { items: 1 } : { folders: 1 };
}

/**
 * Creates ONE counted row: reserves its predicted size AND the row itself against
 * its kind's cap (one conditional update, so the cap is atomic: F-15), saves it,
 * settles the size of what was stored. Refused with {@link VaultRowLimitError}
 * at the cap and {@link VaultQuotaExceededError} past the quota, before anything
 * is written. An error from the save propagates (after the reservation is handed
 * back when the save certainly did not apply), so a caller still maps a
 * duplicate key to its own 409.
 */
export async function createCountedRow<
  T extends { toObject(options: typeof STORED_IMAGE): unknown },
>(
  kind: CountedKind,
  userId: string,
  data: Record<string, unknown>,
  create: () => Promise<T>,
): Promise<T> {
  const reservation = await reserveVaultWrite(userId, {
    bytes: countedBytesOfNew(kind, data),
    ...oneRowOf(kind),
  });
  let created: T;
  try {
    created = await create();
  } catch (error: unknown) {
    return releaseOnDefiniteFailure(reservation, error);
  }
  await settleVaultWrite(reservation, countedBytes(kind, storedImage(created)), oneRowOf(kind));
  return created;
}

/**
 * Deletes ONE counted row matching `filter` (which carries `_id` and `userId`, cast)
 * and returns how many counted bytes went with it, or `null` when nothing matched.
 * The database measures the row in the same atomic operation that removes it, so
 * the bytes are those of the row this call removed and of no other.
 */
export async function deleteCountedRow(
  kind: CountedKind,
  filter: Record<string, unknown>,
  session?: ClientSession,
): Promise<{ counted: number; row: Record<string, unknown> } | null> {
  const removed = await MODEL_OF[kind].collection.findOneAndDelete(filter, {
    projection: { itemType: 1, counted: countedBytesExpression(kind) },
    ...(session ? { session } : {}),
  });
  if (!removed) return null;
  return { counted: Number(removed.counted), row: removed };
}

/** Candidate ids one call of {@link deleteCountedItems} reads per round. */
const COUNTED_DELETE_BATCH = 500;

/**
 * Deletes the vault ITEMS of `userId` that match `predicate` (which must restate
 * the trash condition), limited to `ids` when given, ROW BY ROW, and reports how
 * many went and how many counted bytes went with them.
 *
 * Row by row so that each row's bytes are subtracted by the one call that actually
 * removed it: a batch delete that credited every row "gone afterwards" to itself
 * subtracted twice a row another request (a permanent delete, a second empty-trash,
 * the nightly purge) removed in between. A row restored since the candidates were
 * read no longer matches the restated predicate and is neither deleted nor
 * counted. The caller reserves (touch first) before and settles after.
 *
 * `tally` is updated row by row and is what the caller settles, in a `finally`:
 * a walk that throws part-way has still removed the rows it counted there.
 */
export async function deleteCountedItems(
  userId: string,
  predicate: Record<string, unknown>,
  tally: { deleted: number; bytes: number },
  ids?: readonly mongoose.Types.ObjectId[],
): Promise<void> {
  const owner = new mongoose.Types.ObjectId(userId);
  let after: mongoose.Types.ObjectId | undefined;
  for (;;) {
    const scope: Record<string, unknown> = { ...predicate, userId: owner };
    if (ids) scope._id = { $in: ids };
    if (after) scope._id = ids ? { $in: ids, $gt: after } : { $gt: after };
    const batch = await VaultItem.collection
      .find(scope, {
        projection: { _id: 1 },
        sort: { _id: 1 },
        limit: COUNTED_DELETE_BATCH,
        readPreference: 'primary',
      })
      .toArray();
    for (const { _id } of batch) {
      const gone = await deleteCountedRow('item', { ...predicate, _id, userId: owner });
      if (gone) {
        tally.deleted += 1;
        tally.bytes += gone.counted;
      }
    }
    if (batch.length < COUNTED_DELETE_BATCH) break;
    after = batch.at(-1)?._id;
  }
}

/** Accounts one recount run may take, oldest recount first. */
const QUOTA_RECOUNT_USERS_PER_RUN = 200;
/**
 * How long an account must have gone without a counted write before it is
 * recounted: twice the longest span an operation holds its account between its
 * reservation and its settle (the five-minute vault-key exclusion lock bounds the
 * longest of them, a rotation).
 */
export const QUOTA_RECOUNT_QUIESCENCE_MS = 10 * 60 * 1000;
/**
 * How long one recount run may walk. The maintenance lock is 15 minutes and never
 * renewed; the steps before this one budget 13 of them and the one after it one.
 */
const QUOTA_RECOUNT_BUDGET_MS = 45 * 1000;
/** Consecutive failing accounts that stop the walk (a database that is refusing). */
const QUOTA_RECOUNT_MAX_CONSECUTIVE_FAILURES = 5;
/**
 * The longest each of the two aggregates of one account's total (items, then
 * folders) may take in the recount. The budget is checked between accounts, so
 * this is what bounds an overrun: 45 s plus one account's 2 x 5 s keeps the run
 * inside the maintenance lock with the steps around it.
 */
const QUOTA_RECOUNT_AGGREGATE_MAX_TIME_MS = 5_000;

export interface QuotaRecountSummary {
  recounted: number;
  corrected: number;
  failures: number;
}

/**
 * Corrects the counters that drift: a crash between a row write and its settle, an
 * ambiguous failure whose reservation was kept, a row written by something other
 * than this API. The maintenance step `vault-quota-recount` runs it hourly. All
 * THREE counters are rewritten together: the bytes and the two row counts behind
 * the caps (F-15), from the same two aggregates.
 *
 * Only QUIET accounts are recounted (no counted write for
 * {@link QUOTA_RECOUNT_QUIESCENCE_MS}), oldest recount first, at most
 * {@link QUOTA_RECOUNT_USERS_PER_RUN} a run. The database's total is written with
 * a compare-and-set on the `quotaEpoch` and `vaultBytesWrittenAt` read before it
 * was measured, and every counted write moves both, so a write that begins while
 * the total is being measured makes the set miss and nothing is written. A busy
 * account is outside the candidate set, so it cannot starve the others; a failing
 * one is moved to the back of the queue. An account with no counter yet is
 * installed here too.
 *
 * @param budgetMs How long the run may walk; at least one account is always done.
 */
export async function recountVaultQuotas(
  budgetMs: number = QUOTA_RECOUNT_BUDGET_MS,
): Promise<QuotaRecountSummary> {
  const startedAt = Date.now();
  const quietSince = new Date(startedAt - QUOTA_RECOUNT_QUIESCENCE_MS);
  const candidates = await User.collection
    .find(
      {
        deletionPending: { $ne: true },
        $or: [
          { vaultBytesWrittenAt: { $exists: false } },
          { vaultBytesWrittenAt: { $lt: quietSince } },
        ],
      },
      {
        projection: { vaultBytes: 1, counters: 1, quotaEpoch: 1, vaultBytesWrittenAt: 1 },
        sort: { quotaRecountedAt: 1 },
        limit: QUOTA_RECOUNT_USERS_PER_RUN,
        readPreference: 'primary',
      },
    )
    .toArray();
  const summary: QuotaRecountSummary = { recounted: 0, corrected: 0, failures: 0 };
  let consecutiveFailures = 0;
  for (const account of candidates) {
    const userId = String(account._id);
    try {
      const total = await storedVaultTotals(userId, {
        maxTimeMS: QUOTA_RECOUNT_AGGREGATE_MAX_TIME_MS,
      });
      const result = await User.updateOne(
        {
          _id: account._id,
          quotaEpoch: (account.quotaEpoch as unknown) ?? { $exists: false },
          vaultBytesWrittenAt: (account.vaultBytesWrittenAt as unknown) ?? { $exists: false },
        },
        {
          $set: {
            vaultBytes: total.bytes,
            'counters.items': total.items,
            'counters.folders': total.folders,
            quotaRecountedAt: new Date(),
          },
          $inc: { quotaEpoch: 1 },
        },
        { timestamps: false },
      );
      consecutiveFailures = 0;
      if (result.matchedCount === 1) {
        summary.recounted += 1;
        const counted = {
          bytes: account.vaultBytes as unknown,
          items: (account.counters as StoredCounters['counters'])?.items,
          folders: (account.counters as StoredCounters['counters'])?.folders,
        };
        if (Object.values(counted).some((value) => typeof value !== 'number')) {
          logger.info('Vault quota counters installed by the recount', { userId, stored: total });
        } else if (
          counted.bytes !== total.bytes ||
          counted.items !== total.items ||
          counted.folders !== total.folders
        ) {
          summary.corrected += 1;
          logger.warn('Vault quota recount corrected a drifted counter', {
            userId,
            counted,
            stored: total,
          });
        }
      }
    } catch (error: unknown) {
      summary.failures += 1;
      consecutiveFailures += 1;
      logger.error("Could not recount an account's vault counters", {
        userId,
        error: errorMessage(error),
      });
      // To the back of the queue, so one account that keeps failing cannot hold
      // the front of every run.
      await User.updateOne(
        { _id: account._id },
        { $set: { quotaRecountedAt: new Date() } },
        { timestamps: false },
      ).catch(() => undefined);
      if (consecutiveFailures >= QUOTA_RECOUNT_MAX_CONSECUTIVE_FAILURES) {
        logger.error('Vault quota recount stopped: several accounts in a row failed', summary);
        return summary;
      }
    }
    if (Date.now() - startedAt >= budgetMs) break;
  }
  logger.info('Vault quota recount complete', summary);
  return summary;
}

/** What `/metrics` reports about vault storage, from a background snapshot. */
export interface VaultStorageSnapshot {
  accounts: number;
  totalBytes: number;
  measuredAt: string;
}

/** How old the snapshot may grow before a `/metrics` request starts a refresh. */
const VAULT_STORAGE_SNAPSHOT_MAX_AGE_MS = 5 * 60 * 1000;
/** The refresh is one aggregate over `users`; it gives up rather than queue. */
const VAULT_STORAGE_SNAPSHOT_MAX_TIME_MS = 5_000;

let snapshot: VaultStorageSnapshot | null = null;
let refreshStartedAt = Number.NEGATIVE_INFINITY;
let refreshing = false;

/**
 * The last vault-storage snapshot (`null` until the first refresh has landed),
 * starting a refresh in the background when it is older than five minutes.
 *
 * NEVER awaits the database: `/metrics` is what an operator reads when the
 * database is the problem, so it must answer whatever state the database is in.
 * The refresh is fire-and-forget, bounded by `maxTimeMS`, and a failure is logged
 * and leaves the previous snapshot in place.
 */
export function vaultStorageSnapshot(): VaultStorageSnapshot | null {
  const now = Date.now();
  if (
    !refreshing &&
    now - refreshStartedAt >= VAULT_STORAGE_SNAPSHOT_MAX_AGE_MS &&
    mongoose.connection.readyState === mongoose.ConnectionStates.connected
  ) {
    refreshing = true;
    refreshStartedAt = now;
    void User.aggregate<{ accounts: number; totalBytes: number }>([
      { $match: { vaultBytes: IS_NUMBER } },
      { $group: { _id: null, accounts: { $sum: 1 }, totalBytes: { $sum: '$vaultBytes' } } },
    ])
      .read('primary')
      .option({ maxTimeMS: VAULT_STORAGE_SNAPSHOT_MAX_TIME_MS })
      .then(([row]) => {
        snapshot = {
          accounts: row?.accounts ?? 0,
          totalBytes: row?.totalBytes ?? 0,
          measuredAt: new Date().toISOString(),
        };
      })
      .catch((error: unknown) => {
        logger.warn('Could not refresh the vault storage snapshot for /metrics', {
          error: errorMessage(error),
        });
      })
      .finally(() => {
        refreshing = false;
      });
  }
  return snapshot;
}

/** Forgets the snapshot and the refresh clock. For tests. */
export function resetVaultStorageSnapshot(): void {
  snapshot = null;
  refreshStartedAt = Number.NEGATIVE_INFINITY;
  refreshing = false;
}
