import { isDeepStrictEqual } from 'node:util';

/**
 * Brings a model's TTL indexes in line with a changed retention setting.
 *
 * Three TTL indexes take their retention from the configuration
 * (`AUDIT_LOG_RETENTION_DAYS`, `BACKUP_RETENTION_DAYS`, `BREACH_CACHE_TTL_DAYS`),
 * so changing one of those settings changes the `expireAfterSeconds` the schema
 * declares for an index that already exists. `createIndexes` then fails with
 * IndexOptionsConflict, and `create-indexes` — the production bootstrap step the
 * app waits on — exits 1: a documented setting that stops the stack starting.
 *
 * The application's database user holds `readWrite`, which grants `createIndex`
 * and `dropIndex` but not `collMod`, so the index cannot be altered in place.
 * This drops it, by its existing name, so the `createIndexes` call that follows
 * builds it again with the configured retention. Until that rebuild finishes the
 * TTL monitor reaps nothing from the collection, and a SHORTER retention deletes
 * the newly expired rows on its first pass after the rebuild.
 *
 * Deliberately narrow: an existing index is dropped ONLY when it has the same key
 * pattern as a TTL index the schema declares, is a TTL index itself, and differs
 * from the declaration in `expireAfterSeconds` and nothing else. Any other
 * conflict (a different partial filter, uniqueness, collation) is left in place,
 * so `createIndexes` still reports it. Nothing the schema does not declare is
 * ever touched (unlike Mongoose's `syncIndexes`, which drops every index it does
 * not know about).
 *
 * @returns One entry per index it dropped, with the retention it had and the one
 *          it will be rebuilt with (empty when nothing changed).
 */
async function dropTtlIndexesWithChangedRetention(model: IndexedModel): Promise<RetentionChange[]> {
  const declared = (model.schema.indexes() as [Record<string, unknown>, DeclaredOptions][]).filter(
    (index): index is [Record<string, unknown>, DeclaredTtlOptions] =>
      typeof index[1].expireAfterSeconds === 'number',
  );

  let existing: ExistingIndex[];
  try {
    existing = (await model.collection.indexes()) as ExistingIndex[];
  } catch (err: unknown) {
    // A collection that does not exist yet has no index to conflict with; any
    // other failure is the caller's to report.
    if (!isNamespaceNotFound(err)) throw err;
    return [];
  }

  const dropped: RetentionChange[] = [];
  for (const [keys, options] of declared) {
    const current = existing.find((index) => sameKeyPattern(index.key, keys));
    // Absent (not built yet), or not a TTL index at all: nothing to rebuild here.
    if (current?.expireAfterSeconds === undefined) continue;
    const from = current.expireAfterSeconds;
    const to = options.expireAfterSeconds;
    if (from === to || !sameOptionsApartFromRetention(current, options)) continue;
    try {
      await model.collection.dropIndex(current.name);
    } catch (err: unknown) {
      // Another run dropped it first: the rebuild that follows is still owed.
      if (!isIndexNotFound(err)) throw err;
    }
    dropped.push({ name: current.name, fromSeconds: from, toSeconds: to });
  }
  return dropped;
}

/** The options of an index as the schema declares them. */
interface DeclaredOptions {
  expireAfterSeconds?: number;
  partialFilterExpression?: unknown;
  unique?: boolean;
  sparse?: boolean;
  collation?: unknown;
}

/** A declared TTL index's options. */
type DeclaredTtlOptions = DeclaredOptions & { expireAfterSeconds: number };

/** An index as the server describes it (`listIndexes`). */
interface ExistingIndex extends DeclaredOptions {
  name: string;
  key: Record<string, unknown>;
}

/** The parts of a Mongoose model this module reads (any model satisfies it). */
interface IndexedModel {
  schema: { indexes(): unknown[] };
  collection: {
    indexes(): Promise<unknown[]>;
    dropIndex(name: string): Promise<unknown>;
  };
}

/** A TTL index rebuilt because its configured retention changed. */
export interface RetentionChange {
  name: string;
  /** The `expireAfterSeconds` the index had. */
  fromSeconds: number;
  /** The `expireAfterSeconds` the configuration asks for. */
  toSeconds: number;
}

/**
 * Options that make two indexes on one key pattern different indexes. Compared
 * as given: a declaration spelling out a default (`unique: false`) differs from
 * an index that omits it, which leaves the conflict to be reported — the safe
 * direction for a check that decides whether to DROP something.
 */
const IDENTITY_OPTIONS = ['partialFilterExpression', 'unique', 'sparse', 'collation'] as const;

function sameOptionsApartFromRetention(current: ExistingIndex, declared: DeclaredOptions): boolean {
  return IDENTITY_OPTIONS.every((option) => isDeepStrictEqual(current[option], declared[option]));
}

/** Same fields, same directions, same ORDER (a compound key's order is its meaning). */
function sameKeyPattern(key: Record<string, unknown>, keys: Record<string, unknown>): boolean {
  return isDeepStrictEqual(Object.entries(key), Object.entries(keys));
}

function hasServerCode(err: unknown, code: number): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === code;
}

function isNamespaceNotFound(err: unknown): boolean {
  return hasServerCode(err, 26);
}

/** `IndexNotFound`, or `NamespaceNotFound` when the whole collection went meanwhile. */
function isIndexNotFound(err: unknown): boolean {
  return hasServerCode(err, 27) || hasServerCode(err, 26);
}

/**
 * `model.createIndexes()`, preceded by {@link dropTtlIndexesWithChangedRetention}:
 * the one way the index-building entry points (`create-indexes`, the breach seed
 * command) build a model's indexes. Returns the TTL indexes it rebuilt for a
 * changed retention.
 */
export async function createIndexesWithCurrentRetention(
  model: IndexedModel & { createIndexes(): Promise<unknown> },
): Promise<RetentionChange[]> {
  const rebuilt = await dropTtlIndexesWithChangedRetention(model);
  await model.createIndexes();
  return rebuilt;
}
