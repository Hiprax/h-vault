/**
 * Import conflict resolution — the heart of identity-correct, batch-independent
 * import.
 *
 * `resolveImport` runs ONCE over the WHOLE incoming set against the WHOLE vault
 * and decides, for every incoming row, exactly one outcome: insert a new item,
 * update an existing one in place, or report it as a duplicate/no-op. Because
 * resolution is holistic, splitting the resulting operations across any number
 * of transport requests cannot change the outcome — which is precisely what
 * eliminates the 0.2.0 batch-boundary defect (ten accounts collapsing to one
 * depending on how a payload was chunked).
 *
 * Identity is computed CLIENT-SIDE from decrypted content (see `identity.ts`):
 * a login with both a resolvable host and a username matches on host+username;
 * everything else matches on exact content. The resolver performs NO encryption
 * and NO network I/O. Its only asynchrony is identity hashing, so it is a pure
 * function of `(existing, incoming, strategy)` and exhaustively testable.
 *
 * Semantics (PLAN §1.5–1.6):
 *  - Only NON-trashed, decodable existing items are match candidates. A
 *    placeholder kept after a decrypt/validation failure is excluded from the
 *    index entirely, so it can never become an `overwrite` target and have its
 *    real ciphertext replaced.
 *  - Matching never crosses item types (the type is part of every key).
 *  - Intra-file exact duplicates (same identity key AND same content) collapse:
 *    first wins under `skip`, last wins under `overwrite`, none collapse under
 *    `keep_both`; the losers are reported as `duplicateInFile`.
 *  - Rows that share a logical key but differ in content are genuinely distinct
 *    credentials and are all kept (inserted, or — under `overwrite` — the LAST
 *    one wins the single update against the existing item and the rest insert).
 *
 * A row the custom-field limit CUT (`customFieldsLimit.ts`) carries a second
 * identity, the row it was cut from, through the optional `alternateOf`. A cut
 * row no longer hashes like the entry it came from, so:
 *  - it matches an existing item by its cut OR its untrimmed identity, and is
 *    `unchanged` under `overwrite` when EITHER content equals the stored one.
 *    That is what keeps a re-import from duplicating an entry stored in full
 *    before the limit existed, or stored cut since;
 *  - the file still collapses on the CUT keys, because the cut rows are what is
 *    written; rows that only became identical through the cut are named in
 *    `mergedByLimit` so the user is told;
 *  - the `overwrite` slot belongs to the MATCHED existing item, so two rows that
 *    reach one item by different keys can never both update it.
 * With no `alternateOf` every key and outcome is exactly what it was without one.
 */

import { computeItemKeys } from './identity';
import { isUndecodableData } from '../../lib/vaultData';
import type { ItemType } from '@hvault/shared';

export type ConflictStrategy = 'skip' | 'overwrite' | 'keep_both';

/** The minimal decrypted shape the resolver reads to compute an identity. */
export interface IdentityFields {
  itemType: ItemType;
  name: string;
  data: Record<string, unknown>;
}

/** The minimal existing-item shape: identity fields plus id and trash flag. */
export interface ResolvableExistingItem extends IdentityFields {
  id: string;
  deletedAt?: string | undefined;
}

/** One resolved update: the incoming row and the existing item it targets. */
export interface ResolvedUpdate<I, E> {
  incoming: I;
  existing: E;
}

/** A row folded into another during the intra-file collapse only because of the cut. */
export interface LimitMerge<I> {
  /** The row that is kept. */
  kept: I;
  /** The row reported as `duplicateInFile`, whose untrimmed content differed. */
  absorbed: I;
}

/**
 * The outcome of resolution. Every incoming row appears in exactly one bucket,
 * so the five array lengths sum to `incoming.length`:
 *  - `inserts` — no existing match (or `keep_both`); create a new item.
 *  - `updates` — matched an existing item whose content differs; overwrite it.
 *  - `duplicateSkipped` — matched an existing item under `skip`; do nothing.
 *  - `duplicateInFile` — an intra-file exact duplicate that lost its collapse.
 *  - `unchanged` — matched under `overwrite` but content is already identical;
 *    no write is emitted, which is what makes an `overwrite` re-import a no-op.
 *
 * `mergedByLimit` is present only when `alternateOf` was given. It is not a
 * bucket: each `absorbed` row is also in `duplicateInFile`.
 */
export interface ImportResolution<I, E> {
  inserts: I[];
  updates: ResolvedUpdate<I, E>[];
  duplicateSkipped: I[];
  duplicateInFile: I[];
  unchanged: I[];
  mergedByLimit?: LimitMerge<I>[];
}

interface ItemKeys {
  identityKey: string;
  contentKey: string;
}

interface KeyedIncoming<I> extends ItemKeys {
  item: I;
  /** The keys of the row this one was cut from, when the limit cut it. */
  alternate?: ItemKeys;
}

interface IndexedExisting<E> {
  item: E;
  contentKey: string;
}

export async function resolveImport<I extends IdentityFields, E extends ResolvableExistingItem>({
  existing,
  incoming,
  strategy,
  alternateOf,
}: {
  existing: readonly E[];
  incoming: readonly I[];
  strategy: ConflictStrategy;
  /** The row a cut row was cut from, or `undefined` for a row the limit left alone. */
  alternateOf?: ((item: I) => I | undefined) | undefined;
}): Promise<ImportResolution<I, E>> {
  const result: ImportResolution<I, E> = {
    inserts: [],
    updates: [],
    duplicateSkipped: [],
    duplicateInFile: [],
    unchanged: [],
    ...(alternateOf ? { mergedByLimit: [] } : {}),
  };

  // 1. Index existing candidates (non-trashed, decodable) by identity key. When
  //    the vault already holds duplicates sharing one key, the first in the
  //    provided order wins the slot — they are duplicates, so any one is a valid
  //    target. `keep_both` never matches, so the index is only built otherwise.
  const index = new Map<string, IndexedExisting<E>>();
  if (strategy !== 'keep_both') {
    // Key the candidates concurrently but ASSIGN them in array order: when the
    // vault already holds duplicates sharing one identity key, the first in the
    // given order must deterministically win the slot. Both are valid targets
    // (they are duplicates), but the choice must not hinge on the order in which
    // the hashing promises happen to settle.
    const candidates = existing.filter(
      (item) => item.deletedAt === undefined && !isUndecodableData(item.data),
    );
    const keyedExisting = await Promise.all(
      candidates.map(async (item) => ({ item, ...(await computeItemKeys(item)) })),
    );
    for (const { item, identityKey, contentKey } of keyedExisting) {
      if (!index.has(identityKey)) index.set(identityKey, { item, contentKey });
    }
  }

  // 2. Key every incoming row, preserving file order, and a cut row's original too.
  const keyed: KeyedIncoming<I>[] = await Promise.all(
    incoming.map(async (item) => {
      const keys = await computeItemKeys(item);
      const original = alternateOf?.(item);
      if (original === undefined) return { item, ...keys };
      return { item, ...keys, alternate: await computeItemKeys(original) };
    }),
  );

  // 3. Collapse intra-file exact duplicates (same identity AND same content).
  //    `keep_both` never collapses. The winner is the first (skip) or last
  //    (overwrite) occurrence in file order; losers are reported and dropped.
  const survivors = collapseIntraFileDuplicates(
    keyed,
    strategy,
    result.duplicateInFile,
    result.mergedByLimit,
  );

  // 4. Match survivors against the existing index and apply the strategy.
  if (strategy === 'keep_both') {
    for (const s of survivors) result.inserts.push(s.item);
    return result;
  }

  const matches = survivors.map((s) => ({ s, key: matchedKey(index, s) }));

  if (strategy === 'skip') {
    for (const { s, key } of matches) {
      if (key !== undefined) result.duplicateSkipped.push(s.item);
      else result.inserts.push(s.item);
    }
    return result;
  }

  // overwrite: among survivors matching the SAME existing item, only the LAST in
  // file order wins the single update slot; earlier ones become inserts (they
  // are content-distinct by construction — exact duplicates already collapsed).
  // The slot is keyed by the existing item's own index key, never by the row's:
  // a cut row can reach an item through its alternate identity, and two rows
  // reaching one item by different keys must still share one slot.
  const lastSlotIndex = new Map<string, number>();
  matches.forEach(({ key }, i) => {
    if (key !== undefined) lastSlotIndex.set(key, i);
  });
  matches.forEach(({ s, key }, i) => {
    const matched = key === undefined || lastSlotIndex.get(key) !== i ? undefined : index.get(key);
    if (!matched) {
      result.inserts.push(s.item);
      return;
    }
    // The winning survivor for this existing item. If its content already equals
    // what is stored, in either its cut or its untrimmed form, the overwrite is a
    // no-op; otherwise it updates in place.
    if (s.contentKey === matched.contentKey || s.alternate?.contentKey === matched.contentKey) {
      result.unchanged.push(s.item);
    } else {
      result.updates.push({ incoming: s.item, existing: matched.item });
    }
  });
  return result;
}

/**
 * The index key of the existing item a survivor matches: its own identity first,
 * then the identity of the row it was cut from. `undefined` when neither is held.
 */
function matchedKey<I, E>(
  index: ReadonlyMap<string, IndexedExisting<E>>,
  s: KeyedIncoming<I>,
): string | undefined {
  if (index.has(s.identityKey)) return s.identityKey;
  const alternate = s.alternate?.identityKey;
  return alternate !== undefined && index.has(alternate) ? alternate : undefined;
}

/**
 * Collapse rows that share BOTH an identity key and a content key. The composite
 * grouping key is an unambiguous JSON tuple (an identity key can itself contain
 * the field separator). Winners are returned in the original file order; losers
 * are pushed onto `duplicateInFile`.
 *
 * The keys are the PRIMARY ones, a cut row's cut keys. When `mergedByLimit` is
 * given, a loser whose untrimmed content differs from its winner's is also named
 * there: the two only became one row because of the cut.
 */
function collapseIntraFileDuplicates<I>(
  keyed: KeyedIncoming<I>[],
  strategy: ConflictStrategy,
  duplicateInFile: I[],
  mergedByLimit: LimitMerge<I>[] | undefined,
): KeyedIncoming<I>[] {
  if (strategy === 'keep_both') return keyed;

  // Group the occurrences per composite key in a single pass, recording the
  // winner as it goes: under `overwrite` the last write wins, under `skip` the
  // first. `winners` is then a reference set, so no re-indexing (and no non-null
  // assertion) is needed.
  const groups = new Map<string, { winner: KeyedIncoming<I>; members: KeyedIncoming<I>[] }>();
  for (const entry of keyed) {
    const composite = JSON.stringify([entry.identityKey, entry.contentKey]);
    const group = groups.get(composite);
    if (!group) {
      groups.set(composite, { winner: entry, members: [entry] });
      continue;
    }
    group.members.push(entry);
    if (strategy === 'overwrite') group.winner = entry;
  }
  const winners = new Set<KeyedIncoming<I>>([...groups.values()].map((g) => g.winner));

  const survivors: KeyedIncoming<I>[] = [];
  for (const entry of keyed) {
    if (winners.has(entry)) survivors.push(entry);
    else duplicateInFile.push(entry.item);
  }

  if (mergedByLimit) {
    for (const { winner, members } of groups.values()) {
      for (const member of members) {
        if (member !== winner && untrimmedContentKey(member) !== untrimmedContentKey(winner)) {
          mergedByLimit.push({ kept: winner.item, absorbed: member.item });
        }
      }
    }
  }
  return survivors;
}

/** The content key of what the file held for this row, before any cut. */
function untrimmedContentKey<I>(entry: KeyedIncoming<I>): string {
  return entry.alternate?.contentKey ?? entry.contentKey;
}
