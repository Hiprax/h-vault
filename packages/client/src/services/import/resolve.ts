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

/**
 * The outcome of resolution. Every incoming row appears in exactly one bucket,
 * so the five array lengths sum to `incoming.length`:
 *  - `inserts` — no existing match (or `keep_both`); create a new item.
 *  - `updates` — matched an existing item whose content differs; overwrite it.
 *  - `duplicateSkipped` — matched an existing item under `skip`; do nothing.
 *  - `duplicateInFile` — an intra-file exact duplicate that lost its collapse.
 *  - `unchanged` — matched under `overwrite` but content is already identical;
 *    no write is emitted, which is what makes an `overwrite` re-import a no-op.
 */
export interface ImportResolution<I, E> {
  inserts: I[];
  updates: ResolvedUpdate<I, E>[];
  duplicateSkipped: I[];
  duplicateInFile: I[];
  unchanged: I[];
}

interface KeyedIncoming<I> {
  item: I;
  identityKey: string;
  contentKey: string;
}

interface IndexedExisting<E> {
  item: E;
  contentKey: string;
}

export async function resolveImport<I extends IdentityFields, E extends ResolvableExistingItem>({
  existing,
  incoming,
  strategy,
}: {
  existing: readonly E[];
  incoming: readonly I[];
  strategy: ConflictStrategy;
}): Promise<ImportResolution<I, E>> {
  const result: ImportResolution<I, E> = {
    inserts: [],
    updates: [],
    duplicateSkipped: [],
    duplicateInFile: [],
    unchanged: [],
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

  // 2. Key every incoming row, preserving file order.
  const keyed: KeyedIncoming<I>[] = await Promise.all(
    incoming.map(async (item) => {
      const { identityKey, contentKey } = await computeItemKeys(item);
      return { item, identityKey, contentKey };
    }),
  );

  // 3. Collapse intra-file exact duplicates (same identity AND same content).
  //    `keep_both` never collapses. The winner is the first (skip) or last
  //    (overwrite) occurrence in file order; losers are reported and dropped.
  const survivors = collapseIntraFileDuplicates(keyed, strategy, result.duplicateInFile);

  // 4. Match survivors against the existing index and apply the strategy.
  if (strategy === 'keep_both') {
    for (const s of survivors) result.inserts.push(s.item);
    return result;
  }

  if (strategy === 'skip') {
    for (const s of survivors) {
      if (index.has(s.identityKey)) result.duplicateSkipped.push(s.item);
      else result.inserts.push(s.item);
    }
    return result;
  }

  // overwrite: among survivors matching the SAME existing item, only the LAST in
  // file order wins the single update slot; earlier ones become inserts (they
  // are content-distinct by construction — exact duplicates already collapsed).
  const lastSlotIndex = new Map<string, number>();
  survivors.forEach((s, i) => {
    if (index.has(s.identityKey)) lastSlotIndex.set(s.identityKey, i);
  });
  survivors.forEach((s, i) => {
    const matched = index.get(s.identityKey);
    if (!matched || lastSlotIndex.get(s.identityKey) !== i) {
      result.inserts.push(s.item);
      return;
    }
    // The winning survivor for this existing item. If its content already equals
    // what is stored, the overwrite is a no-op; otherwise it updates in place.
    if (s.contentKey === matched.contentKey) result.unchanged.push(s.item);
    else result.updates.push({ incoming: s.item, existing: matched.item });
  });
  return result;
}

/**
 * Collapse rows that share BOTH an identity key and a content key. The composite
 * grouping key is an unambiguous JSON tuple (an identity key can itself contain
 * the field separator). Winners are returned in the original file order; losers
 * are pushed onto `duplicateInFile`.
 */
function collapseIntraFileDuplicates<I>(
  keyed: KeyedIncoming<I>[],
  strategy: ConflictStrategy,
  duplicateInFile: I[],
): KeyedIncoming<I>[] {
  if (strategy === 'keep_both') return keyed;

  // Record the winning occurrence per composite key in a single pass: under
  // `overwrite` the last write wins, under `skip` the first. `winners` is then a
  // reference set, so no re-indexing (and no non-null assertion) is needed.
  const winnerByComposite = new Map<string, KeyedIncoming<I>>();
  for (const entry of keyed) {
    const composite = JSON.stringify([entry.identityKey, entry.contentKey]);
    if (strategy === 'overwrite' || !winnerByComposite.has(composite)) {
      winnerByComposite.set(composite, entry);
    }
  }
  const winners = new Set<KeyedIncoming<I>>(winnerByComposite.values());

  const survivors: KeyedIncoming<I>[] = [];
  for (const entry of keyed) {
    if (winners.has(entry)) survivors.push(entry);
    else duplicateInFile.push(entry.item);
  }
  return survivors;
}
