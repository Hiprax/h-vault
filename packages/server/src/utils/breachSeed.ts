import type { AnyBulkWriteOperation } from 'mongoose';
import { PwnedRangeCache, type IPwnedRangeCache } from '../models/PwnedRangeCache.js';
import { fetchRangeFromHibp } from './hibp.js';

/**
 * Bulk seed of the HIBP Pwned Passwords corpus into {@link PwnedRangeCache}.
 *
 * Under k-anonymity the server needs the COMPLETE range per prefix to answer a
 * negative, and prefixes are uniformly distributed, so only a full-corpus import
 * meaningfully removes on-demand HIBP calls. This is deliberately an opt-in,
 * operator-run job (tens of GB), never auto-downloaded on boot.
 *
 * The importer is idempotent and resumable: an interrupted run can be re-run and
 * will skip prefixes already present (and still fresh, when `staleAfterDays` is
 * given). It never throws for a single failed prefix — those are collected in
 * {@link SeedResult.failed} so a re-run can fill the gaps.
 */

/** 16^5 — the total number of 5-hex-char prefixes. */
export const TOTAL_PREFIXES = 0x10_00_00;

const DEFAULT_CONCURRENCY = 16;
const DEFAULT_BATCH_SIZE = 1000;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY_MS = 250;
const MS_PER_DAY = 86_400_000;

/** Cooperative abort handle (a plain mutable flag, so callers can trap SIGINT). */
export interface SeedSignal {
  aborted: boolean;
}

export interface SeedOptions {
  /** Refetch every prefix even if it is already cached. */
  force?: boolean;
  /** Max concurrent outbound HIBP fetches. */
  concurrency?: number;
  /** First prefix index (0..TOTAL_PREFIXES-1), inclusive. Default 0. */
  fromPrefix?: number;
  /** Last prefix index, inclusive. Default TOTAL_PREFIXES-1. */
  toPrefix?: number;
  /**
   * When set, an existing entry is skipped only if younger than this many days;
   * older entries are refetched. When omitted (and not `force`), ANY existing
   * entry is skipped (pure idempotent fill).
   */
  staleAfterDays?: number;
  /** Per-prefix retry attempts on transient failure. Default 3. */
  retries?: number;
  /** Base backoff between retries (linear). Default 250ms. */
  retryDelayMs?: number;
  /** Upsert flush batch size. Default 1000. */
  batchSize?: number;
  signal?: SeedSignal;
  /** Progress callback, fired roughly every 1000 processed prefixes and once at the end. */
  onProgress?: (done: number, total: number, failed: number) => void;
}

export interface SeedResult {
  /** Prefixes successfully fetched and upserted this run. */
  fetched: number;
  /** Prefixes skipped because they were already present and fresh. */
  skipped: number;
  /** Prefixes that failed after all retries (candidates for a re-run). */
  failed: string[];
  /** Whether the run stopped early because of a cooperative abort. */
  aborted: boolean;
}

/** Format a prefix index as its 5-char uppercase hex representation. */
export function toPrefixHex(n: number): string {
  return n.toString(16).toUpperCase().padStart(5, '0');
}

async function sleep(ms: number): Promise<void> {
  if (ms <= 0) return;
  await new Promise<void>((resolve) => setTimeout(resolve, ms));
}

async function loadSkipSet(
  force: boolean,
  staleAfterDays: number | undefined,
): Promise<Set<string>> {
  if (force) return new Set<string>();
  const skip = new Set<string>();
  const filter: Record<string, unknown> = {};
  if (staleAfterDays !== undefined) {
    filter.fetchedAt = { $gte: new Date(Date.now() - staleAfterDays * MS_PER_DAY) };
  }
  const cursor = PwnedRangeCache.find(filter, { prefix: 1 }).lean().cursor();
  for await (const doc of cursor) {
    skip.add(doc.prefix);
  }
  return skip;
}

export async function seedBreachCorpus(opts: SeedOptions = {}): Promise<SeedResult> {
  const from = opts.fromPrefix ?? 0;
  const to = opts.toPrefix ?? TOTAL_PREFIXES - 1;
  const concurrency = opts.concurrency ?? DEFAULT_CONCURRENCY;
  const batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
  const retries = opts.retries ?? DEFAULT_RETRIES;
  const retryDelayMs = opts.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  const signal = opts.signal;
  const total = Math.max(0, to - from + 1);

  const skip = await loadSkipSet(opts.force ?? false, opts.staleAfterDays);

  const result: SeedResult = { fetched: 0, skipped: 0, failed: [], aborted: false };
  let ops: AnyBulkWriteOperation<IPwnedRangeCache>[] = [];
  let cursor = from;
  let processed = 0;

  const flush = async (): Promise<void> => {
    if (ops.length === 0) return;
    const batch = ops;
    ops = [];
    // A write failure here (e.g. disk exhaustion) is surfaced to the caller
    // (the CLI logs it and exits non-zero); a re-run resumes from what landed.
    // NOTE: validators are deliberately NOT run on these upserts — Mongoose's
    // `required` check on a String rejects '', and an EMPTY range is legitimate
    // (a prefix with no real breached suffixes). See the same note in getRange.
    await PwnedRangeCache.bulkWrite(batch, { ordered: false });
  };

  const fetchWithRetry = async (prefix: string): Promise<string | null> => {
    for (let attempt = 0; attempt <= retries; attempt++) {
      if (signal?.aborted) return null;
      try {
        return await fetchRangeFromHibp(prefix);
      } catch {
        if (attempt < retries) await sleep(retryDelayMs * (attempt + 1));
      }
    }
    return null;
  };

  const worker = async (): Promise<void> => {
    for (;;) {
      if (signal?.aborted) {
        result.aborted = true;
        return;
      }
      const n = cursor++;
      if (n > to) return;
      processed++;
      const prefix = toPrefixHex(n);
      if (skip.has(prefix)) {
        result.skipped++;
      } else {
        const range = await fetchWithRetry(prefix);
        if (range === null) {
          if (signal?.aborted) {
            result.aborted = true;
            return;
          }
          result.failed.push(prefix);
        } else {
          ops.push({
            updateOne: {
              filter: { prefix },
              update: { $set: { range, source: 'seed', fetchedAt: new Date() } },
              upsert: true,
            },
          });
          result.fetched++;
          if (ops.length >= batchSize) await flush();
        }
      }
      if (opts.onProgress && processed % 1000 === 0) {
        opts.onProgress(processed, total, result.failed.length);
      }
    }
  };

  const workerCount = Math.min(concurrency, Math.max(1, total));
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  await flush();
  if (opts.onProgress) opts.onProgress(processed, total, result.failed.length);
  return result;
}
