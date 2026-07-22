#!/usr/bin/env tsx
/**
 * Opt-in full-corpus breach seed.
 *
 * Imports the HIBP Pwned Passwords corpus into the `pwned_range_cache`
 * collection so password-breach lookups can be answered entirely from the local
 * database (offline / zero-third-party-dependency operation). This is HEAVY:
 * ~1,048,576 range requests, tens of GB transferred, ~15-25 GB on disk after
 * WiredTiger compression. It is idempotent and resumable — safe to re-run.
 *
 * Usage:
 *   npm run seed-breaches -w packages/server
 *   npm run seed-breaches -w packages/server -- --concurrency=24
 *   npm run seed-breaches -w packages/server -- --from=00000 --to=00FFF   (a slice)
 *   npm run seed-breaches -w packages/server -- --force                   (refetch all)
 *   npm run seed-breaches -w packages/server -- --stale-days=30           (refresh entries older than 30d)
 *
 * Requires MONGODB_URI (or a root .env).
 */

import mongoose from 'mongoose';
import { config } from '../src/config/index.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';
import {
  seedBreachCorpus,
  toPrefixHex,
  TOTAL_PREFIXES,
  type SeedSignal,
} from '../src/utils/breachSeed.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { BREACH_SEED_LOCK_NAME, BREACH_SEED_LOCK_TTL_MS } from '../src/jobs/breachSeed.js';

interface CliArgs {
  force: boolean;
  concurrency: number | undefined;
  from: number | undefined;
  to: number | undefined;
  staleDays: number | undefined;
}

function parseArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = {
    force: false,
    concurrency: undefined,
    from: undefined,
    to: undefined,
    staleDays: undefined,
  };
  for (const raw of argv) {
    if (raw === '--force') {
      args.force = true;
      continue;
    }
    const eq = raw.indexOf('=');
    if (!raw.startsWith('--') || eq === -1) continue;
    const key = raw.slice(2, eq);
    const value = raw.slice(eq + 1);
    switch (key) {
      case 'concurrency':
        args.concurrency = Number.parseInt(value, 10);
        break;
      case 'from':
        args.from = Number.parseInt(value, 16);
        break;
      case 'to':
        args.to = Number.parseInt(value, 16);
        break;
      case 'stale-days':
        args.staleDays = Number.parseInt(value, 10);
        break;
      default:
        break;
    }
  }
  return args;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const from = args.from ?? 0;
  const to = args.to ?? TOTAL_PREFIXES - 1;

  if (
    !Number.isInteger(from) ||
    !Number.isInteger(to) ||
    from < 0 ||
    to > TOTAL_PREFIXES - 1 ||
    from > to
  ) {
    console.error(`Invalid --from/--to range: ${toPrefixHex(from)}..${toPrefixHex(to)}`);
    process.exitCode = 1;
    return;
  }

  // Fail fast on a malformed numeric flag. Without this a typo'd --concurrency
  // parses to NaN, which collapses the worker pool to zero and makes the run
  // report "fetched 0, failed 0" as if it had succeeded.
  if (
    args.concurrency !== undefined &&
    (!Number.isInteger(args.concurrency) || args.concurrency < 1)
  ) {
    console.error('Invalid --concurrency: expected a positive integer (e.g. --concurrency=24).');
    process.exitCode = 1;
    return;
  }
  if (args.staleDays !== undefined && (!Number.isInteger(args.staleDays) || args.staleDays < 0)) {
    console.error('Invalid --stale-days: expected a non-negative integer (e.g. --stale-days=30).');
    process.exitCode = 1;
    return;
  }

  const total = to - from + 1;
  const fullRun = from === 0 && to === TOTAL_PREFIXES - 1;

  console.log(`Connecting to MongoDB: ${config.MONGODB_URI.replace(/\/\/[^@]+@/, '//***@')}`);
  await mongoose.connect(config.MONGODB_URI, {
    maxPoolSize: config.MONGO_MAX_POOL_SIZE,
    minPoolSize: config.MONGO_MIN_POOL_SIZE,
    serverSelectionTimeoutMS: 10_000,
  });

  // Ensure the unique prefix index exists before bulk upserting.
  await PwnedRangeCache.createIndexes();

  const lockId = await acquireJobLock(BREACH_SEED_LOCK_NAME, BREACH_SEED_LOCK_TTL_MS);
  if (!lockId) {
    console.error('Another breach-seed run holds the lock. Aborting to avoid a concurrent seed.');
    await mongoose.disconnect();
    process.exitCode = 1;
    return;
  }

  console.log('');
  console.log(
    `Seeding ${String(total)} prefix range(s) [${toPrefixHex(from)}..${toPrefixHex(to)}]`,
  );
  if (fullRun) {
    console.log('WARNING: a full-corpus seed transfers roughly 30-40 GB and stores');
    console.log('         ~15-25 GB on disk (after WiredTiger compression). Ensure the');
    console.log('         MongoDB data volume has at least 40 GB free before continuing.');
    console.log('         The run is resumable — Ctrl-C stops it cleanly and a re-run continues.');
  }
  console.log('');

  const signal: SeedSignal = { aborted: false };
  const onSignal = (): void => {
    if (!signal.aborted) {
      console.log('\nAbort requested — flushing the in-flight batch and stopping...');
      signal.aborted = true;
    }
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);

  const started = Date.now();
  try {
    const result = await seedBreachCorpus({
      force: args.force,
      ...(args.concurrency !== undefined ? { concurrency: args.concurrency } : {}),
      fromPrefix: from,
      toPrefix: to,
      ...(args.staleDays !== undefined ? { staleAfterDays: args.staleDays } : {}),
      signal,
      onProgress: (done, tot, failed) => {
        const pct = tot > 0 ? ((done / tot) * 100).toFixed(1) : '100.0';
        console.log(
          `  ${String(done)}/${String(tot)} (${pct}%) — failed so far: ${String(failed)}`,
        );
      },
    });

    const secs = ((Date.now() - started) / 1000).toFixed(0);
    console.log('');
    console.log(
      `Done in ${secs}s — fetched ${String(result.fetched)}, skipped ${String(result.skipped)}, failed ${String(result.failed.length)}${result.aborted ? ' (aborted early)' : ''}.`,
    );
    if (result.failed.length > 0) {
      const preview = result.failed.slice(0, 20).join(', ');
      console.error(
        `${String(result.failed.length)} prefix(es) failed after retries (re-run to fill the gaps). First few: ${preview}`,
      );
      process.exitCode = 1;
    }
  } catch (error: unknown) {
    console.error('Seed aborted with an error:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    await releaseJobLock(BREACH_SEED_LOCK_NAME, lockId);
    await mongoose.disconnect();
  }
}

main().catch((error: unknown) => {
  console.error('Fatal error:', error);
  process.exitCode = 1;
});
