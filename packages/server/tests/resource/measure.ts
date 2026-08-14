/**
 * The measurement seam for the `test:resource` suite.
 *
 * Everything in this directory answers one question: does an operation on a
 * FULL vault stay inside a time and memory budget, and does the streaming path
 * that exists to bound memory actually stream? Both halves need a measurement
 * that is honest about what it can and cannot see, so the mechanics live here
 * rather than being restated in five files.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. RSS IS SAMPLED, NOT DIFFED AT THE ENDS. `process.memoryUsage.rss()` before
 *     and after an operation reports whatever V8 happened to be holding at those
 *     two instants, which for a request that allocates 20 MB and then drops it
 *     can be zero. The peak is what the budget is about, so it is polled while
 *     the operation runs and the poll is cheap enough (a counter read, no
 *     allocation) to run at {@link SAMPLE_INTERVAL_MS}.
 *
 *  b. ONE MEASURED SCENARIO PER FILE, AND THAT IS WHY THIS DIRECTORY HAS SEVEN
 *     FILES INSTEAD OF THE TWO THE OBVIOUS LAYOUT WOULD GIVE. V8 does not return
 *     freed pages to the OS promptly, so a second scenario in the same worker
 *     starts from a floor the first one raised: its `peak - start` growth reads
 *     LOW, and a memory budget that reads low is a budget that cannot fail. The
 *     suite's global `afterEach` truncates every collection as well, so a vault
 *     seeded in `beforeAll` survives exactly one test in any case. Vitest's
 *     `forks` pool gives each test FILE its own process, so a file boundary is
 *     the cheapest real isolation available here. `processMaxRssMb`
 *     (the kernel's own high-water mark for the worker) is reported beside the
 *     sampled numbers as the corroborating figure.
 *
 *  c. THE MEASUREMENT INCLUDES THE TEST PROCESS, NOT JUST THE SERVER. Supertest
 *     drives the real Express app IN THIS PROCESS, so a scenario whose response
 *     body is 20 MB pays for that body twice: once where the handler builds it
 *     and once where superagent buffers it. That is stated in each budget's
 *     docblock rather than corrected for, because subtracting an estimate would
 *     make the number less trustworthy, not more — and the budget is a ceiling
 *     on the whole operation either way.
 *
 *  d. EVERY SCENARIO WRITES ITS OUTCOME TO A REPORT, measured or not. `scripts/ci/resource-gate.mjs`
 *     aggregates them into `resource.json`, which is what the gate publishes and
 *     what `.testfortress/baseline.json` records. A budget nobody can read after
 *     the fact is a budget nobody can re-derive when it needs to move.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import mongoose from 'mongoose';
import { REPO_ROOT } from '../tempDir.js';

/** How often the RSS poller reads the counter while a scenario runs. */
const SAMPLE_INTERVAL_MS = 20;

const BYTES_PER_MB = 1024 * 1024;

/** Where each scenario drops its numbers for `resource-gate.mjs` to collect. */
const SCENARIO_REPORT_DIR = path.join(REPO_ROOT, '.testfortress', 'reports', 'resource-scenarios');

const mb = (bytes: number): number => Number((bytes / BYTES_PER_MB).toFixed(2));

/** What one measured operation cost. */
export interface Measured<T> {
  result: T;
  durationMs: number;
  /** RSS when the operation started. */
  rssStartMb: number;
  /** The highest RSS observed while it ran. */
  peakRssMb: number;
  /** `peakRssMb - rssStartMb`: what THIS operation added. */
  rssGrowthMb: number;
  /** The kernel's high-water mark for the whole worker, for corroboration. */
  processMaxRssMb: number;
}

/**
 * Runs `operation`, polling RSS throughout, and returns its result beside the
 * cost.
 *
 * The poller is `unref`'d so a scenario that throws can never hold the worker
 * open, and it is cleared in a `finally` so a rejection is still measured.
 */
export async function measure<T>(operation: () => Promise<T>): Promise<Measured<T>> {
  const rssStart = process.memoryUsage.rss();
  let peak = rssStart;
  const poller = setInterval(() => {
    const now = process.memoryUsage.rss();
    if (now > peak) peak = now;
  }, SAMPLE_INTERVAL_MS);
  poller.unref();

  const startedAt = Date.now();
  try {
    const result = await operation();
    const durationMs = Date.now() - startedAt;
    // One last read: an operation shorter than the sample interval would
    // otherwise report a peak of exactly its starting value.
    const final = process.memoryUsage.rss();
    if (final > peak) peak = final;
    return {
      result,
      durationMs,
      rssStartMb: mb(rssStart),
      peakRssMb: mb(peak),
      rssGrowthMb: mb(peak - rssStart),
      processMaxRssMb: mb(process.resourceUsage().maxRSS * 1024),
    };
  } finally {
    clearInterval(poller);
  }
}

/**
 * How many documents mongod has returned to clients since this server started.
 *
 * This is the seam that tells a CURSOR apart from a `find().lean()`, and it is
 * read from the SERVER rather than instrumented in the driver on purpose: the
 * claim under test is "the application stopped asking for documents", and the
 * only party that knows how many documents were actually handed over is the one
 * that handed them over. A driver-side spy would have to be installed by
 * changing how the suite connects, which is exactly the kind of harness-only
 * seam that stops resembling production.
 *
 * `metrics.document.returned` is a monotonic counter, so a scenario takes the
 * difference across the operation it measures. Each test file gets its own
 * mongod (see `tests/mongoHarness.ts`), so nothing else is contributing to it.
 */
export async function documentsReturned(): Promise<number> {
  const db = mongoose.connection.db;
  if (!db) throw new Error('documentsReturned() called without a live mongoose connection');
  const status = (await db.command({ serverStatus: 1 })) as {
    metrics: { document: { returned: number } };
  };
  return Number(status.metrics.document.returned);
}

/** One case's line in `resource.json`. */
export interface ScenarioCase {
  /** The invariant the payload below is evidence for. */
  invariant: string;
  [metric: string]: unknown;
}

interface ScenarioFile {
  scenario: string;
  measuredAt: string;
  cases: Record<string, ScenarioCase>;
}

/**
 * Records one case's outcome where the gate can find it.
 *
 * EVERY case records, not only the ones with a memory budget. `resource-gate.mjs`
 * compares what arrived against the case counts declared in
 * `scripts/ci/lib/resource-budgets.mjs`, so a scenario that stopped running — a
 * renamed file, a `describe` that never executed, an `include` that quietly
 * stopped matching — is a failure rather than a silence. Budgets are then checked
 * against whichever cases carry a `durationMs`, so an unmeasured case needs no
 * special declaration.
 *
 * The write MERGES, because a scenario with two cases writes twice and the suite
 * shuffles, so neither ordering may lose the other's result.
 *
 * `.testfortress/**` is one of the few paths the repo-write guard
 * (`tests/harness/repoWrites.ts`) allows, because it IS the gate surface. The
 * gate deletes this directory before each run, so a stale file can never stand in
 * for a scenario that did not execute.
 */
export function recordScenarioCase(scenario: string, caseId: string, report: ScenarioCase): void {
  mkdirSync(SCENARIO_REPORT_DIR, { recursive: true });
  const file = path.join(SCENARIO_REPORT_DIR, `${scenario}.json`);
  let existing: ScenarioFile = { scenario, measuredAt: new Date().toISOString(), cases: {} };
  if (existsSync(file)) {
    existing = JSON.parse(readFileSync(file, 'utf8')) as ScenarioFile;
  }
  existing.measuredAt = new Date().toISOString();
  existing.cases[caseId] = report;
  writeFileSync(file, `${JSON.stringify(existing, null, 2)}\n`, 'utf8');
}
