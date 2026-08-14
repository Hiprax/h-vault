/**
 * The committed budgets for `test:resource`, and the scenarios that produce them.
 *
 * ONE definition, in `.mjs`, because three different consumers need the same
 * numbers and any second copy of them is a copy that will disagree:
 *
 *   • the scenarios themselves (`packages/server/tests/resource/*.test.ts`),
 *     which assert against them — this is where the gate actually fails;
 *   • `scripts/ci/resource-gate.mjs`, which checks that every scenario reported
 *     and restates the verdict in `resource.json`;
 *   • `scripts/ci/ratchet-check.mjs`, which reads these constants FROM THIS FILE
 *     into the comparison and declares them `lower`-is-better, so raising a
 *     ceiling here is a regression on the `audit:ratchet:full` gate that runs on
 *     every push, and `--accept` cannot move it upward.
 *
 * The TypeScript suites import this file directly (`allowJs` is on in
 * `packages/server/tsconfig.test.json`, and `gate-surface.test.ts` already
 * imports `lib/tiers.mjs` the same way), so the numbers are shared rather than
 * mirrored.
 *
 * ---------------------------------------------------------------------------
 * HOW THESE NUMBERS WERE SET
 * ---------------------------------------------------------------------------
 *
 * Measured on the reference machine (4 cores, 31 GB, Linux, mongodb-memory-server
 * on a tmpfs) over {@link NOISE_BAND.runs} consecutive runs of the whole suite,
 * one scenario per forked worker, no other gate running. `NOISE_BAND` records the
 * observed spread for each metric as a percentage of its median; each ceiling is
 * then set well above the observed maximum, because a budget that fires on a
 * loaded laptop is a budget that gets deleted.
 *
 * A budget here is a CEILING ON A REGRESSION, not a performance target. The
 * question each one answers is "did this operation change ORDER OF MAGNITUDE?",
 * which is the class of change that matters — swapping a cursor for a full read,
 * dropping an index, turning one round trip into ten thousand. A 20% drift is
 * below what any of these can see, and saying so is the honest description of the
 * gate rather than a caveat on it.
 */

/**
 * The scenarios, in the order the gate runs them, and the report each writes.
 *
 * A scenario listed here that writes no report is a FAILURE, not an absence:
 * that is the shape a suite silently narrowed by a bad `include` produces. `cases`
 * is the number of outcomes each file records, so a `describe` that loses a test
 * is caught the same way, and `measured` says whether the scenario carries a
 * time and memory budget at all.
 */
export const RESOURCE_SCENARIOS = [
  {
    id: 'backup-streaming',
    cases: 1,
    file: 'tests/resource/backup-streaming.test.ts',
    measured: true,
    subject: 'a 10,000-item vault four times the backup cap, refused with 413',
  },
  {
    id: 'backup-full-vault',
    cases: 1,
    file: 'tests/resource/backup-full-vault.test.ts',
    measured: true,
    subject: 'a 10,000-item vault just under the backup cap, collected in full',
  },
  {
    id: 'rotation-volume',
    cases: 1,
    file: 'tests/resource/rotation-volume.test.ts',
    measured: true,
    subject: 'a 10,000-item vault key rotation',
  },
  {
    id: 'rotation-atomicity',
    cases: 1,
    file: 'tests/resource/rotation-atomicity.test.ts',
    measured: false,
    subject: 'a full-vault rotation naming one unknown id, which must change nothing',
  },
  {
    id: 'restore-volume',
    cases: 1,
    file: 'tests/resource/restore-volume.test.ts',
    measured: true,
    subject: 'a ~25 MiB backup restored through the 30 MB route parser',
  },
  {
    id: 'restore-body-boundary',
    cases: 2,
    file: 'tests/resource/restore-body-boundary.test.ts',
    measured: false,
    subject: 'the restore body boundary from above: 400 from Zod, 413 from the parser',
  },
  {
    id: 'job-index-plans',
    cases: 2,
    file: 'tests/resource/job-index-plans.test.ts',
    measured: false,
    subject: "the two cross-user cleanup sweeps' query plans",
  },
];

/**
 * The ceilings. Every one is a CEILING ON A STEP CHANGE, and the docblock on each
 * says what it can and cannot see.
 */
export const RESOURCE_BUDGETS = {
  backupStreaming: {
    /**
     * Observed 268-443 ms over five runs. The ceiling is an order of magnitude
     * above that and deliberately does NOT try to see the cursor regression: a
     * `find().lean()` takes 759-895 ms here, which is only 1.7x the observed
     * maximum, and a threshold in that gap would fire on any loaded machine. The
     * other two numbers below are what catch it. This one catches a hang.
     */
    durationMs: 5_000,
    /**
     * THE ONE BUDGET IN THIS FILE THAT SEES A NAMED REGRESSION, with both bands
     * measured. The cursor implementation grows RSS by 43.4-58.1 MB over eleven
     * runs; replacing the item cursor with `find().lean()` grows it by
     * 118.5-156.4 MB over three. 95 MB sits 1.63x above the highest good run and
     * 0.80x below the lowest bad one — clear of both, with no overlap to argue
     * about.
     */
    rssGrowthMb: 95,
    /**
     * The fraction of the vault mongod was asked for before the 413. Measured at
     * 0.332 in ELEVEN out of eleven runs — this is the deterministic half of the
     * scenario, unaffected by machine load — against 1.0003 for `find().lean()`
     * (the three extra documents are the user lookup and the folder cursor). The
     * ceiling is 0.60 rather than 0.35 because the exact figure depends on the
     * driver's batch size, which is not this application's contract; what IS the
     * contract is that most of the vault is never asked for.
     */
    deliveredFraction: 0.6,
  },
  backupFullVault: {
    /** Observed 439-724 ms. An order-of-magnitude ceiling; see the note above. */
    durationMs: 6_000,
    /** Observed 52.0-58.4 MB (the tightest band here, 11%). Ceiling at ~2x. */
    rssGrowthMb: 120,
  },
  rotationVolume: {
    /** Observed 6.7-9.9 s for 10,000 sequential updates. Ceiling at ~4.5x. */
    durationMs: 45_000,
    /** Observed 66.7-126.1 MB — the widest band here, 50%. Ceiling at ~1.75x. */
    rssGrowthMb: 220,
  },
  restoreVolume: {
    /** Observed 17.4-21.1 s for 10,000 inserted rows. Ceiling at ~3.5x. */
    durationMs: 75_000,
    /** Observed 111.4-143.5 MB for a 26 MB body. Ceiling at ~1.8x. */
    rssGrowthMb: 260,
  },
};

/**
 * The measured spread each ceiling was set against: five consecutive runs of the
 * whole suite on the reference machine, idle, one scenario per forked worker.
 *
 * Recorded rather than summarised because it is what makes the ceilings
 * reviewable — and because it is the honest statement of this gate's resolution.
 * A metric whose good runs vary by 50% cannot detect a 20% regression, and
 * pretending otherwise is how a budget becomes a flaky test that someone deletes.
 * `.testfortress/suppressions.json` carries the matching `KNOWN-GAP` entry.
 */
export const NOISE_BAND = {
  runs: 5,
  measuredOn: '2026-08-13',
  host: '4 cores, 31 GB, Linux, mongodb-memory-server on tmpfs',
  scenarios: {
    'backup-streaming.durationMs': { min: 268, median: 352, max: 443, spreadPct: 49.7 },
    'backup-streaming.rssGrowthMb': { min: 43.43, median: 45.24, max: 58.11, spreadPct: 32.4 },
    'backup-full-vault.durationMs': { min: 439, median: 605, max: 724, spreadPct: 47.1 },
    'backup-full-vault.rssGrowthMb': { min: 52.03, median: 56.95, max: 58.42, spreadPct: 11.2 },
    'rotation-volume.durationMs': { min: 6682, median: 9311, max: 9943, spreadPct: 35.0 },
    'rotation-volume.rssGrowthMb': { min: 66.68, median: 118.82, max: 126.05, spreadPct: 50.0 },
    'restore-volume.durationMs': { min: 17447, median: 19845, max: 21059, spreadPct: 18.2 },
    'restore-volume.rssGrowthMb': { min: 111.36, median: 138.97, max: 143.49, spreadPct: 23.1 },
  },
  /**
   * The one measurement with NO spread, over eleven runs, and the reason the
   * streaming scenario has a real verdict rather than only a sanity ceiling.
   */
  deterministic: {
    'backup-streaming.documentsDelivered': { runs: 11, value: 3320, of: 10000 },
  },
  /**
   * The same two metrics under the regression the streaming scenario exists to
   * catch — the item cursor replaced by `find().lean()` — so the separation
   * between the bands is on the record rather than asserted.
   */
  regressionBand: {
    'backup-streaming.documentsDelivered': { runs: 3, value: 10003 },
    'backup-streaming.rssGrowthMb': { runs: 3, min: 118.54, max: 156.41 },
  },
};
