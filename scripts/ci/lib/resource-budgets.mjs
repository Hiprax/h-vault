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
  {
    id: 'documents-part-upload',
    cases: 1,
    file: 'tests/resource/documents-part-upload.test.ts',
    measured: true,
    subject:
      'a document at the configured maximum size delivered part by part through the real route',
  },
  {
    id: 'documents-list-volume',
    cases: 1,
    file: 'tests/resource/documents-list-volume.test.ts',
    measured: true,
    subject: 'a full account of MAX_DOCUMENTS_PER_USER documents walked page by page',
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
  documentsPartUpload: {
    /**
     * Observed 790-809 ms over five runs for 100 MB across thirteen parts — the
     * tightest band in this file at 2.4%. The ceiling is an order of magnitude
     * above it and deliberately does NOT try to see the retention regression
     * below: that costs only 851-874 ms, which is 1.08x the observed maximum and
     * far inside any machine's noise. This one catches a hang, or a part route
     * that started doing per-part work it did not do before. The memory ceiling
     * is what catches retention.
     */
    durationMs: 8_000,
    /**
     * THE BUDGET WITH A MEASURED REGRESSION ON BOTH SIDES. The route as written
     * grows RSS by 82.28-86.39 MB over six runs; making the storage double RETAIN
     * each part instead of hashing and dropping it — which is what a handler that
     * accumulated parts, or a double somebody "fixed" to store them, would cost —
     * grows it by 149-167 MB over five. 120 MB sits 1.39x above the highest good
     * run and 0.81x below the lowest bad one, with no overlap to argue about, and
     * the good band's 2-4% spread means that headroom is many multiples of the
     * noise.
     *
     * Note what the two bands are NOT separated by: thirteen retained 8 MiB parts
     * are 104 MB of ciphertext, and the measured gap is about 70. V8 collects some
     * of it while the transfer is still running, which is exactly why this number
     * was measured rather than computed.
     */
    rssGrowthMb: 120,
  },
  documentsListVolume: {
    /**
     * Observed 650-683 ms over five runs for twenty-five pages of two hundred
     * rows. An order-of-magnitude ceiling: the regression this scenario exists to
     * catch costs 1,875 ms, which is only 2.7x the observed maximum, so duration
     * cannot be the thing that catches it. `deliveredFraction` is.
     */
    durationMs: 6_000,
    /**
     * Observed 24.2-31.2 MB. A SANITY ceiling, and honestly labelled as one: the
     * measured regression grows RSS by 39.4 MB, which is 1.26x the observed
     * maximum and inside the band's own spread, so this number cannot see it
     * either. A page is a page whether it was sliced in mongod or in the handler,
     * and the account is only five megabytes on disk. What this catches is a
     * handler that started holding the whole account across the walk.
     */
    rssGrowthMb: 90,
    /**
     * THE ONE WITH TEETH, and deterministic. `metrics.document.returned` divided
     * by the account's row count. Measured at 1.01 in FIVE out of five runs — 5,050
     * documents for a 5,000-row account, which is two hundred rows plus the count's
     * single aggregation row plus the authenticating user lookup, times twenty-five
     * pages — against 25.01 in three out of three with `sendDocumentPage`'s
     * `.skip().limit()` replaced by a full read and a JavaScript slice. The ceiling
     * is 2.0 rather than 1.1 because the exact figure depends on the driver's batch
     * behaviour and on how many round trips authentication costs, neither of which
     * is this application's contract; what IS the contract is that a page costs one
     * page, not one account.
     */
    deliveredFraction: 2.0,
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
    // The two document scenarios, measured 2026-09-02 on the same host under the
    // same protocol: five consecutive runs of the whole suite, one scenario per
    // forked worker, nothing else running — plus the gate's own run, whose
    // documents-part-upload rssGrowthMb of 82.28 MB came in BELOW the five-run
    // minimum of 82.85 and widened that band rather than being left out of it. So
    // its min and max are over SIX measurements, which is the sample size
    // SUP-0027 quotes for it; the median stayed the five-run one, because a run
    // recorded for its extreme does not re-centre a sample.
    'documents-part-upload.durationMs': { min: 790, median: 803, max: 809, spreadPct: 2.4 },
    'documents-part-upload.rssGrowthMb': { min: 82.28, median: 85.32, max: 86.39, spreadPct: 4.8 },
    'documents-list-volume.durationMs': { min: 650, median: 657, max: 683, spreadPct: 5.0 },
    'documents-list-volume.rssGrowthMb': { min: 24.19, median: 28.2, max: 31.2, spreadPct: 24.9 },
  },
  /**
   * The one measurement with NO spread, over eleven runs, and the reason the
   * streaming scenario has a real verdict rather than only a sanity ceiling.
   */
  deterministic: {
    'backup-streaming.documentsDelivered': { runs: 11, value: 3320, of: 10000 },
    'documents-list-volume.documentsDelivered': { runs: 5, value: 5050, of: 5000 },
  },
  /**
   * The same two metrics under the regression the streaming scenario exists to
   * catch — the item cursor replaced by `find().lean()` — so the separation
   * between the bands is on the record rather than asserted.
   */
  regressionBand: {
    'backup-streaming.documentsDelivered': { runs: 3, value: 10003 },
    'backup-streaming.rssGrowthMb': { runs: 3, min: 118.54, max: 156.41 },
    // The storage double made to RETAIN each part rather than hash and drop it.
    'documents-part-upload.rssGrowthMb': { runs: 5, min: 148.6, max: 167.43 },
    // `sendDocumentPage`'s `.skip().limit()` replaced by a full read and a slice.
    'documents-list-volume.documentsDelivered': { runs: 3, value: 125050 },
    'documents-list-volume.deliveredFraction': { runs: 3, value: 25.01 },
  },
};
