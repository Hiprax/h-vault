import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import { SEED, PINNED_LOCALE, RUN_TZ } from './tests/determinism.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Isolate V8 coverage output when a secondary (out-of-band) gate runs alongside
// the primary one: two `vitest run --coverage` invocations sharing a
// `reportsDirectory` race on its `.tmp` scratch folder and crash with
// "Something removed the coverage directory". `VITEST_COVERAGE_DIR`, when set,
// gives each run its own directory; unset, it resolves to the canonical
// `<pkg>/coverage` that CI's artifact upload consumes (Vitest's default — no
// behavior change).
const coverageDir = process.env.VITEST_COVERAGE_DIR
  ? path.resolve(process.env.VITEST_COVERAGE_DIR, 'server')
  : path.resolve(__dirname, 'coverage');

// The gate surface's report directory (`.testfortress/reports`), resolved from
// this file rather than from `process.cwd()` so the JUnit report lands in the
// same place whether the suite is run from the package or from the repo root.
// The tuple is annotated rather than inferred: an unannotated `['junit', {…}]`
// inside an array literal widens to `(string | {…})[]`, which does not match
// vitest's reporter tuple type — and the resulting error is reported against
// an unrelated property further down the config.
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  { outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-server.xml') },
];

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    pool: 'forks',
    // The ONE directory this suite does not pick up, and the reason is not that
    // its assertions are weaker.
    //
    // `tests/resource/**` measures wall-clock duration and peak RSS while
    // building 10,000-item vaults — a minute of work whose numbers are only
    // meaningful in a process running nothing else. Included here they would (a)
    // add that minute to every push, against a 12-minute tier budget, and (b) be
    // measured under three-way worker contention, which is how a budget becomes a
    // coin toss. They run as `test:resource` (Tier 2) through
    // `vitest.resource.config.ts`, which serializes them.
    //
    // This is a NEW directory carved out at the moment it was written, not an
    // existing suite quietly parked: nothing that ran here before still runs
    // nowhere. `gate-surface.test.ts` asserts every file under `tests/resource`
    // is claimed by the resource gate, so a scenario cannot fall between the two
    // configs and be run by neither.
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/resource/**'],
    // There is deliberately no `singleFork` here. The key this file used to
    // carry — `forks: { singleFork: true }` — is not a Vitest 4 option at all
    // (neither `test.forks` nor `test.poolOptions` exists in this version), so it
    // was inert: two test files run in two different worker processes, measured.
    // The suite has therefore been running file-parallel and green all along, and
    // the type checker now rejects the key rather than accepting a setting that
    // does nothing. Do not "restore" it as `fileParallelism: false`: pinning the
    // suite to one worker hides shared state instead of fixing it.
    // `default` keeps the human output; `junit` is what the pipeline reads. A
    // suite whose only output is a terminal cannot be ratcheted or audited.
    reporters: ['default', junitReporter],
    // Order independence is a property of the suite, so it is MEASURED on every
    // run rather than hoped for. Shuffling files exposes cross-file state;
    // shuffling tests (which reorders `describe` blocks within a file too)
    // exposes the in-file kind, which is what a shared mongoose connection and a
    // module-level cache actually produce. The seed is pinned so a failing order
    // is reproducible: an unseeded shuffle turns a real defect into an anecdote.
    // Never "fix" a failure here by switching this off (Forbidden Action 7) — a
    // suite that only passes in declaration order is a suite with an undeclared
    // dependency.
    sequence: {
      shuffle: true,
      seed: SEED,
      // Pinned rather than left to the default, because a load-bearing mechanism
      // rests on it: `useReplicaSetConnection` (tests/mongoHarness.ts) restores
      // the borrowed connection in an `afterAll`, and `mongoHarness.test.ts`
      // OBSERVES that restore from an `afterAll` it registers first — which only
      // works while teardown runs in reverse registration order. `'stack'` IS the
      // resolved default, but Vitest's own CLI help text advertises
      // `(default: "parallel")`, so a contributor reconciling the config with the
      // docs would silently turn that assertion into a coin toss. Stated here so
      // the mechanism is a decision instead of an inherited accident.
      hooks: 'stack',
    },
    coverage: {
      // `cobertura` sits beside lcov because patch-coverage tooling reads
      // Cobertura XML and nothing here should have to re-derive it from lcov.
      provider: 'v8',
      reporter: ['text', 'lcov', 'cobertura'],
      reportsDirectory: coverageDir,
      include: ['src/**/*.ts'],
      // Only genuine process entry points are excluded. Every other module —
      // including the Passport JWT strategy, the rate limiters, the env config
      // and the startup migration runner — is real, security-relevant code that
      // the suite already exercises, so it is MEASURED rather than hidden. An
      // exclusion list that quietly omits testable modules inflates the reported
      // percentage without covering anything.
      exclude: [
        'src/**/*.d.ts',
        'src/**/*.test.ts',
        // Process entry point: binds the port, installs signal handlers and
        // schedules the cron jobs as a side effect of import. Importing it under
        // the test runner would start a live server. The logic worth testing is
        // already extracted into `utils/gracefulShutdown.ts` (covered) — what
        // remains here is the wiring that only a real boot can exercise.
        'src/server.ts',
        // Process entry point: connects to Mongo, acquires the breach-seed job
        // lock, traps SIGINT/SIGTERM and runs the corpus import as a side effect
        // of import — the same class as `src/server.ts`. Its testable logic (arg
        // parsing) lives in `cli/seedBreachesArgs.ts`, which stays MEASURED.
        'src/cli/seedBreaches.ts',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
        statements: 90,
      },
    },
    env: {
      NODE_ENV: 'test',
      // The determinism pins, in the config so they apply before the first
      // module of a test file is evaluated, and NOT as a `TZ=UTC npm test`
      // prefix: this project is developed on Windows too, where that prefix is
      // not valid shell syntax, so a prefix-based pin is one half the
      // contributors silently do not get. `tests/setup.ts` re-applies them (see
      // `tests/determinism.ts`), and `tests/determinism.test.ts` asserts both
      // halves are present.
      // `RUN_TZ` is `PINNED_TZ` ('UTC') for every gate but one: the property
      // gate runs its suites a second time with `HVAULT_TZ=America/New_York`,
      // because `combineExpiry`'s documented repeated-hour hazard is
      // structurally unreachable in a zone with no DST transitions. Resolved in
      // `tests/harness/determinism.ts` from an ALLOWLIST of two zones, so this
      // is still a pin and not a machine-dependent read.
      TZ: RUN_TZ,
      LANG: PINNED_LOCALE,
      // `LC_ALL` as well as `LANG`, because glibc and ICU resolve `LC_ALL`
      // first: with only `LANG` pinned, a developer who exports
      // `LC_ALL=de_DE.UTF-8` runs the suite in a different locale than CI.
      LC_ALL: PINNED_LOCALE,
      SEED: String(SEED),
      PORT: '5555',
      MONGODB_URI: 'mongodb://localhost:27017/hvault-test',
      JWT_ACCESS_SECRET: 'test-access-secret-for-testing-only-32chars!',
      JWT_REFRESH_SECRET: 'test-refresh-secret-for-testing-only-32chars!',
      JWT_ACCESS_EXPIRY: '15m',
      CORS_ORIGIN: 'http://localhost:5173',
      APP_URL: 'http://localhost:5000',
      APP_NAME: 'H-Vault',
      BCRYPT_ROUNDS: '4',
      SESSION_SECRET: 'TestSessionSecret4Testing!!12345',
      // Pinned for the same reason as the SMTP vars below: so the developer's root
      // .env cannot leak into the suite. This one is load-bearing. The controllers
      // encrypt and decrypt 2FA TOTP secrets with `TWO_FACTOR_ENCRYPTION_KEY ??
      // SESSION_SECRET`, while the tests seed those secrets using SESSION_SECRET
      // directly. Leave this unset and a developer who sets a dedicated 2FA key in
      // .env - which .env.example recommends for production - makes the controller
      // decrypt with a different key than the test encrypted with. Every TOTP
      // secret then fails to decrypt and 27 tests across four files turn red with
      // opaque 500s that have nothing to do with the change under test. Pinning it
      // to the same value keeps the resolved key identical either way.
      TWO_FACTOR_ENCRYPTION_KEY: 'TestSessionSecret4Testing!!12345',
      // Pinned EMPTY for the same reason as the SMTP vars: a developer's root
      // .env must not change the shape of the application under test. This one
      // decides whether a ROUTE EXISTS — `app.ts` registers `/api/v1/metrics`
      // only inside `if (config.METRICS_TOKEN)` — so with a token set in .env
      // the app mounts an endpoint `tests/support/routeTable.ts` classifies as
      // absent, and `route-table.test.ts` goes red for a reason unrelated to
      // any change. `config/index.ts` maps '' to undefined inside a
      // `z.preprocess`, so the empty string leaves the route unmounted rather
      // than failing the `.min(16)` bound.
      METRICS_TOKEN: '',
      BACKUP_MAX_SIZE_MB: '25',
      BACKUP_RETENTION_DAYS: '30',
      EXPORT_MAX_SIZE_MB: '25',
      MONGO_MAX_POOL_SIZE: '10',
      MONGO_MIN_POOL_SIZE: '2',
      AUDIT_LOG_RETENTION_DAYS: '365',
      // Override SMTP vars so root .env values don't leak into tests
      EMAIL_PROVIDER: 'smtp',
      SMTP_HOST: '',
      SMTP_USER: '',
      SMTP_PASS: '',
      SMTP_FROM: '',
    },
  },
});
