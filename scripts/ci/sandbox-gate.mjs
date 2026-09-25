#!/usr/bin/env node
/**
 * `test:sandbox` — the isolated render document, rendered by a real browser
 * under the headers the BUILT artifact sends.
 *
 * Every other browser run drives the Vite dev server, which has neither helmet
 * nor Nginx, so `/sandbox.html` arrives there with no Content-Security-Policy at
 * all. `test:smoke` asserts the policy and the two `sandbox-assets/` headers over
 * HTTP, directive by directive, but never runs a browser — so a policy correct
 * on the wire that still breaks a renderer in a real engine (a `blob:` media
 * source, a `data:` image, a module script refused across the opaque origin) had
 * no gate in front of it. This one stands up exactly what `test:smoke` stands up,
 * adds the pinned object-storage engine the document store needs, and points
 * `playwright.sandbox.config.ts` at it through `E2E_BASE_URL`.
 *
 *   node --import tsx scripts/ci/sandbox-gate.mjs     the gate (what the pipeline runs)
 *   npm run test:sandbox                              the same thing
 *
 * Its release-tier sibling is the Nginx leg of `test:deploy`, which runs the same
 * config through the Compose stack's one published port: there the inner Nginx
 * serves `sandbox-assets/` from its OWN header set and adds its header floor to
 * the proxied document, which no Express-only run can reach.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE ARTIFACT, NOT THE SOURCES, AND IN PRODUCTION MODE. Staged and booted by
 *     `lib/artifact.mjs`, the one copy `test:smoke` uses too: the route that
 *     attaches the sandbox policy, the `sandbox-assets/` headers and the service
 *     worker exist ONLY in a production build served in production mode.
 *
 *  b. THE DEPLOYMENT'S BOOTSTRAP RUNS FIRST. Production turns `autoIndex` off and
 *     the Compose stack runs `create-indexes` as a one-shot before the app starts,
 *     so this gate does the same against its own mongod rather than booting a
 *     server whose rate-limit and upload collections have no indexes at all.
 *
 *  c. `tsx` IS THE LOADER, and only for two imports: the storage harness
 *     (`tests/harness/s3Server.ts`) and the server's own storage provider, whose
 *     HeadBucket is the readiness probe — the same two `e2e/start-server.ts`
 *     uses, so "ready" means ready for the server's own client rather than merely
 *     that a socket answers.
 *
 *  d. `docker` IS DECLARED, NOT DISCOVERED. Without the engine the server reports
 *     the document store off and every preview spec fails for a reason that says
 *     nothing about the policy, so a missing daemon is reported by the runner as
 *     COULD NOT RUN (exit 2), never as a red gate.
 *
 *  e. A GREEN PLAYWRIGHT EXIT IS NOT THE VERDICT. The run's own JUnit report must
 *     name every file in the suite, each having executed a test and skipped none
 *     (`lib/sandbox-browser.mjs`), because a stale `testMatch` entry or a
 *     `test.skip` exits 0 having rendered less than this gate claims.
 *
 *  f. TEARDOWN OWNS A CONTAINER, A RAM-BACKED DBPATH AND A SERVER, so it runs on
 *     every exit, SIGTERM included. The storage harness installs signal handlers
 *     that remove its container and exit at once; they are replaced here, as in
 *     `e2e/start-server.ts`, so a signal stops the server and mongod too instead of
 *     stranding them.
 */
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { runExe, runNpm } from './lib/proc.mjs';
import { color, formatDuration, symbol } from './lib/ui.mjs';
import { ensureReportDir, reportPath, writeJsonReport } from './lib/reports.mjs';
import { applyRseqTunable } from './lib/mongo-rseq.mjs';
import {
  BOOT_DEADLINE_MS,
  bootArtifact,
  freePort,
  missingArtifact,
  productionEnv,
  removeWorkspace,
  stageArtifact,
  stopArtifact,
} from './lib/artifact.mjs';
import { SANDBOX_JUNIT, SANDBOX_SUITE, sandboxRunProblems } from './lib/sandbox-browser.mjs';

/** The https origin production requires of `APP_URL` and `CORS_ORIGIN`. */
const ORIGIN = 'https://sandbox.hvault.test';

// SERVER-121912: this gate spawns a real mongod, so it is one of the
// repository's mongod launch sites. Applied at MODULE SCOPE for the reason
// `smoke-gate.mjs` gives; the merge is `scripts/ci/lib/mongo-rseq.mjs`.
applyRseqTunable();

const started = Date.now();
const steps = [];
const failures = [];

const record = (name, ok, detail, extra = {}) => {
  steps.push({ name, ok, detail, ...extra });
  if (ok) console.log(color.green(`  ${symbol.pass} ${name} — ${detail}`));
  else {
    failures.push(`${name}: ${detail}`);
    console.error(color.red(`  ${symbol.fail} ${name} — ${detail}`));
  }
  return ok;
};

ensureReportDir();
// A report left by an earlier run would satisfy (e) for a run that rendered
// nothing.
rmSync(reportPath(SANDBOX_JUNIT), { force: true });
console.log(
  color.bold('\n  sandbox — the isolated document, in a browser, under production headers\n'),
);

let workspace;
let mongo;
let engine;
let child;
let tornDown;

// (f) At most once, whoever asks first: the signal handler and the normal path
// can both reach it, and a second mongod stop entered while the first is still
// running trips the memory server's own assertion.
const teardown = () => {
  tornDown ??= (async () => {
    await stopArtifact(child);
    for (const [name, stop] of [
      ['mongod', () => mongo?.stop()],
      ['storage engine', () => engine?.stop()],
    ]) {
      try {
        await stop();
      } catch (error) {
        record('teardown', false, `the ${name} did not stop cleanly: ${String(error)}`);
      }
    }
    removeWorkspace(workspace);
  })();
  return tornDown;
};

const writeReport = (extra = {}) =>
  writeJsonReport('sandbox.json', {
    version: 1,
    task: 'test:sandbox',
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    bootDeadlineMs: BOOT_DEADLINE_MS,
    suite: SANDBOX_SUITE,
    failures,
    steps,
    ...extra,
  });

let playwrightExit = null;
try {
  const missing = missingArtifact();
  if (missing) throw new Error(missing);

  const staged = stageArtifact('hvault-sandbox-');
  workspace = staged.workspace;
  const { artifact } = staged;
  record('stage', true, 'dist + public + sandbox-document staged beside a linked dependency tree');

  const { MongoMemoryServer } = await import('mongodb-memory-server');
  mongo = await MongoMemoryServer.create({ instance: { dbName: 'hvault' } });
  const mongoUri = mongo.getUri('hvault');
  record('mongod', true, 'a real mongod is listening for the artifact');

  // (c) The same engine and the same readiness probe as the E2E harness.
  const { startStorageEngine } = await import('../../tests/harness/s3Server.ts');
  const { createS3Provider } =
    await import('../../packages/server/src/services/storage/s3Provider.ts');
  engine = await startStorageEngine({
    probe: (connection) => createS3Provider(connection).headBucket(),
  });
  // (f) Take the signals back from the harness.
  process.removeAllListeners('SIGINT');
  process.removeAllListeners('SIGTERM');
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      record('signal', false, `${signal} received before the run finished`);
      void teardown().then(() => {
        writeReport();
        process.exit(1);
      });
    });
  }
  record('storage', true, `the pinned engine answers on ${engine.endpoint} (${engine.image})`);

  const port = await freePort();
  const env = productionEnv({
    port,
    mongoUri,
    origin: ORIGIN,
    extra: {
      S3_ENDPOINT: engine.endpoint,
      S3_REGION: engine.region,
      S3_BUCKET: engine.bucket,
      S3_ACCESS_KEY_ID: engine.accessKeyId,
      S3_SECRET_ACCESS_KEY: engine.secretAccessKey,
      S3_FORCE_PATH_STYLE: String(engine.forcePathStyle),
    },
  });

  // (b) The bootstrap, exactly as the stack's one-shot runs it.
  const indexes = await runExe(
    process.execPath,
    ['--import', 'tsx', 'packages/server/scripts/create-indexes.ts'],
    { env },
  );
  if (!record('indexes', indexes === 0, `create-indexes exited ${String(indexes)}`)) {
    throw new Error('the index bootstrap failed');
  }

  // (f) Known to the teardown from the moment it exists, not from when it
  // answers: a signal during the boot wait must stop it too.
  const boot = await bootArtifact({
    workspace,
    artifact,
    env,
    onSpawn: (spawned) => {
      child = spawned;
    },
  });
  if (
    !record(
      'boot',
      boot.health.ok,
      boot.health.ok
        ? `listening and connected after ${formatDuration(boot.health.waitedMs)}`
        : `no healthy response within ${String(BOOT_DEADLINE_MS)}ms — ${boot.health.detail}`,
      boot.health.ok ? {} : { output: boot.output() },
    )
  ) {
    throw new Error('the artifact did not boot');
  }

  playwrightExit = await runNpm(
    [
      'exec',
      '--',
      'playwright',
      'test',
      '--config',
      'playwright.sandbox.config.ts',
      '--forbid-only',
    ],
    { env: { E2E_BASE_URL: boot.baseUrl, MONGODB_URI: mongoUri } },
  );

  // (e) The report, not the exit code, is the verdict on what ran.
  const junit = existsSync(reportPath(SANDBOX_JUNIT))
    ? readFileSync(reportPath(SANDBOX_JUNIT), 'utf8')
    : null;
  const problems = sandboxRunProblems(junit);
  record(
    'browser',
    playwrightExit === 0 && problems.length === 0,
    playwrightExit === 0 && problems.length === 0
      ? `${SANDBOX_SUITE.join(' and ')} rendered every preview under the served policy`
      : [`playwright exited ${String(playwrightExit)}`, ...problems].join('; '),
  );
} catch (error) {
  record('sandbox', false, error instanceof Error ? error.message : String(error));
} finally {
  await teardown();
}

writeReport({ playwrightExit });

if (failures.length > 0) {
  console.error(color.red(`\n${symbol.fail} sandbox: ${String(failures.length)} failed check(s)`));
  for (const failure of failures) console.error(color.red(`      ${failure}`));
  process.exit(1);
}
console.log(
  color.green(
    `\n${symbol.pass} sandbox: every preview rendered in a real engine under the artifact's own headers (${formatDuration(Date.now() - started)})`,
  ),
);
