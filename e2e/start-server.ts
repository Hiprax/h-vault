import { MongoMemoryServer } from 'mongodb-memory-server';
import { spawn } from 'node:child_process';
import { applyMongoKernelCompat } from '../packages/server/tests/mongoKernelCompat.js';
import { createS3Provider } from '../packages/server/src/services/storage/s3Provider.js';
import { startStorageEngine, type StorageEngine } from '../tests/harness/s3Server.js';

/**
 * E2E server startup script.
 *
 * Starts an in-memory MongoDB on port 27017 (the standard port) and the real
 * object-storage engine in a container, then launches `npm run dev` with
 * dev-safe environment variables. Because MMS uses the standard port, both the
 * server and E2E tests (which default to `mongodb://127.0.0.1:27017/hvault`)
 * connect to the same instance.
 *
 * If port 27017 is already occupied (e.g. real MongoDB running), MMS is skipped
 * and the existing instance is used instead.
 */

const MONGO_PORT = 27017;
const MONGO_URI = `mongodb://127.0.0.1:${String(MONGO_PORT)}/hvault`;

/**
 * The per-document ceiling and the per-user allowance this harness pins, in MB.
 *
 * They are here rather than in a spec because they are read by `loadConfig` at
 * the dev server's boot: nothing a test does can change them afterwards, so the
 * only place they can be chosen is the process that spawns it.
 *
 * Both are deliberately TINY, and only ONE of them is here for a journey. The
 * allowance is: `e2e/documents.spec.ts` owns a refusal that has to take an
 * account past it, and at the shipped 2048 MB that would mean pushing gigabytes
 * through a browser's AES-GCM, a dev server and a container to prove an
 * arithmetic comparison. The number is the operator's to choose in any
 * deployment, so choosing a small one exercises the same code and the same
 * branch.
 *
 * The per-document cap is here only BECAUSE of that: `loadConfig` carries a
 * `.refine` requiring the allowance to be at least the cap, so a 1 MB allowance
 * forces a cap no larger. There is deliberately no end-to-end journey for the
 * cap itself — it is refused in the browser before a byte is read, so nothing
 * reaches this harness at all, and it is covered where it can be observed
 * directly, in `packages/client/tests/components/documents-upload.test.tsx`
 * ("refuses a file over the advertised cap, reading none of it").
 *
 * The visible consequence, stated so it is a decision rather than a surprise:
 * with a 1 MB ceiling and an 8 MiB plaintext chunk, EVERY end-to-end upload is a
 * single segment and takes the `PutObject` path. Multi-segment framing is
 * covered where it can be covered honestly and cheaply — the server integration
 * suite, and `test:storage` against the real engine at the real 8 MiB part size.
 */
const MAX_DOCUMENT_SIZE_MB = 1;
const DOCUMENT_STORAGE_QUOTA_MB_PER_USER = 1;

const E2E_ENV: Record<string, string> = {
  NODE_ENV: 'development',
  JWT_ACCESS_SECRET: 'e2e-test-access-secret-minimum-32-characters-long',
  JWT_REFRESH_SECRET: 'e2e-test-refresh-secret-minimum-32-characters-long',
  SESSION_SECRET: 'e2e-test-session-secret-minimum-32-characters-long',
  // Pin Vite to loopback regardless of the developer's shell environment, so the
  // dev server matches Playwright's baseURL / health probe. The PORT is
  // deliberately NOT pinned here: it is forwarded from the parent process, and
  // playwright.config.ts resolves it through the same `resolveDevPort` helper
  // Vite uses, so a `VITE_PORT` override moves both together (default 5173).
  VITE_HOST: '127.0.0.1',
  // Explicitly disable email to prevent the developer's .env SMTP/Gmail settings
  // from leaking into E2E tests. Without this, backup trigger tests fail because
  // emailConfigured=true causes backup status='failed' when SMTP sends fail.
  SMTP_HOST: '',
  SMTP_USER: '',
  SMTP_PASS: '',
  GMAIL_USERNAME: '',
  GMAIL_PASSWORD: '',
  MAX_DOCUMENT_SIZE_MB: String(MAX_DOCUMENT_SIZE_MB),
  DOCUMENT_STORAGE_QUOTA_MB_PER_USER: String(DOCUMENT_STORAGE_QUOTA_MB_PER_USER),
};

/**
 * SERVER-121912 — let mongod actually start on Linux kernels >= 6.19 (Ubuntu 26.04).
 *
 * `mongodb-memory-server` downloads and spawns a REAL mongod, defaulting to the 8.x
 * line — the very line where TCMalloc moved to per-CPU caches that violate the rseq
 * ABI as it changed in that kernel, so mongod's startup check aborts. Without this,
 * `npm run test:e2e` (which the project's pre-completion checklist mandates) dies at
 * mongod launch on a modern host, for a reason that looks nothing like the change
 * under test. The production stack pins mongo:8.0 and needs the same tunable, which
 * it sets in docker-compose.yml.
 *
 * Shared with the unit-test harness so the two cannot drift, and a MERGE rather than
 * an overwrite — see mongoKernelCompat.ts. The spawned mongod inherits process.env.
 */
applyMongoKernelCompat();

/**
 * Stand the object-storage engine up, or explain why the suite cannot run.
 *
 * The document store is not optional scenery for this harness: with no `S3_*`
 * configured the server reports `documents: { enabled: false }`, the client hides
 * the whole section, and `e2e/documents.spec.ts`, `e2e/document-viewer.spec.ts`
 * and four of the accessibility views would fail with symptoms that say nothing
 * about the code. So the engine is a hard requirement, and `test:e2e` and
 * `test:a11y` both DECLARE `docker` in `.testfortress/verify.json` and in
 * `scripts/ci/local-ci.mjs` — a declared prerequisite that is missing is reported
 * as "could not run" (exit 2), never as a red gate.
 *
 * The readiness probe is the SERVER'S OWN provider, built from the same factory
 * the dev server will build one from, so "ready" means ready for that client's
 * credentials, signing and addressing rather than merely that a socket answers.
 * `tests/harness/s3Server.ts` polls it; it never sleeps, because `test:flake`
 * runs this suite repeatedly and a fixed wait is either ten times too long or a
 * race that surfaces in run seven.
 */
async function startStorage(): Promise<StorageEngine> {
  try {
    return await startStorageEngine({
      probe: (connection) => createS3Provider(connection).headBucket(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      'the E2E harness could not start the object-storage engine, so the document store ' +
        'would be switched off and its specs would fail for a reason that is not about them. ' +
        'A working Docker daemon is a declared prerequisite of `test:e2e` and `test:a11y`.\n' +
        message,
    );
  }
}

async function main(): Promise<void> {
  let mongod: MongoMemoryServer | undefined;

  try {
    mongod = await MongoMemoryServer.create({
      instance: { port: MONGO_PORT },
    });
  } catch (error) {
    // A port clash genuinely means "a real MongoDB is already listening here",
    // which is fine — the harness just uses it. ANY other failure (above all
    // mongod refusing to start, e.g. the rseq abort on Linux >= 6.19) must NOT be
    // swallowed: doing so leaves the E2E run pointed at no database at all, and
    // every test then fails for a reason that has nothing to do with what it tests.
    const message = error instanceof Error ? error.message : String(error);
    if (!/EADDRINUSE|already in use|listen/i.test(message)) {
      throw error;
    }
    console.warn(`[e2e] port ${String(MONGO_PORT)} is busy — assuming a real MongoDB is running`);
  }

  const engine = await startStorage();
  console.log(`[e2e] object storage on ${engine.endpoint} (${engine.image})`);

  // THIS PROCESS TAKES THE SIGNALS BACK, and the reason is a leak rather than a
  // preference. `startStorageEngine` installs its own SIGINT/SIGTERM handlers that
  // remove the container and then call `process.exit(1)` — correct for a vitest
  // file, which has nothing else to wind down, and wrong here. Node CLONES the
  // listener array before dispatching a signal, so a handler registered later
  // cannot cancel one registered earlier, and the harness's `process.exit(1)`
  // would abort this process in the middle of `mongod.stop()`. Playwright ends
  // every run with SIGTERM, so that is not an edge case: it would strand a
  // RAM-backed mongod dbPath under /tmp on EVERY run.
  //
  // `engine.stop()` is called from the teardown below instead, and the harness's
  // `process.on('exit')` hook — a synchronous `docker rm -f`, which no async
  // teardown could replace — is deliberately left in place as the last resort.
  process.removeAllListeners('SIGINT');
  process.removeAllListeners('SIGTERM');

  const env: Record<string, string> = {
    ...filterEnv(process.env),
    ...E2E_ENV,
    MONGODB_URI: MONGO_URI,
    // The four connection variables the server validates ALL-OR-NONE, plus the two
    // that have defaults. They are spread AFTER the developer's own environment on
    // purpose: `config/index.ts` calls `dotenv.config()` without `override`, so
    // process.env wins over the repository's `.env`, and a developer who points
    // `S3_*` at a real bucket does not have this suite write to it.
    S3_ENDPOINT: engine.endpoint,
    S3_REGION: engine.region,
    S3_BUCKET: engine.bucket,
    S3_ACCESS_KEY_ID: engine.accessKeyId,
    S3_SECRET_ACCESS_KEY: engine.secretAccessKey,
    S3_FORCE_PATH_STYLE: String(engine.forcePathStyle),
  };

  // NOT `detached`, and that is a MEASURED decision rather than a default left
  // alone. `npm run dev` is `concurrently` under a shell, so `child.kill()`
  // signals the shell and leaves `vite` and `tsx watch` holding ports 5173 and
  // 5000 — which is untidy, and which matters more now that this harness owns a
  // container too: `reuseExistingServer` is on outside CI, so a later run can
  // adopt a dev server whose storage engine has since been removed and see every
  // document spec fail against a 503.
  //
  // Spawning `detached` and signalling the process GROUP looks like the fix and
  // is worse. Measured, on a run whose six specs all passed: the group kill still
  // did not reach `concurrently`'s children, AND Playwright's own webServer
  // teardown then never completed — the orphans hold the inherited stdout pipe
  // that Playwright waits on, and putting them outside the group it kills turned a
  // leak into a HANG. A gate that hangs after a green run is strictly worse than
  // one that leaves a dev server up, so this stays as it is.
  //
  // If a run ever fails inside the document specs with a 503, check for a dev
  // server from an earlier run first: `ss -tln | grep 5173`.
  const child = spawn('npm run dev', {
    env,
    stdio: 'inherit',
    shell: true,
    cwd: process.cwd(),
  });

  // Teardown reaches mongod from two directions at once: Playwright sends
  // SIGTERM to this process, and killing the child then fires its `exit`
  // handler. Both used to call `mongod.stop()`, and a second stop entered while
  // the first is still tearing the instance down trips MMS's own assertion
  // ("Cannot cleanup because \"instance.mongodProcess\" is still defined"),
  // which crashes the harness AFTER a fully green run. Stop at most once and
  // have every caller await that single attempt.
  let mongoStop: Promise<unknown> | undefined;
  const stopMongo = (): Promise<unknown> => {
    if (!mongod) return Promise.resolve();
    mongoStop ??= mongod.stop();
    return mongoStop;
  };

  // `engine.stop()` needs no guard of its own because it latches its PROMISE, the
  // way `stopMongo` does right above — not merely a "already stopping" flag. The
  // distinction is the whole reason this comment names it: both callers below reach
  // teardown at once, the second one calls `process.exit()` as soon as its await
  // resolves, and a second `stop()` that resolved on its own would let that exit run
  // while `docker rm -f` was still in flight. That stranded one engine per run.
  const stopEverything = (): Promise<unknown> =>
    Promise.all([stopMongo().catch(() => undefined), engine.stop().catch(() => undefined)]);

  // Logged, not silent: the teardown owns a container and a RAM-backed dbPath, and
  // its two lines are the only way to tell a teardown that ran from one that was
  // killed before it could. A run that prints the first without the second has
  // leaked both, which is exactly how the SIGKILL below was found.
  const cleanup = (): void => {
    console.log('[e2e] signal received, tearing down');
    child.kill();
    void stopEverything();
  };

  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);

  child.on('exit', (code) => {
    void stopEverything().then(() => {
      console.log('[e2e] teardown complete: storage engine removed, mongod stopped');
      process.exit(code ?? 1);
    });
  });
}

/** Copies process.env filtering out undefined values (spawn env requires string values). */
function filterEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

void main();
