import { MongoMemoryServer } from 'mongodb-memory-server';
import { spawn } from 'node:child_process';
import { applyMongoKernelCompat } from '../packages/server/tests/mongoKernelCompat.js';

/**
 * E2E server startup script.
 *
 * Starts an in-memory MongoDB on port 27017 (the standard port), then launches
 * `npm run dev` with dev-safe environment variables. Because MMS uses the
 * standard port, both the server and E2E tests (which default to
 * `mongodb://127.0.0.1:27017/hvault`) connect to the same instance.
 *
 * If port 27017 is already occupied (e.g. real MongoDB running), MMS is skipped
 * and the existing instance is used instead.
 */

const MONGO_PORT = 27017;
const MONGO_URI = `mongodb://127.0.0.1:${String(MONGO_PORT)}/hvault`;

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

  const env: Record<string, string> = {
    ...filterEnv(process.env),
    ...E2E_ENV,
    MONGODB_URI: MONGO_URI,
  };

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

  const cleanup = (): void => {
    child.kill();
    void stopMongo().catch(() => undefined);
  };

  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);

  child.on('exit', (code) => {
    void stopMongo()
      .catch(() => undefined)
      .then(() => {
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
