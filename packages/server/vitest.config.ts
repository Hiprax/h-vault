import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

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

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    pool: 'forks',
    forks: {
      singleFork: true,
    },
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
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
      PORT: '5555',
      MONGODB_URI: 'mongodb://localhost:27017/hvault-test',
      JWT_ACCESS_SECRET: 'test-access-secret-for-testing-only-32chars!',
      JWT_REFRESH_SECRET: 'test-refresh-secret-for-testing-only-32chars!',
      JWT_ACCESS_EXPIRY: '15m',
      JWT_REFRESH_EXPIRY: '7d',
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
      RATE_LIMIT_WINDOW_MS: '900000',
      RATE_LIMIT_MAX: '1000',
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
