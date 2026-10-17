/**
 * F-20: `create-indexes` runs with ONLY the index configuration, and builds every
 * TTL index with the retention it is given.
 *
 * The Docker stack's `hvault-bootstrap` one-shot runs this script, and it used to
 * be handed every application secret because the script (and three models it
 * loads) imported the application configuration, which refuses to load without
 * them. A bootstrap given only the database URI would have refused to start, and
 * one whose retention settings were missing would have built the TTL indexes with
 * DEFAULT retention, silently turning a configured 90 days into 365.
 *
 * So the script runs here in a child process whose environment holds nothing but
 * the seven keys `config/indexConfigSchema.ts` declares, against this worker's own
 * mongod (a database name of its own), with non-default retentions; the indexes
 * it built are then read back. The child runs from a temporary copy of the
 * server sources laid out like the repository, for the reason
 * `tests/upgrade/bootProbe.ts` gives: the configuration loads the `.env` at the
 * repository root, so a developer's real `.env` would otherwise supply the very
 * secrets this test withholds.
 *
 * The negative half runs the same environment into the application
 * configuration, which must still refuse to load: the bootstrap's configuration
 * is narrower, the application's is not weakened.
 */
import { describe, it, expect, afterAll } from 'vitest';
import { cpSync, mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import mongoose from 'mongoose';
import { REPO_ROOT, createTestTempDir } from './tempDir.js';
import { getStandaloneUri } from './mongoHarness.js';

const execFileAsync = promisify(execFile);

/** Measured at about 3 s on the reference machine (tsx transpiles the models); a hang is a failure. */
const RUN_DEADLINE_MS = 60_000;
const DAY_S = 86_400;

/** The retentions the run is given: none of them is a schema default. */
const RETENTION = { audit: 90, backup: 14, breach: 7 } as const;

interface RunResult {
  exitCode: number;
  output: string;
}

/** A temporary repository root holding a copy of the server's sources and scripts. */
function stageServer(): string {
  const root = createTestTempDir('hv-index-boot-');
  const server = path.join(root, 'packages', 'server');
  mkdirSync(server, { recursive: true });
  for (const dir of ['src', 'scripts']) {
    cpSync(path.join(REPO_ROOT, 'packages', 'server', dir), path.join(server, dir), {
      recursive: true,
    });
  }
  symlinkSync(path.join(REPO_ROOT, 'node_modules'), path.join(root, 'node_modules'), 'junction');
  writeFileSync(
    path.join(server, 'package.json'),
    `${JSON.stringify({ name: '@hvault/server-index-boot', private: true, type: 'module' })}\n`,
  );
  // An empty root .env: the configuration must find nothing there.
  writeFileSync(path.join(root, '.env'), '');
  return server;
}

async function run(cwd: string, args: string[], env: Record<string, string>): Promise<RunResult> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, ['--import', 'tsx', ...args], {
      cwd,
      timeout: RUN_DEADLINE_MS,
      // Nothing inherited: the worker's environment carries every secret
      // `vitest.config.ts` pins, which is exactly what must be absent here.
      env: { PATH: process.env['PATH'] ?? '', HOME: cwd, TZ: 'UTC', LANG: 'C.UTF-8', ...env },
      maxBuffer: 8 * 1024 * 1024,
    });
    return { exitCode: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    const failure = error as { code?: unknown; stdout?: string; stderr?: string; killed?: boolean };
    return {
      exitCode: typeof failure.code === 'number' ? failure.code : failure.killed ? 124 : 1,
      output: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
    };
  }
}

const database = `hvault-index-boot-${randomBytes(4).toString('hex')}`;

/** Exactly the keys `config/indexConfigSchema.ts` declares, and nothing else. */
function indexOnlyEnv(): Record<string, string> {
  const uri = new URL(getStandaloneUri());
  uri.pathname = `/${database}`;
  return {
    NODE_ENV: 'production',
    MONGODB_URI: uri.toString(),
    MONGO_MAX_POOL_SIZE: '4',
    MONGO_MIN_POOL_SIZE: '0',
    AUDIT_LOG_RETENTION_DAYS: String(RETENTION.audit),
    BACKUP_RETENTION_DAYS: String(RETENTION.backup),
    BREACH_CACHE_TTL_DAYS: String(RETENTION.breach),
  };
}

interface IndexInfo {
  name: string;
  key: Record<string, number>;
  expireAfterSeconds?: number;
  unique?: boolean;
}

async function indexesOf(collection: string): Promise<IndexInfo[]> {
  const db = mongoose.connection.useDb(database, { useCache: false });
  return (await db.collection(collection).indexes()) as IndexInfo[];
}

afterAll(async () => {
  await mongoose.connection.useDb(database, { useCache: false }).dropDatabase();
});

describe('F-20: create-indexes with only the index configuration', () => {
  it('builds every index, each TTL index at the retention it was given', async () => {
    const staged = stageServer();
    const result = await run(staged, ['scripts/create-indexes.ts'], indexOnlyEnv());

    expect(result.output).not.toMatch(/\[FAIL\]|Fatal error|Invalid environment configuration/);
    expect(result.exitCode, result.output).toBe(0);
    expect(result.output).toContain('Index creation complete.');
    // The URI's credentials are masked in what it prints (none here, but the
    // line is the one the operator reads in `docker compose logs`).
    expect(result.output).toContain('Connecting to MongoDB:');

    const ttl = (indexes: IndexInfo[], field: string) =>
      indexes.find((index) => index.key[field] === 1 && index.expireAfterSeconds !== undefined)
        ?.expireAfterSeconds;
    expect(ttl(await indexesOf('audit_logs'), 'timestamp')).toBe(RETENTION.audit * DAY_S);
    expect(ttl(await indexesOf('backup_logs'), 'timestamp')).toBe(RETENTION.backup * DAY_S);
    // On-demand breach ranges expire at four freshness windows (see PwnedRangeCache).
    expect(ttl(await indexesOf('pwned_range_cache'), 'fetchedAt')).toBe(
      RETENTION.breach * 4 * DAY_S,
    );
    // Not only the TTL indexes: the unique index that refuses a second account.
    expect(
      (await indexesOf('users')).some((index) => index.key['email'] === 1 && index.unique),
    ).toBe(true);
  });

  it('still leaves the application configuration refusing to load without its secrets', async () => {
    const staged = stageServer();
    writeFileSync(
      path.join(staged, 'load-app-config.mts'),
      "await import('./src/config/index.js');\nprocess.stdout.write('APP_CONFIG_LOADED\\n');\n",
    );
    // An HTTPS origin, so the refusal left to observe is the one about secrets
    // (a production boot refuses a plain-HTTP CORS_ORIGIN first).
    const result = await run(staged, ['./load-app-config.mts'], {
      ...indexOnlyEnv(),
      CORS_ORIGIN: 'https://hvault.test',
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).not.toContain('APP_CONFIG_LOADED');
    expect(result.output).toContain(
      'JWT_ACCESS_SECRET must be set to a secure value in non-development environments',
    );
  });

  it('refuses an index configuration it cannot use, naming the key', async () => {
    const staged = stageServer();
    const result = await run(staged, ['scripts/create-indexes.ts'], {
      ...indexOnlyEnv(),
      AUDIT_LOG_RETENTION_DAYS: '0',
      MONGO_MIN_POOL_SIZE: '9',
      MONGO_MAX_POOL_SIZE: '3',
    });

    expect(result.exitCode).not.toBe(0);
    expect(result.output).toContain('Invalid environment configuration');
    expect(result.output).toContain('AUDIT_LOG_RETENTION_DAYS');
    expect(result.output).toContain(
      'MONGO_MIN_POOL_SIZE cannot be greater than MONGO_MAX_POOL_SIZE',
    );
    expect(result.output).not.toContain('Connecting to MongoDB');
  });
});
