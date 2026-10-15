/**
 * F-20: the index bootstrap reads a secret-free configuration, and nothing else.
 *
 * `scripts/create-indexes.ts` is what the Docker stack's `hvault-bootstrap`
 * one-shot runs. It used to import `config/index.ts`, whose schema refuses to
 * load without every application secret, and three models imported it for
 * their TTL retention, so the one-shot had to be handed the whole root `.env`
 * (`env_file`). It now reads `config/indexConfig.ts` (its schema in
 * `config/indexConfigSchema.ts`), which declares only the
 * database URI, the pool sizes, the three retention settings and `NODE_ENV`, and
 * the compose file hands the one-shot exactly those keys by interpolation.
 *
 * These tests hold the three things that must agree for that to stay true:
 * the import closure of the entry point (it must never reach the secret-bearing
 * module again), the keys the index-building code reads (each must be declared
 * by the secret-free module), and the keys the compose file passes (exactly the
 * declared ones, defaulting to the schema's own defaults). The boot itself, with
 * only those keys set, is `create-indexes-boot.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { parse } from 'yaml';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = path.resolve(HERE, '..');
const REPO = path.resolve(SERVER, '..', '..');
const ENTRY = path.join(SERVER, 'scripts', 'create-indexes.ts');
const APP_CONFIG = path.join(SERVER, 'src', 'config', 'index.ts');

/** A relative specifier as TypeScript's bundler resolution maps it to a source file. */
function resolveRelative(from: string, specifier: string): string | undefined {
  if (!specifier.startsWith('.')) return undefined;
  const base = path.resolve(path.dirname(from), specifier);
  const candidates = [base.replace(/\.js$/, '.ts'), `${base}.ts`, path.join(base, 'index.ts')];
  return candidates.find((candidate) => existsSync(candidate));
}

/**
 * Every source file the entry point loads, transitively, through relative
 * imports (static, dynamic and re-exports, as TypeScript's own pre-processor
 * reports them). Package imports end the walk: they are not this repository's
 * configuration.
 */
function importClosure(entry: string): Set<string> {
  const seen = new Set<string>();
  const pending = [entry];
  while (pending.length > 0) {
    const file = pending.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const info = ts.preProcessFile(readFileSync(file, 'utf8'), true, true);
    for (const imported of info.importedFiles) {
      const resolved = resolveRelative(file, imported.fileName);
      if (resolved) pending.push(resolved);
    }
  }
  return seen;
}

const relative = (file: string) => path.relative(SERVER, file);

/**
 * A read of the process environment by the module itself: `process.env` (or
 * `globalThis.process.env`), but not as a member of another object. The
 * mutation runner instruments every source file with a prelude that reads
 * `g.process.env.__STRYKER_ACTIVE_MUTANT__`, and these tests read the files it
 * instrumented, so that member access must not count as one.
 */
const DIRECT_ENV_READ = /(?<![\w$.])process\.env\b|\bglobalThis\.process\.env\b/;

describe('F-20: the index bootstrap never loads the secret-bearing configuration', () => {
  it('reaches neither config/index.ts nor anything only it would load', () => {
    const closure = importClosure(ENTRY);
    // Not vacuous: the walk does reach the models whose indexes it builds.
    expect([...closure].map(relative)).toEqual(
      expect.arrayContaining([
        'scripts/indexedModels.ts',
        'src/models/AuditLog.ts',
        'src/models/BackupLog.ts',
        'src/models/PwnedRangeCache.ts',
        'src/models/User.ts',
      ]),
    );
    expect(closure.has(APP_CONFIG)).toBe(false);
    // The logger is reached only through the application configuration today;
    // the bootstrap writes to stdout, so it should not open log files either.
    expect(closure.has(path.join(SERVER, 'src', 'utils', 'logger.ts'))).toBe(false);
  });

  it("counts a module's own environment read, not the mutation runner's instrumentation", () => {
    expect('const ttl = Number(process.env.BACKUP_RETENTION_DAYS);').toMatch(DIRECT_ENV_READ);
    expect('const t = process.env["X"];').toMatch(DIRECT_ENV_READ);
    expect('globalThis.process.env.X').toMatch(DIRECT_ENV_READ);
    // The instrumenter's prelude, verbatim in shape (syntax-helpers.js).
    expect(
      'if (ns.activeMutant === undefined && g.process && g.process.env && g.process.env.__STRYKER_ACTIVE_MUTANT__) {',
    ).not.toMatch(DIRECT_ENV_READ);
  });

  it('reads every setting it uses from the secret-free module, and only declared keys', async () => {
    const { INDEX_CONFIG_KEYS } = await import('../src/config/indexConfigSchema.js');
    const closure = importClosure(ENTRY);
    const read = new Set<string>();
    for (const file of closure) {
      const source = readFileSync(file, 'utf8');
      for (const match of source.matchAll(/\bindexConfig\.([A-Z][A-Z0-9_]*)\b/g)) {
        read.add(match[1]!);
      }
      // No other configuration object may be consulted on this path.
      expect(source, relative(file)).not.toMatch(/\bconfig\.[A-Z][A-Z0-9_]+/);
      // ...and nothing reads the environment around it: a direct read works in
      // development (the whole .env is loaded) and is undefined in the bootstrap,
      // which is given only the declared keys. Only the two config modules may.
      if (!/src\/config\/(?:indexConfig|envFile)\.ts$/.test(file)) {
        expect(source, relative(file)).not.toMatch(DIRECT_ENV_READ);
      }
    }
    // The three retention settings and the connection settings are all read here.
    expect([...read].sort()).toEqual(
      expect.arrayContaining([
        'AUDIT_LOG_RETENTION_DAYS',
        'BACKUP_RETENTION_DAYS',
        'BREACH_CACHE_TTL_DAYS',
        'MONGODB_URI',
        'MONGO_MAX_POOL_SIZE',
        'MONGO_MIN_POOL_SIZE',
      ]),
    );
    for (const key of read) expect(INDEX_CONFIG_KEYS, key).toContain(key);
  });

  it('declares no secret: exactly the connection, pool, retention and mode settings', async () => {
    const { INDEX_CONFIG_KEYS } = await import('../src/config/indexConfigSchema.js');
    expect([...INDEX_CONFIG_KEYS].sort()).toEqual([
      'AUDIT_LOG_RETENTION_DAYS',
      'BACKUP_RETENTION_DAYS',
      'BREACH_CACHE_TTL_DAYS',
      'MONGODB_URI',
      'MONGO_MAX_POOL_SIZE',
      'MONGO_MIN_POOL_SIZE',
      'NODE_ENV',
    ]);
    for (const key of INDEX_CONFIG_KEYS) {
      expect(key).not.toMatch(/SECRET|PASSWORD|PASS$|TOKEN|_KEY/);
    }
  });

  it('is composed into the application configuration, which reads the same values', async () => {
    const { INDEX_CONFIG_KEYS } = await import('../src/config/indexConfigSchema.js');
    const { indexConfig } = await import('../src/config/indexConfig.js');
    const { ENV_SCHEMA_KEYS, config } = await import('../src/config/index.js');
    for (const key of INDEX_CONFIG_KEYS) {
      expect(ENV_SCHEMA_KEYS, key).toContain(key);
      expect(config[key], key).toBe(indexConfig[key]);
    }
  });
});

describe('F-20: the index configuration refuses what it cannot use', () => {
  it('lists every issue under the one heading, each as `  KEY: message`', async () => {
    const { parseIndexConfig } = await import('../src/config/indexConfigSchema.js');
    let thrown: unknown;
    try {
      parseIndexConfig({ AUDIT_LOG_RETENTION_DAYS: '0', BREACH_CACHE_TTL_DAYS: '366' });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    const lines = (thrown as Error).message.split('\n');
    expect(lines[0]).toBe('Invalid environment configuration:');
    expect(lines.slice(1)).toEqual([
      expect.stringMatching(/^ {2}AUDIT_LOG_RETENTION_DAYS: \S/),
      expect.stringMatching(/^ {2}BREACH_CACHE_TTL_DAYS: \S/),
    ]);
  });

  it('refuses an inverted pool, naming the minimum', async () => {
    const { parseIndexConfig } = await import('../src/config/indexConfigSchema.js');
    expect(() => parseIndexConfig({ MONGO_MIN_POOL_SIZE: '9', MONGO_MAX_POOL_SIZE: '3' })).toThrow(
      'Invalid environment configuration:\n  MONGO_MIN_POOL_SIZE: MONGO_MIN_POOL_SIZE cannot be greater than MONGO_MAX_POOL_SIZE',
    );
    // Equal is allowed: the boundary, not an off-by-one.
    expect(parseIndexConfig({ MONGO_MIN_POOL_SIZE: '3', MONGO_MAX_POOL_SIZE: '3' })).toMatchObject({
      MONGO_MIN_POOL_SIZE: 3,
      MONGO_MAX_POOL_SIZE: 3,
    });
  });

  it('writes a nested issue path dotted, as the application configuration always has', async () => {
    const { invalidEnvironmentConfiguration } = await import('../src/config/indexConfigSchema.js');
    expect(
      invalidEnvironmentConfiguration([
        { path: ['SMTP', 'HOST'], message: 'm', code: 'custom', input: undefined },
        { path: [], message: 'n', code: 'custom', input: undefined },
      ]).message,
    ).toBe('Invalid environment configuration:\n  SMTP.HOST: m\n  : n');
  });

  it('applies the documented defaults and coerces numbers', async () => {
    const { parseIndexConfig } = await import('../src/config/indexConfigSchema.js');
    expect(parseIndexConfig({})).toEqual({
      NODE_ENV: 'development',
      MONGODB_URI: 'mongodb://localhost:27017/hvault',
      MONGO_MAX_POOL_SIZE: 10,
      MONGO_MIN_POOL_SIZE: 2,
      BACKUP_RETENTION_DAYS: 30,
      AUDIT_LOG_RETENTION_DAYS: 365,
      BREACH_CACHE_TTL_DAYS: 30,
    });
    expect(parseIndexConfig({ AUDIT_LOG_RETENTION_DAYS: '90' }).AUDIT_LOG_RETENTION_DAYS).toBe(90);
  });
});

describe('F-20: the compose file hands the bootstrap exactly those keys', () => {
  interface Service {
    environment?: Record<string, unknown>;
    env_file?: unknown;
  }
  const compose = parse(readFileSync(path.join(REPO, 'docker-compose.yml'), 'utf8'), {
    merge: true,
  }) as { services: Record<string, Service | undefined> };
  const bootstrap = compose.services['hvault-bootstrap'];
  const app = compose.services['hvault-app'];

  it('passes no env_file, and an environment of exactly the declared keys', async () => {
    const { INDEX_CONFIG_KEYS } = await import('../src/config/indexConfigSchema.js');
    expect(bootstrap).toBeDefined();
    expect(bootstrap?.env_file).toBeUndefined();
    expect(Object.keys(bootstrap?.environment ?? {}).sort()).toEqual([...INDEX_CONFIG_KEYS].sort());
  });

  it('connects with the same scoped URI as the app, in production mode', () => {
    const env = bootstrap?.environment ?? {};
    expect(env['MONGODB_URI']).toBe(app?.environment?.['MONGODB_URI']);
    expect(String(env['MONGODB_URI'])).toMatch(/\$\{MONGO_APP_PASSWORD:\?/);
    expect(env['NODE_ENV']).toBe('production');
  });

  it("interpolates every other key from .env, defaulting to the schema's own default", async () => {
    const { INDEX_CONFIG_KEYS, parseIndexConfig } =
      await import('../src/config/indexConfigSchema.js');
    const defaults = parseIndexConfig({});
    const env = bootstrap?.environment ?? {};
    const interpolated = INDEX_CONFIG_KEYS.filter(
      (key) => !['MONGODB_URI', 'NODE_ENV'].includes(key),
    );
    expect(interpolated.length).toBe(5);
    for (const key of interpolated) {
      const match = /^\$\{([A-Z0-9_]+):-([^}]+)\}$/.exec(String(env[key]));
      expect(match, `${key}: ${String(env[key])}`).not.toBeNull();
      // The SAME variable name as the app reads from .env, so one setting drives
      // both: a retention changed in .env must reach the index the bootstrap builds.
      expect(match![1]).toBe(key);
      // A default that drifted from the schema's would build a TTL index the app
      // does not agree with on any deployment whose .env leaves the key unset.
      expect(match![2], key).toBe(String(defaults[key]));
    }
  });
});
