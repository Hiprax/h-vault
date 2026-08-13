/**
 * `test:upgrade`, second half — configuration written for the PREVIOUS release,
 * booting the current one.
 *
 * The upgrade an operator actually performs is: pull the new release, keep the
 * `.env`, restart. Nothing has ever checked that this works. Two ways it can
 * fail, and they fail in opposite directions:
 *
 *   A VARIABLE THAT WAS REMOVED must be IGNORED, not fatal. `ENABLE_METRICS`,
 *   `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX` and `JWT_REFRESH_EXPIRY` were all
 *   declared once and are read by nothing today. If the schema ever became
 *   strict about unknown keys, every operator upgrading from a release that
 *   shipped those lines would get a container that will not start, over a
 *   setting the application stopped having.
 *
 *   A VARIABLE THAT IS REQUIRED must fail LOUDLY, FAST and BY NAME. The three
 *   secrets have `dev-` defaults so that development needs no setup at all —
 *   which means an absent one does not fail at the schema, it fails at the
 *   `dev-` guard, and only outside development. A change that dropped that guard
 *   would boot a production password manager on signing keys published in this
 *   repository, with nothing said about it.
 *
 * The fixture is `tests/fixtures/v0.7.0.env`: the configuration template release
 * 0.7.0 shipped, verbatim except for the three secrets its own comments tell an
 * operator to replace. Its header records that provenance.
 *
 * Each case boots a real, separate process against a real `.env` file, at a
 * temporary repository root the operator's own `.env` cannot reach. See
 * `bootProbe.ts` for why that is the only honest way to express "this variable
 * is not set", and for what the probe deliberately does not cover.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { BOOT_FAST_MS, TIMEOUT_EXIT, bootWithEnvFile } from './bootProbe.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** The previous release's configuration file, exactly as it is committed. */
const N_MINUS_ONE_ENV = readFileSync(path.join(here, '..', 'fixtures', 'v0.7.0.env'), 'utf-8');

/**
 * The three secrets the application requires, in the sense that matters: each
 * has a `dev-` default, so leaving one out is not a missing key — it is a
 * deployment running on a published secret unless something refuses it.
 */
const REQUIRED_SECRETS = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'SESSION_SECRET'] as const;

/**
 * Variables this application used to declare and no longer reads. An operator's
 * `.env` is a file that accumulates: it is copied once from the template of
 * whichever release they started on and edited by hand thereafter, so all four
 * of these are still sitting in real files today. Two of them
 * (`RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX`) shipped in the 0.7.0 template and
 * are already in the fixture; `JWT_REFRESH_EXPIRY` shipped up to 0.4.0 and
 * `ENABLE_METRICS` was never in a template at all, so both are appended here
 * rather than added to a file that is otherwise verbatim.
 */
const REMOVED_VARIABLES = [
  'ENABLE_METRICS',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_MAX',
  'JWT_REFRESH_EXPIRY',
] as const;

/** Deletes a key's assignment line, leaving the rest of the file untouched. */
function withoutKey(envFile: string, key: string): string {
  const kept = envFile.split('\n').filter((line) => !new RegExp(`^\\s*${key}\\s*=`).test(line));
  // A `sed` that matched nothing is the classic way a negative test quietly
  // stops testing anything, so the removal has to be observable.
  if (kept.length === envFile.split('\n').length) {
    throw new Error(`${key} is not assigned in the fixture, so removing it proves nothing`);
  }
  return kept.join('\n');
}

/** Replaces a key's value, or appends the assignment when it is absent. */
function withKey(envFile: string, key: string, value: string): string {
  const pattern = new RegExp(`^\\s*${key}\\s*=.*$`, 'm');
  return pattern.test(envFile)
    ? envFile.replace(pattern, `${key}=${value}`)
    : `${envFile}\n${key}=${value}\n`;
}

/** The fixture as an operator running it in production would have it. */
const asProduction = (envFile: string): string => withKey(envFile, 'NODE_ENV', 'production');

// ─────────────────────────────────────────────────────────────────────────────
// The previous release's .env boots the current server
// ─────────────────────────────────────────────────────────────────────────────

// What follows is deliberately named for what it proves. `config/index.ts` is
// the boot-time consumer of every environment variable and the first application
// module `server.ts` imports, so a variable that was removed, renamed or left
// unset decides the process's fate there — but loading it is not the same as
// starting a server. The full artefact boot is `test:smoke` and the full stack
// boot is `test:deploy`; both already run.
describe("a .env from the previous release loads the current server's configuration", () => {
  it('loads the 0.7.0 configuration file unchanged, and honours its values', async () => {
    const boot = await bootWithEnvFile(N_MINUS_ONE_ENV);

    expect(boot.exitCode, boot.output).toBe(0);
    expect(boot.config).toBeDefined();

    // Booting is not enough on its own: a schema that silently fell back to its
    // own defaults for everything would also exit 0. These are values the FILE
    // supplies, so they prove the file was read and applied.
    expect(boot.config).toMatchObject({
      NODE_ENV: 'development',
      PORT: 5000,
      APP_NAME: 'H-Vault',
      APP_URL: 'https://vault.example.com',
      CORS_ORIGIN: 'https://vault.example.com',
      MONGODB_URI: 'mongodb://localhost:27017/hvault',
      BCRYPT_ROUNDS: 12,
      REFRESH_TOKEN_DAYS: 7,
      REFRESH_TOKEN_REMEMBER_DAYS: 30,
      TRUSTED_DEVICE_DAYS: 30,
      BACKUP_MAX_SIZE_MB: 25,
      FILE_ENCRYPTION_MAX_SIZE_MB: 100,
      HIBP_CACHE_MAX_BYTES: 67_108_864,
      JWT_ACCESS_SECRET: 'n-minus-one-fixture-access-secret-32-plus',
    });
  });

  it('boots the same file in production, which is where the guards actually bite', async () => {
    // The development boot above passes several checks vacuously: the `dev-`
    // secret guard, the HTTPS-only CORS rule and the incomplete-SMTP error are
    // all non-development-only. An upgrade that only worked in development would
    // be no upgrade at all.
    const boot = await bootWithEnvFile(asProduction(N_MINUS_ONE_ENV));

    expect(boot.exitCode, boot.output).toBe(0);
    expect(boot.config).toMatchObject({ NODE_ENV: 'production' });
    // The template leaves SMTP entirely empty, which is a warning rather than an
    // error — the all-or-none rule is what would make a HALF-filled one fatal.
    expect(boot.output).toContain('SMTP not configured');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Variables the application no longer has
// ─────────────────────────────────────────────────────────────────────────────

/**
 * What each removed variable is set to for the cases below.
 *
 * Every value here is one the declaration that used to exist would have
 * REJECTED — a zero window, a negative ceiling, a non-boolean, an unparseable
 * duration. That is the point: if any of these keys is ever reintroduced with
 * its old bounds, the boot fails loudly instead of passing on a value that
 * happens to be valid for both the old schema and no schema at all.
 */
const REMOVED_VARIABLE_VALUES: Record<(typeof REMOVED_VARIABLES)[number], string> = {
  ENABLE_METRICS: 'yes-please',
  RATE_LIMIT_WINDOW_MS: '0',
  RATE_LIMIT_MAX: '-1',
  JWT_REFRESH_EXPIRY: 'never',
};

describe('a variable this release removed is ignored rather than fatal', () => {
  /** The fixture plus every removed variable, at a value the old schema refused. */
  const withEveryRemovedVariable = REMOVED_VARIABLES.reduce(
    (envFile, key) => withKey(envFile, key, REMOVED_VARIABLE_VALUES[key]),
    asProduction(N_MINUS_ONE_ENV),
  );

  it('boots with all four of them present', async () => {
    const boot = await bootWithEnvFile(withEveryRemovedVariable);
    expect(boot.exitCode, boot.output).toBe(0);
  });

  it('surfaces none of them on the configuration it loaded', async () => {
    // The other half of "ignored": not merely tolerated at the boundary, but
    // absent from the object the application reads. A key that reappeared here
    // would be a setting nothing implements — which is exactly how the
    // `RATE_LIMIT_*` pair came to be declared, defaulted, documented and read by
    // nobody, while every limiter carried its own window and ceiling.
    const boot = await bootWithEnvFile(withEveryRemovedVariable);
    expect(boot.config).toBeDefined();
    for (const key of REMOVED_VARIABLES) {
      expect(Object.keys(boot.config!), key).not.toContain(key);
    }
  });

  it('never lets one of them become a validation error', async () => {
    // Scoped to the ERROR path on purpose. An earlier version of this asserted
    // the boot said nothing about these keys at all, which forbade a strictly
    // BETTER future behaviour — "RATE_LIMIT_MAX is set in your .env and is
    // ignored" is more use to an operator than silence, and the day someone adds
    // it Law 2 would have pointed at the code rather than at this assertion.
    // What must never happen is one of them reaching the block that refuses the
    // boot.
    const boot = await bootWithEnvFile(withEveryRemovedVariable);
    const refusal = /Invalid environment configuration:[\s\S]*/.exec(boot.output)?.[0] ?? '';
    expect(refusal, 'the boot was refused at all').toBe('');
    for (const key of REMOVED_VARIABLES) {
      expect(refusal, key).not.toContain(key);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Variables the application requires
// ─────────────────────────────────────────────────────────────────────────────

describe('a required variable that is absent fails clearly, quickly and by name', () => {
  it.each(REQUIRED_SECRETS)('refuses to boot production without %s', async (key) => {
    const boot = await bootWithEnvFile(withoutKey(asProduction(N_MINUS_ONE_ENV), key));

    // Non-zero, and specifically not the timeout sentinel: a boot that HANGS
    // waiting on something is a different failure from one that refuses, and an
    // operator watching a restart loop has to be able to tell them apart.
    expect(boot.exitCode, boot.output).not.toBe(0);
    expect(boot.exitCode, 'the boot hung instead of refusing').not.toBe(TIMEOUT_EXIT);

    // By NAME. "Invalid environment configuration" on its own sends an operator
    // through forty variables one at a time.
    expect(boot.output).toContain(key);
    expect(boot.output).toContain(
      `${key} must be set to a secure value in non-development environments`,
    );

    // And it never reached a usable configuration.
    expect(boot.config).toBeUndefined();

    // FAST, against a bound well below the probe's kill deadline. This is the
    // difference between an operator reading an error and an operator reading a
    // crash loop, and it only says anything because the two numbers differ —
    // see BOOT_FAST_MS for what happened when they did not.
    expect(boot.durationMs).toBeLessThan(BOOT_FAST_MS);
  });

  it.each(REQUIRED_SECRETS)('refuses to boot production when %s is left blank', async (key) => {
    // The likelier mistake, and a different code path: the template ships some
    // keys with empty values, so "I copied it and filled in the ones that
    // shouted at me" leaves a blank rather than a missing line. A blank is not a
    // `dev-` default — it is a zero-length secret, caught by the length bound.
    const boot = await bootWithEnvFile(withKey(asProduction(N_MINUS_ONE_ENV), key, ''));

    expect(boot.exitCode, boot.output).not.toBe(0);
    expect(boot.exitCode, 'the boot hung instead of refusing').not.toBe(TIMEOUT_EXIT);
    expect(boot.output).toContain('Invalid environment configuration');
    expect(boot.output).toContain(key);
    expect(boot.config).toBeUndefined();
  });

  it('accepts the same file with every secret present, so the sweep proves the secret', async () => {
    // The control the sweep needs. Without it, every case above would also pass
    // if the probe were broken in a way that made EVERY boot fail — a bad temp
    // root, a missing symlink, a tsx that cannot resolve. This is the assertion
    // that says the failures are about the variable and not about the harness.
    const boot = await bootWithEnvFile(asProduction(N_MINUS_ONE_ENV));
    expect(boot.exitCode, boot.output).toBe(0);
    for (const key of REQUIRED_SECRETS) {
      expect(boot.config?.[key]).toEqual(expect.any(String));
    }
  });
});
