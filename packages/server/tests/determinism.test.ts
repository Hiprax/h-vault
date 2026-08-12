/**
 * The determinism contract of this package's suite, asserted rather than assumed.
 *
 * Every assertion here names a way the harness could silently stop being
 * deterministic: a dropped `TZ` pin makes every date assertion depend on the
 * machine, a dropped `LANG`/`LC_ALL` pin makes collation and number formatting
 * depend on the developer's desktop, a dropped `sequence.shuffle` lets order
 * dependence accumulate unseen (Forbidden Action 7), and an unseeded generator
 * turns a failure into an anecdote nobody can reproduce.
 */
import { describe, expect, it } from 'vitest';
import config from '../vitest.config.js';
import {
  DEFAULT_SEED,
  PINNED_LOCALE,
  PINNED_TZ,
  SEED,
  resolveSeed,
  resolvedOrderSeed,
  seedBanner,
  seededRandom,
} from './determinism.js';

describe('determinism harness — clock and locale', () => {
  it('runs in UTC, so a local-time Date and its UTC counterpart are the same instant', () => {
    // A zone-less ISO string is parsed as LOCAL time by ES2015+. Under any
    // non-UTC zone these two differ, which is precisely how a date assertion
    // starts passing in Berlin and failing in Denver.
    expect(new Date('2026-01-15T12:00:00').getTime()).toBe(Date.UTC(2026, 0, 15, 12, 0, 0));
    expect(new Date('2026-07-15T12:00:00').getTime()).toBe(Date.UTC(2026, 6, 15, 12, 0, 0));
  });

  it('reports a zero UTC offset in both halves of the year, so no DST transition exists', () => {
    // Checked in January AND July: a zone such as America/New_York has a
    // non-zero offset in both, but a zone such as Europe/London has offset 0 in
    // January only — asserting one month would accept it and then break every
    // summer.
    expect(new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset()).toBe(0);
    expect(new Date(Date.UTC(2026, 6, 15)).getTimezoneOffset()).toBe(0);
  });

  it('resolves Intl to the pinned timezone', () => {
    expect(Intl.DateTimeFormat().resolvedOptions().timeZone).toBe(PINNED_TZ);
    expect(process.env.TZ).toBe(PINNED_TZ);
  });

  it('pins LC_ALL as well as LANG, because LC_ALL wins where both are set', () => {
    expect(process.env['LANG']).toBe(PINNED_LOCALE);
    expect(process.env['LC_ALL']).toBe(PINNED_LOCALE);
  });
});

describe('determinism harness — the seed', () => {
  it('defaults to the documented seed and exports it to child processes', () => {
    expect(SEED).toBe(DEFAULT_SEED);
    // Children (mongod, any spawned helper) must draw from the same seed the
    // failure banner prints, or the printed value is a claim about a different run.
    expect(process.env['SEED']).toBe(String(DEFAULT_SEED));
  });

  it('reads an explicit seed and treats unset or empty as the default', () => {
    expect(resolveSeed('42')).toBe(42);
    expect(resolveSeed('0')).toBe(0);
    expect(resolveSeed(undefined)).toBe(DEFAULT_SEED);
    expect(resolveSeed('')).toBe(DEFAULT_SEED);
    expect(resolveSeed('   ')).toBe(DEFAULT_SEED);
  });

  it('refuses a malformed seed rather than silently using the default', () => {
    // A silent fallback would make the printed "reproduce with SEED=..." line a
    // lie about the run that just happened.
    expect(() => resolveSeed('abc')).toThrow(/SEED must be a non-negative integer/);
    expect(() => resolveSeed('1.5')).toThrow(/received "1\.5"/);
    expect(() => resolveSeed('-1')).toThrow(/non-negative/);
    // `1e3` is an integer in exponent notation, so it is ACCEPTED and read as
    // 1000. Asserting the value, not merely the absence of a throw: a parser
    // that quietly fell back to the default would also "not throw".
    expect(resolveSeed('1e3')).toBe(1000);
  });

  it('produces a reproducible stream for one seed and a different one for another', () => {
    const first = Array.from({ length: 8 }, seededRandom(99));
    const second = Array.from({ length: 8 }, seededRandom(99));
    const other = Array.from({ length: 8 }, seededRandom(100));

    expect(first).toEqual(second);
    expect(first).not.toEqual(other);
    for (const value of first) {
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(1);
    }
    // Not a constant sequence: a generator that returns the same number forever
    // is reproducible and useless.
    expect(new Set(first).size).toBeGreaterThan(1);
  });

  it('names the seed and a seed-carrying reproduce command in the failure banner', () => {
    const banner = seedBanner();
    expect(banner).toContain(`SEED=${String(SEED)}`);
    // The reproduce command must not rely on a shell env prefix: `TZ=x cmd` and
    // `SEED=x cmd` do not work in cmd.exe or PowerShell, and this project is
    // developed on Windows too.
    expect(banner).not.toMatch(/^SEED=\d+ /);
  });

  it('reproduces the ORDER the runner actually used, not the data seed', () => {
    // The two seeds are different things and only agree by default: the config
    // initializes `sequence.seed` from `SEED`, and `--sequence.seed=<n>` on the
    // command line breaks the tie — which is exactly the run you are on when you
    // are bisecting an order dependence. A banner naming the data seed there
    // hands you a command that reproduces a DIFFERENT order than the one that
    // just failed.
    //
    // Driven with an injected value rather than the ambient one, so this fails
    // when the banner goes back to printing the module constant. Asserting
    // `seedBanner()` against `SEED` cannot: it compares the function with the one
    // constant the function already uses.
    const foreignOrderSeed = SEED + 8_675_309;

    const banner = seedBanner(foreignOrderSeed);
    expect(banner).toContain(`--sequence.seed=${String(foreignOrderSeed)}`);
    expect(banner).toContain(`order seed=${String(foreignOrderSeed)}`);
    expect(banner).not.toContain(`--sequence.seed=${String(SEED)}`);
    // The data seed is still reported: it is what `seededRandom` drew from, and
    // dropping it would make generated fixtures irreproducible.
    expect(banner).toContain(`data SEED=${String(SEED)}`);
  });

  it('admits it does not know the order seed rather than inventing one', () => {
    // `__vitest_worker__` is the runner's internal state. If a future Vitest
    // moves or renames it, the banner must degrade to "unknown" and point at the
    // runner's own seed line — never silently fall back to the data seed, which
    // would restore exactly the misreport this pair of tests exists to catch.
    const banner = seedBanner(undefined);
    expect(banner).toContain('order seed=unknown');
    expect(banner).not.toMatch(/--sequence\.seed=\d/);
  });

  it('reads the resolved shuffle seed out of the runner, including a CLI override', () => {
    // The shape actually observed in a worker: `config.sequence.seed` carries the
    // value after CLI merging, which is why it is read from there and not from
    // the config module (that one cannot see `--sequence.seed=`).
    expect(resolvedOrderSeed({ config: { sequence: { seed: 424_242 } } })).toBe(424_242);
    // Anything that is not a finite number is "unknown", not a coerced 0.
    expect(resolvedOrderSeed(undefined)).toBeUndefined();
    expect(resolvedOrderSeed({})).toBeUndefined();
    expect(resolvedOrderSeed({ config: { sequence: { seed: 'nope' } } })).toBeUndefined();
    // The ambient reading is the live one: this suite runs shuffled, so the
    // runner must be exposing a seed at all.
    //
    // Deliberately NOT compared with `config.test.sequence.seed`. That is the
    // CONFIG-MODULE value, and a `--sequence.seed=<n>` override is precisely the
    // thing that does not change it — so asserting the two agree would re-encode
    // the very conflation this group of tests exists to catch, and would go red
    // on any deliberate override. (Observed: it did, under
    // `--sequence.seed=90210`.)
    expect(typeof resolvedOrderSeed()).toBe('number');
  });
});

describe('determinism harness — the runner is configured for it', () => {
  it('shuffles files and tests with the pinned seed', () => {
    // Read from the config MODULE, not from its source text: this fails when the
    // setting is actually gone, and cannot be satisfied by a comment mentioning it.
    expect(config.test?.sequence?.shuffle).toBe(true);
    expect(config.test?.sequence?.seed).toBe(SEED);
  });

  it('tears hooks down in reverse registration order, which mongoHarness depends on', () => {
    // `useReplicaSetConnection` restores the borrowed mongoose connection in an
    // `afterAll`, and `mongoHarness.test.ts` OBSERVES that restore from an
    // `afterAll` registered BEFORE it — which is only later-first while `hooks`
    // is `'stack'`. Vitest resolves that as the default, but its CLI help
    // advertises `(default: "parallel")`, so a contributor reconciling config
    // with docs could flip it and turn this phase's central assertion into a
    // coin toss that still reports green. Pinned in the config and asserted here.
    expect(config.test?.sequence?.hooks).toBe('stack');
  });

  it('pins the timezone and locale in the config env, not only in the setup file', () => {
    expect(config.test?.env?.['TZ']).toBe(PINNED_TZ);
    expect(config.test?.env?.['LANG']).toBe(PINNED_LOCALE);
    expect(config.test?.env?.['LC_ALL']).toBe(PINNED_LOCALE);
  });
});
