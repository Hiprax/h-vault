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
  DST_TZ,
  PINNED_LOCALE,
  PINNED_TZ,
  RUN_TZ,
  SEED,
  resolveRunTz,
  resolveSeed,
  resolvedOrderSeed,
  seedBanner,
  seededRandom,
  zoneFacts,
} from './determinism.js';

describe('determinism harness — clock and locale', () => {
  it('runs in the resolved zone, so a local-time Date reads as that zone says', () => {
    // A zone-less ISO string is parsed as LOCAL time by ES2015+. Under any
    // unpinned zone these differ from the recorded values, which is precisely how
    // a date assertion starts passing in Berlin and failing in Denver.
    //
    // Asserted against RUN_TZ's hand-checked facts rather than against UTC's
    // literals, because `test:dst` runs this whole suite in America/New_York and
    // a hardcoded `Date.UTC(..., 12)` would then describe a clock the run is not
    // using. The DST row's two values differ by an hour, so a zone pin that
    // silently reverted to UTC fails there rather than passing.
    const facts = zoneFacts(RUN_TZ);
    expect(new Date('2026-01-15T12:00:00').getTime()).toBe(facts.winterNoon);
    expect(new Date('2026-07-15T12:00:00').getTime()).toBe(facts.summerNoon);
  });

  it('reports the resolved zone’s UTC offset in both halves of the year', () => {
    // Checked in January AND July, because one month is not enough to identify a
    // zone: Europe/London has offset 0 in January only, so a January-only
    // assertion accepts it and then breaks every summer. In the DST leg the two
    // months differ (EST 300, EDT 240), which is the transition the leg exists
    // to make reachable.
    const facts = zoneFacts(RUN_TZ);
    expect(new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset()).toBe(facts.winterOffsetMinutes);
    expect(new Date(Date.UTC(2026, 6, 15)).getTimezoneOffset()).toBe(facts.summerOffsetMinutes);
  });

  it('keeps the DEFAULT zone free of DST transitions, which is why it is the default', () => {
    // The invariant the two assertions above used to carry implicitly. It is a
    // statement about PINNED_TZ, so it holds in either leg — unlike "this run has
    // a zero offset", which the DST leg deliberately falsifies.
    expect(zoneFacts(PINNED_TZ).winterOffsetMinutes).toBe(0);
    expect(zoneFacts(PINNED_TZ).summerOffsetMinutes).toBe(0);
    expect(zoneFacts(DST_TZ).winterOffsetMinutes).not.toBe(zoneFacts(DST_TZ).summerOffsetMinutes);
  });

  it('honours HVAULT_TZ when the DST gate sets it, rather than falling back to the pin', () => {
    // The other half of `dst-gate.mjs`'s zone probe, and it closes the failure the
    // allowlist cannot see. `resolveRunTz` THROWS on a WRONG zone but returns the
    // pin for a MISSING one — so if `HVAULT_TZ` reached this worker and the config
    // failed to read it, `RUN_TZ` would be UTC, every assertion above would pass,
    // and `test:dst` would report a green leg in a zone it never ran in.
    //
    // Conditional because this file runs in BOTH legs: on the push tier the
    // variable is genuinely absent and there is nothing to check.
    const requested = process.env['HVAULT_TZ'];
    if (requested !== undefined && requested.trim() !== '') {
      expect(RUN_TZ, 'HVAULT_TZ was set but the harness did not resolve to it').toBe(
        requested.trim(),
      );
      expect(process.env.TZ).toBe(requested.trim());
    }
  });

  it('checks BOTH recorded zones against the platform, not only the one this run uses', () => {
    // Without this, `ZONE_FACTS[DST_TZ]` is only ever compared with reality when a
    // T2 gate runs, so a swapped 300/240 would sit green on every push and surface
    // as a mysterious DST failure at release time. Read through `Intl` with an
    // EXPLICIT `timeZone`, which is independent of the zone this process is in, so
    // the whole table is validated in either leg.
    const offsetMinutes = (zone: string, instant: number): number => {
      const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: zone,
        timeZoneName: 'longOffset',
      }).formatToParts(new Date(instant));
      const name = parts.find((part) => part.type === 'timeZoneName')?.value ?? '';
      // 'GMT-05:00', or plain 'GMT' for a zero offset.
      const matched = /GMT([+-])(\d{2}):(\d{2})/.exec(name);
      if (!matched) return 0;
      const magnitude = Number(matched[2]) * 60 + Number(matched[3]);
      // `getTimezoneOffset()` reports minutes BEHIND UTC as positive, which is the
      // opposite sign to the offset `Intl` prints. The `|| 0` normalises NEGATIVE
      // ZERO: some ICU builds render UTC as `GMT+00:00`, which negates to `-0`,
      // and `Object.is(-0, +0)` is false — so without it this fails on the one
      // zone it is least interesting about.
      return (matched[1] === '-' ? magnitude : -magnitude) || 0;
    };

    for (const zone of [PINNED_TZ, DST_TZ]) {
      const facts = zoneFacts(zone);
      expect(offsetMinutes(zone, Date.UTC(2026, 0, 15)), `${zone} winter`).toBe(
        facts.winterOffsetMinutes,
      );
      expect(offsetMinutes(zone, Date.UTC(2026, 6, 15)), `${zone} summer`).toBe(
        facts.summerOffsetMinutes,
      );
      // And the recorded instants agree with those offsets: a zone-less noon is
      // local noon, so it is UTC noon pushed forward by the offset.
      expect(facts.winterNoon, `${zone} winter noon`).toBe(
        Date.UTC(2026, 0, 15, 12) + facts.winterOffsetMinutes * 60_000,
      );
      expect(facts.summerNoon, `${zone} summer noon`).toBe(
        Date.UTC(2026, 6, 15, 12) + facts.summerOffsetMinutes * 60_000,
      );
    }
  });

  it('refuses a zone nobody has recorded facts for', () => {
    // `zoneFacts` answering with UTC's numbers for an unknown zone would make
    // every assertion above it pass while describing a different clock.
    expect(() => zoneFacts('Europe/Berlin')).toThrow(/no recorded clock facts/i);
  });

  it('resolves Intl to the resolved timezone', () => {
    expect(Intl.DateTimeFormat().resolvedOptions().timeZone).toBe(RUN_TZ);
    expect(process.env.TZ).toBe(RUN_TZ);
    // The ordinary suites run with `HVAULT_TZ` unset, so the resolved zone is the
    // pin; `test:dst` and the property gate's DST legs are the two that set it.
    // Stated as a property of the RESOLVER rather than of this run, because the
    // latter is exactly what stopped this file from being runnable in both.
    expect(resolveRunTz(undefined)).toBe(PINNED_TZ);
  });

  it('lets the property gate select the DST zone, from an allowlist of exactly two', () => {
    // `HVAULT_TZ` exists for one reason: `combineExpiry`'s repeated-hour branch is
    // unreachable in a zone with no DST transition, so the property gate runs its
    // suites a second time in `DST_TZ`. It is an ALLOWLIST rather than a
    // passthrough because the pin's whole purpose is that a suite's verdict cannot
    // depend on the machine it ran on — an env var accepting any zone would hand
    // that dependency straight back.
    expect(resolveRunTz(undefined)).toBe(PINNED_TZ);
    expect(resolveRunTz('')).toBe(PINNED_TZ);
    expect(resolveRunTz('   ')).toBe(PINNED_TZ);
    expect(resolveRunTz('UTC')).toBe(PINNED_TZ);
    expect(resolveRunTz(DST_TZ)).toBe(DST_TZ);
    expect(resolveRunTz(` ${DST_TZ} `)).toBe(DST_TZ);
    // The two zones differ in BOTH halves of the year, so a DST leg that silently
    // fell back to UTC could not pass for one.
    expect(DST_TZ).not.toBe(PINNED_TZ);
  });

  it('refuses an unknown zone rather than silently running in the pinned one', () => {
    // A silent fallback would make the gate's claim to have run in a DST-observing
    // zone a lie about the run that just happened — the same reason `resolveSeed`
    // throws on a malformed seed.
    expect(() => resolveRunTz('Europe/Berlin')).toThrow(/HVAULT_TZ must be/);
    expect(() => resolveRunTz('America/new_york')).toThrow(/received "America\/new_york"/);
    expect(() => resolveRunTz('utc')).toThrow(/HVAULT_TZ must be/);
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
    // RUN_TZ, not PINNED_TZ: the config reads RUN_TZ so the DST legs are not
    // silently clobbered back to UTC, and a hardcoded constant would only ever be
    // asserted in the leg that does not need it.
    expect(config.test?.env?.['TZ']).toBe(RUN_TZ);
    expect(config.test?.env?.['LANG']).toBe(PINNED_LOCALE);
    expect(config.test?.env?.['LC_ALL']).toBe(PINNED_LOCALE);
  });
});
