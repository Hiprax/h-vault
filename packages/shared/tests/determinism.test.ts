/**
 * This package's half of the determinism contract.
 *
 * The harness module's own unit tests (seed parsing, the generator, the failure
 * banner) live with the implementation, in
 * `packages/server/tests/determinism.test.ts`. What is package-specific — and so
 * asserted here — is that the pins took effect in this package's environment and
 * that its runner config still carries them. This package validates datetime
 * strings and length bounds for a living, so a zone or locale that drifts is
 * exactly the class of defect nobody would attribute to the harness.
 */
import { describe, expect, it } from 'vitest';
import config from '../vitest.config.js';
import { PINNED_LOCALE, PINNED_TZ, RUN_TZ, SEED, resolveRunTz, zoneFacts } from './determinism.js';

describe('determinism harness (shared)', () => {
  it('runs in the zone the harness resolved, so a zone-less date literal is the instant it reads as', () => {
    // Asserted against RUN_TZ's hand-checked facts rather than against UTC's
    // literals, because `test:dst` runs this same file in America/New_York and a
    // hardcoded zero would then be describing a clock the run is not using. Both
    // halves of the year: a zone that is UTC only in winter (Europe/London)
    // would satisfy a January-only assertion and break every summer, and in the
    // DST leg the two rows differ by an hour, which is the property that makes
    // that leg worth running.
    const facts = zoneFacts(RUN_TZ);
    expect(new Date('2026-01-15T12:00:00').getTime()).toBe(facts.winterNoon);
    expect(new Date('2026-07-15T12:00:00').getTime()).toBe(facts.summerNoon);
    expect(new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset()).toBe(facts.winterOffsetMinutes);
    expect(new Date(Date.UTC(2026, 6, 15)).getTimezoneOffset()).toBe(facts.summerOffsetMinutes);
  });

  it('defaults to UTC, so an unset HVAULT_TZ can never inherit the machine zone', () => {
    // The invariant the previous version of the test above was really carrying:
    // not "this run is in UTC" (which the DST leg deliberately falsifies) but
    // "UTC is what you get unless something asked for otherwise". Asserted by
    // CALLING the resolver, not by reading two literals back out of the table it
    // shares a module with — the latter is turned red only by editing a constant,
    // which is the definition of a test that measures existence.
    expect(resolveRunTz(undefined)).toBe(PINNED_TZ);
    expect(resolveRunTz('')).toBe(PINNED_TZ);
    expect(zoneFacts(PINNED_TZ).winterOffsetMinutes).toBe(0);
    expect(zoneFacts(PINNED_TZ).summerOffsetMinutes).toBe(0);
  });

  it('runs in the DEFAULT zone unless HVAULT_TZ asked otherwise', () => {
    // What got looser when the hardcoded `RUN_TZ === PINNED_TZ` assertion had to
    // go: nothing then said an ORDINARY run is in the default zone, so an exported
    // `HVAULT_TZ` in a developer's shell would silently turn every push-tier run
    // into a DST run and every zone-derived expectation would agree with itself.
    // Stated as the conditional it actually is, so it holds in both legs.
    const requested = process.env['HVAULT_TZ'];
    if (requested === undefined || requested.trim() === '') {
      expect(RUN_TZ, 'HVAULT_TZ is unset, so this run must be in the pin').toBe(PINNED_TZ);
    } else {
      expect(RUN_TZ, 'HVAULT_TZ was set but the harness did not resolve to it').toBe(
        requested.trim(),
      );
    }
  });

  it('pins timezone, locale and seed on the environment', () => {
    expect(Intl.DateTimeFormat().resolvedOptions().timeZone).toBe(RUN_TZ);
    expect(process.env.TZ).toBe(RUN_TZ);
    expect(process.env['LANG']).toBe(PINNED_LOCALE);
    expect(process.env['LC_ALL']).toBe(PINNED_LOCALE);
    expect(process.env['SEED']).toBe(String(SEED));
  });

  it('keeps shuffle and the pins in the runner config', () => {
    // Read from the config MODULE rather than its source text, so this fails when
    // the setting is genuinely gone and cannot be satisfied by a comment.
    expect(config.test?.sequence?.shuffle).toBe(true);
    expect(config.test?.sequence?.seed).toBe(SEED);
    // Teardown order is pinned, not inherited: Vitest resolves `hooks` to
    // `'stack'` by default but its CLI help advertises `"parallel"`, so the
    // default is not something to build on silently.
    expect(config.test?.sequence?.hooks).toBe('stack');
    // RUN_TZ, not PINNED_TZ: the config itself reads RUN_TZ so the DST leg is
    // not silently clobbered back to UTC, and an assertion that hardcoded the
    // constant would pass only in the leg that does not need it.
    expect(config.test?.env?.['TZ']).toBe(RUN_TZ);
    expect(config.test?.env?.['LANG']).toBe(PINNED_LOCALE);
    expect(config.test?.env?.['LC_ALL']).toBe(PINNED_LOCALE);
  });
});
