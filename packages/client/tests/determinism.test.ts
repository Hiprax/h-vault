/**
 * This package's half of the determinism contract.
 *
 * The harness module's own unit tests (seed parsing, the generator, the failure
 * banner) live with the implementation, in
 * `packages/server/tests/determinism.test.ts`. What is package-specific — and so
 * asserted here — is that the pins actually took effect in THIS environment, which
 * is jsdom rather than node and therefore a separate global setup, and that this
 * package's runner config still carries them.
 */
import { describe, expect, it } from 'vitest';
import config from '../vitest.config.js';
import { PINNED_LOCALE, PINNED_TZ, SEED } from './determinism.js';

describe('determinism harness (client, jsdom)', () => {
  it('runs in UTC, so a zone-less date literal is the instant it reads as', () => {
    // Zone-less ISO strings are parsed as LOCAL time. Under any other zone these
    // differ, which is how a date-formatting assertion passes in Berlin and fails
    // in Denver. Checked in both halves of the year so a zone that is UTC only in
    // winter (Europe/London) cannot satisfy it.
    expect(new Date('2026-01-15T12:00:00').getTime()).toBe(Date.UTC(2026, 0, 15, 12));
    expect(new Date('2026-07-15T12:00:00').getTime()).toBe(Date.UTC(2026, 6, 15, 12));
    expect(new Date(Date.UTC(2026, 0, 15)).getTimezoneOffset()).toBe(0);
    expect(new Date(Date.UTC(2026, 6, 15)).getTimezoneOffset()).toBe(0);
  });

  it('resolves Intl to UTC inside jsdom', () => {
    expect(Intl.DateTimeFormat().resolvedOptions().timeZone).toBe(PINNED_TZ);
  });

  it('pins timezone, locale and seed on the environment', () => {
    expect(process.env.TZ).toBe(PINNED_TZ);
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
    expect(config.test?.env?.['TZ']).toBe(PINNED_TZ);
    expect(config.test?.env?.['LANG']).toBe(PINNED_LOCALE);
    expect(config.test?.env?.['LC_ALL']).toBe(PINNED_LOCALE);
  });
});
