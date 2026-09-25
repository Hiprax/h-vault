/**
 * `formatDuration` (`scripts/ci/lib/ui.mjs`): how the local pipeline prints how
 * long a gate took, in every step line, every gate's own summary and the run's
 * total against its tier budget.
 *
 * Those numbers are copied into the README's measured tables and compared by eye
 * against budgets, so a spelling that cannot occur on a clock is a defect, not a
 * cosmetic: a run printed `mutation-diff passed in 20m 60s` for 1,259.6 seconds,
 * because the seconds were rounded AFTER the minutes had been split off.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { formatDuration } from '../../../scripts/ci/lib/ui.mjs';
import { PROPERTY_RUNS, propertyRun } from '../../../tests/harness/property.js';

describe('formatDuration', () => {
  it('prints tenths of a second below a minute', () => {
    expect(formatDuration(0)).toBe('0.0s');
    expect(formatDuration(93)).toBe('0.1s');
    expect(formatDuration(4_449)).toBe('4.4s');
    expect(formatDuration(59_900)).toBe('59.9s');
  });

  it('prints minutes and zero-padded seconds from a minute up', () => {
    expect(formatDuration(60_000)).toBe('1m 00s');
    expect(formatDuration(127_000)).toBe('2m 07s');
    expect(formatDuration(2_962_000)).toBe('49m 22s');
  });

  it('carries a second that rounds up to sixty into the minutes, never printing "60s"', () => {
    // The measured case: 1,259.6 s is 20 minutes 59.6 seconds, which is 21m 00s.
    expect(formatDuration(1_259_594)).toBe('21m 00s');
    expect(formatDuration(119_500)).toBe('2m 00s');
    // And at the seam between the two spellings: 59.96 s is a minute, not "60.0s".
    expect(formatDuration(59_960)).toBe('1m 00s');
    expect(formatDuration(59_949)).toBe('59.9s');
  });

  it('only ever prints a reading a clock could show, and never runs backwards', () => {
    // Read back in WHOLE milliseconds, so the accuracy check is integer
    // arithmetic: in floating point, 0.2 - 0.15 is 0.05000000000000002, and a
    // correct "0.2s" for 150 ms would fail a half-a-tenth bound on a new seed.
    const parseMs = (text: string): { ms: number; unit: number } => {
      const minutes = /^(\d+)m (\d{2})s$/.exec(text);
      if (minutes) {
        const seconds = Number(minutes[2]);
        expect(seconds, text).toBeLessThan(60);
        return { ms: Number(minutes[1]) * 60_000 + seconds * 1000, unit: 1000 };
      }
      const tenths = /^(\d+)\.(\d)s$/.exec(text);
      expect(tenths, `"${text}" is neither spelling`).not.toBeNull();
      const whole = Number(tenths![1]);
      expect(whole, text).toBeLessThan(60);
      return { ms: whole * 1000 + Number(tenths![2]) * 100, unit: 100 };
    };
    fc.assert(
      fc.property(fc.nat({ max: 36_000_000 }), fc.nat({ max: 5_000 }), (ms, later) => {
        const shown = parseMs(formatDuration(ms));
        // Within half a displayed unit of the truth.
        expect(Math.abs(shown.ms - ms)).toBeLessThanOrEqual(shown.unit / 2);
        // A longer run never reads as a shorter one.
        expect(parseMs(formatDuration(ms + later)).ms).toBeGreaterThanOrEqual(shown.ms);
      }),
      propertyRun({ numRuns: PROPERTY_RUNS }),
    );
  });

  it('reads the half-a-tenth cases back exactly, where floating point would not', () => {
    // 150 ms is 0.15 s: "0.2s" is the correct rounding and is exactly 50 ms away.
    for (const [ms, text] of [
      [150, '0.2s'],
      [350, '0.4s'],
      [750, '0.8s'],
      [1_150, '1.2s'],
    ] as const) {
      expect(formatDuration(ms)).toBe(text);
    }
  });
});
