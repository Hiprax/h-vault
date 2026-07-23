/**
 * Unit tests for the breach-seeder CLI argument parser.
 *
 * `parseArgs` is the pure, dependency-free half of the seeder that moved from
 * `scripts/seed-breaches.ts` into `src/cli/` (Phase 2). It only turns an argv
 * array into a plain shape; range/integer VALIDATION lives in the entry point
 * (`seedBreaches.ts`), so these tests assert the raw parsed values — including
 * the `NaN`/negative/out-of-range results the entry point then rejects.
 */
import { describe, it, expect } from 'vitest';
import { parseArgs } from '../src/cli/seedBreachesArgs.js';

describe('parseArgs (breach-seeder CLI)', () => {
  it('returns all defaults for an empty argv', () => {
    expect(parseArgs([])).toEqual({
      force: false,
      concurrency: undefined,
      from: undefined,
      to: undefined,
      staleDays: undefined,
    });
  });

  it('sets force for the bare --force toggle', () => {
    expect(parseArgs(['--force']).force).toBe(true);
  });

  it('parses --concurrency as a base-10 integer', () => {
    expect(parseArgs(['--concurrency=24']).concurrency).toBe(24);
  });

  it('parses --from and --to as base-16 (hex) prefix indices', () => {
    const args = parseArgs(['--from=00000', '--to=00FFF']);
    expect(args.from).toBe(0);
    expect(args.to).toBe(0x00fff);
    expect(args.to).toBe(4095);
  });

  it('parses --stale-days as a base-10 integer', () => {
    expect(parseArgs(['--stale-days=30']).staleDays).toBe(30);
  });

  it('parses a full combination of flags together', () => {
    expect(
      parseArgs(['--force', '--concurrency=8', '--from=1', '--to=A', '--stale-days=7']),
    ).toEqual({
      force: true,
      concurrency: 8,
      from: 1,
      to: 10,
      staleDays: 7,
    });
  });

  it("yields NaN for a non-hex range value (validation is the entry point's job)", () => {
    const args = parseArgs(['--from=ZZZ', '--to=GG']);
    expect(Number.isNaN(args.from)).toBe(true);
    expect(Number.isNaN(args.to)).toBe(true);
  });

  it('yields NaN for a non-integer --concurrency', () => {
    expect(Number.isNaN(parseArgs(['--concurrency=abc']).concurrency)).toBe(true);
  });

  it('preserves a negative --stale-days verbatim', () => {
    expect(parseArgs(['--stale-days=-5']).staleDays).toBe(-5);
  });

  it('ignores an unknown --flag=value', () => {
    expect(parseArgs(['--wat=1'])).toEqual({
      force: false,
      concurrency: undefined,
      from: undefined,
      to: undefined,
      staleDays: undefined,
    });
  });

  it('ignores a bare positional argument (no leading --)', () => {
    expect(parseArgs(['seed', 'now'])).toEqual({
      force: false,
      concurrency: undefined,
      from: undefined,
      to: undefined,
      staleDays: undefined,
    });
  });

  it('ignores a long flag with no = separator', () => {
    // `--verbose` is not `--force` and has no `=`, so it is skipped entirely.
    expect(parseArgs(['--verbose']).force).toBe(false);
  });

  it('lets a later occurrence of a flag win', () => {
    expect(parseArgs(['--concurrency=4', '--concurrency=16']).concurrency).toBe(16);
  });

  it('keeps everything after the first = as the value', () => {
    // Only the first `=` splits key from value; the rest is the raw value.
    expect(Number.isNaN(parseArgs(['--concurrency=1=2']).concurrency)).toBe(false);
    expect(parseArgs(['--concurrency=1=2']).concurrency).toBe(1);
  });
});
