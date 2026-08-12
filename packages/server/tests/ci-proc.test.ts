/**
 * Regression tests for the local-pipeline process helpers.
 *
 * `scripts/ci/lib/proc.mjs` is the load-bearing runner behind every `npm run ci`
 * gate and the pre-push hook. On win32 it must spawn npm through a shell (npm is
 * a `.cmd` shim), and Node 24 emits DEP0190 when an args array is combined with
 * `shell: true`. `resolveSpawn` pre-joins the args into the command string on
 * that path so the warning never fires while the command line stays byte-for-byte
 * identical. These tests pin that behaviour, since the helper otherwise has no
 * coverage of its spawn shape.
 */
import { describe, it, expect } from 'vitest';
import { resolveSpawn, assertShellSafeArgs } from '../../../scripts/ci/lib/proc.mjs';

// The exact npm arg arrays the pipeline passes through `runNpm` (GATES in
// scripts/ci/local-ci.mjs). Every one must fold losslessly into a shell string.
const GATE_ARGS: readonly (readonly string[])[] = [
  ['run', 'build'],
  ['run', 'lint:report'],
  ['run', 'format:check'],
  ['run', 'type-check'],
  ['run', 'test:unit'],
  ['run', 'test:integration'],
  ['run', 'audit:prod'],
  ['run', 'test:e2e', '--', '--forbid-only', '--retries=2'],
];

describe('resolveSpawn (DEP0190 shell-join)', () => {
  it('pre-joins args into the command and empties the args array when shell is true', () => {
    expect(resolveSpawn('npm', ['run', 'build'], true)).toEqual({
      command: 'npm run build',
      args: [],
    });
  });

  it('produces the same final command line Node would build for the e2e gate', () => {
    expect(resolveSpawn('npm', GATE_ARGS.at(-1) as string[], true).command).toBe(
      'npm run test:e2e -- --forbid-only --retries=2',
    );
  });

  it('keeps args verbatim when shell is false (POSIX npm + every runExe)', () => {
    expect(resolveSpawn('npm', ['run', 'build'], false)).toEqual({
      command: 'npm',
      args: ['run', 'build'],
    });
  });

  it('does not join when shell is true but there are no args', () => {
    expect(resolveSpawn('npm', [], true)).toEqual({ command: 'npm', args: [] });
  });

  it('folds every real gate arg array losslessly (join round-trips by space split)', () => {
    for (const args of GATE_ARGS) {
      const resolved = resolveSpawn('npm', args as string[], true);
      expect(resolved.args).toEqual([]);
      expect(resolved.command.split(' ')).toEqual(['npm', ...args]);
    }
  });
});

describe('assertShellSafeArgs', () => {
  it('accepts every real gate arg array', () => {
    // Every argument the pipeline actually spawns passes the allowlist. If
    // this ever fails it names the offending gate rather than reporting an
    // anonymous "expected function not to throw".
    for (const args of GATE_ARGS) {
      assertShellSafeArgs(args as string[]);
    }

    expect(GATE_ARGS.length).toBeGreaterThan(0);
  });

  it('rejects an argument containing whitespace', () => {
    expect(() => assertShellSafeArgs(['run', 'a b'])).toThrow(/unsafe argument/);
  });

  it.each(['a&b', 'a|b', 'a<b', 'a>b', 'a^b', 'a%b', 'a(b', 'a)b', 'a"b'])(
    'rejects a cmd.exe metacharacter argument (%s)',
    (bad) => {
      expect(() => assertShellSafeArgs([bad])).toThrow(/unsafe argument/);
    },
  );

  it('makes resolveSpawn throw rather than silently mis-execute an unsafe join', () => {
    expect(() => resolveSpawn('npm', ['run', 'a b'], true)).toThrow(/unsafe argument/);
  });
});
