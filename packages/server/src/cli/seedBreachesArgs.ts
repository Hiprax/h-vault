/**
 * Argument parsing for the opt-in breach-corpus seeder (`seedBreaches.ts`).
 *
 * Kept as a pure, dependency-free module so it can be unit-tested without a
 * database connection or a running server. The thin entry point owns all I/O
 * (Mongo connection, job lock, signal handling); this module only turns an argv
 * array into a plain {@link CliArgs} shape.
 *
 * Parsing is intentionally NON-validating: `--from`/`--to` are read as base-16
 * and `--concurrency`/`--stale-days` as base-10 integers, and a malformed value
 * yields `NaN` (or an out-of-range number) rather than throwing here. Range and
 * integer validation lives in the entry point, which can fail fast with a
 * human-readable message and a non-zero exit code.
 */

export interface CliArgs {
  /** Refetch every prefix even if it is already cached (`--force`). */
  force: boolean;
  /** Max concurrent outbound HIBP fetches (`--concurrency=N`), or undefined for the default. */
  concurrency: number | undefined;
  /** First prefix index, parsed from 5-hex `--from=`, or undefined for 0. */
  from: number | undefined;
  /** Last prefix index, parsed from 5-hex `--to=`, or undefined for the last prefix. */
  to: number | undefined;
  /** Refresh entries older than this many days (`--stale-days=N`), or undefined. */
  staleDays: number | undefined;
}

/**
 * Parse the seeder's CLI flags. Unknown flags and bare positional arguments are
 * ignored. `--force` is a boolean toggle; the remaining flags take a `=value`.
 */
export function parseArgs(argv: readonly string[]): CliArgs {
  const args: CliArgs = {
    force: false,
    concurrency: undefined,
    from: undefined,
    to: undefined,
    staleDays: undefined,
  };
  for (const raw of argv) {
    if (raw === '--force') {
      args.force = true;
      continue;
    }
    const eq = raw.indexOf('=');
    if (!raw.startsWith('--') || eq === -1) continue;
    const key = raw.slice(2, eq);
    const value = raw.slice(eq + 1);
    switch (key) {
      case 'concurrency':
        args.concurrency = Number.parseInt(value, 10);
        break;
      case 'from':
        args.from = Number.parseInt(value, 16);
        break;
      case 'to':
        args.to = Number.parseInt(value, 16);
        break;
      case 'stale-days':
        args.staleDays = Number.parseInt(value, 10);
        break;
      default:
        break;
    }
  }
  return args;
}
