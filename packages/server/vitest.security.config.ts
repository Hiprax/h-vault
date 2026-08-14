import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The `test:security` suite: cross-user authorization, run as its own gate.
 *
 * Every file here also runs under `test:integration`, which is the whole
 * server suite — so this narrows NOTHING. It exists because "no user can reach
 * another user's row" deserves a gate a reviewer can point at when an endpoint
 * is added, and because that gate must be able to fail on its own
 * (`verify:selftest` plants an ownership filter removed from a controller and
 * requires exactly this command to go red).
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line: a config that names its files is a suite definition, whereas a
 * filter on a runner invocation is the shape the integrity doctrine forbids.
 *
 * The list is kept honest by `gate-surface.test.ts`, which asserts every entry
 * exists on disk. Vitest itself is NOT that guard: it exits non-zero only when
 * the include set matches NOTHING, so renaming one of these four would leave
 * the other three running and this gate quietly 25% smaller.
 */
export const SECURITY_SUITE = [
  // The table itself: exhaustive against the real Express router stack.
  'tests/route-table.test.ts',
  // The matrix it drives.
  'tests/authz-matrix.test.ts',
  // What the table cannot express: collection scoping, and a foreign id
  // carried in a request body rather than in the URL.
  'tests/cross-user-isolation.test.ts',
  'tests/phase7-cross-user-edge-cases.test.ts',
];

/**
 * Its OWN JUnit report.
 *
 * Load-bearing, and it was a real defect first: driving this suite from the
 * command line left the base config's inline `outputFile` in charge, so the run
 * overwrote `junit-server.xml` — the artifact `audit:ratchet:full` reads the
 * server package's test count from. A subset's count would then have been
 * ratcheted as the whole suite's, and the next full run would have looked like
 * a recovery rather than the correction it was. `gate-surface.test.ts` asserts
 * the two names differ.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  { outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-security.xml') },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    // Assigned, never merged: `mergeConfig` concatenates arrays, which would
    // leave the base's default include beside this one (running the whole
    // suite) and two JUnit reporters writing two files.
    include: SECURITY_SUITE,
    reporters: ['default', junitReporter],
  },
});
