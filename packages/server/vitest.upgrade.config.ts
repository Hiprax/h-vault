import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The `test:upgrade` suite: data and configuration from the PREVIOUS release,
 * read by this one.
 *
 * Both files also run under `test:integration`, which is the whole server suite
 * — so this narrows NOTHING, and the assertions are on the push gate. What the
 * named run adds is a gate a reviewer can point at when a schema, a model or the
 * environment contract changes, and a wall-clock deadline of its own: the config
 * half boots real child processes, and a boot that HANGS is a different defect
 * from one that refuses.
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line, and `gate-surface.test.ts` asserts every entry exists AND that
 * nothing on disk is left to no gate at all — vitest errors only on an EMPTY
 * match, so a half-stale list would shrink this gate in silence.
 */
export const UPGRADE_SUITE = [
  // N-1 DATA: a vault written by 0.7.0, decrypted, validated and read back
  // through the current models and routes.
  'tests/upgrade/n-minus-1.test.ts',
  // N-1 CONFIGURATION: that release's .env booting this release's server, the
  // variables it has since removed being ignored, and every required one
  // failing by name when it is absent.
  'tests/upgrade/config-compat.test.ts',
];

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-server.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the server package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json` — see the header of
 * `scripts/ci/upgrade-gate.mjs`.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-upgrade.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: UPGRADE_SUITE,
    reporters: ['default', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
