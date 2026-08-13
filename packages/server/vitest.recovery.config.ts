import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The `test:recovery` suite: the disaster cases.
 *
 * Both files also run under `test:integration`, which is the whole server suite
 * — so this narrows NOTHING, and every assertion is on the push gate. What the
 * named run adds is a gate a reviewer can point at when the backup format, the
 * rotation fence or the import's transaction boundary changes, plus a
 * wall-clock deadline of its own: these cases spawn real child processes and
 * SIGKILL them, so a probe that HANGS is a different defect from one that fails
 * and has to be reportable as such.
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line, and `gate-surface.test.ts` asserts every entry exists AND that
 * nothing on disk is left to no gate at all — vitest errors only on an EMPTY
 * match, so a half-stale list would shrink this gate in silence.
 */
export const RECOVERY_SUITE = [
  // A backup file leaving one database and arriving in another, on a second
  // mongod, with every item decrypted and compared byte for byte.
  'tests/recovery/restore-drill.test.ts',
  // A real process killed mid-write, at five points around the rotation fence
  // and the import's transaction boundary.
  'tests/recovery/crash-consistency.test.ts',
];

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-server.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the server package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json` — see the header of
 * `scripts/ci/recovery-gate.mjs`.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-recovery.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: RECOVERY_SUITE,
    reporters: ['default', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
