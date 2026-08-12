import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's leg of the `test:fuzz` gate: the backup-restore folder-graph
 * remapping, driven with adversarial backup documents against a real mongod.
 *
 * Every file here also runs under `test:integration`, which is the whole server
 * suite — so this narrows NOTHING. It exists for the reason the client leg does:
 * "an arbitrary backup file restores to an acyclic forest, or is refused, and
 * never loses a row to a duplicate key the per-row catch swallowed" is the claim
 * whose violation already cost this project silent data loss once, and it
 * deserves a gate a reviewer can point at.
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line, and `gate-surface.test.ts` asserts every entry exists — vitest
 * errors only on an EMPTY match, so a half-stale list would shrink this gate in
 * silence.
 */
export const SERVER_FUZZ_SUITE = ['tests/fuzz/restore.fuzz.test.ts'];

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-server.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the server package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json` — see the header of
 * `scripts/ci/fuzz-gate.mjs`.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-fuzz-server.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: SERVER_FUZZ_SUITE,
    reporters: ['default', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
