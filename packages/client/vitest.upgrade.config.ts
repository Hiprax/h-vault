import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * This package's leg of the `test:upgrade` gate: the previous release's
 * ciphertext, opened by the crypto this release ships.
 *
 * It exists because the server leg structurally cannot make the gate's headline
 * claim — `cryptoService.ts` lives here, and a server test cannot import it — so
 * "a vault written by the previous release decrypts under the current one" had
 * no assertion at all until this leg was added.
 *
 * The file also runs under `test:unit`, which is the whole client suite, so this
 * narrows NOTHING. `gate-surface.test.ts` asserts the membership exists and that
 * nothing under `tests/upgrade` is left to no gate — vitest errors only on an
 * EMPTY match, so a half-stale list would shrink this leg in silence.
 */
export const CLIENT_UPGRADE_SUITE = ['tests/upgrade/n-minus-1-crypto.test.ts'];

/**
 * Its OWN JUnit report, for the same reason as every other subset gate: pointed
 * at `junit-client.xml` it would overwrite the artifact `audit:ratchet:full`
 * reads the client package's test count from.
 *
 * Deliberately NOT declared in `.testfortress/verify.json` — see the header of
 * `scripts/ci/upgrade-gate.mjs`.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-upgrade-client.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: CLIENT_UPGRADE_SUITE,
    reporters: ['default', junitReporter],
    // Six 600,000-iteration PBKDF2 derivations at ~0.4 s each, plus a deliberate
    // wrong-password derivation. The per-test budgets in the suite are the real
    // bound; this only has to be larger than they are.
    testTimeout: 120_000,
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
