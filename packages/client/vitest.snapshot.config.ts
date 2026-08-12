import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The `test:snapshot` gate: the export wire formats compared byte for byte
 * against their committed goldens, plus the export/import round trip.
 *
 * "Snapshot" here means a GOLDEN FILE that a human recorded and verified against
 * a third party's documented format — not a vitest `toMatchSnapshot()`, and the
 * difference is the whole point. Nothing in this suite can regenerate a golden;
 * there is no `--update` path, because a snapshot that rewrites itself on demand
 * records whatever the code does today and calls it the specification.
 *
 * The file also runs under `test:unit`, so this narrows nothing. It is its own
 * gate because a drift here is invisible until a user tries to leave: the bytes
 * are what Bitwarden and Chrome parse, and nobody notices a renamed column until
 * a migration silently loses a column of passwords.
 *
 * `gate-surface.test.ts` asserts every entry exists on disk, for the reason
 * every other subset config records: vitest errors only on an EMPTY match.
 */
export const CLIENT_SNAPSHOT_SUITE = ['tests/export/formats.golden.test.ts'];

/**
 * Its OWN JUnit report — `junit-export.xml`, the name the plan's gate table
 * declares. Pointed at `junit-client.xml` it would overwrite the artifact
 * `audit:ratchet:full` reads the client package's test count from.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  {
    outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-export.xml'),
  },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    include: CLIENT_SNAPSHOT_SUITE,
    reporters: ['default', junitReporter],
    coverage: { ...baseTest.coverage, enabled: false },
  },
});
