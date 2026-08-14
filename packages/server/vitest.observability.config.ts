import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import baseConfig from './vitest.config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * The `test:observability` suite: what the server says about itself, run as its
 * own gate.
 *
 * Three surfaces carry a request's secrets back out of the process after it has
 * arrived — the log line describing the request, the audit row describing what
 * was done, and the error body describing what went wrong — and a leak into any
 * of them is durable, invisible from the client, and usually long-retained.
 * These files are what hold that line.
 *
 * Every file here also runs under `test:integration`, which is the whole server
 * suite — so this narrows NOTHING. It exists for the same two reasons
 * `test:security` does: "no secret leaves through a log, an audit row or an
 * error body" deserves a gate a reviewer can point at when a controller starts
 * logging something new, and that gate must be able to fail on its own
 * (`verify:selftest` plants `exposeServerErrors: true` in app.ts and requires
 * exactly this command to go red).
 *
 * The membership is declared HERE rather than as positional filters on the
 * command line: a config that names its files is a suite definition, whereas a
 * filter on a runner invocation is the shape the integrity doctrine forbids.
 *
 * The list is kept honest by `gate-surface.test.ts`, which asserts every entry
 * exists on disk. Vitest itself is NOT that guard: it exits non-zero only when
 * the include set matches NOTHING, so renaming one of these four would leave the
 * other three running and this gate quietly 25% smaller.
 */
export const OBSERVABILITY_SUITE = [
  // Request-body masking, audit rows, and production error bodies.
  'tests/request-logger-masking.test.ts',
  // PII (an email address) inside structured logger metadata.
  'tests/phase2-topology-and-log-pii.test.ts',
  // What an error message is allowed to tell a caller, including the
  // anti-enumeration responses that must stay indistinguishable.
  'tests/error-message-leakage.test.ts',
  // That the rows exist at all, and carry the actions they claim to.
  'tests/audit-logging.test.ts',
];

/**
 * Its OWN JUnit report, for the reason `vitest.security.config.ts` records: a
 * subset run that writes `junit-server.xml` overwrites the artifact
 * `audit:ratchet:full` reads the server package's test count from, and the
 * subset's count would then be ratcheted as the whole suite's.
 * `gate-surface.test.ts` asserts the names differ.
 */
const junitReporter: ['junit', { outputFile: string }] = [
  'junit',
  { outputFile: path.resolve(__dirname, '../../.testfortress/reports/junit-observability.xml') },
];

const baseTest = baseConfig.test!;

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseTest,
    // Assigned, never merged: `mergeConfig` concatenates arrays, which would
    // leave the base's default include beside this one (running the whole suite)
    // and two JUnit reporters writing two files.
    include: OBSERVABILITY_SUITE,
    reporters: ['default', junitReporter],
  },
});
