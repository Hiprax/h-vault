/**
 * SERVER-121912 — make mongod start on Linux kernels >= 6.19 (Ubuntu 26.04 and newer).
 *
 * The typed façade the TypeScript harnesses use. The merge itself lives ONCE, in
 * `scripts/ci/lib/mongo-rseq.mjs`, because a third launch site — `scripts/ci/smoke-gate.mjs`
 * — is plain JavaScript with no build step in front of it and cannot import a `.ts`
 * module. Read that file for the whole story: why the tunable is load-bearing on the
 * 8.x line, why it has to be a merge rather than `??=`, and why an explicit
 * `glibc.pthread.rseq=0` already in the environment is left alone.
 *
 * Reaching a pipeline helper from the suite is the established arrangement here, not
 * a one-off: `packages/server/tsconfig.test.json` carries `allowJs` for exactly this,
 * and a dozen suites already import `scripts/ci/lib/*.mjs` so TypeScript infers their
 * types from the real sources instead of from a `.d.mts` sidecar free to drift.
 *
 * There are five launch sites in total. Two are the compose files, which set
 * `GLIBC_TUNABLES` in the container's environment. Three are Node programs that spawn
 * a REAL mongod through `mongodb-memory-server` (it downloads the binary, defaulting
 * to the 8.x line): `tests/mongoHarness.ts`, which constructs every standalone and
 * replica set the server suite uses; `e2e/start-server.ts`; and the smoke gate. Miss
 * one and `npm test` / `npm run test:e2e` / `npm run test:smoke`, all three mandated
 * by the project's pre-completion checklist, die at mongod launch on a modern host for
 * a reason that looks nothing like the change under test.
 * `tests/docker-hardening.test.ts` ENUMERATES those sites rather than listing them,
 * so a sixth cannot be added without the tunable.
 */

import {
  applyRseqTunable,
  withRseqTunable as mergeRseqTunable,
} from '../../../scripts/ci/lib/mongo-rseq.mjs';

/**
 * Returns `current` with `glibc.pthread.rseq=1` guaranteed present, appending to any
 * tunables already set, and leaving an explicit `glibc.pthread.rseq=` choice alone.
 * A typed re-export of the shared merge, kept so the harnesses and
 * `mongo-kernel-compat.test.ts` name one function rather than reaching across the
 * repository for it.
 */
export function withRseqTunable(current: string | undefined): string {
  return mergeRseqTunable(current);
}

/**
 * Applies the tunable to a process environment in place. Call it BEFORE the mongod is
 * spawned — the child inherits `process.env`, which is the whole mechanism.
 */
export function applyMongoKernelCompat(env: NodeJS.ProcessEnv = process.env): void {
  applyRseqTunable(env);
}
