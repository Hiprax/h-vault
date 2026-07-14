/**
 * SERVER-121912 — make mongod start on Linux kernels >= 6.19 (Ubuntu 26.04 and newer).
 *
 * MongoDB 8.0 moved TCMalloc to per-CPU caches, and that TCMalloc drives them with
 * restartable sequences in a way that violates the rseq ABI as it changed in kernel
 * 6.19. mongod's startup self-check aborts, and it is still unpatched upstream.
 *
 * Every place this repository launches a mongod has to set the tunable, and there are
 * four: `docker-compose.yml` and `docker-compose.dev.yml` (which set it in the
 * container's environment), plus the two Node harnesses — `tests/setup.ts` and
 * `e2e/start-server.ts` — because `mongodb-memory-server` DOWNLOADS AND SPAWNS A REAL
 * mongod (defaulting to the 8.x line). Miss the harnesses and `npm test` /
 * `npm run test:e2e`, both mandated by the project's pre-completion checklist, die at
 * mongod launch on a modern host for a reason that looks nothing like the change under
 * test. This module is the single implementation the two harnesses share, so they
 * cannot drift.
 *
 * Why this is a MERGE and not `env.GLIBC_TUNABLES ??= 'glibc.pthread.rseq=1'`:
 * GLIBC_TUNABLES is a COLON-SEPARATED list. With `??=`, an operator or CI runner that
 * sets any unrelated tunable (`glibc.malloc.tcache_count=0`, say) silently loses the
 * rseq setting entirely — and gets back the crash, in an environment where the one
 * thing that changed was something apparently unrelated.
 */

const RSEQ_TUNABLE = 'glibc.pthread.rseq=1';

/**
 * Returns `current` with `glibc.pthread.rseq=1` guaranteed present, appending to any
 * tunables already set. An explicit `glibc.pthread.rseq=` choice already in `current`
 * is left ALONE — including `=0`. That is deliberate: `0` is the value that crashes,
 * so nobody sets it by accident, and someone who sets it on purpose (to reproduce the
 * abort, or because a future mongod fixes the ABI violation and they want the faster
 * allocator path back) should not be silently overridden by a test harness.
 */
export function withRseqTunable(current: string | undefined): string {
  const trimmed = current?.trim();
  if (!trimmed) return RSEQ_TUNABLE;
  if (/(?:^|:)glibc\.pthread\.rseq=/.test(trimmed)) return trimmed;
  return `${trimmed}:${RSEQ_TUNABLE}`;
}

/**
 * Applies the tunable to a process environment in place. Call it BEFORE the mongod is
 * spawned — the child inherits `process.env`, which is the whole mechanism.
 */
export function applyMongoKernelCompat(env: NodeJS.ProcessEnv = process.env): void {
  env['GLIBC_TUNABLES'] = withRseqTunable(env['GLIBC_TUNABLES']);
}
