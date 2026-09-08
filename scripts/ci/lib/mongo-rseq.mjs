/**
 * SERVER-121912 — the one implementation of the tunable every mongod launch site
 * in this repository has to set, on Linux kernels >= 6.19 (Ubuntu 26.04 and newer).
 *
 * MongoDB 8.0 moved TCMalloc to per-CPU caches, and that TCMalloc drives them with
 * restartable sequences in a way that violates the rseq ABI as it changed in kernel
 * 6.19. mongod's startup self-check
 * (`isTCMallocPerCPUCacheActive() && !isKernelSafeForTCMallocPerCPUCache()`) aborts,
 * and it is still unpatched upstream. Handing rseq to glibc deactivates the per-CPU
 * cache, the guard passes, and mongod runs — no version pin needed.
 *
 * ## Why this file is here and not in `packages/server/tests/`
 *
 * There are five launch sites: `docker-compose.yml` and `docker-compose.dev.yml`
 * set the variable in the container's environment, and three Node programs spawn a
 * real mongod through `mongodb-memory-server` (which DOWNLOADS a mongod binary,
 * defaulting to the 8.x line) — `packages/server/tests/mongoHarness.ts` for the
 * server suite, `e2e/start-server.ts` for Playwright, and `scripts/ci/smoke-gate.mjs`
 * to boot the built artifact against one.
 *
 * The third is plain JavaScript with no build step in front of it, so it cannot
 * import a `.ts` module; it used to restate the merge in four hand-copied lines,
 * which is precisely the arrangement the drift test in
 * `packages/server/tests/docker-hardening.test.ts` was supposed to prevent and did
 * not (that test listed two harnesses by name and never looked at the gate). Putting
 * the merge in `scripts/ci/lib/` — plain JS, importable by the gate directly and by
 * the TypeScript harnesses through the `allowJs` the server and client test configs
 * already carry for these pipeline helpers — leaves exactly one implementation for
 * all three.
 *
 * Pure by contract: `scripts/ci/lib/**` modules run no gate at module scope, because a
 * test may import one. `gate-surface.test.ts` enforces the neighbouring half of that —
 * it walks every module in this directory and fails one that re-exports from a gate
 * SCRIPT, which would carry the side effect in through the back door — but it cannot
 * check for side effects here directly, so purity in this file is a convention its
 * author keeps rather than a property a gate proves.
 *
 * ## Why this is a MERGE and not `env.GLIBC_TUNABLES ??= …`
 *
 * `GLIBC_TUNABLES` is a COLON-SEPARATED list. With `??=`, an operator or CI runner
 * that sets any unrelated tunable (`glibc.malloc.tcache_count=0`, say) silently
 * loses the rseq setting entirely — and gets back the crash, in an environment where
 * the one thing that changed was something apparently unrelated.
 */

/** The value. `0` is mongod's own default and exactly the value that crashes. */
export const RSEQ_TUNABLE = 'glibc.pthread.rseq=1';

/**
 * Returns `current` with `glibc.pthread.rseq=1` guaranteed present, appending to any
 * tunables already set. An explicit `glibc.pthread.rseq=` choice already in `current`
 * is left ALONE — including `=0`. That is deliberate: `0` is the value that crashes,
 * so nobody sets it by accident, and someone who sets it on purpose (to reproduce the
 * abort, or because a future mongod fixes the ABI violation and they want the faster
 * allocator path back) should not be silently overridden by a test harness.
 *
 * @param {string | undefined} current - The existing `GLIBC_TUNABLES` value, if any.
 * @returns {string} The value to set.
 */
export function withRseqTunable(current) {
  const trimmed = current?.trim();
  if (!trimmed) return RSEQ_TUNABLE;
  if (/(?:^|:)glibc\.pthread\.rseq=/.test(trimmed)) return trimmed;
  return `${trimmed}:${RSEQ_TUNABLE}`;
}

/**
 * Applies the tunable to a process environment in place. Call it BEFORE the mongod is
 * spawned — the child inherits `process.env`, which is the whole mechanism.
 *
 * @param {Record<string, string | undefined>} [env] - Defaults to `process.env`.
 * @returns {void}
 */
export function applyRseqTunable(env = process.env) {
  env['GLIBC_TUNABLES'] = withRseqTunable(env['GLIBC_TUNABLES']);
}
