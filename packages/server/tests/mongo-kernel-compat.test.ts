/**
 * SERVER-121912 regression guard.
 *
 * The production stack pins mongo:8.0 and both Node test harnesses spawn a real
 * mongod 8.x through mongodb-memory-server, so `glibc.pthread.rseq=1` is what keeps
 * MongoDB starting at all on a Linux 6.19+ kernel (Ubuntu 26.04 and newer). The
 * failure it prevents is a startup abort — a crash-loop in production, and a test run
 * that dies before its first assertion on a developer's machine.
 *
 * The interesting case is the MERGE: GLIBC_TUNABLES is a colon-separated list, so the
 * obvious `??=` silently drops the rseq setting the moment anything else sets an
 * unrelated tunable.
 */
import { describe, it, expect } from 'vitest';
import { withRseqTunable, applyMongoKernelCompat } from './mongoKernelCompat.js';

const RSEQ = 'glibc.pthread.rseq=1';

describe('mongo kernel compat (SERVER-121912)', () => {
  it('sets the tunable when nothing is set', () => {
    expect(withRseqTunable(undefined)).toBe(RSEQ);
    expect(withRseqTunable('')).toBe(RSEQ);
    expect(withRseqTunable('   ')).toBe(RSEQ);
  });

  it('MERGES with unrelated tunables instead of dropping them — or itself', () => {
    // The whole point. With `??=`, this environment loses the rseq fix entirely and
    // mongod goes back to aborting at startup, for a reason that has nothing to do
    // with the tunable someone actually set.
    expect(withRseqTunable('glibc.malloc.tcache_count=0')).toBe(
      `glibc.malloc.tcache_count=0:${RSEQ}`,
    );
    expect(withRseqTunable('glibc.malloc.arena_max=2:glibc.malloc.tcache_count=0')).toBe(
      `glibc.malloc.arena_max=2:glibc.malloc.tcache_count=0:${RSEQ}`,
    );
  });

  it('is idempotent — applying it twice does not append a second copy', () => {
    expect(withRseqTunable(RSEQ)).toBe(RSEQ);
    expect(withRseqTunable(withRseqTunable(withRseqTunable(undefined)))).toBe(RSEQ);
    expect(withRseqTunable(`glibc.malloc.arena_max=2:${RSEQ}`)).toBe(
      `glibc.malloc.arena_max=2:${RSEQ}`,
    );
  });

  it('leaves an explicit operator choice alone, including the dangerous rseq=0', () => {
    // 0 is mongod's own default and precisely the value that crashes, so nobody sets
    // it by accident. Someone who sets it deliberately — to reproduce the abort, or
    // because a future mongod fixes the ABI violation — must not be silently
    // overridden by a test harness.
    expect(withRseqTunable('glibc.pthread.rseq=0')).toBe('glibc.pthread.rseq=0');
    expect(withRseqTunable('glibc.malloc.arena_max=2:glibc.pthread.rseq=0')).toBe(
      'glibc.malloc.arena_max=2:glibc.pthread.rseq=0',
    );
  });

  it('does not mistake a differently-named tunable for the rseq one', () => {
    // A substring match on `glibc.pthread.rseq=` would wrongly treat this as "already
    // set" and skip the append, so the anchor (start-of-string or a colon) matters.
    expect(withRseqTunable('glibc.pthread.rseq_extra=1')).toBe(
      `glibc.pthread.rseq_extra=1:${RSEQ}`,
    );
  });

  it('applies to an environment object in place, which is how the child inherits it', () => {
    const env: NodeJS.ProcessEnv = { GLIBC_TUNABLES: 'glibc.malloc.arena_max=2' };
    applyMongoKernelCompat(env);
    expect(env['GLIBC_TUNABLES']).toBe(`glibc.malloc.arena_max=2:${RSEQ}`);

    const empty: NodeJS.ProcessEnv = {};
    applyMongoKernelCompat(empty);
    expect(empty['GLIBC_TUNABLES']).toBe(RSEQ);
  });

  it('has already been applied to this very process by the test setup', () => {
    // tests/setup.ts runs before any test file; mongodb-memory-server spawns mongod
    // from this process's environment, so if this is not true the suite could not
    // have got this far on a 6.19+ kernel.
    expect(process.env['GLIBC_TUNABLES']).toContain(RSEQ);
  });
});
