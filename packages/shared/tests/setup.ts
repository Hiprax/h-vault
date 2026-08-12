/**
 * Setup for the shared package's suite.
 *
 * This package is pure schema and constant code: it opens no sockets, writes no
 * files and starts no server, so the harness it needs is only the determinism
 * pins. It gets them for the same reason the other two do — a Zod refine on a
 * datetime, a length bound compared under a locale-aware collation, or a
 * property-based generator seeded from the wall clock would each make this
 * suite's verdict depend on the machine it ran on.
 */
import { beforeEach } from 'vitest';
import { applyDeterminismPins, printSeedBannerOnce } from './determinism.js';
import { installSocketEgressGuard } from './egressGuard.js';

applyDeterminismPins();

/**
 * Block outbound network access for this package's suite too. Installed at module
 * scope so it also covers a test file's import-time code.
 */
installSocketEgressGuard();

/** Name the seed beside the first failure in each file (see tests/harness/determinism.ts). */
beforeEach((ctx) => {
  ctx.onTestFailed(() => {
    printSeedBannerOnce();
  });
});
