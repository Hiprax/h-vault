import '@testing-library/jest-dom';
import { beforeEach } from 'vitest';
import { applyDeterminismPins, printSeedBannerOnce } from './determinism.js';
import { installEgressGuard } from './egressGuard.js';
import { installRepoWriteGuard } from './tempDir.js';

/**
 * Pin timezone, locale and the seed inside the harness rather than as a shell
 * prefix (`TZ=UTC npm test` is not valid syntax on Windows, where this project is
 * also developed, so a prefix-based pin is one half the contributors silently do
 * not get). `vitest.config.ts` carries the same values in `test.env` so they
 * apply before the first module is evaluated; this re-applies them so the pin
 * survives an invocation that bypassed the config's env block.
 */
applyDeterminismPins();

/**
 * Block outbound network access for the whole suite, and block writes into the
 * checkout. Both at module scope, so they also cover a test file's import-time
 * code.
 *
 * The write guard is installed here even though no client test writes a file
 * today. That is the point: it is cheap now and it makes the FIRST such test
 * fail with a message naming `createTestTempDir()`, rather than quietly leaving
 * a fixture in the working tree for `audit:integrity` to trip over later. The
 * server tier has carried it since this harness landed; leaving one tier
 * unguarded is how the two drift.
 */
installEgressGuard();
installRepoWriteGuard();

/**
 * Name the seed beside the first failure in each file, so a shuffled run's order
 * is reproducible. A hook rather than a reporter: a reporter is configuration a
 * contributor can drop without noticing, while this rides along with the setup
 * file every test file already loads.
 */
beforeEach((ctx) => {
  ctx.onTestFailed(() => {
    printSeedBannerOnce();
  });
});

// Ensure Web Crypto API is available in jsdom environment
if (!globalThis.crypto?.subtle) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { webcrypto } = require('node:crypto');
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
  });
}

// Polyfill scrollIntoView for jsdom, which implements no layout and therefore
// ships no implementation of it. Any component that keeps a keyboard-active row
// inside a scrollport calls it (the saved-address picker does), and without this
// the call is a TypeError rather than a no-op. Polyfilled here rather than
// guarded at each call site: a `?.()` on a method the DOM lib types as always
// present is exactly the redundant condition `no-unnecessary-condition` flags,
// and production browsers all have it.
if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function scrollIntoView(): void {
    /* no layout in jsdom, so there is nothing to scroll */
  };
}

// Polyfill matchMedia for jsdom (required by uiStore and other components)
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
