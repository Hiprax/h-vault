import '@testing-library/jest-dom';
import { afterEach, beforeEach } from 'vitest';
import { applyDeterminismPins, printSeedBannerOnce } from './determinism.js';
import { installEgressGuard } from './egressGuard.js';
import { uninstallTestClock } from './clock.js';
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

/**
 * The safety net under the test clock.
 *
 * `tests/clock.ts` restores in every place it is used — `withTestClock`'s
 * `finally`, and a describe-scoped `afterEach` beside each bare
 * `installTestClock`. This makes that structural rather than a matter of
 * per-file discipline: a file that installs a fake clock and fails before its own
 * cleanup would otherwise leave the whole WORKER frozen, and every later file in
 * it would then run against an instant that stopped inside a test it has never
 * heard of — an order-dependent failure produced by the very mechanism installed
 * to remove one, and one that `test:flake` would surface as a mystery.
 *
 * `vi.useRealTimers()` is a no-op when no fake clock is installed (asserted in
 * `packages/server/tests/clock.test.ts`), and `sequence.hooks: 'stack'` runs this
 * hook LAST — after every describe-scoped `afterEach` — so a suite that installs
 * its clock in a `beforeEach` is unaffected.
 */
afterEach(() => {
  uninstallTestClock();
});

/**
 * A React state update outside `act(...)` fails the test that caused it.
 *
 * React only LOGS that warning, so a test whose component settles after its
 * synchronous assertions passes while the update it never awaited lands
 * unobserved, and the suite's output fills with lines nobody reads (seventy of
 * them once, all from the release-notes host). The wrapper records the warning
 * and still prints it; this hook, which runs after the test body's pending
 * microtasks, turns it into a failure naming the component. A test that
 * silences `console.error` itself is unaffected: that is its own decision.
 */
const updatesOutsideAct: string[] = [];
const printConsoleError = console.error.bind(console);
console.error = (...args: unknown[]): void => {
  const [message, component] = args;
  if (typeof message === 'string' && message.includes('not wrapped in act(')) {
    updatesOutsideAct.push(typeof component === 'string' ? component : 'a component');
  }
  printConsoleError(...args);
};
afterEach(() => {
  if (updatesOutsideAct.length === 0) return;
  const components = [...new Set(updatesOutsideAct.splice(0))].join(', ');
  throw new Error(
    `React reported a state update outside act(...) in ${components}: await what the component does after rendering, or keep it from settling in this test.`,
  );
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

// jsdom has no media engine: its `HTMLMediaElement.prototype.play` only logs
// "Not implemented". The camera preview awaits `play()` (and tolerates a refusal),
// so here it resolves, as a browser's does once playback starts.
if (typeof HTMLMediaElement !== 'undefined') {
  HTMLMediaElement.prototype.play = function play(): Promise<void> {
    return Promise.resolve();
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
