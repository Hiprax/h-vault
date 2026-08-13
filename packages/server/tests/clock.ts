/**
 * This package's view of the repo-wide test clock.
 *
 * Re-exported through a package-local module for the same reason
 * `determinism.ts` is: the contract is identical in every package and three
 * copies of it would drift, while every test file keeps importing a path inside
 * its own package. See `tests/harness/clock.ts` for why the seam is opt-in and
 * why `toFake: ['Date']` is its default.
 */
export * from '../../../tests/harness/clock.js';
