/**
 * This package's view of the repo-wide determinism harness.
 *
 * The implementation is shared (`tests/harness/determinism.ts` at the repo root)
 * because the contract is identical in all three packages and three copies of it
 * would drift: the day one of them stops pinning `LC_ALL`, that package's suite
 * silently starts depending on the developer's desktop locale. Re-exported
 * through a package-local module so `vitest.config.ts` and every test file keep
 * importing a path inside their own package.
 */
export * from '../../../tests/harness/determinism.js';
