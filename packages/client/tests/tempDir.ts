/**
 * This package's view of the repo-wide filesystem-isolation harness.
 *
 * The implementation is shared (`tests/harness/repoWrites.ts` at the repo root),
 * because its allowlist names paths in every package: three per-package copies
 * would be three lists that drift, and the tier that copied it last is the one
 * that silently stops guarding. Re-exported through a package-local module so
 * call sites keep importing a path inside their own package.
 */
export * from '../../../tests/harness/repoWrites.js';
