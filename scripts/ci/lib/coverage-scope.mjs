/**
 * The DECLARED coverage scope, derived rather than restated.
 *
 * `coverage-check.mjs` needs one thing the coverage reports cannot tell it: for
 * a file that appears in NO report, is that because it was deliberately excluded
 * (a process entry point) or because it is new and nothing has ever measured it?
 * The reports look identical in both cases — the file is simply absent — and the
 * second case is the hole that makes "100% of changed lines are covered" a false
 * claim. So the scope has to be declared somewhere.
 *
 * It is NOT declared here. It is derived from `mutation-scope.mjs`, whose
 * `MUTATION_LEGS[].mutate` globs are already "packages/*​/src/** minus the
 * coverage-excluded entry points, minus the presentational primitives", and
 * whose negation list `gate-surface.test.ts` pins against the three vitest
 * configs. A second hand-written copy of the exclusions is exactly how a
 * denominator drifts: the copy is edited, the original is not, and the diff
 * looks like housekeeping rather than like a weakening.
 *
 * TWO deliberate differences from the mutation scope, and both widen this one:
 *
 *   1. `packages/client/src/components/ui/**` is IN scope here. Mutation
 *      excludes it because a class-name mutant is cosmetic; coverage measures it
 *      and always has, so excluding it here would let a changed UI primitive
 *      slip past unmeasured.
 *   2. `src/**​/*.test.ts(x)` is excluded here and not there. The three coverage
 *      configs declare that exclusion; the mutation legs do not need it because
 *      no test file lives under `src/` today (measured: zero). Carrying it keeps
 *      this module a faithful projection of the coverage configuration rather
 *      than of the tree as it happens to be arranged this week.
 */
import { MUTATION_LEGS, PRESENTATIONAL_EXCLUDE } from './mutation-scope.mjs';

/** See difference (2): declared by all three coverage configs. */
const COLOCATED_TEST_EXCLUDES = [
  '!packages/shared/src/**/*.test.ts',
  '!packages/server/src/**/*.test.ts',
  '!packages/client/src/**/*.test.ts',
  '!packages/client/src/**/*.test.tsx',
];

/**
 * Every glob deciding whether a path is production code this project measures.
 * Positives first, then negations; a later negation wins.
 */
export const COVERAGE_SCOPE_GLOBS = [
  ...MUTATION_LEGS.flatMap((leg) => leg.mutate).filter(
    (glob) => glob !== PRESENTATIONAL_EXCLUDE, // difference (1)
  ),
  ...COLOCATED_TEST_EXCLUDES,
];

/**
 * A glob matcher for the four shapes above and no more: `**​/`, `**`, `*` and
 * literals. Hand-rolled so this stays dependency-free, which is adequate for a
 * committed, pinned list of ten globs and is the first thing to replace with a
 * real matcher if that list ever stops being either.
 *
 * ONE PASS, and that is the load-bearing part rather than a style choice.
 *
 * The first version of this function chained four `.replace` calls — escape the
 * metacharacters, then `**​/`, then `**`, then `*` — reasoning that ordering
 * longest-first stops a short pattern eating a long one's prefix. It does. What
 * it does not stop is each pass re-scanning the OUTPUT of the ones before it:
 * `**​/` became `(?:.*​/)?`, and the `*` pass then rewrote the `*` inside that
 * replacement, yielding `(?:.[^/]*​/)?` — which matches at most ONE path
 * segment. Every production file two or more directories below `src/` silently
 * left the scope (21 of them here) and the gate reported green over what was
 * left. A single `replace` over an alternation, longest branch first, cannot do
 * that: `String.replace` never re-scans what a replacement inserted.
 */
export function globToRegExp(glob) {
  const source = glob.replace(/\*\*\/|\*\*|\*|[.+^${}()|[\]\\?]/g, (token) => {
    // Zero or more whole path segments, so `a/**​/b` matches `a/b` and `a/x/y/b`.
    if (token === '**/') return '(?:[^/]*/)*';
    if (token === '**') return '.*';
    if (token === '*') return '[^/]*';
    return `\\${token}`;
  });
  return new RegExp(`^${source}$`);
}

const POSITIVE = COVERAGE_SCOPE_GLOBS.filter((glob) => !glob.startsWith('!')).map(globToRegExp);
const NEGATIVE = COVERAGE_SCOPE_GLOBS.filter((glob) => glob.startsWith('!')).map((glob) =>
  globToRegExp(glob.slice(1)),
);

/**
 * True when a repo-relative POSIX path is production code inside the measured
 * scope — so a change to it is a change whose coverage this project claims.
 */
export function inCoverageScope(relPath) {
  if (NEGATIVE.some((re) => re.test(relPath))) return false;
  return POSITIVE.some((re) => re.test(relPath));
}

/**
 * Which package owns a repo-relative path, as the baseline keys them.
 * `packages/server/src/app.ts` → `packages/server`.
 */
export function packageOfPath(relPath) {
  const match = /^(packages\/[^/]+)\//.exec(relPath);
  return match ? match[1] : null;
}
