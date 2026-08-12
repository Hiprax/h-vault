/**
 * SPDX expression adjudication for the `audit:licenses` gate.
 *
 * Kept here, pure and dependency-free, so it can be tested without running npm
 * or license-checker: `packages/server/tests/static-floor-gates.test.ts` drives
 * the table this file exists to get right.
 *
 * Three rules, in order:
 *
 *  1. `AND` BINDS TIGHTER THAN `OR`, which is what SPDX says. An expression is
 *     therefore an OR of AND-groups: `MIT AND ISC OR CC0-1.0` is
 *     `(MIT AND ISC) OR (CC0-1.0)`. Splitting on `OR` first and then comparing
 *     the whole left side against an allowlist — as an earlier version did —
 *     reports a legitimately-allowed compound as unlisted.
 *  2. DENY WINS OUTRIGHT, ACROSS EVERY TERM AND EVERY OPERATOR. A dual licence
 *     that offers a copyleft option still puts that option in the tree, and no
 *     scanner can prove which one an operator chose. A copyleft term anywhere in
 *     the expression is a violation.
 *  3. ANYTHING NOT RECOGNISED IS A VIOLATION, NEVER A PASS. `UNLICENSED`,
 *     `SEE LICENSE IN LICENSE` and an empty expression all fail closed.
 *
 * Two normalisations happen first. A trailing `*` is license-checker's marker
 * for "read from a LICENSE file rather than declared" — the licence is real, so
 * it is stripped for matching and reported separately by the caller. And
 * `<licence> WITH <exception>` is adjudicated on the LICENCE: an exception only
 * ever loosens the terms of the licence it qualifies, so `Apache-2.0 WITH
 * LLVM-exception` is an Apache-2.0 decision.
 *
 * Parentheses are flattened rather than parsed. That is exact for the shapes npm
 * packages actually publish (`(MIT OR Apache-2.0)`, `(MIT AND CC0-1.0)`) and
 * conservative for a nested expression, which would be evaluated with `AND`
 * grouping only — failing closed, never open.
 */

/** license-checker's `MIT*` means "inferred from a LICENSE file"; the licence is still MIT. */
export const stripInferred = (term) => String(term).replace(/\*$/, '').trim();

/** `Apache-2.0 WITH LLVM-exception` is an Apache-2.0 decision. */
export const stripException = (term) => term.split(/\s+WITH\s+/)[0].trim();

/**
 * Splits an SPDX expression into an OR of AND-groups.
 *
 * @param {string} expression
 * @returns {string[][]} one array of terms per OR-branch; every term in a branch must be allowed
 */
export function spdxTerms(expression) {
  const cleaned = String(expression ?? '')
    .replace(/[()]/g, ' ')
    .trim();
  if (!cleaned) return [['']];
  return cleaned
    .split(/\s+OR\s+/)
    .map((branch) =>
      branch
        .split(/\s+AND\s+/)
        .map((term) => stripException(stripInferred(term)))
        .filter(Boolean),
    )
    .map((branch) => (branch.length > 0 ? branch : ['']));
}

/**
 * @param {string} expression  an SPDX expression as license-checker reports it
 * @param {{allow: Set<string>|string[], deny: Set<string>|string[], denyPatterns: string[]}} policy
 * @returns {{verdict: 'allowed'|'denied'|'unlisted', term: string}}
 */
export function adjudicate(expression, policy) {
  const allow = policy.allow instanceof Set ? policy.allow : new Set(policy.allow);
  const deny = policy.deny instanceof Set ? policy.deny : new Set(policy.deny);
  const patterns = policy.denyPatterns ?? [];
  const branches = spdxTerms(expression);

  // (2) deny sweeps every term of every branch, before allow is consulted.
  for (const branch of branches) {
    for (const term of branch) {
      const denied =
        deny.has(term) ||
        patterns.some((pattern) => term.toUpperCase().includes(String(pattern).toUpperCase()));
      if (denied) return { verdict: 'denied', term };
    }
  }

  // (1) a branch passes only when EVERY one of its terms is allowed.
  for (const branch of branches) {
    if (branch.every((term) => allow.has(term))) {
      return { verdict: 'allowed', term: branch.join(' AND ') };
    }
  }

  // (3) nothing recognised: name the first unrecognised term, and fail.
  const firstBranch = branches[0] ?? [''];
  const offending = firstBranch.find((term) => !allow.has(term)) ?? firstBranch[0] ?? '';
  return { verdict: 'unlisted', term: offending };
}
