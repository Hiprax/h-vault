/**
 * Tier selection and the exit-code contract.
 *
 * Both are pure, and they are pure on purpose: they are the two decisions that
 * decide what a pipeline run MEANS, and a decision that can only be exercised by
 * running the whole pipeline is a decision nothing tests.
 */

/**
 * Tiers are CUMULATIVE. `verify` (T1) is a superset of `verify:fast` (T0), not a
 * disjoint set of checks — otherwise a gate could be quietly demoted out of the
 * push gate by moving it down a tier.
 */
export const TIER_SELECTOR = { 0: [0], 1: [0, 1], 2: [0, 1, 2], full: [0, 1, 2] };

/**
 * How long a tier is allowed to take, in seconds, on the reference machine.
 *
 * These are DESIGN budgets, not gates, and the distinction is deliberate in both
 * directions. They are not gates because the wall clock of the machine a
 * contributor happens to be on is not a property of this repository: failing a
 * push because a laptop was compiling something else would teach people to bypass
 * the push hook outright, which costs far more than a slow run. But they are also not
 * decoration: every run records `budgetSeconds` beside its own `durationMs` in
 * `summary.json` and prints the comparison, so "T0 is still cheap enough to run
 * constantly" is a measurement anyone can check rather than a claim from the day
 * it was written.
 *
 * T0 is 90 s because it is meant to be run without thinking about it; the
 * measured value is ~82 s, and the eight seconds of headroom are the reason a
 * gate is not added to T0 without re-measuring. T1 is 12 minutes rather than a
 * rounder 10 because the server suite alone is ~150 s and Playwright is ~6
 * minutes: a budget nobody meets is a budget nobody respects. T2 is unbounded on
 * purpose — `mutation` re-runs the suite once per mutant, and any number written
 * here would be fiction.
 */
export const TIER_BUDGET_SECONDS = { 0: 90, 1: 720, 2: null };

/**
 * The budget for a selected tier set: the budget of the HIGHEST tier selected,
 * because tiers are cumulative and a run of T0+T1 is a T1 run.
 *
 * @param {readonly number[]} tiers
 * @returns {number | null} seconds, or null when the tier is unbounded.
 */
export function tierBudgetSeconds(tiers) {
  if (!Array.isArray(tiers) || tiers.length === 0) return null;
  const highest = Math.max(...tiers);
  return TIER_BUDGET_SECONDS[highest] ?? null;
}

/**
 * @param {string} name
 * @returns {number[] | null} the tiers to run, or null when the name is unknown.
 */
export function resolveTiers(name) {
  return TIER_SELECTOR[name] ?? null;
}

/**
 * An explicit `--only` is a deliberate request for those exact gates, so it
 * OVERRIDES the tier filter rather than intersecting with it: `--only=e2e` must
 * never resolve to nothing merely because e2e is not in the default tier.
 *
 * @template {{ id: string, tier: number }} Gate
 * @param {readonly Gate[]} gates
 * @param {{ only?: readonly string[], tiers?: readonly number[] }} [options]
 * @returns {Gate[]}
 */
export function selectGates(gates, { only = [], tiers = [0, 1] } = {}) {
  return gates.filter((gate) =>
    only.length > 0 ? only.includes(gate.id) : tiers.includes(gate.tier),
  );
}

/**
 * The statuses that make a gate's dependents pointless to run.
 *
 * A dependency the operator SKIPPED on purpose is deliberately not one of them:
 * `HVAULT_SKIP_GATES=build` means "I already built", and taking the type check,
 * both test gates and E2E down with it would turn one skip into five.
 */
const BLOCKING_STATUSES = ['fail', 'error'];

/**
 * @param {readonly string[]} dependsOn
 * @param {(id: string) => string | undefined} statusOf
 * @returns {string | undefined} the first dependency that broke, if any
 */
export function blockingDependency(dependsOn, statusOf) {
  return dependsOn.find((id) => BLOCKING_STATUSES.includes(statusOf(id) ?? ''));
}

/**
 * The exit-code contract.
 *
 *   0  every selected gate passed or legitimately skipped
 *   1  at least one gate FAILED — the code is broken, and that is definite
 *   2  nothing failed, but at least one gate COULD NOT RUN — the verdict is
 *      unknown, which is a different problem an agent must be able to tell apart
 *
 * A failure outranks a "could not run" because it is actionable and certain: the
 * run found a real defect, and reporting that as "misconfigured" would bury it.
 *
 * @param {readonly { status: string }[]} results
 * @returns {0 | 1 | 2}
 */
export function resolveExitCode(results) {
  if (results.some((result) => result.status === 'fail')) return 1;
  if (results.some((result) => result.status === 'error')) return 2;
  return 0;
}
