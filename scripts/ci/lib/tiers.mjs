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
