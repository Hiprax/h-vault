/**
 * Stryker configuration — the `test:mutation` gate's subject.
 *
 * ONE config file, parameterised by `HVAULT_MUTATION_LEG`, because Stryker's
 * Vitest runner takes exactly one vitest config and this repository has three
 * suites with three different environments. `scripts/ci/mutation-gate.mjs` runs
 * one leg per package and merges the three reports; running a leg by hand is
 *
 *     HVAULT_MUTATION_LEG=shared npx stryker run
 *
 * A second mode serves `scripts/ci/mutation-diff-gate.mjs`, the per-change leg:
 * `HVAULT_MUTATION_DIFF_PLAN` names a plan the gate wrote, and the run mutates
 * exactly the plan's ranges, from scratch, into its own report and sandbox. The
 * builder for both modes is `scripts/ci/lib/stryker-config.mjs`, so the gates can
 * read the configuration without evaluating this file.
 *
 * The scope itself lives in `scripts/ci/lib/mutation-scope.mjs` and is imported
 * rather than restated here, so the gate, the ratchet and this file can never
 * disagree about what is being mutated. That is also why this is `.mjs` and not
 * the `.json` a default `stryker init` writes: a JSON config would be a second
 * copy of the denominator.
 *
 * Not configured, deliberately:
 *   - `thresholds.break`. The floor is `.testfortress/baseline.json`'s
 *     `mutation.overall`, enforced per leg AND overall by the gate, so there is
 *     exactly one place the number lives and it is the one the ratchet reads.
 *     A `break` here would be a second, hand-maintained copy of it.
 *   - a dashboard reporter. Every gate in this repository runs locally and
 *     reports locally; nothing uploads.
 */
import { buildStrykerConfig } from './scripts/ci/lib/stryker-config.mjs';

export default buildStrykerConfig(process.env);
