/**
 * The property-based testing harness: one place that decides how a property run
 * is seeded, how many cases it draws, and what it prints when it fails.
 *
 * A property test differs from an example test in one respect that matters to
 * this repository's determinism contract: it CHOOSES its own inputs. Left to
 * itself, fast-check seeds that choice from the clock, so a red run names a
 * counterexample the next run will not reproduce — which turns a real defect
 * into an anecdote, exactly what `tests/harness/determinism.ts` exists to
 * prevent for the rest of the suite.
 *
 * So every property in this repository runs at the ONE data seed
 * ({@link SEED}), and every `fc.assert` call site passes {@link propertyRun}
 * rather than relying on fast-check's defaults. Three consequences, all of them
 * intended:
 *
 *   1. The same N cases are drawn on every machine and every run, so a green run
 *      here means the same thing tomorrow as it did today.
 *   2. A failure is reproducible by anyone: fast-check's own report carries the
 *      `seed` and the shrunk `path`, the setup file's banner names the data seed
 *      and the runner's order seed beside it, and {@link propertyRun} pins them
 *      into the assertion message too.
 *   3. Drawing a DIFFERENT sample is a deliberate act — `SEED=12345 npm run
 *      test:property` — rather than something that happens to you. A
 *      counterexample found that way is committed as its own named regression
 *      test, so the suite only ever gains cases.
 *
 * `numRuns` is a budget, not an aspiration. These suites run twice in the
 * `test:property` gate (once per timezone) AND a third time inside the ordinary
 * unit/integration gates, so a property that draws 1,000 cases costs three
 * times what its author measured. The three named budgets below say what each
 * class of property can afford; a property that needs more says so at its call
 * site, with the measurement that justifies it.
 */
import fc from 'fast-check';
import { SEED, seedBanner, resolvedOrderSeed } from './determinism.js';

/**
 * Cases drawn by a property over PURE, in-process logic (a formatter, a schema,
 * a string transformation). Measured: 100 cases of the heaviest such property
 * here costs well under a second.
 */
export const PROPERTY_RUNS = 100;

/**
 * Cases drawn by a property that performs real AES-256-GCM work through
 * SubtleCrypto. Lower than {@link PROPERTY_RUNS} because each case is a real
 * encrypt + decrypt (plus base64 in both directions) rather than a function
 * call.
 */
export const CRYPTO_RUNS = 25;

/**
 * Cases drawn by a property whose inputs are measured in hundreds of kilobytes,
 * or that drives a real database through a sequence of HTTP requests. Small on
 * purpose: the value of these is that the size class is exercised AT ALL, and
 * fast-check's shrinker does the rest once one of them fails.
 */
export const HEAVY_RUNS = 5;

/**
 * The parameters every `fc.assert` in this repository runs with.
 *
 * Pass it explicitly at each call site rather than installing it with
 * `fc.configureGlobal`: a global would be invisible at the assertion, would
 * depend on a setup file having been loaded, and would silently stop applying to
 * a file that is run on its own — which is precisely when someone is bisecting a
 * failure and most needs the seed to be the one the report named.
 */
export function propertyRun(overrides: fc.Parameters<unknown> = {}): fc.Parameters<unknown> {
  return {
    seed: SEED,
    numRuns: PROPERTY_RUNS,
    // The shrunk counterexample plus the path that reaches it. `verbose: true`
    // is fast-check's `Verbose` level: it reports on FAILURE only, so a green
    // run stays silent.
    verbose: true,
    // Keep shrinking after the first failing case. `endOnFailure: true` reports
    // the first counterexample found rather than the smallest, and the smallest
    // is the one that becomes a readable regression test.
    endOnFailure: false,
    ...overrides,
  };
}

/**
 * The one-line provenance stamp for a property assertion message.
 *
 * fast-check already prints `seed` and `path` in its own failure report; this
 * adds the harness's view — the data seed, the runner's order seed, the pinned
 * zone and locale — to the assertion itself, so a JUnit report that carries only
 * the failure message still says how to reproduce the run.
 */
export function propertyBanner(): string {
  return seedBanner(resolvedOrderSeed());
}

/**
 * A string arbitrary drawn from an explicit alphabet.
 *
 * Used where a generated value must be guaranteed NOT to contain a sentinel the
 * property then searches for. `fc.string()` over unicode could produce the
 * sentinel by chance, and a property that fails once in a thousand seeds is a
 * property nobody trusts; restricting the alphabet makes the exclusion a fact
 * about the generator rather than a probability.
 */
export function stringFromAlphabet(
  alphabet: string,
  constraints: { minLength?: number; maxLength?: number } = {},
): fc.Arbitrary<string> {
  return fc.string({
    unit: fc.constantFrom(...alphabet.split('')),
    minLength: constraints.minLength ?? 0,
    maxLength: constraints.maxLength ?? 12,
  });
}
