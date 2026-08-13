/**
 * The determinism pins for this package's suite.
 *
 * Time, locale, ordering and randomness are properties of the HARNESS, not of
 * each test: a suite whose verdict depends on the machine's timezone, the
 * developer's `LANG`, or the order the runner happened to pick is not a gate,
 * it is a coin toss with good manners.
 *
 * Everything here is applied INSIDE the harness rather than by prefixing the
 * gate command (`TZ=UTC npm test`). Two reasons, and the second is the binding
 * one:
 *
 *   1. A prefix only pins the run that used it. An IDE-launched test, a
 *      `--reporter` one-off, `vitest --ui`, or a bare `npx vitest` all skip it.
 *   2. This project is developed on Windows as well as Linux, and
 *      `TZ=x <command>` is not a thing cmd.exe or PowerShell understands. A
 *      prefix-based pin is therefore a pin that only half the contributors get,
 *      which is indistinguishable from no pin at all the moment a date-formatting
 *      assertion lands.
 *
 * `vitest.config.ts` carries the same values in `test.env` so they are present
 * before the first module of a test file is evaluated; this module re-asserts
 * them (assignment, not `vi.stubEnv`, so nothing resets them per test) for the
 * case where the suite is driven through a config that forgot them, and it owns
 * the one seed that every generator in the suite must draw from.
 *
 * It imports NOTHING — not even `vitest` — on purpose: `vitest.config.ts` reads
 * `SEED` from here to set `sequence.seed`, and a config file that imported the
 * runner's own test API would be reaching for worker state that does not exist
 * yet at config-load time.
 */

/**
 * The seed used when `SEED` is unset. Stated here rather than inline so the
 * manifest (`.testfortress/verify.json`'s `env.SEED`) and the harness cannot
 * disagree silently.
 */
export const DEFAULT_SEED = 1337;

/** The timezone every tier runs in. */
export const PINNED_TZ = 'UTC';

/**
 * The one DST-observing zone this repository is allowed to run a suite in.
 *
 * `combineExpiry` (VaultItemForm) has a documented repeated-hour hazard: during
 * a fall-back transition two distinct instants render to the SAME date and time
 * pair, and the "did either control move?" test is a STRING comparison
 * specifically because an instant comparison can satisfy at most one of them.
 * That branch is UNREACHABLE under {@link PINNED_TZ} — UTC has no transitions —
 * so a suite that only ever runs in UTC cannot tell the fixed implementation
 * from the broken one. The property gate therefore runs its suites a second time
 * in this zone.
 *
 * America/New_York rather than any other: its transitions are the ones every
 * reference and every bug report about this class uses, and its offset is
 * non-zero in BOTH halves of the year, so a zone pin that silently reverted to
 * UTC fails visibly instead of passing.
 */
export const DST_TZ = 'America/New_York';

/**
 * Parses the `HVAULT_TZ` environment variable: which of the two allowed zones
 * this run uses.
 *
 * An ALLOWLIST, not a passthrough, and that is the whole point. The pin exists
 * so a suite's verdict cannot depend on the machine it ran on; an env var that
 * accepted any zone would hand that dependency straight back, and the failure
 * would look like a broken test rather than an unpinned harness. Unset or empty
 * means {@link PINNED_TZ}, so every existing invocation is unchanged; anything
 * other than the two allowed values THROWS rather than falling back, for the
 * same reason {@link resolveSeed} does — a silent fallback makes the zone this
 * run reports a lie about the zone it used.
 */
export function resolveRunTz(raw: string | undefined): string {
  if (raw === undefined || raw.trim() === '') return PINNED_TZ;

  const zone = raw.trim();
  if (zone !== PINNED_TZ && zone !== DST_TZ) {
    throw new Error(
      `HVAULT_TZ must be ${PINNED_TZ} or ${DST_TZ}; received ${JSON.stringify(raw)}. ` +
        `Unset it to use the default (${PINNED_TZ}).`,
    );
  }
  return zone;
}

/**
 * The timezone THIS run uses: {@link PINNED_TZ} unless the property gate's
 * DST leg asked for {@link DST_TZ}.
 *
 * Read once at module load, like {@link SEED}, so the config file and the setup
 * file cannot disagree about it: `vitest.config.ts` puts this in `test.env` (it
 * applies before the first module of a test file is evaluated) and
 * {@link applyDeterminismPins} re-applies the same value inside the worker.
 */
export const RUN_TZ = resolveRunTz(process.env['HVAULT_TZ']);

/**
 * What each allowed zone actually MEANS, in numbers computed by hand rather than
 * by the same platform call the assertions use.
 *
 * The determinism suites used to hardcode UTC's answers (`getTimezoneOffset()`
 * is 0, a zone-less noon is `Date.UTC(…, 12)`). That was correct and it was also
 * why those suites could never run anywhere else: `test:dst` runs the WHOLE
 * suite in {@link DST_TZ}, and an assertion that says "the offset is zero" is
 * then a statement about the harness's own pin rather than about the zone the
 * run asked for.
 *
 * Parameterising it is a strengthening, not a relaxation, for two reasons:
 *
 *   1. Each row is still an exact, hand-checked expectation — `2026-01-15T12:00`
 *      with no zone is 17:00Z in New York (EST, UTC-5) and 16:00Z on
 *      `2026-07-15` (EDT, UTC-4) — so a machine zone that leaked past the pin
 *      fails in either leg, exactly as before.
 *   2. The {@link DST_TZ} row's two values DIFFER BY AN HOUR, which pins the one
 *      property that makes a DST leg worth running at all. A zone pin that
 *      silently reverted to UTC would satisfy the old "offset is 0" assertion in
 *      the DST leg; it cannot satisfy this one.
 *
 * `getTimezoneOffset()` reports minutes BEHIND UTC as POSITIVE, so UTC-5 is 300.
 */
const ZONE_FACTS: Record<
  string,
  {
    winterOffsetMinutes: number;
    summerOffsetMinutes: number;
    winterNoon: number;
    summerNoon: number;
  }
> = {
  [PINNED_TZ]: {
    winterOffsetMinutes: 0,
    summerOffsetMinutes: 0,
    winterNoon: Date.UTC(2026, 0, 15, 12),
    summerNoon: Date.UTC(2026, 6, 15, 12),
  },
  [DST_TZ]: {
    winterOffsetMinutes: 300,
    summerOffsetMinutes: 240,
    winterNoon: Date.UTC(2026, 0, 15, 17),
    summerNoon: Date.UTC(2026, 6, 15, 16),
  },
};

/**
 * The hand-checked facts for one allowed zone.
 *
 * Throws on anything else rather than returning a default, for the same reason
 * {@link resolveRunTz} does: a zone with no recorded facts is a zone nobody has
 * checked, and answering with UTC's numbers would make every assertion below it
 * pass while describing a different clock.
 */
export function zoneFacts(zone: string): {
  winterOffsetMinutes: number;
  summerOffsetMinutes: number;
  winterNoon: number;
  summerNoon: number;
} {
  const facts = ZONE_FACTS[zone];
  if (!facts) {
    throw new Error(
      `No recorded clock facts for ${JSON.stringify(zone)}. ` +
        `Only ${PINNED_TZ} and ${DST_TZ} are allowed zones; add a row to ZONE_FACTS with hand-checked values.`,
    );
  }
  return facts;
}

/**
 * The locale every tier runs in. `LC_ALL` is pinned alongside `LANG` because
 * glibc and ICU resolve `LC_ALL` FIRST: a developer with `LC_ALL=de_DE.UTF-8`
 * exported (common on a localized desktop) would make a `LANG`-only pin inert,
 * and the failure surfaces as a locale-formatted number or a collation order
 * nobody can reproduce.
 */
export const PINNED_LOCALE = 'C.UTF-8';

/**
 * Parses the `SEED` environment variable.
 *
 * A malformed value THROWS instead of falling back to {@link DEFAULT_SEED}: the
 * whole point of the seed is that "reproduce with this seed" is a true
 * statement, and a silent fallback makes the printed seed a lie about the run
 * that just happened. An unset or empty value is not malformed — it means
 * "use the default".
 */
export function resolveSeed(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === '') return DEFAULT_SEED;

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(
      `SEED must be a non-negative integer; received ${JSON.stringify(raw)}. ` +
        `Unset it to use the default (${String(DEFAULT_SEED)}).`,
    );
  }
  return parsed;
}

/** The one seed for this run. Every generator in the suite draws from it. */
export const SEED = resolveSeed(process.env['SEED']);

/**
 * A deterministic uniform generator (mulberry32), for any test that needs
 * pseudo-random input.
 *
 * Deliberately NOT `Math.random`: an unseeded generator makes a failure a
 * one-off anecdote rather than a reproducible defect. Callers that need
 * independent streams pass their own `seed` derived from {@link SEED} (e.g.
 * `seededRandom(SEED + 1)`), so one stream's consumption cannot shift another's
 * values — which is the failure mode of sharing a single generator instance
 * across suites that run in a shuffled order.
 */
export function seededRandom(seed: number = SEED): () => number {
  let state = (seed + 0x6d2b79f5) | 0;

  return function next(): number {
    state = (state + 0x6d2b79f5) | 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Pins timezone and locale on `process.env`.
 *
 * `process.env.TZ` is honoured by Node at runtime (assigning it invalidates the
 * cached zone), so this works even though the process started elsewhere. It is
 * called from `tests/setup.ts` before any application module is evaluated, and
 * also exported so the pin can be asserted by its own test rather than assumed.
 */
export function applyDeterminismPins(): void {
  // {@link RUN_TZ}, not {@link PINNED_TZ}: they are the same value everywhere
  // except the property gate's DST leg, and hard-coding the constant here would
  // silently CLOBBER that leg back to UTC — leaving a gate that claims to run in
  // a DST-observing zone and does not, which is worse than not having it.
  process.env.TZ = RUN_TZ;
  process.env['LANG'] = PINNED_LOCALE;
  process.env['LC_ALL'] = PINNED_LOCALE;
  // Children (mongod, any spawned helper) inherit the seed, so a subprocess
  // cannot draw from a different one than the parent printed.
  process.env['SEED'] = String(SEED);
}

/**
 * The shuffle seed the RUNNER actually used for this run, or `undefined` when it
 * cannot be read.
 *
 * There are TWO seeds and conflating them makes the banner lie. {@link SEED} is
 * the DATA seed, read from the environment at module load and fed to
 * {@link seededRandom}. `sequence.seed` is the ORDER seed, which
 * `vitest.config.ts` initializes from `SEED` — so the two agree until someone
 * passes `--sequence.seed=<n>` on the command line, which is exactly what you do
 * when bisecting an order dependence. A banner that printed the module constant
 * in that situation named an order that does not reproduce the failure it was
 * printed beside, which is worse than printing nothing.
 *
 * `__vitest_worker__` is the runner's internal worker state, so this reads it
 * defensively and reports `undefined` rather than guessing: the fallback path in
 * {@link seedBanner} says the seed is unknown and points at the runner's own
 * "Running tests with seed" line instead of inventing a number.
 */
export function resolvedOrderSeed(...args: [worker?: unknown]): number | undefined {
  // Read POSITIONALLY rather than through a default value, because the two calls
  // mean different things and a default cannot tell them apart:
  // `resolvedOrderSeed(undefined)` asks "what does THIS (empty) worker state say",
  // and must answer "nothing"; `resolvedOrderSeed()` asks "what does the ambient
  // runner say". With a default parameter the first silently becomes the second,
  // and the "degrade to unknown" behaviour could never be tested.
  const worker =
    args.length > 0 ? args[0] : (globalThis as { __vitest_worker__?: unknown }).__vitest_worker__;

  const seed = (worker as { config?: { sequence?: { seed?: unknown } } } | undefined)?.config
    ?.sequence?.seed;
  return typeof seed === 'number' && Number.isFinite(seed) ? seed : undefined;
}

/**
 * The one-line banner that names the run, printed beside a failure.
 *
 * `orderSeed` is an explicit parameter with no default, so a test can drive both
 * branches with a value it chose. Asserting the banner against {@link SEED}
 * alone is a tautology — it compares the function with the one constant the
 * function already uses, and stays green precisely when the two seeds diverge,
 * which is the case the banner exists for.
 */
export function seedBanner(orderSeed?: number): string {
  // Takes the seed rather than reading it, so the banner is a pure function of its
  // input: an assertion that drove it with the module's own constant could not
  // tell a correct banner from one that had gone back to printing the data seed.
  // `printSeedBannerOnce` supplies `resolvedOrderSeed()`.
  const order =
    orderSeed === undefined
      ? `unknown (see the runner's "Running tests with seed" line above)`
      : String(orderSeed);
  const reproduce =
    orderSeed === undefined
      ? 'npx vitest run --sequence.shuffle --sequence.seed=<that seed>'
      : `npx vitest run --sequence.shuffle --sequence.seed=${String(orderSeed)}`;

  return (
    `[determinism] data SEED=${String(SEED)} · order seed=${order} · ` +
    `TZ=${RUN_TZ} LANG=${PINNED_LOCALE} — reproduce this order with: ${reproduce}`
  );
}

/**
 * One-shot latch for the banner, so a broadly-failing file names the seed once
 * beside its first failure rather than a hundred times. Each test file has its
 * own module registry under `pool: 'forks'`, so the latch is per file.
 *
 * The `beforeEach`/`onTestFailed` registration itself lives in each package's
 * `tests/setup.ts`, which is the only place allowed to touch the runner's API.
 */
let bannerPrinted = false;

export function printSeedBannerOnce(write: (message: string) => void = console.error): void {
  if (bannerPrinted) return;
  bannerPrinted = true;
  write(seedBanner(resolvedOrderSeed()));
}
