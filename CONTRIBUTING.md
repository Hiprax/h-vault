# Contributing to H-Vault

Thanks for considering a contribution. H-Vault is a password manager, so the bar for
correctness is higher than usual — this document is short, but the parts about the
pipeline and about tests are not optional.

**Found a security vulnerability? Do not open an issue or a PR.** Follow
[SECURITY.md](SECURITY.md) and report it privately.

## Getting set up

You need **Node 24+** (pinned in `.nvmrc`) and **Docker** (for MongoDB, and for the
`docker` pipeline gate).

```bash
git clone https://github.com/Hiprax/h-vault.git
cd h-vault
npm install                                   # installs all workspaces
cp .env.example .env                          # then set the three required secrets
docker compose -f docker-compose.dev.yml up -d   # MongoDB
npm run build:shared                          # shared must be built before server/client
npm run dev                                   # http://localhost:5173
```

`packages/shared` is a build-time dependency of both other packages. If the server or
client fails to resolve `@hvault/shared`, you skipped `npm run build:shared`.

The client dev server binds **5173** (Vite's default) and the API binds 5000. If 5173 is
taken on your machine, override it through the process environment — Playwright's E2E
config reads the same variable, so both move together:

```bash
VITE_PORT=5180 npm run dev
```

Set it in your shell, not in `.env`: Vite does not load the root `.env`. On Windows, if a
dev port fails with `EACCES` rather than `EADDRINUSE`, the OS has reserved it (Hyper-V /
WSL2 / Docker claim dynamic ranges); list them with
`netsh int ipv4 show excludedportrange protocol=tcp` and pick a port outside them.

## The pipeline runs on your machine, not on a runner

There is **no CI workflow that tests your code**. The `pre-push` hook runs the entire
pipeline locally — twenty-eight gates including the full test suite, the export-format
goldens, patch coverage on the lines you changed, a smoke run of the built artifact, the
browser bundle's size budgets, container builds with Trivy scanning, and CodeQL — and
refuses the push if any of them fail. A
commit that reaches `main` has already passed everything. Eight further gates sit in the
release tier: `fuzz`, whose suites still run inside the ordinary test gates on every push
so that only the separately-reported, deadline-bounded run is held back; `resource`, the
volume and memory budgets, which builds ten-thousand-item vaults and therefore both takes
a minute and needs a machine that is not running three other workers for its numbers to
mean anything; `upgrade`, which reads a vault and a `.env` written by the previous release
and, like `fuzz`, keeps its assertions on the push tier while the named, deadline-bounded
run waits for a release; `recovery`, which restores a backup onto a second database and
kills a real server process mid-write, and which needs its deadline more than any other
gate because it spawns processes in order to kill them; `dst`, which re-runs the whole
suite in `America/New_York` because everything this application renders about time is
computed in local time and every other gate runs where local time and UTC are the same
thing; `deploy`, the deployment clean room, which stands the whole Compose stack up from
nothing and is far too heavy for a hook — its fast sibling `smoke` covers the built
artifact on every push; `flake`, ten complete runs of every suite in ten different
shuffled orders plus the Playwright suite three times over, which is about an hour; and
`mutation`, the oracle, which re-runs the suite once per mutant and is measured in hours.
All eight run in `npm run verify:full`.

The gates are grouped into tiers by how long they take, so there is something worth
running at every point in the loop:

```bash
npm run verify:fast               # the fast tier (T0): engines, secrets, lint, format, types
npm run ci                        # everything the pre-push hook runs (T0 + T1)
npm run verify:full               # the above plus the release tier (T0 + T1 + T2)
npm run ci:local                  # all of it again, from a fresh worktree at HEAD (clean room)
npm run ci -- --list              # the gates, their tiers, and what each one replaces
npm run ci -- --only=lint,test    # a subset, while iterating
npm run ci -- --bail              # stop at the first failure instead of running them all
npm run ci -- --json              # one JSON document describing the run
```

Tiers are **cumulative** — `verify` is a superset of `verify:fast`, and `verify:full` of both — so
a gate cannot be demoted out of the push gate by moving it down a tier. Each has a stated budget on
the reference machine: **T0 90 s**, **T1 12 minutes**, **T2 unbounded**. Those are design budgets
rather than gates, because the wall clock of your laptop is not a property of this repository and
failing a push over it would only teach people to reach for `--no-verify`. They are still measured:
every run records `budgetSeconds` beside its own `durationMs` in `summary.json` and prints the
comparison. The numbers live in `scripts/ci/lib/tiers.mjs`. If you add a gate to T0, re-measure —
the measured value is ~82 s against a 90 s budget, and there is not much room in it.

The runner **aggregates by default**: it runs every selected gate and reports all the
failures, rather than costing you a round trip per failure. A gate whose dependency
failed is reported as not reached rather than run again to fail the same way.

Exit codes carry meaning. `0` is a pass, `1` means a gate failed, and `2` means a gate
**could not run** — a missing prerequisite, a misconfiguration, or a gate that passed
without writing the report it promises. Treat a `2` as "we do not know yet", never as a
soft pass.

Every gate leaves a machine-readable report in `.testfortress/reports/` (JUnit XML for
the suites, SARIF for lint, JSON for the secret scan, and each gate's transcript beside
them). `.testfortress/verify.json` is the registry: for each gate, its canonical name,
the command that runs it, its tier, its criterion and its report. The pipeline checks
itself against that file on every run and refuses to start if the two disagree, so a
gate can never quietly stop being the thing the registry says it is.

`verify:fast` deliberately does not build; it consumes `packages/shared/dist` rather
than producing it. Run `npm run build:shared` once after a clean checkout — the runner
will tell you so if you forget.

Run `npm run ci` before you open a pull request.

### Eight gates whose failure asks for something specific

Most gates tell you what to fix. These eight are worth reading before you meet them,
because the obvious way past each of them is the wrong one.

- **`coverage`** holds each package to the line, branch and function coverage already
  recorded for it, and requires **100% coverage of the production lines your change
  touches**. The package percentages are an average over thousands of lines, so a new
  module with no tests at all barely moves them; this is the gate that notices. Three
  things are worth knowing before you meet it. First, **branch coverage is the thin
  metric** — server sits at 91.39% and client at 92.45%, so a handful of uncovered
  `if`/`??`/`?.`/default-parameter arms in one new module will fail the run. Budget branch
  tests, not just line tests. Second, a changed production file that appears in **no**
  coverage report fails the gate by name, because a file nothing measured is otherwise
  indistinguishable from a file that does not exist, and it would read as 100% patch
  coverage over zero lines. Third, the **only** way to ship an uncovered line is a dated,
  owned, expiring `COV-DIFF-EXEMPT` entry in `.testfortress/suppressions.json` naming that
  file and bounding how many lines it excuses — there is no pragma, no ignore file and no
  `--fail-under` to lower, and the entry stops excusing anything the day it expires. It
  needs `diff-cover` on your `PATH` (`uv tool install diff-cover`, or
  `pipx install diff-cover`); without it the gate reports **could not run** rather than
  passing quietly.

- **`deadcode`** runs `knip` (unused files, exports, exported types and dependencies, plus
  dependencies used without being declared) and `jscpd` (duplication). The answer to a
  finding is to **delete the code** — or to drop the `export` keyword when a symbol is only
  used inside its own module, or to declare a dependency that is genuinely used. Neither
  `knip.jsonc` nor `.jscpd.json` has an ignore list, and adding one is not an option: an
  ignore entry is how a dead-code gate goes green without a line being removed.
- **The duplication ceiling in `.jscpd.json` is the measured value and only ever falls.**
  `.testfortress/baseline.json` records the same number with a lower-is-better direction,
  so raising the ceiling to make room for a new clone fails the `ratchet-full` gate.
- **`config`** lints the release workflow (`actionlint`), both Dockerfiles (`hadolint`) and
  the OpenAPI document that `packages/server/src/config/swagger.ts` builds (`spectral`). It
  fails on error-level findings; everything below that is counted into
  `warnings.audit:config` in the baseline, where it can be paid down and cannot grow. It
  needs `actionlint` and `hadolint` on your `PATH`; without them the gate reports **could
  not run** rather than passing quietly.
- **`openapi`** asks a different question from `config`: not whether the OpenAPI document is
  well-formed, but whether shipping it would break somebody's client. `oasdiff` compares the
  document the server generates against `packages/server/openapi.snapshot.json` — the
  committed contract of the release that snapshot names — and a breaking change fails unless
  the root `package.json` MAJOR has been raised in the same commit. Removing a field from a
  response breaks no type and fails no test, which is exactly why it needs its own gate.
  **The snapshot moves only in the same commit as the version it describes**; refreshing it
  on its own erases the evidence of whatever it was about to be compared against. It needs
  `oasdiff` on your `PATH`; without it the gate reports **could not run**.
- **`security`** runs the cross-user authorization matrix. It reads the real Express router
  stack and compares it against `packages/server/tests/support/routeTable.ts`, which
  classifies every route: its method and path, whether the path carries an id the caller
  must own, whether authentication and CSRF apply, and which rate limiters are mounted.
  **Adding an endpoint fails this gate until the route is classified there** — that is the
  point of it, because the cross-user coverage it replaced was written per endpoint by hand
  and a new route silently got none. Classifying a route as taking an owned id then fails
  the matrix until the route is given a scenario. Neither deleting a row nor dropping a file
  from `SECURITY_SUITE` is an answer to a red run here; both are how this gate stops
  checking the thing it exists to check.
- **`property`** runs the property-based suites, which GENERATE their inputs, once in
  `UTC` and once in `America/New_York`. A failure names a counterexample and the seed that
  reproduces it. **The fix is never to narrow the generator.** Shrink the counterexample,
  decide whether the code or the property is wrong, and commit that exact case as a named
  regression test beside the property — the suite then only ever gains cases. A generator
  constraint is legitimate only when the excluded inputs are ones the property genuinely
  does not claim anything about, and it carries a comment saying which and why. The two
  timezones are not interchangeable: `combineExpiry`'s repeated-hour branch cannot be
  reached in a zone with no daylight-saving transition, so the second leg is the only
  thing standing between that fix and a silent regression.
- **`flake`** runs every suite ten times, each in a different shuffled order derived from
  the one pinned seed, and the Playwright suite three times over with retries pinned off.
  Its verdict is a **rate**, and the report says what that rate licenses you to claim: ten
  clean runs bound the per-run flake probability near one in ten, they do not establish
  zero. **A red run here is a bug report about the code or the harness, never noise.** The
  three things that look like fixes and are not: a `retries` count (which reports that a
  test passed eventually — the pipeline used to carry `--retries=2` and it concealed two
  genuine failures, recorded in `e2e/helpers.ts`), a raised timeout (which converts a race
  into a slower race), and pinning the suite to one worker (which hides shared state
  instead of finding it). The two real answers are to fix it at its cause, or — if you
  genuinely cannot yet — to quarantine that one test in its own task with a dated,
  expiring `kind: quarantine` entry in `.testfortress/suppressions.json`. **Quarantine is
  a thirty-day loan, not a graveyard**: the test still runs, in its own tier, with its own
  report, and a flaky test is never deleted. Both numbers are ratcheted and they move in
  opposite directions — `flake.runs` upward, so the sample can never quietly shrink, and
  `flake.failures` downward, so an observed flake can never quietly be normalised.
- **`dst`** re-runs every suite in `America/New_York`. A test that passes in UTC and fails
  here has an undeclared dependency on the machine's timezone, and the answer is to make
  the assertion state which zone it means — the harness exports `zoneFacts(RUN_TZ)` for
  exactly that. **Pinning the gate back to UTC is not an answer**; it is the gate deleting
  itself. Note what it adds over `property`, which also runs two zones: that gate's config
  includes `tests/property/**` and nothing else, so until this one existed roughly 7,400 of
  this repository's tests had only ever been executed where local time and UTC agree.
- **`secrets-full`** scans the working tree and **every blob in git history**. A finding in
  history is already compromised: it is in every clone and every fork, and no later commit
  takes it back. **Rotate the credential first.** Rewriting history is optional cleanup
  afterwards, never the fix.

### Escape hatches

Three exist, in increasing order of bluntness. They live here, in prose, rather than in
the scripts that define the gates: a bypass command written inside a gate-defining file
is indistinguishable, to a reader and to the integrity scan alike, from that gate
documenting its own defeat. The hatches themselves are unchanged and still work.

| Hatch                               | Effect                                                                                                  |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `HVAULT_SKIP_GATES=docker,e2e`      | Skips the named gates for one run. Every other gate still runs, and the skip is printed in the summary. |
| Passing `--no-verify` to `git push` | Skips the pre-push hook entirely, so nothing is checked.                                                |
| `HUSKY=0` in the environment        | Disables every hook, including pre-commit. The bluntest of the three.                                   |

The first is the one to reach for: it is scoped, it is visible in the run summary, and it
leaves the other twenty-six gates in place. **Say so in the pull request description
whenever you use any of them**, and name the gate you skipped and why. A skipped gate is
a claim someone else now has to check.

None of them is a way to land work that does not pass. If a gate is wrong, fix the gate;
if the code is wrong, fix the code. See the next section.

## You may not make a gate pass by weakening it

This is the one rule with no exceptions. No `.skip`, `.only` or deleted test to reach
green; no neutered exit code, discarded error output or `--if-present`; no `@ts-ignore`,
`as any` or `eslint-disable` to silence a diagnostic; no lowered threshold, widened
exclusion, added retry or blanket snapshot update. When a test and the code disagree, the
code is the suspect.

Three gates enforce it rather than trusting it:

- **`integrity`** scans every tracked and untracked file for those markers and fails
  unless each one is gone or recorded in `.testfortress/suppressions.json` with an owner,
  a reason, an expiry and the exact rule it excuses. Some of them cannot be recorded at
  all: inside a file that DEFINES a gate — `package.json`, the manifest, anything under
  `scripts/ci/` or `.husky/` — a neutered exit code, a committed test filter, a strictness
  downgrade, a tautology, a swallowed failure or a hook bypass is a defect to fix.
  Documentation is exempt, which is why this file can name the patterns it forbids.
- **`ratchet`** compares the gated numbers against `.testfortress/baseline.json`. Each
  field has a direction: coverage, test counts and the measured file set may only rise;
  warnings and suppressions may only fall. Moving a number needs
  `node scripts/ci/ratchet-check.mjs --accept --reason "..."`, which moves each field only
  in its improving direction and refuses while anything is failing or unmeasured.
- **`npm run verify:selftest`** plants one defect per registered gate in a throw-away copy
  of the tree and requires every gate to go red. **Adding a gate obliges you to add its
  defect-injection case** to `scripts/ci/lib/selftest-defects.mjs` in the same change; a
  registered gate without one is a hard error naming it.

If a gate genuinely cannot be met, the honest move is a dated, expiring ledger entry that
says so — never a quiet edit to the gate. Know what one costs before you write it:

- **It expires**, at most 90 days out, and 30 for a type-checker or linter suppression. When the
  date passes, `integrity` fails. An entry buys time; it never buys permission.
- **It is pinned to one occurrence** — the exact rule id (never the looser `kind`, which several
  rules share), the file, a `symbol` anchor, and at most three hits. Move the code and the anchor
  stops matching, which is a failure rather than a silent renewal.
- **It lowers a ceiling you will have to live under.** `suppressions.count` and
  `suppressions.totalHits` are ratcheted downward, so today's total becomes tomorrow's limit: an
  entry removed cannot be spent again on something else without an explicit, reasoned `--accept`.
- **It needs an owner, a reason and approval**, and the reason has to be an argument. "Flaky" is
  not one; "the JWT `iat` has one-second precision, so this wait buys a strictly later second, and
  the injectable clock removes it" is.

Five things cannot be written down at all inside a gate-defining file, and coverage or mutation
**scope** cannot be written down anywhere — that one is policed by the ratchet's absolute
denominators and measured file sets, because a percentage whose denominator can shrink is not a
gate.

## What a good change looks like

- **Tests are required** for any behavior change. Every package enforces coverage
  thresholds (90% on all four metrics for `server` and `client`; `shared` is stricter),
  and the `test` gate fails the push if a change drops below them. Test the behavior, not
  the implementation: assertions that cannot fail are worse than no test at all. Test
  files are type-checked too — `npm run type-check` covers each package's `tests/` and the
  Playwright specs in `e2e/`, under the same strictness as the shipped source, so a
  fixture with a wrong or missing field is a compiler error rather than a silent pass.
- **Update the docs in the same change.** `README.md` for anything user-facing, and
  `CHANGELOG.md` for anything a user or operator could notice — add a bullet under
  `## [Unreleased]` using the Keep a Changelog categories (`Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security`). A `docs-sync` test asserts that parts of
  the README stay in step with the code, so it will tell you if you missed one.
- **Touching crypto, auth, or the backup/restore path?** Say so explicitly in the PR
  description and explain why the change is safe. These paths carry the whole product;
  they are reviewed on the assumption that a subtle mistake there is unrecoverable for a
  user.
- **Formatting and linting are automatic.** Prettier and ESLint (with
  `eslint-plugin-security`) run on staged files via `lint-staged` in `pre-commit`, and the
  pipeline enforces `--max-warnings=0`. Don't fight the formatter; run `npm run format`.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `perf:`, `build:`). This is a
convention, not a hook. Release notes no longer come from the commit history — they are
the `CHANGELOG.md` section for the version being released — so the place to write for
users is that entry, and a clear subject line is for the people reading `git log`.

1. Fork, and branch from `main` (`git checkout -b feat/my-feature`).
2. Make the change, with tests and docs.
3. `npm run ci` — green.
4. Open a pull request describing **what** changed and **why**, and how you verified it.

The release workflow is the only workflow in the repository and the only thing that spends
Actions minutes. It runs `npm run ci` on a clean checkout first, and tags and publishes only
if that passes — the local run before your push is not a substitute, because the escape
hatches above mean an unchecked commit can reach `main`.

A push to `main` releases only when the root `package.json` version has been bumped and
`CHANGELOG.md` has a matching `## [X.Y.Z]` section; that section becomes the Release body.
An ordinary push publishes nothing and says so.

## Project layout

```text
packages/shared   # Zod schemas, TypeScript types, constants — built first
packages/server   # Express 5 API, Mongoose models, background jobs
packages/client   # React 19 SPA, Web Crypto, Zustand stores
e2e/              # Playwright specs
scripts/ci/       # the local pipeline (this repo's real CI)
docker/           # Dockerfile targets, internal + system Nginx configs
```

## Reporting bugs and requesting features

Open an issue with the matching template. For a bug, the version, the deployment mode
(Docker / PM2 / dev), and the exact reproduction steps are what make it actionable. If
you are unsure whether something is a bug or a security issue, treat it as a security
issue and report it privately.
