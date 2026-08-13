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
pipeline locally — twenty-seven gates including the full test suite, the export-format
goldens, patch coverage on the lines you changed, a smoke run of the built artifact, the
browser bundle's size budgets, container builds with Trivy scanning, and CodeQL — and
refuses the push if any of them fail. A
commit that reaches `main` has already passed everything. Five further gates sit in the
release tier: `fuzz`, whose suites still run inside the ordinary test gates on every push
so that only the separately-reported, deadline-bounded run is held back; `resource`, the
volume and memory budgets, which builds ten-thousand-item vaults and therefore both takes
a minute and needs a machine that is not running three other workers for its numbers to
mean anything; `upgrade`, which reads a vault and a `.env` written by the previous release
and, like `fuzz`, keeps its assertions on the push tier while the named, deadline-bounded
run waits for a release; `recovery`, which restores a backup onto a second database and
kills a real server process mid-write, and which needs its deadline more than any other
gate because it spawns processes in order to kill them; and `deploy`, the deployment clean
room, which stands the whole Compose stack up from nothing and is far too heavy for a hook
— its fast sibling `smoke` covers the built artifact on every push. All five run in
`npm run verify:full`.

The gates are grouped into tiers by how long they take, so there is something worth
running at every point in the loop:

```bash
npm run verify:fast               # the fast tier (~80s): engines, secrets, lint, format, types
npm run ci                        # everything the pre-push hook runs (15–30 min)
npm run verify:full               # the above plus the release tier (fuzz, volume budgets, upgrade path, recovery drills, deploy drill)
npm run ci:local                  # all of it again, from a fresh worktree at HEAD (clean room)
npm run ci -- --list              # the gates, their tiers, and what each one replaces
npm run ci -- --only=lint,test    # a subset, while iterating
npm run ci -- --bail              # stop at the first failure instead of running them all
npm run ci -- --json              # one JSON document describing the run
```

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

### Seven gates whose failure asks for something specific

Most gates tell you what to fix. These seven are worth reading before you meet them,
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
leaves the other twenty-three gates in place. **Say so in the pull request description
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
says so — never a quiet edit to the gate.

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
convention, not a hook — but the release notes are generated from the commit history, so
a clear subject line ends up in front of users.

1. Fork, and branch from `main` (`git checkout -b feat/my-feature`).
2. Make the change, with tests and docs.
3. `npm run ci` — green.
4. Open a pull request describing **what** changed and **why**, and how you verified it.

Every push to `main` is released automatically: the release workflow tags the commit and
publishes a GitHub Release. That is the only workflow in the repository and the only thing
that spends Actions minutes.

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
