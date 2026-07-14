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
npm run dev                                   # http://localhost:3000
```

`packages/shared` is a build-time dependency of both other packages. If the server or
client fails to resolve `@hvault/shared`, you skipped `npm run build:shared`.

## The pipeline runs on your machine, not on a runner

There is **no CI workflow that tests your code**. The `pre-push` hook runs the entire
pipeline locally — eleven gates including the full test suite, container builds with
Trivy scanning, and CodeQL — and refuses the push if any of them fail. A commit that
reaches `main` has already passed everything.

```bash
npm run ci                        # everything the pre-push hook runs (15–30 min)
npm run ci -- --list              # the gates, and what each one replaces
npm run ci -- --only=lint,test    # a subset, while iterating
npm run ci -- --continue          # don't stop at the first failure
```

Run `npm run ci` before you open a pull request. If a gate legitimately cannot run in
your environment, `HVAULT_SKIP_GATES=docker,e2e git push` skips named gates — say so in
the PR description if you use it.

## What a good change looks like

- **Tests are required** for any behavior change. Every package enforces coverage
  thresholds (90% on all four metrics for `server` and `client`; `shared` is stricter),
  and the `test` gate fails the push if a change drops below them. Test the behavior, not
  the implementation: assertions that cannot fail are worse than no test at all.
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
