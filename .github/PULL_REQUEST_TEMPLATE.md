## What and why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## How it was verified

<!-- How do you know it works? Tests added, manual steps taken, edge cases considered. -->

## Checklist

- [ ] `npm run ci` passes locally (the `pre-push` hook runs it; note here if any gate was skipped, and why)
- [ ] Tests added or updated for the behavior change — they fail without the fix
- [ ] `CHANGELOG.md` updated under `## [Unreleased]` (skip only if nothing user-visible changed)
- [ ] `README.md` updated if anything user-facing, environment, or setup related changed

## Security impact

<!--
Does this touch crypto, authentication, session handling, rate limiting, or the
backup/restore path? If so, say what the change is and why it is safe. If it touches
none of them, write "none".

Never use a pull request to disclose a vulnerability — see SECURITY.md.
-->
