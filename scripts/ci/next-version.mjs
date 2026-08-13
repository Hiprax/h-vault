#!/usr/bin/env node
/**
 * Decides whether this commit is a release, and under which tag.
 *
 * Used by `.github/workflows/release.yml` (and runnable by hand:
 * `npm run release:next-version`). The decision itself lives in
 * `lib/version.mjs`, which is unit-tested; this file only supplies the git and
 * package.json facts, writes the result out, and turns a refusal into an exit
 * code.
 *
 * When GITHUB_OUTPUT is set, the result is appended there as step outputs:
 *
 *   tag=v1.1.2
 *   version=1.1.2          # the root package.json version, the version of truth
 *   should_release=true    # publish a Release from this commit
 *   create_tag=true        # ...and create the tag first (false = it already exists)
 *
 * Exit codes: 0 = decided (whether or not a release is due) · 1 = the tag that
 * would be created disagrees with the version of truth, so nothing may be
 * published. That second case is the guard: `package.json` is what
 * `scripts/inject-version.js` compiles into `APP_VERSION`, which `/health` and
 * the OpenAPI document both serve, so a tag that disagrees with it publishes a
 * release whose own artifact contradicts its name.
 *
 * Human-readable commentary goes to stderr, so `node next-version.mjs` can be
 * captured cleanly in a shell.
 */
import { appendFileSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, repoRoot } from './lib/proc.mjs';
import { planRelease } from './lib/version.mjs';

function git(args) {
  const result = captureExe('git', args);
  if (!result.ok) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr.trim()}`);
  }
  return result.stdout
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
}

const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));

const plan = planRelease({
  tags: git(['tag', '--list']),
  headTags: git(['tag', '--points-at', 'HEAD']),
  pkgVersion: pkg.version,
});

const githubOutput = process.env['GITHUB_OUTPUT'];
if (githubOutput) {
  appendFileSync(
    githubOutput,
    `tag=${plan.tag}\n` +
      `version=${plan.version}\n` +
      `should_release=${String(plan.shouldRelease)}\n` +
      `create_tag=${String(plan.createTag)}\n`,
  );
}

if (plan.mismatch) {
  console.error(`Refusing to release: ${plan.reason}`);
  process.exit(1);
}

console.error(
  plan.shouldRelease
    ? `Releasing ${plan.tag} — ${plan.reason}`
    : `Nothing to release — ${plan.reason}`,
);
console.log(plan.tag);
