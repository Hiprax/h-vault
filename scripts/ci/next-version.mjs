#!/usr/bin/env node
/**
 * Prints the tag the current commit should be released under.
 *
 * Used by `.github/workflows/release.yml` (and runnable by hand:
 * `npm run release:next-version`). The decision itself lives in
 * `lib/version.mjs`, which is unit-tested; this file only supplies the git and
 * package.json facts and writes the result out.
 *
 * When GITHUB_OUTPUT is set, the result is appended there as step outputs:
 *
 *   tag=v1.1.2
 *   tag_exists=false     # HEAD was not already tagged, so the tag must be created
 *
 * Human-readable commentary goes to stderr, so `node next-version.mjs` can be
 * captured cleanly in a shell.
 */
import { appendFileSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { captureExe, repoRoot } from './lib/proc.mjs';
import { computeNextTag } from './lib/version.mjs';

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

const { tag, tagExists } = computeNextTag({
  tags: git(['tag', '--list']),
  headTags: git(['tag', '--points-at', 'HEAD']),
  pkgVersion: pkg.version,
});

const githubOutput = process.env['GITHUB_OUTPUT'];
if (githubOutput) {
  appendFileSync(githubOutput, `tag=${tag}\ntag_exists=${String(tagExists)}\n`);
}

console.error(
  tagExists
    ? `HEAD is already tagged ${tag} — no new tag will be created.`
    : `Next release tag: ${tag}`,
);
console.log(tag);
