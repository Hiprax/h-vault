#!/usr/bin/env node
/**
 * Extracts one release's section from CHANGELOG.md, for the release workflow to
 * publish as the GitHub Release body.
 *
 *   node scripts/ci/changelog-extract.mjs 0.8.0            → the section on stdout
 *   node scripts/ci/changelog-extract.mjs 0.8.0 --check    → nothing on stdout; exit code only
 *
 * Exit codes: 0 = the section exists and has content · 1 = it does not.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THIS REPLACES `--generate-notes`, WHICH DISCARDED THE CHANGELOG. This
 *     project treats a CHANGELOG.md entry as a blocking requirement of every
 *     change, and the release then published a list of commit subjects instead
 *     — so the curated, user-facing prose that the requirement exists to produce
 *     never reached a single reader. The release body is now that prose.
 *
 *  b. A MISSING SECTION IS A FAILURE, NOT AN EMPTY BODY. Publishing a release
 *     with no notes is indistinguishable from publishing one whose notes were
 *     silently dropped, and the second is the failure mode worth catching. An
 *     empty section counts as missing for the same reason: a heading with
 *     nothing under it documents nothing.
 *
 *  c. `[Unreleased]` CAN NEVER SATISFY A VERSION. The heading match is exact, so
 *     cutting a release without renaming that heading fails here rather than
 *     publishing the pending section under a version number it does not describe
 *     — and then publishing the same text again under the next one.
 *
 *  d. THE LINK-REFERENCE BLOCK IS NOT PART OF THE LAST SECTION. Keep a Changelog
 *     puts the `[x.y.z]: https://…/compare/…` definitions at the foot of the
 *     file, below the oldest release's section with no heading between them. A
 *     naive "read to the next heading or EOF" therefore appends the whole link
 *     table to the oldest release's notes.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** A Markdown link-reference definition: `[0.8.0]: https://github.com/…`. */
const LINK_DEFINITION = /^\[[^\]]+\]:\s+\S+/;

/**
 * Returns the body of `## [version]`, trimmed, or null when there is no such
 * section or it is empty.
 *
 * @param {string} markdown  the whole CHANGELOG.md
 * @param {string} version   a plain `X.Y.Z`
 * @returns {string|null}
 */
export function extractRelease(markdown, version) {
  const lines = markdown.split(/\r?\n/);
  // Exact, and anchored: `## [0.8.0]` must not be answered by `## [0.8.0-rc.1]`
  // or by `## [Unreleased]` (decision c).
  const heading = new RegExp(`^##\\s+\\[${version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\]`);
  const start = lines.findIndex((line) => heading.test(line));
  if (start === -1) return null;

  /** @type {string[]} */
  const body = [];
  for (const line of lines.slice(start + 1)) {
    // The next release's heading ends this one. `## ` only: a `### Added`
    // subheading is part of the section and must be kept.
    if (/^##\s/.test(line)) break;
    // (d) the foot of the file.
    if (LINK_DEFINITION.test(line)) break;
    body.push(line);
  }

  const text = body.join('\n').trim();
  return text.length > 0 ? text : null;
}

/** True when this module was started as a program rather than imported. */
function isEntryPoint() {
  const invoked = process.argv[1];
  if (invoked === undefined) return false;
  return path.resolve(invoked) === path.resolve(fileURLToPath(import.meta.url));
}

if (isEntryPoint()) {
  const args = process.argv.slice(2);
  const checkOnly = args.includes('--check');
  const version = args.find((arg) => !arg.startsWith('--'));

  if (version === undefined) {
    console.error('changelog-extract: usage: changelog-extract.mjs <X.Y.Z> [--check]');
    process.exit(1);
  }

  const file = path.resolve(fileURLToPath(import.meta.url), '..', '..', '..', 'CHANGELOG.md');
  let markdown;
  try {
    markdown = readFileSync(file, 'utf8');
  } catch (error) {
    console.error(`changelog-extract: cannot read CHANGELOG.md: ${error.message}`);
    process.exit(1);
  }

  const section = extractRelease(markdown, version);
  if (section === null) {
    console.error(
      `changelog-extract: CHANGELOG.md has no "## [${version}]" section with content. ` +
        'Cutting a release means renaming "## [Unreleased]" to that heading and dating it, ' +
        'so the release notes are the curated entry rather than a list of commit subjects.',
    );
    process.exit(1);
  }

  if (!checkOnly) process.stdout.write(`${section}\n`);
  process.exit(0);
}
