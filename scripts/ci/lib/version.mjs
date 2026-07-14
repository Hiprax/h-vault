/**
 * Tag selection for the release-on-every-push workflow.
 *
 * The contract, in one line: every push to `main` gets exactly one tag, and a
 * tag is never minted twice.
 *
 * Two inputs decide the next tag — the highest `vX.Y.Z` tag that already exists,
 * and the version in package.json:
 *
 *   * normally the next tag is the highest existing tag with its patch bumped,
 *     so pushes walk v1.1.0 → v1.1.1 → v1.1.2 without anyone touching a file;
 *   * a manual bump of package.json wins whenever it is *higher* than that,
 *     which is how a minor/major release is cut (1.1.x → set 1.2.0 → v1.2.0).
 *
 * package.json is never rewritten by the workflow. Committing a version bump
 * back to `main` from CI would re-trigger the push workflow, and the release
 * would start releasing itself.
 *
 * Only plain `vX.Y.Z` tags participate. Anything else (`v1.2.0-rc.1`,
 * `nightly`) is ignored rather than parsed, so a hand-made tag can never
 * become the base for an automated one.
 */

const SEMVER_TAG = /^v(\d+)\.(\d+)\.(\d+)$/;
const SEMVER_VERSION = /^(\d+)\.(\d+)\.(\d+)/;

/** `v1.2.3` → [1, 2, 3]; anything else → null. */
export function parseTag(tag) {
  const match = SEMVER_TAG.exec(tag.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** `1.2.3` / `1.2.3-beta.1` → [1, 2, 3]; anything else → null. */
export function parseVersion(version) {
  const match = SEMVER_VERSION.exec(version.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** Standard semver ordering: negative when a < b. */
export function compare(a, b) {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

export const format = (parts) => `v${String(parts[0])}.${String(parts[1])}.${String(parts[2])}`;

/**
 * Decides which tag this push should produce.
 *
 * @param {object} input
 * @param {string[]} input.tags        every tag in the repository
 * @param {string[]} input.headTags    tags already pointing at HEAD
 * @param {string}   input.pkgVersion  `version` from package.json
 * @returns {{ tag: string, tagExists: boolean }}
 *
 * `tagExists: true` means HEAD is already tagged — a re-run, a
 * `workflow_dispatch` on an unchanged commit, or a push that raced another
 * release. The caller must then NOT create the tag again; it may still need to
 * create the missing GitHub Release for it, which is what makes the whole
 * workflow idempotent.
 */
export function computeNextTag({ tags, headTags, pkgVersion }) {
  const alreadyTagged = headTags
    .map((tag) => ({ tag: tag.trim(), parts: parseTag(tag) }))
    .filter((entry) => entry.parts !== null)
    .sort((a, b) => compare(a.parts, b.parts));

  // HEAD carries a release tag already: reuse it rather than stacking a second
  // tag on the same commit.
  const highestOnHead = alreadyTagged.at(-1);
  if (highestOnHead) {
    return { tag: highestOnHead.tag, tagExists: true };
  }

  const existing = tags.map(parseTag).filter((parts) => parts !== null);
  const highest = existing.sort(compare).at(-1);

  const fromPackage = parseVersion(pkgVersion);
  if (!fromPackage) {
    throw new Error(`package.json version is not semver: ${JSON.stringify(pkgVersion)}`);
  }

  // No release has ever been cut: package.json's version is the first tag.
  if (!highest) {
    return { tag: format(fromPackage), tagExists: false };
  }

  const bumped = [highest[0], highest[1], highest[2] + 1];

  // A hand-edited package.json only wins when it is genuinely ahead of the tag
  // series; otherwise a forgotten (or reverted) version field would try to mint
  // a tag that already exists.
  const next = compare(fromPackage, bumped) > 0 ? fromPackage : bumped;
  return { tag: format(next), tagExists: false };
}
