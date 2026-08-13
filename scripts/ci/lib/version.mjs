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
function parseTag(tag) {
  const match = SEMVER_TAG.exec(tag.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** `1.2.3` / `1.2.3-beta.1` → [1, 2, 3]; anything else → null. */
function parseVersion(version) {
  const match = SEMVER_VERSION.exec(version.trim());
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** Standard semver ordering: negative when a < b. */
function compare(a, b) {
  return a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
}

const format = (parts) => `v${String(parts[0])}.${String(parts[1])}.${String(parts[2])}`;

/** `0.8.0` → `0`; anything that is not semver → null. The MAJOR component alone. */
export function majorOf(version) {
  const parts = parseVersion(version);
  return parts === null ? null : parts[0];
}

/**
 * Does `current` carry the MAJOR bump that would license a breaking API change
 * against a contract snapshot describing `snapshot`?
 *
 * Used by `scripts/ci/openapi-gate.mjs`. The naive test — `major(current) >
 * major(snapshot)` — is a hole, and the hole is permanent once opened. The
 * exemption exists for the commit that raises MAJOR *without* refreshing the
 * snapshot; refresh the snapshot and there are no findings at all, so the
 * exemption is never needed. From that commit on the snapshot's MAJOR is behind
 * for good, and every later release in the line satisfies `1 > 0` and carries
 * unversioned breaking changes for free — a gate that stopped gating with
 * nobody editing it.
 *
 * So the exemption belongs to the release that IS the bump: one MAJOR above the
 * snapshot, and the `.0.0` of that line. Anything else must refresh the
 * snapshot, which is the rule the snapshot is meant to encode anyway.
 *
 * @param {string} snapshotVersion  `info.version` of the committed snapshot
 * @param {string} currentVersion   `info.version` of the generated document
 * @returns {boolean}
 */
export function majorBumpAccountsForBreaking(snapshotVersion, currentVersion) {
  const from = majorOf(snapshotVersion);
  const to = majorOf(currentVersion);
  if (from === null || to === null) return false;
  return to === from + 1 && currentVersion.trim() === `${String(to)}.0.0`;
}

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

/**
 * Decides whether THIS push is a release, and refuses to mint a tag that
 * disagrees with the version of truth.
 *
 * `computeNextTag` above answers "what is the next tag in the series?". That is
 * a different question from "should anything be published from this commit?",
 * and conflating the two is the defect this exists to close: the series walks
 * v0.8.0 → v0.8.1 on its own, while `package.json` — which `scripts/inject-
 * version.js` compiles into `APP_VERSION`, which `/health` and the OpenAPI
 * document both serve — stays at 0.8.0. The published release then carries a
 * tag no artifact inside it agrees with.
 *
 * So the version of truth leads and the tag follows. Three outcomes:
 *
 *   * HEAD already carries `v<version>` — the release commit, tagged by an
 *     earlier run. Publish (or re-publish) without creating a second tag, which
 *     is what heals a run interrupted between tagging and publishing.
 *   * `v<version>` exists on some OTHER commit — this version has already been
 *     released, so an ordinary push to `main` that bumped nothing publishes
 *     NOTHING and says so. This is the common case and it is not a failure.
 *   * `v<version>` exists nowhere — a release is due. The tag is created only
 *     when the series agrees that `v<version>` is the tag to create; when it
 *     does not, `mismatch` is set and the caller must refuse. That branch is
 *     reachable exactly when the tags have run ahead of `package.json`, which
 *     is precisely the situation that would publish v0.9.1 from an artifact
 *     reporting 0.8.0.
 *
 * @param {object} input
 * @param {string[]} input.tags        every tag in the repository
 * @param {string[]} input.headTags    tags already pointing at HEAD
 * @param {string}   input.pkgVersion  `version` from the root package.json
 * @returns {{ tag: string, versionTag: string, version: string,
 *             shouldRelease: boolean, createTag: boolean, mismatch: boolean,
 *             reason: string }}
 */
export function planRelease({ tags, headTags, pkgVersion }) {
  const version = pkgVersion.trim();
  // Deliberately stricter than `parseVersion`, which tolerates a `-beta.1`
  // suffix and drops it. A tag is `vX.Y.Z` and nothing else, so a version this
  // scheme cannot represent would be released under a tag naming a DIFFERENT
  // version — the very mismatch this function exists to refuse. Refuse it here
  // instead of silently truncating it.
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    return {
      tag: '',
      versionTag: '',
      version,
      shouldRelease: false,
      createTag: false,
      mismatch: true,
      reason: `package.json version ${JSON.stringify(version)} is not a plain X.Y.Z, so no vX.Y.Z tag can name it`,
    };
  }

  const versionTag = `v${version}`;
  const plainTags = new Set(tags.map((tag) => tag.trim()).filter((tag) => parseTag(tag) !== null));
  const plainHeadTags = new Set(
    headTags.map((tag) => tag.trim()).filter((tag) => parseTag(tag) !== null),
  );

  if (plainHeadTags.has(versionTag)) {
    return {
      tag: versionTag,
      versionTag,
      version,
      shouldRelease: true,
      createTag: false,
      mismatch: false,
      reason: `HEAD is already tagged ${versionTag}; the release itself is still reconciled`,
    };
  }

  if (plainTags.has(versionTag)) {
    return {
      tag: versionTag,
      versionTag,
      version,
      shouldRelease: false,
      createTag: false,
      mismatch: false,
      reason: `${versionTag} was already released from another commit — bump package.json to cut a new one`,
    };
  }

  const { tag } = computeNextTag({ tags, headTags, pkgVersion: version });
  if (tag !== versionTag) {
    return {
      tag,
      versionTag,
      version,
      shouldRelease: false,
      createTag: false,
      mismatch: true,
      reason:
        `the tag series would mint ${tag}, but package.json says ${version} — ` +
        `publishing ${tag} would ship an artifact whose /health and OpenAPI document both report ${version}`,
    };
  }

  return {
    tag,
    versionTag,
    version,
    shouldRelease: true,
    createTag: true,
    mismatch: false,
    reason: `${versionTag} has never been released and matches package.json`,
  };
}
