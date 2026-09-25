/**
 * "Since the trunk": the ONE definition of the commit a per-change gate compares
 * the working tree against.
 *
 * Two gates ask the question — `coverage:check` (every changed production line
 * is covered) and `test:mutation:diff` (every changed production line is
 * asserted) — and they must get the same answer, or one gate would be measuring
 * a different change from the other on the very same push. So the resolution
 * lives here, and both gates call it.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. THE BASE MUST RESOLVE, or the gate cannot run. Falling back to "no base,
 *     therefore nothing changed" would turn every environment with an unusual
 *     checkout into a silent pass — 100% of nothing. `HVAULT_DIFF_BASE` names
 *     another ref; otherwise `main`, then `origin/main`.
 *
 *  b. ON THE TRUNK, THE SUBJECT IS THE LAST COMMIT. A build ON the trunk has no
 *     diff against the trunk: `release.yml` builds a push to `main`, where `main`
 *     and `HEAD` are the same commit, and anyone committing straight to `main`
 *     locally is in the same position. There, "this change" IS `HEAD^..HEAD`.
 *     A genuine root commit keeps the empty diff, because nothing precedes it.
 *
 *  c. A SHALLOW TRUNK CLONE IS REFUSED. A trunk build whose HEAD has no parent
 *     is either a real root commit (an empty diff is honest) or a shallow clone
 *     whose graft boundary is HEAD (the history exists and this machine cannot
 *     see it, so an empty diff is a lie that reads as a pass). They are
 *     indistinguishable from the rev alone, so git is asked which one this is.
 *
 *  d. NOTHING HERE EXITS. `git` is injected and a failure is THROWN, so each
 *     gate reports it in its own voice as "could not run" and a test can drive
 *     this against a real throwaway repository.
 */

/**
 * @typedef {object} DiffBase
 * @property {string} ref       the ref that resolved (`main`, `origin/main`, or the requested one)
 * @property {string} mergeBase the commit to diff the working tree against
 * @property {boolean} onTrunk  true when HEAD is the trunk and the subject is HEAD~1..HEAD
 */

/**
 * @param {object} options
 * @param {(args: string[]) => string | null} options.git runs git; trimmed stdout, or null on failure
 * @param {string | undefined} [options.requested] `HVAULT_DIFF_BASE`, when set
 * @returns {DiffBase}
 * @throws {Error} when no base resolves, HEAD does not resolve, or a shallow trunk hides the parent
 */
export function resolveDiffBase({ git, requested }) {
  const candidates = requested ? [requested] : ['main', 'origin/main'];
  const ref = candidates.find((name) =>
    git(['rev-parse', '--verify', '--quiet', `${name}^{commit}`]),
  );
  if (!ref) {
    throw new Error(
      `none of ${candidates.join(', ')} resolves to a commit, so there is no trunk to compare against. ` +
        'Set HVAULT_DIFF_BASE to the ref this branch forked from.',
    );
  }
  if (!git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}'])) {
    throw new Error('HEAD does not resolve to a commit, so there is nothing to diff');
  }
  const rawMergeBase = git(['merge-base', ref, 'HEAD']) ?? ref;
  const headSha = git(['rev-parse', 'HEAD']);
  const onTrunk = headSha !== null && rawMergeBase === headSha;
  const firstParent = onTrunk ? git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}~1']) : null;
  if (onTrunk && firstParent === null && git(['rev-parse', '--is-shallow-repository']) === 'true') {
    throw new Error(
      'this is a shallow clone of the trunk, so the commit before HEAD is not present and ' +
        '"the lines this change touched" cannot be identified. Fetch the history (fetch-depth: 0) ' +
        'and re-run.',
    );
  }
  return { ref, mergeBase: firstParent ?? rawMergeBase, onTrunk };
}
