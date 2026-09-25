/**
 * The ONE unified diff the coverage gate measures: every change since the merge
 * base, numbered in the working tree and nowhere else.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS: THREE COORDINATE SYSTEMS, UNIONED
 * ---------------------------------------------------------------------------
 *
 * `diff-cover` builds its changed-line set by unioning three separate `git diff`
 * invocations (`diff_cover/git_diff.py`): `<base>...HEAD`, `git diff` and
 * `git diff --cached`. Each numbers its `+` lines in a DIFFERENT file — HEAD,
 * the working tree, and the index — and those numbers are then looked up in
 * coverage data produced by running the suites against the WORKING TREE.
 *
 * On a clean tree the three agree and nothing is wrong. On a dirty one — a
 * developer running the push gate before committing, or a review pass that is
 * required to leave uncommitted work behind — they do not, and the union is a
 * set of line numbers belonging to no single file.
 *
 * MEASURED on this repository: the gate reported
 * `packages/server/src/controllers/userController.ts:371` as an uncovered
 * changed line. At HEAD that line is a COMMENT inside a block the change added;
 * in the working tree it is an older, unrelated `!user` guard. The gate was
 * asking about a line the change never touched — and it refused a push for it.
 *
 * It fails in the dangerous direction too, which is what makes this a fix rather
 * than a tidy-up: a genuinely uncovered NEW line goes unreported whenever its
 * HEAD-coordinate number happens to land on a covered line of the working tree.
 * The smallest demonstration is one commit that appends a line and one
 * uncommitted deletion above it, and it is the fixture `coverage-gate.test.ts`
 * uses: the union reports line 7 of a six-line file and misses the line that
 * actually changed.
 *
 * So the gate generates the diff itself, in one coordinate system, and hands it
 * to diff-cover with `--diff-file`. `git diff <mergeBase>` — two dots, no
 * `HEAD` — compares the WORKING TREE against the base, which already folds in
 * the committed, staged and unstaged changes diff-cover asks for separately, and
 * numbers all of them in the file the suites actually executed.
 *
 * ---------------------------------------------------------------------------
 * LOAD-BEARING DECISIONS
 * ---------------------------------------------------------------------------
 *
 *  a. UNTRACKED FILES ARE APPENDED BY HAND. `--diff-file` puts diff-cover on
 *     `GitDiffFileTool`, whose `untracked()` returns an empty string, so
 *     `--include-untracked` silently stops meaning anything. A brand-new module
 *     nobody has committed is precisely the case the gate exists for, so each one
 *     is turned into a real "new file" diff with
 *     `git diff --no-index /dev/null <path>`. `/dev/null` is a literal git
 *     special-cases in `--no-index` mode (`diff-no-index.c`'s `get_mode`), not a
 *     device this reads, so it works off POSIX too.
 *
 *  b. `--no-index` EXITS 1 WHEN THE INPUTS DIFFER, which is every call here: a
 *     file compared against nothing always differs. Only a status ABOVE 1 is a
 *     failure. Treating 1 as one would make the gate unrunnable the moment
 *     anybody added a file.
 *
 *     MEASURED, and the reason (c) is the rule rather than the status: a path
 *     that has VANISHED between `git ls-files --others` and this call also exits
 *     1 (`error: Could not access '<path>'`) with no output at all, so it is
 *     dropped by (c) rather than by an exit code. That is the right answer — the
 *     file is not there to measure — and it cannot hide an untested module,
 *     because the gate's other half enumerates the changed production files
 *     itself and reports any one that is in scope and in no coverage report.
 *
 *  c. A SECTION WITH NO HUNK HEADER IS DROPPED. git emits `Binary files … differ`
 *     for a binary file and a bare header for an empty one; neither carries the
 *     `+++` line diff-cover reads the new path from, so appending one would
 *     either break its parser or teach it a path with no lines. Dropping it
 *     matches what diff-cover does with an undecodable untracked file today —
 *     `_get_file_lines` catches `UnicodeDecodeError` and reports zero lines.
 *
 *  d. EVERY CONFIG KEY THAT COULD MOVE A PATH IS PINNED. diff-cover's parser
 *     anchors on `^diff --git "?a/.*"? "?b/([^\n"]*)"?` (`diff_reporter.py`'s
 *     `SRC_FILE_RE`), so the `a/` and `b/` prefixes are load-bearing and FIVE
 *     separate settings can change them: `diff.noprefix`, `diff.mnemonicprefix`,
 *     `diff.srcPrefix`, `diff.dstPrefix` and `diff.relative`. A developer with
 *     any one of them in `~/.gitconfig` would hand diff-cover a path matching no
 *     coverage record — and an unmatched path is not an error there, it is
 *     silently full coverage over nothing. `core.quotePath` is pinned for the
 *     same reason one step further out: it decides whether a non-ASCII path
 *     arrives escaped. diff-cover pins only the first two when it drives git
 *     itself, so this is deliberately stricter than the tool it feeds.
 *
 *  e. THE `\ No newline at end of file` MARKER IS STRIPPED. diff-cover's
 *     `_parse_lines` treats every line that does not begin with `+`, `-` or `@@`
 *     as CONTEXT and increments the line counter for it. Inside a `-U0` hunk that
 *     marker sits between the `-` line and the `+` line, so leaving it in shifts
 *     every added line in that hunk by one — the same class of off-by-one this
 *     whole module exists to remove, arriving through a different door. Matched on
 *     the leading `\ ` rather than on the sentence, which is the patch format's
 *     marker and not prose; an added line whose CONTENT starts with a backslash
 *     begins with `+`, so it is never touched.
 *
 *  f. NOTHING HERE READS THE FILESYSTEM OR EXITS. `git` is injected, so the
 *     caller owns the process boundary and a test can drive this against a real
 *     throwaway repository; a failure is thrown, so the gate can report it as
 *     "could not run" rather than as a coverage verdict it never computed.
 */

/**
 * The fixed argv prefix for every diff taken here.
 *
 * `-U0` because only the hunk headers matter: context lines would be parsed as
 * unchanged and cost nothing but size. The six `-c` settings are (d): every one
 * of them can move a path out from under diff-cover's `a/`-`b/` parser.
 */
const GIT_DIFF_ARGS = [
  '-c',
  'diff.mnemonicprefix=no',
  '-c',
  'diff.noprefix=no',
  '-c',
  'diff.srcPrefix=a/',
  '-c',
  'diff.dstPrefix=b/',
  '-c',
  'diff.relative=false',
  '-c',
  'core.quotePath=false',
  'diff',
  '--no-color',
  '--no-ext-diff',
  '-U0',
];

/** Every hunk header git can emit, anchored at the start of a line. */
const HUNK_HEADER = /^@@ /m;

/** The patch format's no-newline marker, on its own line. See (e). */
const NO_NEWLINE_MARKER = /^\\ .*\n?/gm;

/** @typedef {{ status: number, stdout: string, stderr: string }} GitResult */

/**
 * One section of the document diff-cover will parse: the no-newline markers
 * removed (e), and a final newline guaranteed so the next section starts on its
 * own line.
 */
const section = (text) => {
  const stripped = text.replace(NO_NEWLINE_MARKER, '');
  return stripped === '' || stripped.endsWith('\n') ? stripped : `${stripped}\n`;
};

/**
 * Builds the unified diff of everything that changed since `mergeBase`.
 *
 * @param {object} options
 * @param {string} options.mergeBase the ALREADY-RESOLVED commit to compare against
 * @param {string[]} [options.untracked] repo-relative paths of untracked files to fold in
 * @param {(args: string[]) => GitResult} options.git runs `git` with the given argv
 * @returns {string} one unified diff, entirely in working-tree line numbers
 * @throws {Error} when git cannot produce the diff — never a partial answer
 */
export function buildChangedDiff({ mergeBase, untracked = [], git }) {
  const tracked = git([...GIT_DIFF_ARGS, mergeBase]);
  if (tracked.status !== 0) {
    throw new Error(
      `git diff against ${mergeBase} failed (exit ${String(tracked.status)}): ` +
        `${tracked.stderr.trim() || tracked.stdout.trim() || 'no output'}`,
    );
  }

  let unified = section(tracked.stdout);

  for (const rel of untracked) {
    const added = git([...GIT_DIFF_ARGS, '--no-index', '/dev/null', rel]);
    // (b) 1 is "the inputs differ", which is every call here.
    if (added.status > 1) {
      throw new Error(
        `git diff --no-index for the untracked ${rel} failed (exit ${String(added.status)}): ` +
          `${added.stderr.trim() || added.stdout.trim() || 'no output'}`,
      );
    }
    // (c) no hunk header means no added lines to measure: binary, or empty.
    if (!HUNK_HEADER.test(added.stdout)) continue;
    unified += section(added.stdout);
  }

  return unified;
}
