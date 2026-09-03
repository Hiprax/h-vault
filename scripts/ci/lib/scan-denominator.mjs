/**
 * The DENOMINATOR verdict for a secret scan.
 *
 * `secret-scan.mjs` runs its scan at module top level, so importing it performs
 * a scan and the decision it makes about "how much did I actually read?" cannot
 * be unit-tested in place. It lives here for the same reason `lib/version.mjs`
 * holds the release policy: the rule is worth pinning, and the program that
 * applies it is not importable.
 *
 * WHY THE RULE IS NOT SIMPLY "ZERO IS FATAL".
 *
 * A finding count means nothing without the number of files it was counted
 * over. One over-broad exclusion pattern, or a `git ls-files` that silently
 * returns nothing, and the gate reports "no secrets found" having read no bytes
 * at all. That is why zero scanned files fails, and that reasoning is intact.
 *
 * But zero scanned files has THREE causes and only two of them are that
 * failure:
 *
 *   1. NOTHING WAS ENUMERATED. git returned no paths whatsoever — a broken
 *      call, a broken mode, a directory that is not a repository. Fatal in
 *      every mode: the scan holds no evidence about anything at all.
 *
 *   2. EVERY ENUMERATED PATH WAS EXCLUDED. Mode-dependent, and this is the
 *      distinction the guard used to lack:
 *
 *        * over the WHOLE TREE it is the over-broad-pattern failure the guard
 *          exists to catch. A repository of thousands of source files cannot
 *          legitimately be nothing but documentation and fixtures, so an
 *          enumeration that says otherwise means the exclusion list has grown a
 *          pattern matching everything. FATAL, unchanged.
 *
 *        * over a STAGED SET it is ordinary. The enumeration is one commit's
 *          files, and a commit touching only `SECURITY.md`, or only tests, is a
 *          commit whose every file the scanner was deliberately told to skip.
 *          Nothing is owed and nothing is wrong: it PASSES. It has to, because
 *          the alternative is a pre-commit hook that refuses every
 *          documentation-only and test-only commit — and a hook that refuses
 *          ordinary work is a hook someone reaches past once and then always
 *          (the escape hatches are catalogued in CONTRIBUTING.md, deliberately
 *          nowhere near a file that defines a gate).
 *
 *   3. FILES SURVIVED EXCLUSION BUT NONE COULD BE READ. `git show :path`
 *      failing, a file vanishing mid-scan. Fatal in every mode: bytes were owed
 *      to the scan and the scan did not get them.
 *
 * The relaxation is therefore MODE-AWARE rather than global, deliberately.
 * Making it global would buy the same green pre-commit hook at the price of the
 * whole-tree gate's only defence against its own exclusion list — the one place
 * the check has real power, since only there is "everything was excluded" a
 * claim about the repository rather than about one commit.
 */

/** How many excluded paths a message names before summarising the remainder. */
const NAMED_EXCLUSIONS = 5;

/** `a, b, c and 4 more` — enough to identify the exclusion, bounded for a hook. */
function nameThem(files) {
  const shown = files.slice(0, NAMED_EXCLUSIONS);
  const rest = files.length - shown.length;
  return rest > 0 ? `${shown.join(', ')} and ${String(rest)} more` : shown.join(', ');
}

/**
 * Decides whether a scan read enough to be believed.
 *
 * The message carries no `secret-scan:` prefix and no symbol: the caller owns
 * both, so the same string reads correctly behind a pass mark or a fail mark.
 *
 * @param {object} input
 * @param {boolean} input.staged      true in the pre-commit (`--staged`) mode
 * @param {number} input.enumerated   paths git returned, BEFORE exclusion
 * @param {string[]} input.excluded   the paths the exclusion list removed
 * @param {number} input.scanned      files actually read and scanned
 * @returns {{ ok: boolean, reason: 'incoherent' | 'empty-enumeration' | 'all-excluded' | 'nothing-readable' | 'scanned', message: string }}
 */
export function evaluateDenominator({ staged, enumerated, excluded, scanned }) {
  const scannable = enumerated - excluded.length;

  // Counts that cannot describe a real scan are FATAL rather than merely
  // impossible. Today's only caller derives all three from one deduped list
  // partitioned by `isExcluded`, so none of this is reachable from it — but this
  // module exists precisely so the rule can be pinned away from that caller, and
  // a gate that answers "ok" to arithmetic it cannot explain is the failure the
  // denominator exists to prevent. Answering `ok: false` costs a second caller
  // a loud error; answering `ok: true` costs it a silent green.
  //
  // Testing `scannable` rather than `enumerated` is deliberate and does the work
  // of three separate clauses: it is NaN when `excluded` is not an array (an
  // `.length` of `undefined` poisons the subtraction, and every later comparison
  // against NaN is false, so the unguarded version returned `ok: true` over
  // arithmetic it could not do — measured), and non-integer when `enumerated`
  // is.
  //
  // There is deliberately NO `scannable < 0` clause, though the case is refused:
  // a negative `scannable` with a non-negative `scanned` always satisfies
  // `scanned > scannable`, and a negative `scanned` has its own clause, so the
  // two together leave it no input to decide. It was written, measured to be an
  // equivalent mutant no test could kill, and removed. Each clause that remains
  // is individually killable with inputs satisfying the declared types.
  if (
    !Number.isInteger(scannable) ||
    !Number.isInteger(scanned) ||
    scanned < 0 ||
    scanned > scannable
  ) {
    return {
      ok: false,
      reason: 'incoherent',
      message:
        `refusing to judge incoherent counts (enumerated ${String(enumerated)}, excluded ` +
        `${Array.isArray(excluded) ? String(excluded.length) : 'not an array'}, scanned ` +
        `${String(scanned)}) — a denominator that cannot describe a real scan cannot vouch for one`,
    };
  }

  if (enumerated === 0) {
    return {
      ok: false,
      reason: 'empty-enumeration',
      message:
        '0 files enumerated — ' +
        (staged
          ? 'the staged set came back empty, so the bytes of this commit were never read'
          : 'git listed no files at all, so the enumeration is broken') +
        ', and a scan of nothing finds nothing',
    };
  }

  // `=== 0`, not `<= 0`: a negative `scannable` was already refused above, so a
  // wider comparison here would only be a second, silent way to reach the pass.
  if (scannable === 0) {
    if (!staged) {
      return {
        ok: false,
        reason: 'all-excluded',
        message:
          `all ${String(enumerated)} enumerated file(s) are on the exclusion list — over the whole ` +
          'tree that means the exclusion list is over-broad, and a scan of nothing finds nothing',
      };
    }
    return {
      ok: true,
      reason: 'all-excluded',
      message:
        `nothing to scan — all ${String(enumerated)} staged file(s) are on the exclusion list: ` +
        nameThem(excluded),
    };
  }

  if (scanned === 0) {
    return {
      ok: false,
      reason: 'nothing-readable',
      message:
        `${String(scannable)} file(s) survived the exclusion list but none could be read — ` +
        'a scan of nothing finds nothing',
    };
  }

  return { ok: true, reason: 'scanned', message: `no secrets in ${String(scanned)} file(s)` };
}
