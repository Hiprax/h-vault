/**
 * LCOV totals, parsed once for the two gates that read them.
 *
 * `ratchet-check.mjs` compares a package's coverage against `baseline.json`, and
 * `coverage-check.mjs` enforces the same floors at the moment it has the number.
 * Two readers of one artifact is deliberate — the gate enforces its own floor and
 * the ratchet is the second reader, exactly as `mutation-gate.mjs` and the
 * ratchet split the mutation score — but two PARSERS of one artifact would not
 * be: they would eventually disagree about what "the branch percentage" means,
 * and the gate that happened to be more generous would be the one that ran.
 *
 * LCOV rather than the Cobertura document beside it, for one specific reason:
 * only LCOV carries the `SF:` records that enumerate the files actually
 * instrumented, and that set is the scope-narrowing defence both gates depend
 * on. Cobertura is kept for `diff-cover`, which reads it natively.
 */

/** A percentage to two decimals, or `undefined` when the denominator is zero. */
export const pct = (hit, total) => (total ? +((hit / total) * 100).toFixed(2) : undefined);

/**
 * @param {string} text        the contents of an `lcov.info`
 * @param {(p: string) => string} [normalize]  applied to every `SF:` path
 * @returns {{line?: number, branch?: number, function?: number,
 *            linesTotal?: number, filesMeasured?: string[]}}
 */
export function parseLcov(text, normalize = (p) => p) {
  const files = [...text.matchAll(/^SF:(.+)$/gm)].map((m) => normalize(m[1]));
  const sum = (re) => [...text.matchAll(re)].reduce((n, m) => n + Number(m[1]), 0);
  const lf = sum(/^LF:(\d+)$/gm);
  const lh = sum(/^LH:(\d+)$/gm);
  const brf = sum(/^BRF:(\d+)$/gm);
  const brh = sum(/^BRH:(\d+)$/gm);
  const fnf = sum(/^FNF:(\d+)$/gm);
  const fnh = sum(/^FNH:(\d+)$/gm);
  return {
    line: pct(lh, lf),
    branch: pct(brh, brf),
    function: pct(fnh, fnf),
    linesTotal: lf || undefined,
    filesMeasured: files.length ? [...new Set(files)].sort() : undefined,
  };
}
