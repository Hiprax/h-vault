/**
 * knip's JSON report → the counts and findings the `deadcode` gate adjudicates.
 *
 * Pure, so `packages/server/tests/static-floor-gates.test.ts` can drive the one
 * property that matters here: **a category this file has never heard of is still
 * counted.** knip renames issue types between majors (`classMembers` became
 * `namespaceMembers`), and a fixed list of keys silently drops the renamed one —
 * the gate then prints "0 unused" while knip itself is exiting 1. So the loop
 * reads every array-valued key and falls back to `unmapped:<key>`; the map below
 * exists only to give the baseline stable field names and to keep every known
 * category present at zero, because a baseline field with no fresh number is an
 * unmeasured field, which the ratchet treats as a failure.
 */

/** knip's per-file issue keys, and the label each gets in the report. */
export const KNIP_LABELS = {
  files: 'unusedFiles',
  dependencies: 'unusedDependencies',
  devDependencies: 'unusedDevDependencies',
  optionalPeerDependencies: 'unusedOptionalPeerDependencies',
  unlisted: 'unlistedDependencies',
  binaries: 'unlistedBinaries',
  unresolved: 'unresolvedImports',
  exports: 'unusedExports',
  types: 'unusedTypes',
  namespaceMembers: 'unusedNamespaceMembers',
  enumMembers: 'unusedEnumMembers',
  classMembers: 'unusedClassMembers',
  duplicates: 'duplicateExports',
  catalog: 'unusedCatalogEntries',
  catalogReferences: 'unlistedCatalogReferences',
};

/**
 * @param {{file?: string, [category: string]: unknown}[]} issues  knip's `issues` array
 * @returns {{counts: Record<string, number>, findings: {category: string, file: string, name?: string, line?: number}[]}}
 */
export function summariseKnip(issues) {
  const counts = Object.fromEntries(Object.values(KNIP_LABELS).map((label) => [label, 0]));
  const findings = [];

  for (const issue of issues ?? []) {
    const file = String(issue.file ?? '');
    for (const [category, entries] of Object.entries(issue)) {
      if (!Array.isArray(entries) || entries.length === 0) continue;
      const label = KNIP_LABELS[category] ?? `unmapped:${category}`;
      counts[label] = (counts[label] ?? 0) + entries.length;
      for (const entry of entries) {
        // knip's JSON reporter emits `{name, line, col, pos}` for a symbol and a
        // bare string for a file.
        const name = typeof entry === 'string' ? entry : (entry?.name ?? '');
        findings.push({
          category: label,
          file,
          ...(name ? { name: String(name) } : {}),
          ...(entry && typeof entry === 'object' && entry.line ? { line: Number(entry.line) } : {}),
        });
      }
    }
  }

  return { counts, findings };
}
