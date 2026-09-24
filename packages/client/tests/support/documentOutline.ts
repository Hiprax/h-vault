/**
 * The document outline, as a screen reader's heading and landmark menus see it.
 *
 * `test:a11y` runs axe over the rendered application and fails on these same
 * structural rules (`heading-order`, `landmark-unique`), but it does so late and
 * only over the states its walk reaches. These helpers let a unit test pin the
 * outline of one component in one state, and fail with WHICH step broke it
 * rather than with a boolean.
 */

/** Every `h1`…`h6` under `root`, as numeric levels in document order. */
export function headingLevels(root: ParentNode = document.body): number[] {
  return [...root.querySelectorAll('h1, h2, h3, h4, h5, h6')].map((heading) =>
    Number(heading.tagName.slice(1)),
  );
}

/** A heading that goes deeper than one level below the heading before it. */
interface SkippedHeadingLevel {
  /** Position in the list `headingLevels` returned. */
  index: number;
  from: number;
  to: number;
}

/**
 * The first step in `levels` that descends by more than one, or `null`.
 *
 * axe's rule, restated: the first heading may be at any level and a heading may
 * rise to ANY shallower level, but it may only go one level deeper than the
 * heading before it. `h1 → h3` skips a level; `h3 → h1 → h2` does not.
 */
export function firstSkippedHeadingLevel(levels: readonly number[]): SkippedHeadingLevel | null {
  for (let index = 1; index < levels.length; index += 1) {
    const from = levels[index - 1] ?? 0;
    const to = levels[index] ?? 0;
    if (to - from > 1) return { index, from, to };
  }
  return null;
}

/**
 * The accessible name a landmark is told apart by: `aria-label`, else the text
 * of whatever `aria-labelledby` names, else empty.
 *
 * Deliberately narrower than the full accessible-name computation. Landmarks in
 * this application are named by one of those two attributes or not at all, and a
 * landmark named some other way would read here as unnamed, which makes a
 * duplicate MORE likely to be reported, never less.
 */
function landmarkName(element: Element): string {
  const label = element.getAttribute('aria-label');
  if (label !== null) return label.trim();
  const labelledBy = element.getAttribute('aria-labelledby');
  if (labelledBy === null) return '';
  return labelledBy
    .split(/\s+/)
    .map((id) => element.ownerDocument.getElementById(id)?.textContent ?? '')
    .join(' ')
    .trim();
}

/**
 * Every `role name` pair that appears more than once among `landmarks`.
 *
 * Two landmarks of one role are fine only when their names tell them apart; two
 * unnamed `complementary` regions are indistinguishable in a landmark menu, which
 * is the `landmark-unique` finding.
 */
export function duplicateLandmarks(
  landmarks: readonly { role: string; element: Element }[],
): string[] {
  const seen = new Map<string, number>();
  for (const { role, element } of landmarks) {
    const key = `${role} "${landmarkName(element)}"`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  return [...seen].filter(([, count]) => count > 1).map(([key]) => key);
}
