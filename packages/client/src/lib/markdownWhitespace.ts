import type { Element, ElementContent, Root, RootContent } from 'hast';

/**
 * A rehype step that leaves a note's Markdown with only the whitespace its
 * author typed.
 *
 * A note is shown with `white-space: pre-wrap` (see `NoteContent`), so a run of
 * spaces and a single line break survive onto the screen exactly as they were
 * written, which is how columns aligned with spaces in the monospace editor line
 * up in the view as well. Standard Markdown rendering collapses both, and joins
 * the lines of a paragraph into one.
 *
 * `pre-wrap` alone is not enough, because `mdast-util-to-hast` adds whitespace
 * of its own, and under `pre-wrap` every piece of it becomes a blank line nobody
 * typed. This removes exactly those pieces:
 *
 *   - the `"\n"` it puts between the blocks of the root, a list and a quote.
 *     Those containers hold only blocks, so any whitespace-only text in them is
 *     the converter's;
 *   - the `"\n"` it puts inside a list item, around the item's blocks and at its
 *     edges. A TIGHT item inlines its paragraph, so whitespace between two
 *     INLINE children is the author's and stays, and it is judged only against
 *     real elements: raw HTML is removed later by `skipHtml`, so in
 *     `- <b>a</b> <b>b</b>` the space between two raw nodes is the one that keeps
 *     "a b" from becoming "ab";
 *   - the `"\n"` it emits after every `<br>`, which would otherwise make a hard
 *     break two lines.
 *
 * Everything else is kept, and nothing inside `pre` or `code` is looked at: a
 * code block is shown verbatim.
 */
const CONTAINERS_OF_BLOCKS = new Set(['ul', 'ol', 'blockquote']);

const BLOCK_ELEMENTS = new Set([
  'p',
  'ul',
  'ol',
  'pre',
  'blockquote',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'hr',
]);

type Node = RootContent | ElementContent;

function isWhitespaceOnly(node: Node): boolean {
  return node.type === 'text' && /^[\t\n\f\r ]*$/.test(node.value);
}

/** An edge counts as a block boundary: nothing inline sits beyond it. */
function isBlockOrEdge(node: Node | undefined): boolean {
  return node === undefined || (node.type === 'element' && BLOCK_ELEMENTS.has(node.tagName));
}

function keptChildren<T extends Node>(parent: Root | Element, children: T[]): T[] {
  const dropAllWhitespace = parent.type === 'root' || CONTAINERS_OF_BLOCKS.has(parent.tagName);
  const inListItem = parent.type === 'element' && parent.tagName === 'li';
  const kept: T[] = [];
  children.forEach((child, index) => {
    if (isWhitespaceOnly(child)) {
      if (dropAllWhitespace) return;
      if (
        inListItem &&
        (isBlockOrEdge(children[index - 1]) || isBlockOrEdge(children[index + 1]))
      ) {
        return;
      }
    }
    const previous = kept[kept.length - 1];
    if (
      child.type === 'text' &&
      previous?.type === 'element' &&
      previous.tagName === 'br' &&
      child.value.startsWith('\n')
    ) {
      const rest = child.value.slice(1);
      if (rest !== '') kept.push({ ...child, value: rest });
      return;
    }
    kept.push(child);
  });
  return kept;
}

function visit(parent: Root | Element): void {
  if (parent.type === 'element' && (parent.tagName === 'pre' || parent.tagName === 'code')) return;
  parent.children = keptChildren(parent, parent.children);
  for (const child of parent.children) {
    if (child.type === 'element') visit(child);
  }
}

/** The rehype plugin: `rehypePlugins={[rehypeKeepAuthoredWhitespace]}`. */
export function rehypeKeepAuthoredWhitespace(): (tree: Root) => void {
  return (tree) => {
    visit(tree);
  };
}
