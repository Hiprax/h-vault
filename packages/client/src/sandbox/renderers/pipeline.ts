import { unified } from 'unified';
import rehypeSanitize from 'rehype-sanitize';
import { toDom } from 'hast-util-to-dom';
import type { Element, Root, RootContent } from 'hast';

/**
 * The tail every markup renderer shares: sanitize, highlight, become DOM.
 *
 * `markdown.ts` and `html.ts` differ only in how they PARSE — remark plus
 * `rehype-raw` for one, `rehype-parse` for the other — and from the moment there
 * is a hast tree they must be identical, because the security properties belong
 * to this half. One definition, so a change to the sanitizer or the DOM
 * conversion cannot reach one format and miss the other.
 *
 * ---------------------------------------------------------------------------
 * THE ORDER, AND WHY EACH STEP IS WHERE IT IS
 * ---------------------------------------------------------------------------
 *
 * 1. **Drop the raw-text elements.** See {@link RAW_TEXT_ELEMENTS}: this is a
 *    strictly SUBTRACTIVE step that runs before the sanitizer, and the reason it
 *    has to exist is measured rather than theoretical.
 * 2. **Sanitize, with `rehype-sanitize`'s DEFAULT schema, before anything else
 *    touches the tree.** The default schema follows GitHub's own sanitation
 *    rules, which is exactly why a README rendered through it looks like a
 *    README: tables, task lists, strikethrough, autolinks and footnotes survive,
 *    while `<script>`, `on*` handlers, `javascript:` URLs and `style` attributes
 *    do not. Sanitising and rendering-like-GitHub are the same pipeline here,
 *    not two goals in tension.
 * 3. **Highlight AFTER sanitising, and only when there is something to
 *    highlight.** `rehype-highlight` adds `hljs-*` classes, and the default
 *    schema would strip most of them, so running it second is what makes fenced
 *    code colour survive. It is safe in that order because it only ever splits
 *    existing TEXT into spans — it introduces no attribute a document controls.
 *    It is loaded by a DYNAMIC import behind {@link hasHighlightableCode},
 *    because it pulls the whole highlight.js common language set — measured at
 *    ~890 KiB, by a wide margin the largest thing this document can download —
 *    and the commonest preview of all, a README with no fenced code, needs none
 *    of it.
 * 4. **Become DOM NODES, never a string.** There is deliberately no
 *    `rehype-stringify` anywhere in this feature. Serialising the sanitized tree
 *    and assigning it to `innerHTML` re-parses it, and the second parse is where
 *    mutation XSS lives: the parser recovers something the sanitizer's first pass
 *    believed it had removed. Building the DOM directly removes that class of
 *    bug rather than defending against it.
 */

/**
 * Elements whose children are RAW TEXT rather than markup, and which the
 * sanitizer therefore cannot simply unwrap.
 *
 * `hast-util-sanitize` drops a disallowed ELEMENT but KEEPS its children, which
 * is right for `<div>` and wrong for these: measured on `rehype-parse` output, a
 * `<style>body{color:red}</style>` in a stored `.html` file becomes the literal
 * text `body{color:red}` at the top of the rendered page, and `<title>` does the
 * same. Nothing is executed — the isolation and the policy both hold — but the
 * reader is shown a stylesheet as if it were the document's first paragraph.
 *
 * Removing the element AND its subtree before sanitising fixes that. It cannot
 * weaken anything: the step only deletes nodes, so every node the sanitizer sees
 * is a node it would have seen anyway, and it never runs on a tree the sanitizer
 * has already approved.
 *
 * `script` is listed for completeness rather than necessity (its text is already
 * dropped, measured), because a set that is obviously "the raw-text elements"
 * is easier to keep right than one with a documented exception in it.
 */
const RAW_TEXT_ELEMENTS: ReadonlySet<string> = new Set([
  'head',
  'script',
  'style',
  'title',
  'noscript',
  'template',
]);

/** Is this child an element that must be removed whole? */
function isRawTextElement(node: RootContent): boolean {
  return node.type === 'element' && RAW_TEXT_ELEMENTS.has(node.tagName);
}

/** Remove every raw-text element, at every depth. */
function dropRawTextElements(parent: Root | Element): void {
  parent.children = parent.children.filter((child) => !isRawTextElement(child));
  for (const child of parent.children) {
    if (child.type === 'element') dropRawTextElements(child);
  }
}

/** What a markup render produced, and what the reader has to be told about it. */
export interface MarkupRender {
  readonly fragment: DocumentFragment;
  /**
   * True when the document asks for an image from the network.
   *
   * The policy this document is served under has no http or https source for
   * `img-src`, so the request never happens — which is INTENDED, because a
   * remote fetch from a preview is a read receipt for a private file, sent to
   * whoever wrote the document. It is reported rather than repaired: a reader
   * who is not told sees only a broken image and blames the viewer.
   */
  readonly remoteContent: boolean;
}

/**
 * Does the sanitized tree contain a fenced block that declares its language?
 *
 * `rehype-highlight` with `detect: false` acts only on a `<code>` carrying a
 * `language-*` class, so this is precisely the question "would loading the
 * highlighter change anything at all". Asking it before the import is what keeps
 * ~890 KiB of language grammars off the wire for a document that has no code in
 * it — which is most of them.
 *
 * The class survives sanitising: the default schema allows `className` on
 * `code` restricted to `language-*`, the same allowance that makes GitHub's
 * fenced blocks work.
 */
function hasHighlightableCode(node: Root | Element): boolean {
  for (const child of node.children) {
    if (child.type !== 'element') continue;
    if (child.tagName === 'code') {
      const classes = child.properties.className;
      if (
        Array.isArray(classes) &&
        classes.some((name) => typeof name === 'string' && name.startsWith('language-'))
      ) {
        return true;
      }
    }
    if (hasHighlightableCode(child)) return true;
  }
  return false;
}

/**
 * An absolute http(s) or protocol-relative URL, i.e. one the browser would fetch.
 *
 * Prefix comparisons rather than one regular expression: the obvious pattern
 * here is flagged by `eslint-plugin-security` as potentially super-linear, and
 * arguing with an analyzer over an input this document does not control is a
 * worse trade than three `startsWith` calls that cannot be wrong.
 */
function isRemoteUrl(value: string): boolean {
  const lower = value.toLowerCase();
  return lower.startsWith('//') || lower.startsWith('http://') || lower.startsWith('https://');
}

/**
 * Sanitize a hast tree, highlight it, and turn it into DOM nodes.
 *
 * The one entry point both markup renderers use. Anything added here reaches
 * both; anything added to only one of them is a divergence in the half where the
 * security properties live, which is why this function takes the parsed tree
 * rather than the text.
 */
export async function renderSanitizedMarkup(doc: Document, tree: Root): Promise<MarkupRender> {
  dropRawTextElements(tree);

  let sanitized = unified().use(rehypeSanitize).runSync(tree);

  if (hasHighlightableCode(sanitized)) {
    const { default: rehypeHighlight } = await import('rehype-highlight');
    // `detect: false`: highlight a fenced block only when the document SAYS what
    // language it is. Automatic detection guesses, and a guess that is wrong
    // colours a shell script as Perl — which reads as a broken viewer rather
    // than as an absent feature. An unknown language degrades to no
    // highlighting, with no error, which is the intended graceful path.
    // Narrowed back to `Root`: a bare `unified()` carries no parser, so its
    // `runSync` is typed as returning `Node`. `rehype-highlight` is a
    // hast-to-hast transform over the tree just handed to it, so this states the
    // pipeline's own contract rather than an assumption about someone's data.
    sanitized = unified().use(rehypeHighlight, { detect: false }).runSync(sanitized) as Root;
  }

  const fragment = toDom(sanitized, { fragment: true, document: doc }) as DocumentFragment;

  // Every link is opened by the APPLICATION, after the user confirms, and this
  // frame is granted neither `allow-popups` nor `allow-top-navigation`, so it
  // could not follow one itself. `rel` is still set, because the day a link is
  // opened by anything else, these are the three tokens that should already be
  // on it: no opener handle, no referrer, and no endorsement of a document
  // nobody in this project wrote.
  for (const anchor of fragment.querySelectorAll('a')) {
    anchor.setAttribute('rel', 'noopener noreferrer nofollow');
  }

  let remoteContent = false;
  for (const image of fragment.querySelectorAll('img')) {
    if (isRemoteUrl(image.getAttribute('src') ?? '')) remoteContent = true;
  }

  return { fragment, remoteContent };
}

/** The sentence a reader sees when a document asks for something off the network. */
export const REMOTE_CONTENT_NOTICE =
  'This document links to images stored somewhere else on the internet. They are not loaded: fetching one would tell whoever wrote the document that you opened your copy.';
