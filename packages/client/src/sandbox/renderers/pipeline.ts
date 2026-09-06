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
 * 4. **Name every checkbox.** GFM renders a task list as a disabled
 *    `<input type="checkbox">` with the item's text beside it as a SIBLING, and
 *    the sanitizer rewrites every other surviving `<input>` into one of the same
 *    shape. Neither carries an accessible name, which axe grades `critical`
 *    ("Form elements must have labels") — measured, on a plain README's task
 *    list. See {@link nameCheckboxes}.
 * 5. **Become DOM NODES, never a string.** There is deliberately no
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
 * A reference the browser would fetch from an origin other than this document's.
 *
 * RESOLVED rather than prefix-matched, and that is a correction rather than a
 * refinement. The three `startsWith` calls this replaces read `//`, `http://`
 * and `https://`, which is not the grammar the URL parser implements: after a
 * special scheme's colon, ANY two characters drawn from `/` and `\` enter the
 * authority, so `https:\\host/x` and `https:/\host/x` are the same request as
 * `https://host/x`. `hast-util-sanitize` passes all three, because its protocol
 * check reads only as far as the colon (measured against the installed
 * library), so those spellings survived into the document and the sweep did not
 * see them — the reader got a broken image and no sentence. ONE slash is a
 * relative path and stays local, which is the boundary both spellings sit a
 * single character from, and which is why a wider prefix list would have been
 * another guess rather than a fix.
 *
 * Asking `URL` is exact where any prefix list is an approximation, and it needs
 * no regular expression — which is what the note this replaces was really about
 * (the obvious pattern is flagged by `eslint-plugin-security` as potentially
 * super-linear, and arguing with an analyzer over an input this document does
 * not control is a bad trade).
 *
 * Scoped to `http:`/`https:` and to a DIFFERENT origin, because the notice is
 * about a third party learning you opened your copy. `data:` and `blob:` are
 * named by `img-src` and DO render, so announcing them as blocked would be a
 * lie; the document's own origin is what `img-src 'self'` admits, and tells
 * nobody anything. A value `URL` refuses is not a request either.
 */
function isRemoteUrl(value: string, base: URL): boolean {
  let resolved: URL;
  try {
    resolved = new URL(value, base);
  } catch {
    return false;
  }
  if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return false;
  return resolved.origin !== base.origin;
}

/**
 * What separates one `srcset` candidate from the next, and a candidate from its
 * descriptor.
 *
 * A candidate URL may not contain whitespace — that is what makes `srcset`
 * parseable at all — so splitting on runs of whitespace and commas together
 * yields every URL, plus the descriptors (`2x`, `640w`), and a descriptor can
 * never be mistaken for an absolute URL. A URL containing a comma splits into
 * pieces, and the first piece still carries the scheme, which is all
 * {@link isRemoteUrl} reads.
 */
const SRCSET_SEPARATOR = /[\s,]+/;

/**
 * Does this element ask the browser for something off the network?
 *
 * Both attributes on every element, rather than one attribute per tag name,
 * because the pairing is what a per-tag rule keeps getting wrong: `srcset` is a
 * LIST, and its remote candidate is very often not the first one, so testing the
 * whole attribute value finds nothing for `srcset="local.png 1x, https://… 2x"`.
 *
 * `HTMLElement` and not `Element`: this module imports `Element` FROM HAST, so
 * the bare name means a syntax tree node here — the same trap
 * {@link checkboxLabel} carries the note for, and one `tsc` catches while the
 * vitest suite never could.
 */
function referencesRemoteContent(element: HTMLElement, base: URL): boolean {
  if (isRemoteUrl(element.getAttribute('src') ?? '', base)) return true;
  return (element.getAttribute('srcset') ?? '')
    .split(SRCSET_SEPARATOR)
    .some((candidate) => isRemoteUrl(candidate, base));
}

/**
 * The longest accessible name a task item may contribute, in characters.
 *
 * A list item can be a paragraph, and an accessible name is read out in full
 * before anything else about the control — so an unbounded one turns a checkbox
 * into a minute of speech. Cut with an ellipsis rather than at a word boundary:
 * the item's own text follows immediately and carries the rest.
 */
const MAX_CHECKBOX_LABEL_LENGTH = 120;

/** The name for a checkbox that has no list item to take one from. */
const UNNAMED_CHECKBOX_LABEL = 'Checkbox in this document';

/** List elements whose text belongs to a NESTED item rather than to this one. */
const NESTED_LIST_TAGS: ReadonlySet<string> = new Set(['ul', 'ol']);

/**
 * The accessible name for one rendered checkbox: its own list item's text.
 *
 * Nested lists are skipped, because a task with sub-tasks under it would
 * otherwise take the whole subtree as its name — the deeper the list, the longer
 * the name, and the outermost item would recite the entire branch.
 *
 * The parameter is an `HTMLElement` rather than a DOM `Element`, and that is not
 * a preference: this module imports `Element` FROM HAST, so the bare name means
 * a syntax tree node here and a DOM element three lines later would compile
 * against the wrong type entirely — measured, as two type errors that the vitest
 * suite could never have shown, because it does not type-check.
 */
function checkboxLabel(checkbox: HTMLElement): string {
  const item = checkbox.closest('li');
  if (!item) return UNNAMED_CHECKBOX_LABEL;
  let text = '';
  for (const node of item.childNodes) {
    const nested =
      node.nodeType === Node.ELEMENT_NODE &&
      NESTED_LIST_TAGS.has((node as HTMLElement).tagName.toLowerCase());
    if (!nested) text += node.textContent ?? '';
  }
  const collapsed = text.replace(/\s+/g, ' ').trim();
  if (collapsed === '') return UNNAMED_CHECKBOX_LABEL;
  return collapsed.length <= MAX_CHECKBOX_LABEL_LENGTH
    ? collapsed
    : `${collapsed.slice(0, MAX_CHECKBOX_LABEL_LENGTH)}\u2026`;
}

/**
 * Give every rendered checkbox an accessible name.
 *
 * A REAL defect, found by the accessibility gate scanning inside the preview
 * frame and fixed here rather than excluded there. Two kinds of checkbox reach
 * this point and both arrive unnamed:
 *
 *   * GFM's task-list marker. `remark-gfm` emits
 *     `<input type="checkbox" disabled>` and puts the task's text NEXT TO it, as
 *     a sibling of the input rather than as a label — so a screen reader
 *     announces "checkbox, checked" with nothing saying what is checked. axe
 *     grades that `critical`, and it fires on the plainest README there is.
 *   * A form field the sanitizer neutralised. The default schema rewrites every
 *     surviving `<input>` into a disabled checkbox, which is how a stored HTML
 *     document's form is defused; those have no list item to take a name from
 *     and get {@link UNNAMED_CHECKBOX_LABEL}.
 *
 * `aria-label` rather than a wrapping `<label>`: the announcement is the same,
 * and restructuring the sanitized tree to move nodes inside a new element is a
 * far larger change to make on markup a document controls. The state is left
 * alone — `checked` and `disabled` are what a reader needs after the name, and
 * neither `role="presentation"` nor `aria-hidden` could keep them.
 *
 * Runs on the DOM rather than on the hast tree, beside the `rel` pass below, for
 * one reason: the text it reads is the item's RENDERED text, and computing that
 * from a tree would be a second, divergent implementation of `textContent`.
 */
function nameCheckboxes(fragment: DocumentFragment): void {
  for (const checkbox of fragment.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')) {
    checkbox.setAttribute('aria-label', checkboxLabel(checkbox));
  }
}

/**
 * Make `toDom`'s return usable as a fragment, whatever shape it came back in.
 *
 * There WAS an `as DocumentFragment` here, and the cast was wrong rather than
 * merely lazy. `hast-util-to-dom` decides the root's shape from the TREE and not
 * from the options: `lib/index.js:142` sets `rootIsDocument = children.length
 * === 0`, and `:168-172` then builds a `Document` — WITHOUT consulting
 * `fragment: true` at all. Appending a `Document` to an element throws
 * `HierarchyRequestError`, `sandbox.ts` catches it, and the reader is told "The
 * document could not be displayed."
 *
 * Two entirely benign documents land there, and both were measured rather than
 * imagined:
 *
 *   * a `.md` whose only content is an HTML comment. The default sanitize schema
 *     sets no `allowComments`, so the one node the file has is dropped and the
 *     root is left empty.
 *   * a `.html` of `<html><head><title>x</title></head><body></body></html>`.
 *     `head` and `title` are removed whole by {@link RAW_TEXT_ELEMENTS}, and
 *     `html` and `body` are absent from the default schema's tag list so they
 *     are unwrapped. Again: a root with no children.
 *
 * An empty document is a document. It renders as an empty page, which is the
 * truth about the file, and never as a failure.
 *
 * Written as a normalisation rather than as an `if (sanitized.children.length
 * === 0)` short-circuit, because the emptiness is not the invariant worth
 * depending on — the LIBRARY's choice of root is, and it makes that choice for a
 * second reason too (a tree whose first child is an `html` element). That branch
 * is unreachable through this pipeline today, since the default schema does not
 * allow `html` and unwraps it, but a normalisation costs one comparison and
 * survives a schema that later does.
 *
 * `instanceof` rather than a `nodeType` comparison because it NARROWS: the
 * declared return is a six-member union, and narrowing is what lets the common
 * path stay a zero-copy return of the very object the library built. It is
 * realm-correct here because `doc` is always the CURRENT realm's document — the
 * frame's own in production, jsdom's own under vitest — so the nodes and the
 * `DocumentFragment` being compared against come from one realm. A `doc` from
 * somewhere else would be a different call site than this file has ever had.
 */
function asFragment(doc: Document, rendered: ReturnType<typeof toDom>): DocumentFragment {
  if (rendered instanceof DocumentFragment) return rendered;
  const fragment = doc.createDocumentFragment();
  // Spread first: `childNodes` is LIVE, and `append` moves each node out of the
  // list it is being read from.
  fragment.append(...rendered.childNodes);
  return fragment;
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

  const fragment = asFragment(doc, toDom(sanitized, { fragment: true, document: doc }));

  // Every link is opened by the APPLICATION, after the user confirms, and this
  // frame is granted neither `allow-popups` nor `allow-top-navigation`, so it
  // could not follow one itself. `rel` is still set, because the day a link is
  // opened by anything else, these are the three tokens that should already be
  // on it: no opener handle, no referrer, and no endorsement of a document
  // nobody in this project wrote.
  for (const anchor of fragment.querySelectorAll('a')) {
    anchor.setAttribute('rel', 'noopener noreferrer nofollow');
  }

  nameCheckboxes(fragment);

  // Every element carrying either attribute, not `img[src]` alone. The default
  // sanitize schema allows `<picture>` and `<source>`, allows `source: ['srcSet']`,
  // and applies NO protocol filter to `srcSet` (its `protocols` map names `src`,
  // `href`, `cite` and `longDesc` only) — so a remote `<picture><source srcset>`
  // survives whole, is refused by `img-src`, and used to leave the reader a
  // broken image and no sentence explaining it, which is the exact outcome the
  // notice below exists to prevent.
  //
  // An ATTRIBUTE selector rather than a list of tag names, because the schema is
  // the thing that decides which elements can carry these and it is not ours: it
  // allows `source[srcSet]` today and admits nothing else, but a version that
  // also allowed `source[src]`, or `img[srcSet]`, would silently reopen this. The
  // sweep costs one pass. `blob:`, `data:`, every relative path and the
  // document's OWN origin all fail {@link isRemoteUrl}, so an ordinary README
  // raises nothing. The one shape it can over-report is a `data:` candidate in a
  // `srcset` whose payload carries a raw comma — which is not a legal candidate,
  // and which a browser splits the same way, so the banner would sit beside an
  // image it had already failed to select.
  //
  // Telling the reader is the ENTIRE fix. `img-src` in
  // `packages/server/src/config/sandboxCsp.ts` names no host and must not gain
  // one; the request is already blocked, and what was missing was the sentence.
  // Parsed once. Every candidate is resolved against it, and that resolution is
  // the only per-element cost in this loop.
  const base = new URL(doc.baseURI);
  const remoteContent = [...fragment.querySelectorAll<HTMLElement>('[src], [srcset]')].some(
    (element) => referencesRemoteContent(element, base),
  );

  return { fragment, remoteContent };
}

/** The sentence a reader sees when a document asks for something off the network. */
export const REMOTE_CONTENT_NOTICE =
  'This document links to images stored somewhere else on the internet. They are not loaded: fetching one would tell whoever wrote the document that you opened your copy.';
