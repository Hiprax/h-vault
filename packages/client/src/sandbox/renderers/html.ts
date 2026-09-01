import { unified } from 'unified';
import rehypeParse from 'rehype-parse';
import { decodeDocumentText } from '../decode';
import { documentShell, notice } from '../dom';
import { renderSanitizedMarkup } from './pipeline';

/**
 * A stored HTML file, through the SAME sanitizer as markdown.
 *
 * `rehype-parse` is what makes this a separate renderer at all, and it is not
 * optional: without it a `.html` file would be handed to the markdown parser,
 * which would treat its tags as inline HTML inside paragraphs and mangle the
 * document's structure. From the parsed tree onwards the two formats are one
 * code path, because the security properties belong to that half.
 *
 * The banner is PERSISTENT rather than conditional. A stored web page is the
 * format most likely to look subtly wrong — no stylesheet, no scripts, no
 * images from the network — and a reader who is not told assumes the viewer is
 * broken and, worse, may assume they are seeing everything the page contains.
 * Saying it once, always, is cheaper than a per-document guess about whether the
 * absence is noticeable.
 */

/** What is missing from every HTML preview, said plainly and always. */
export const HTML_PREVIEW_NOTICE =
  'This is a stored web page, shown with its scripts, styles and remote content disabled. It will not look the way it did on the site it came from, and parts of it may be missing.';

/**
 * Render a stored HTML document.
 *
 * The whole document is parsed, including its `<head>`, and then `<head>`,
 * `<style>` and `<title>` are removed with their contents before sanitising —
 * see `pipeline.ts`, where that step lives and where the measured reason for it
 * is written down.
 */
export async function renderHtml(doc: Document, bytes: ArrayBuffer): Promise<HTMLElement> {
  const decoded = decodeDocumentText(bytes);
  const shell = documentShell(doc, 'html');
  if (decoded.warning !== null) shell.append(notice(doc, decoded.warning));
  shell.append(notice(doc, HTML_PREVIEW_NOTICE));

  const processor = unified().use(rehypeParse);
  // `remoteContent` is deliberately NOT consulted here, unlike in the markdown
  // renderer. The banner above already tells the reader that remote content is
  // disabled, unconditionally, for every stored page — so raising a second,
  // conditional notice saying the same thing would be noise, and its absence on
  // a page that happens to reference no image would read as a contradiction of
  // the banner rather than as extra precision.
  const { fragment } = await renderSanitizedMarkup(doc, processor.parse(decoded.text));

  const article = doc.createElement('article');
  article.className = 'hv-markdown';
  article.append(fragment);
  shell.append(article);
  return shell;
}
