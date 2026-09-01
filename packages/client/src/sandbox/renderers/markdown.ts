import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import remarkRehype from 'remark-rehype';
import rehypeRaw from 'rehype-raw';
import { decodeDocumentText } from '../decode';
import { documentShell, notice } from '../dom';
import { REMOTE_CONTENT_NOTICE, renderSanitizedMarkup } from './pipeline';

/**
 * Markdown, rendered the way GitHub renders it.
 *
 * That is a security statement as much as a typographic one. The sanitizer this
 * pipeline ends in — `rehype-sanitize` with its DEFAULT schema — is modelled on
 * GitHub's own `SanitizationFilter`, so "make a README look like a README" and
 * "let nothing hostile through" are the same configuration rather than two
 * settings pulling against each other. Tables, task lists, strikethrough,
 * autolinks and footnotes survive because GitHub allows them; `<script>`, `on*`
 * handlers, `javascript:` URLs and `style` attributes do not, because GitHub does
 * not.
 *
 * ---------------------------------------------------------------------------
 * WHY `rehype-raw`, AND WHY IT IS SAFE HERE
 * ---------------------------------------------------------------------------
 *
 * Markdown may contain literal HTML, and a README that says `<img src="badge">`
 * means it. `remark-rehype` with `allowDangerousHtml` carries that HTML through
 * as RAW nodes, and `rehype-raw` re-parses them into real elements — which is
 * exactly what makes them reachable by the sanitizer that runs next. Without
 * `rehype-raw` the raw HTML would either be dropped (a README that renders wrong)
 * or emitted unparsed (a README that renders as an injection). Parsing it and
 * then sanitising it is the only ordering that is both correct and safe, and it
 * is the ordering `renderSanitizedMarkup` enforces for both markup formats.
 *
 * A markdown-NATIVE `[text](javascript:alert(1))` never touches `rehype-raw` at
 * all — it arrives through `remark-rehype` as an ordinary link node — and is
 * stripped by the same sanitizer. That is the likelier real-world vector of the
 * two, and it is covered by the same single step rather than by a second check.
 */

/**
 * Render a markdown document.
 *
 * Asynchronous for exactly one reason: the syntax highlighter is loaded on
 * demand, and only for a document that actually contains a fenced block with a
 * declared language. A README without code — the commonest preview there is —
 * therefore never fetches the ~890 KiB of language grammars.
 */
export async function renderMarkdown(doc: Document, bytes: ArrayBuffer): Promise<HTMLElement> {
  const decoded = decodeDocumentText(bytes);
  const shell = documentShell(doc, 'markdown');
  if (decoded.warning !== null) shell.append(notice(doc, decoded.warning));

  const processor = unified()
    .use(remarkParse)
    .use(remarkGfm)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeRaw);
  const tree = processor.runSync(processor.parse(decoded.text));

  const { fragment, remoteContent } = await renderSanitizedMarkup(doc, tree);
  if (remoteContent) shell.append(notice(doc, REMOTE_CONTENT_NOTICE));

  const article = doc.createElement('article');
  article.className = 'hv-markdown';
  article.append(fragment);
  shell.append(article);
  return shell;
}
