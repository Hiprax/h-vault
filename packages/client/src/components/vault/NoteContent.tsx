import ReactMarkdown from 'react-markdown';
import type { INoteData } from '@hvault/shared';
import { isSafeUrl } from '../../lib/utils';
import { rehypeKeepAuthoredWhitespace } from '../../lib/markdownWhitespace';

/**
 * The ONE renderer for a secure note's content, in either format. It is used by
 * the item view and by the editor's Preview, so the preview shows exactly what
 * the saved note will look like.
 *
 * Both formats are drawn the way the editor draws them: in its monospace font
 * with `white-space: pre-wrap`, so runs of spaces and single line breaks survive
 * and text aligned in the editor stays aligned here. A Markdown note is still
 * rendered as Markdown (bold, headings, lists, links, code) on top of that. The
 * rehype step removes the whitespace the Markdown converter itself adds, which
 * would otherwise be blank lines, and the element styles are the `.note-markdown`
 * rules in `styles/globals.css`, since the Markdown's elements are not authored
 * here to carry classes.
 *
 * The safety of the Markdown path is unchanged: raw HTML is skipped, only the
 * listed elements render, and a link is kept only if `isSafeUrl` accepts it,
 * opening in a new tab with no opener.
 */
const NOTE_BOX_CLASSES =
  'rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 font-mono text-sm whitespace-pre-wrap wrap-break-word text-[hsl(var(--foreground))]';

const ALLOWED_ELEMENTS = [
  'p',
  'a',
  'strong',
  'em',
  'code',
  'pre',
  'ul',
  'ol',
  'li',
  'h1',
  'h2',
  'h3',
  'h4',
  'h5',
  'h6',
  'blockquote',
  'br',
  'hr',
];

const REHYPE_PLUGINS = [rehypeKeepAuthoredWhitespace];

export function NoteContent({ content, format }: { content: string; format: INoteData['format'] }) {
  if (format === 'plaintext') {
    return <div className={NOTE_BOX_CLASSES}>{content}</div>;
  }
  return (
    <div className={`note-markdown ${NOTE_BOX_CLASSES}`}>
      <ReactMarkdown
        skipHtml
        allowedElements={ALLOWED_ELEMENTS}
        rehypePlugins={REHYPE_PLUGINS}
        components={{
          a: ({ href, children }) => (
            <a
              href={href && isSafeUrl(href) ? href : '#'}
              target="_blank"
              rel="noopener noreferrer"
            >
              {children}
            </a>
          ),
          // A long line in a code block scrolls sideways, and a scrollable region
          // has to be reachable from the keyboard.
          pre: ({ children }) => <pre tabIndex={0}>{children}</pre>,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
