/**
 * `NoteContent`: a secure note is shown the way its author typed it.
 *
 * The note editor is a monospace textarea, and people align text in it with
 * runs of spaces ("Field 1:        Test" over "Field 123123:   Test 2"). The view
 * used to lose that: Plain Text kept the spaces but drew them in the
 * proportional font (columns about 20px apart), and Markdown, the default,
 * collapsed the spaces, joined the two lines into one, and drew them in the
 * proportional font too. Both formats now use the editor's font with
 * `white-space: pre-wrap`, and Markdown keeps its formatting on top.
 *
 * `textContent` is compared with `toBe` throughout, never with Testing Library's
 * text matchers: those trim and collapse whitespace by default, which is the
 * very defect this file exists to catch.
 *
 * The rendering itself (column positions, computed fonts, contrast) is measured
 * in a real browser by `e2e/a11y.spec.ts`; jsdom does not lay out.
 */
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import { NoteContent } from '../../src/components/vault/NoteContent';

const ALIGNED = 'Field 1:        Test\nField 123123:   Test 2';

function renderNote(content: string, format: 'markdown' | 'plaintext') {
  const { container } = render(<NoteContent content={content} format={format} />);
  const box = container.firstElementChild;
  if (!(box instanceof HTMLElement)) throw new Error('NoteContent rendered no element');
  return box;
}

/** Every text child of `node` that holds nothing but whitespace. */
function whitespaceOnlyChildren(node: Node): string[] {
  return [...node.childNodes]
    .filter((child) => child.nodeType === Node.TEXT_NODE && /^\s*$/.test(child.textContent ?? ''))
    .map((child) => JSON.stringify(child.textContent));
}

describe('a Plain Text note', () => {
  it('is drawn in the editor font with every space and line break kept', () => {
    const box = renderNote(ALIGNED, 'plaintext');
    expect(box.textContent).toBe(ALIGNED);
    expect(box.classList).toContain('font-mono');
    expect(box.classList).toContain('whitespace-pre-wrap');
    expect(box.classList).toContain('wrap-break-word');
    expect(box.classList).toContain('text-sm');
    // Plain text is never interpreted.
    expect(renderNote('**not bold**', 'plaintext').querySelector('strong')).toBeNull();
    expect(renderNote('**not bold**', 'plaintext').textContent).toBe('**not bold**');
  });
});

describe('a Markdown note', () => {
  it("keeps the author's aligned columns and line break, in the editor font", () => {
    const box = renderNote(ALIGNED, 'markdown');
    const paragraphs = box.querySelectorAll('p');
    expect(paragraphs).toHaveLength(1);
    expect(paragraphs[0]?.textContent).toBe(ALIGNED);
    expect(box.textContent).toBe(ALIGNED);
    for (const token of [
      'note-markdown',
      'font-mono',
      'whitespace-pre-wrap',
      'wrap-break-word',
      'text-sm',
    ]) {
      expect(box.classList, token).toContain(token);
    }
    // The typography plugin these named was never installed: they styled nothing.
    expect(box.className).not.toMatch(/\bprose\b/);
  });

  it('gives a hard break exactly one line', () => {
    const paragraph = renderNote('one  \ntwo', 'markdown').querySelector('p');
    expect(paragraph?.querySelectorAll('br')).toHaveLength(1);
    expect(paragraph?.textContent).toBe('onetwo');
    expect(whitespaceOnlyChildren(paragraph as Node)).toEqual([]);
  });

  it('adds no blank line between blocks, list items or quoted paragraphs', () => {
    const box = renderNote(
      '### Title\n\nPara   one\n\n- a\n- b\n\n1. first\n\n> quoted   text\n> second\n\n---',
      'markdown',
    );
    expect(whitespaceOnlyChildren(box)).toEqual([]);
    for (const container of box.querySelectorAll('ul, ol, li, blockquote')) {
      expect(whitespaceOnlyChildren(container), container.tagName).toEqual([]);
    }
    expect(box.querySelector('h3')?.textContent).toBe('Title');
    expect(box.querySelector('p')?.textContent).toBe('Para   one');
    expect([...box.querySelectorAll('ul > li')].map((li) => li.textContent)).toEqual(['a', 'b']);
    expect(box.querySelector('ol > li')?.textContent).toBe('first');
    expect(box.querySelector('blockquote p')?.textContent).toBe('quoted   text\nsecond');
    expect(box.querySelector('hr')).not.toBeNull();
  });

  it('keeps inline spacing inside a list item, including between two pieces of raw HTML', () => {
    const box = renderNote('- **a**   *b*\n- <b>c</b> <b>d</b>', 'markdown');
    const items = [...box.querySelectorAll('li')].map((li) => li.textContent);
    // Raw HTML is skipped, never rendered, and the space the author put between
    // the two pieces survives the skip.
    expect(items).toEqual(['a   b', 'c d']);
    expect(box.querySelector('b')).toBeNull();
  });

  it('shows a code block verbatim, and lets the keyboard reach it to scroll', () => {
    const box = renderNote('```\na    b\n  c\n```', 'markdown');
    const block = box.querySelector('pre');
    expect(block?.textContent).toBe('a    b\n  c\n');
    expect(block?.tabIndex).toBe(0);
    expect(block?.getAttribute('tabindex')).toBe('0');
  });

  it('still refuses unsafe links and opens safe ones in a new tab, without an opener', () => {
    const box = renderNote(
      '[ok](https://example.com) [bad](javascript:alert(1)) [chat](irc://example.com/room) [here](/relative)',
      'markdown',
    );
    const [safe, unsafe, irc, relative] = [...box.querySelectorAll('a')];
    expect(safe?.getAttribute('href')).toBe('https://example.com');
    expect(safe?.getAttribute('target')).toBe('_blank');
    expect(safe?.getAttribute('rel')).toBe('noopener noreferrer');
    expect(unsafe?.getAttribute('href')).toBe('#');
    // react-markdown's own URL filter lets these through; the note's stricter
    // rule (http, https, mailto) is what turns them into a dead link.
    expect(irc?.getAttribute('href')).toBe('#');
    expect(relative?.getAttribute('href')).toBe('#');
  });

  it('renders every element the note allows, and nothing it does not', () => {
    const box = renderNote(
      [
        '# one',
        '## two',
        '### three',
        '#### four',
        '##### five',
        '###### six',
        '**strong** *em* `code`',
        '- item',
        '1. item',
        '> quote',
        '```\nblock\n```',
        '---',
        '![picture](https://example.com/x.png) ~~struck~~',
      ].join('\n\n'),
      'markdown',
    );
    for (const tag of [
      'h1',
      'h2',
      'h3',
      'h4',
      'h5',
      'h6',
      'strong',
      'em',
      'code',
      'ul',
      'ol',
      'li',
      'blockquote',
      'pre',
      'hr',
    ]) {
      expect(box.querySelector(tag), tag).not.toBeNull();
    }
    // An image is not on the list, so it is dropped rather than fetched.
    expect(box.querySelector('img')).toBeNull();
  });

  it('never renders raw HTML as markup', () => {
    const box = renderNote(
      '<img src="x" onerror="alert(1)">\n\n<script>alert(1)</script>\n\ntext',
      'markdown',
    );
    expect(box.querySelector('img, script')).toBeNull();
    expect(box.textContent).toBe('text');
  });
});
