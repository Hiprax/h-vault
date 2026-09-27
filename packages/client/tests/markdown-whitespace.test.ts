/**
 * `rehypeKeepAuthoredWhitespace`: a note's Markdown keeps the spacing its author
 * typed.
 *
 * A note is shown with `white-space: pre-wrap`, so every space and line break the
 * author wrote stays on screen, which is what makes columns aligned with spaces
 * in the (monospace) editor line up in the view too. That only works once the
 * whitespace the MARKDOWN converter adds is gone: `mdast-util-to-hast` puts a
 * `"\n"` text node between every pair of blocks, inside every list and quote, and
 * after every hard break, and under `pre-wrap` each of those is a blank line the
 * author never typed. This transform removes exactly those and nothing else.
 *
 * The first block builds trees by hand, so each rule and each thing that must
 * survive is pinned in isolation. The second runs the real Markdown pipeline the
 * note view uses (remark-parse + remark-rehype), so the shapes the converter
 * really produces are covered too.
 */
import { describe, expect, it } from 'vitest';
import type { Element, ElementContent, Root, RootContent, Text } from 'hast';
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkRehype from 'remark-rehype';
import { rehypeKeepAuthoredWhitespace } from '../src/lib/markdownWhitespace';

const text = (value: string): Text => ({ type: 'text', value });
const el = (tagName: string, children: ElementContent[] = []): Element => ({
  type: 'element',
  tagName,
  properties: {},
  children,
});
// A raw-HTML node, as remark-rehype emits one for inline HTML. The `hast` types
// only learn about `raw` from mdast-util-to-hast's augmentation, which this file
// does not import, so it is typed as the content it stands in for.
const raw = (value: string): ElementContent =>
  ({ type: 'raw', value }) as unknown as ElementContent;
const root = (children: RootContent[]): Root => ({ type: 'root', children });

function transform(tree: Root): Root {
  rehypeKeepAuthoredWhitespace()(tree);
  return tree;
}

/** A compact rendering of a tree: text as JSON strings, elements as `tag[...]`. */
function shape(node: Root | RootContent | ElementContent): string {
  if (node.type === 'text') return JSON.stringify(node.value);
  if (node.type === 'raw') return 'raw';
  if (node.type === 'element') return `${node.tagName}[${node.children.map(shape).join(',')}]`;
  if (node.type === 'root') return `root[${node.children.map(shape).join(',')}]`;
  return node.type;
}

function viaPipeline(markdown: string): string {
  const processor = unified().use(remarkParse).use(remarkRehype).use(rehypeKeepAuthoredWhitespace);
  return shape(processor.runSync(processor.parse(markdown)));
}

describe('rehypeKeepAuthoredWhitespace, rule by rule', () => {
  it('drops every whitespace-only child of the root, of lists and of quotes', () => {
    const tree = root([
      text('\n'),
      el('p', [text('a')]),
      text('\n'),
      el('ul', [
        text('\n'),
        el('li', [text('b')]),
        text('\n  '),
        el('li', [text('c')]),
        text('\n'),
      ]),
      text('\n'),
      el('ol', [text('\n'), el('li', [text('d')]), text('\n')]),
      text(' \t\n'),
      el('blockquote', [text('\n'), el('p', [text('e')]), text('\n')]),
      text('\r\n'),
      el('hr'),
      text('\f'),
    ]);
    expect(shape(transform(tree))).toBe(
      'root[p["a"],ul[li["b"],li["c"]],ol[li["d"]],blockquote[p["e"]],hr[]]',
    );
  });

  it('drops the whitespace a list item carries around its blocks and at its edges', () => {
    const loose = el('li', [
      text('\n'),
      el('p', [text('one')]),
      text('\n'),
      el('p', [text('two')]),
      text('\n'),
    ]);
    const tightWithNested = el('li', [
      text('item'),
      text('\n'),
      el('ul', [el('li', [text('x')])]),
      text('\n'),
    ]);
    // At an edge the whitespace goes even beside inline content: nothing inline
    // lies beyond the edge for it to separate.
    const paddedInline = el('li', [text(' '), el('em', [text('x')]), text('\n')]);
    transform(root([el('ul', [loose, tightWithNested, paddedInline])]));
    expect(shape(loose)).toBe('li[p["one"],p["two"]]');
    expect(shape(tightWithNested)).toBe('li["item",ul[li["x"]]]');
    expect(shape(paddedInline)).toBe('li[em["x"]]');
  });

  it('drops every kind of block neighbour in a list item, headings and rules included', () => {
    for (const tag of [
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
    ]) {
      const item = el('li', [
        el('strong', [text('x')]),
        text(' '),
        el(tag),
        text(' '),
        el('em', [text('y')]),
      ]);
      transform(root([el('ul', [item])]));
      expect(shape(item), tag).toBe(`li[strong["x"],${tag}[],em["y"]]`);
    }
  });

  it('KEEPS whitespace between inline content in a list item, raw HTML included', () => {
    // A tight item inlines its paragraph, so these spaces are the author's.
    const inline = el('li', [el('strong', [text('a')]), text('   '), el('em', [text('b')])]);
    // `- <b>a</b> <b>b</b>`: the space sits between two raw nodes, which
    // `skipHtml` removes later; dropping it would print "ab".
    const betweenRaw = el('li', [
      raw('<b>'),
      text('a'),
      raw('</b>'),
      text(' '),
      raw('<b>'),
      text('b'),
      raw('</b>'),
    ]);
    transform(root([el('ul', [inline, betweenRaw])]));
    expect(shape(inline)).toBe('li[strong["a"],"   ",em["b"]]');
    expect(shape(betweenRaw)).toBe('li[raw,"a",raw," ",raw,"b",raw]');
  });

  it('only ever removes TEXT: a whitespace-only comment stays where it is', () => {
    const comment = { type: 'comment', value: ' ' } as RootContent;
    const tree = transform(root([comment, el('p', [text('a')])]));
    expect(tree.children[0]).toBe(comment);
  });

  it('keeps whitespace at the edges of a paragraph: only lists and quotes lose theirs', () => {
    const paragraph = el('p', [text(' '), el('em', [text('x')]), text(' ')]);
    transform(root([paragraph]));
    expect(shape(paragraph)).toBe('p[" ",em["x"]," "]');
  });

  it('keeps whitespace that is not alone in its text node, and whitespace inside a paragraph', () => {
    const paragraph = el('p', [
      text('Field 1:        Test\nField 123123:   Test 2'),
      text('   '),
      el('em', [text('x')]),
    ]);
    transform(root([paragraph]));
    expect(shape(paragraph)).toBe(
      'p["Field 1:        Test\\nField 123123:   Test 2","   ",em["x"]]',
    );
  });

  it('drops the one newline after a hard break, and nothing else after it', () => {
    const paragraph = el('p', [
      text('one'),
      el('br'),
      text('\n'),
      text('two'),
      el('br'),
      text('\nthree'),
      el('br'),
      text('four'),
      el('br'),
      el('em', [text('five')]),
    ]);
    transform(root([paragraph]));
    expect(shape(paragraph)).toBe('p["one",br[],"two",br[],"three",br[],"four",br[],em["five"]]');
  });

  it('never touches a code block or inline code', () => {
    const block = el('pre', [el('code', [text('\n'), text('a    b\n  c\n')])]);
    const inline = el('p', [el('code', [text('  x  ')])]);
    // A break inside either keeps the newline after it, which the rule for
    // ordinary text would remove.
    const breakInPre = el('pre', [el('br'), text('\nkept')]);
    const breakInCode = el('p', [el('code', [el('br'), text('\nkept')])]);
    transform(root([block, text('\n'), inline, breakInPre, breakInCode]));
    expect(shape(block)).toBe('pre[code["\\n","a    b\\n  c\\n"]]');
    expect(shape(inline)).toBe('p[code["  x  "]]');
    expect(shape(breakInPre)).toBe('pre[br[],"\\nkept"]');
    expect(shape(breakInCode)).toBe('p[code[br[],"\\nkept"]]');
  });

  it('leaves an empty tree, and a tree with nothing to remove, exactly as it was', () => {
    expect(shape(transform(root([])))).toBe('root[]');
    expect(shape(transform(root([el('p', [text('plain')])])))).toBe('root[p["plain"]]');
  });
});

describe('rehypeKeepAuthoredWhitespace, on what the Markdown pipeline really produces', () => {
  it("keeps the operator's aligned columns, line break and runs of spaces", () => {
    expect(viaPipeline('Field 1:        Test\nField 123123:   Test 2')).toBe(
      'root[p["Field 1:        Test\\nField 123123:   Test 2"]]',
    );
  });

  it('keeps a line break that follows inline formatting: only a <br> takes its newline', () => {
    // A soft break right after emphasis: dropping this newline would join the
    // two lines the author typed.
    expect(viaPipeline('*x*\ny')).toBe('root[p[em["x"],"\\ny"]]');
  });

  it('gives a hard break exactly one line, whichever way it is written', () => {
    expect(viaPipeline('one  \ntwo\\\nthree')).toBe('root[p["one",br[],"two",br[],"three"]]');
  });

  it('leaves no stray lines between blocks, list items or quoted paragraphs', () => {
    expect(viaPipeline('# Title\n\nPara   one\n\n- a\n- b\n\n> quoted   text\n> second')).toBe(
      'root[h1["Title"],p["Para   one"],ul[li["a"],li["b"]],blockquote[p["quoted   text\\nsecond"]]]',
    );
    expect(viaPipeline('- one\n\n- two')).toBe('root[ul[li[p["one"]],li[p["two"]]]]');
    expect(viaPipeline('- item\n  continued\n  - nested')).toBe(
      'root[ul[li["item\\ncontinued",ul[li["nested"]]]]]',
    );
  });

  it('keeps a fenced code block byte for byte', () => {
    expect(viaPipeline('```\na    b\n  c\n```')).toBe('root[pre[code["a    b\\n  c\\n"]]]');
  });
});
