/**
 * The markdown and HTML renderers, asserted on the RENDERED DOM.
 *
 * ## Why this suite reads the DOM and never the sanitizer
 *
 * `rehype-sanitize` returns a tree. What matters is what a BROWSER ends up
 * holding, and the two are not the same question: the whole class of bug this
 * pipeline is shaped to avoid — mutation XSS — lives in the gap between them,
 * where a parser's second pass recovers something a sanitizer's first pass
 * believed it had removed. So every assertion below is a `querySelector` against
 * real jsdom nodes, built by the same `hast-util-to-dom` call production uses.
 *
 * ## The corpus is COMMITTED DATA
 *
 * `tests/sandbox/corpus/hostile.{md,html}` are read from disk rather than
 * inlined, resolved from `import.meta.url` rather than from the working
 * directory. Each entry in them is a separate code path, and the file says so
 * next to each one.
 *
 * ## What is deliberately NOT asserted here
 *
 * That a remote `<img>` fails to load. jsdom neither fetches images nor enforces
 * a Content-Security-Policy, so "the image did not load" is an assertion that
 * cannot fail; and the policy itself lives in the SERVER package
 * (`config/sandboxCsp.ts`), so a client test could only keep a second copy of
 * it. The element SURVIVING sanitisation and the reader being TOLD are what is
 * checked here; the directive that blocks it is pinned where the policy is.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { renderMarkdown } from '../src/sandbox/renderers/markdown';
import { renderHtml, HTML_PREVIEW_NOTICE } from '../src/sandbox/renderers/html';
import { REMOTE_CONTENT_NOTICE } from '../src/sandbox/renderers/pipeline';

// Resolved from THIS FILE, never from `process.cwd()`: the suite is run both
// from the package directory and from the repository root, and a cwd-relative
// path silently reads nothing in one of them.
const corpusDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), 'sandbox/corpus');

const corpus = (name: string): ArrayBuffer => {
  const bytes = readFileSync(path.join(corpusDir, name));
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
};

/** A buffer allocated in THIS realm, the way a structured clone would arrive. */
function bytesOf(text: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(text);
  const buffer = new ArrayBuffer(encoded.byteLength);
  new Uint8Array(buffer).set(encoded);
  return buffer;
}

/**
 * A canary the corpus tries to set.
 *
 * Every hostile entry writes to `window.__pwned`. Asserting the property is
 * still undefined after rendering is the negative that matters most: it fails
 * if ANY of them executed, including through a route nobody thought to write a
 * selector for.
 */
declare global {
  // Declared optional so the resets below can `delete` it: the property must be
  // ABSENT between cases, not merely `undefined`, or a renderer that set it to
  // `undefined` would be indistinguishable from one that never ran.
  var __pwned: number | undefined;
}
interface HostileCanary {
  __pwned?: number;
}
const canary = globalThis as unknown as HostileCanary;

beforeEach(() => {
  delete canary.__pwned;
});

afterEach(() => {
  delete canary.__pwned;
  // The document is emptied between tests, and not only for tidiness. Several
  // cases append a rendered tree so that anything hostile in it gets a live
  // document to act on, and the corpus deliberately contains an `id`. Leave two
  // renders in place at once and jsdom's selector engine resolves an ID
  // selector through `document.getElementById` — which answers with the FIRST
  // element carrying that id, in the OTHER tree — and then reports no match
  // inside the subtree that was asked. That is a harness artefact, not a
  // production condition (one document is one render), and it presents as a
  // sanitiser assertion failing for no reason.
  document.body.replaceChildren();
});

describe('the markdown renderer, on a corpus of hostile documents', () => {
  it('executes nothing at all, which is the assertion that covers a vector nobody listed', async () => {
    document.body.append(await renderMarkdown(document, corpus('hostile.md')));
    expect(canary.__pwned).toBeUndefined();
  });

  it('strips or neutralises every listed vector, judged on the rendered DOM', async () => {
    const rendered = await renderMarkdown(document, corpus('hostile.md'));
    document.body.append(rendered);

    // No element that can execute, fetch or submit survives.
    expect(rendered.querySelector('script')).toBeNull();
    expect(rendered.querySelector('iframe')).toBeNull();
    expect(rendered.querySelector('object')).toBeNull();
    expect(rendered.querySelector('embed')).toBeNull();
    expect(rendered.querySelector('form')).toBeNull();
    expect(rendered.querySelector('svg')).toBeNull();
    expect(rendered.querySelector('style')).toBeNull();

    // No event handler survives on anything that did.
    for (const element of rendered.querySelectorAll('*')) {
      for (const attribute of element.attributes) {
        expect(attribute.name.startsWith('on'), `${element.tagName}[${attribute.name}]`).toBe(
          false,
        );
      }
    }

    // No `style` attribute, which GitHub strips and which is a phishing surface
    // on its own: a fixed, full-viewport overlay drawn over the frame.
    expect(rendered.querySelector('[style]')).toBeNull();

    // Neither spelling of a `javascript:` link keeps its href. Both anchors are
    // still THERE — the sanitizer drops the attribute, not the element — which
    // is why this asserts the href rather than the anchor count.
    const anchors = [...rendered.querySelectorAll('a')];
    for (const anchor of anchors) {
      expect(anchor.getAttribute('href') ?? '').not.toMatch(/^javascript:/i);
    }
    expect(anchors.some((a) => a.textContent === 'raw html javascript link')).toBe(true);
    expect(anchors.some((a) => a.textContent === 'markdown native')).toBe(true);

    // The `<img onerror>` survives as an element with its handler removed, which
    // is the correct outcome: an image is content, a handler is code.
    const broken = [...rendered.querySelectorAll('img')].find((i) => i.getAttribute('src') === 'x');
    expect(broken).toBeDefined();
    expect(broken?.getAttribute('onerror')).toBeNull();
  });

  it('does not leak a stylesheet into the page as readable text', async () => {
    // `hast-util-sanitize` drops a disallowed ELEMENT but KEEPS its children, so
    // an unwrapped `<style>` puts its CSS on screen as a paragraph. Nothing is
    // executed and the isolation holds, but the reader is shown a stylesheet as
    // if it were the document's prose.
    const rendered = await renderMarkdown(document, corpus('hostile.md'));
    expect(rendered.textContent).not.toContain('this must not be readable text');
    expect(rendered.textContent).not.toContain('--leaked');
  });

  it('keeps the DOM-clobbering defence the default schema provides', async () => {
    // `<a id="body">` shadows `document.body` and `<input name="getElementById">`
    // shadows the lookup itself, for any script sharing the document — and this
    // document's own program does. The default schema prefixes every id and
    // name; a future CUSTOM schema would silently drop that, which is why the
    // prefix is pinned rather than assumed.
    const rendered = await renderMarkdown(document, corpus('hostile.md'));
    document.body.append(rendered);

    expect(rendered.querySelector('#body')).toBeNull();
    expect(rendered.querySelector('#user-content-body')).not.toBeNull();
    // Selected by the PREFIXED name, which is the assertion: the corpus writes
    // `name="getElementById"`, so a document still carrying that attribute
    // verbatim would fail the negative below rather than this line.
    expect(rendered.querySelector('input[name="getElementById"]')).toBeNull();
    expect(rendered.querySelector('input[name="user-content-getElementById"]')).not.toBeNull();
    // The lookup the clobber was aiming at still works.
    expect(typeof document.getElementById).toBe('function');
  });

  it('renders a table, a task list and a fenced block, because a README must look like one', async () => {
    const rendered = await renderMarkdown(document, corpus('hostile.md'));

    const table = rendered.querySelector('table');
    expect(table).not.toBeNull();
    expect(table?.querySelectorAll('th')).toHaveLength(2);
    expect(table?.querySelectorAll('tbody tr')).toHaveLength(2);

    // Scoped to the task list. The sanitizer rewrites EVERY surviving `<input>`
    // to a disabled checkbox — which is how it neutralises the corpus's form
    // fields — so an unscoped count would silently include those and pass for
    // the wrong reason.
    const checkboxes = rendered.querySelectorAll('.task-list-item input[type="checkbox"]');
    expect(checkboxes).toHaveLength(2);
    expect((checkboxes[0] as HTMLInputElement).checked).toBe(true);
    expect((checkboxes[0] as HTMLInputElement).disabled).toBe(true);

    // EVERY checkbox carries an accessible name, and the two kinds get different
    // ones. A task-list marker takes its own item's text — `remark-gfm` puts that
    // text NEXT TO the input rather than in a label, so without this a screen
    // reader announces "checkbox, checked" with nothing saying what is checked,
    // which axe grades `critical` and which fires on the plainest README there
    // is. A form field the sanitizer neutralised into a checkbox has no list item
    // to take a name from, so it gets the constant instead.
    expect(checkboxes[0]?.getAttribute('aria-label')).toBe('a completed task');
    expect(checkboxes[1]?.getAttribute('aria-label')).toBe('an incomplete one');
    const neutralised = rendered.querySelector('input[name="user-content-getElementById"]');
    expect(neutralised?.getAttribute('type')).toBe('checkbox');
    expect(neutralised?.getAttribute('aria-label')).toBe('Checkbox in this document');
    // NEGATIVE: naming a control must not have changed what it IS. The state a
    // reader needs after the name is still on it, and nothing was hidden from
    // the accessibility tree to make the finding go away.
    expect((checkboxes[0] as HTMLInputElement).checked).toBe(true);
    expect((checkboxes[1] as HTMLInputElement).checked).toBe(false);
    for (const input of rendered.querySelectorAll('input')) {
      expect(input.getAttribute('aria-hidden')).toBeNull();
      expect(input.getAttribute('role')).toBeNull();
      expect(input.getAttribute('aria-label')).not.toBe('');
    }

    expect(rendered.querySelector('del')?.textContent).toBe('struck through');
    // An autolink, which GFM produces and the sanitizer allows.
    expect(
      [...rendered.querySelectorAll('a')].some(
        (a) => a.getAttribute('href') === 'https://example.com/auto',
      ),
    ).toBe(true);
    // Footnotes survive as markup.
    expect(rendered.querySelector('section.footnotes')).not.toBeNull();

    // Highlighted, and highlighted AFTER sanitising — the classes the
    // highlighter adds would not survive the default schema the other way round.
    const code = rendered.querySelector('pre code');
    expect(code?.className).toContain('hljs');
    expect(code?.querySelector('.hljs-keyword')).not.toBeNull();
  });

  it('names a task from its OWN item, never from the sub-tasks nested under it', async () => {
    // The failure this pins is silent and gets worse with depth: `textContent`
    // on a list item includes every nested list under it, so the outermost task
    // in a three-level plan would announce the entire branch before saying
    // anything about itself.
    const rendered = await renderMarkdown(
      document,
      bytesOf(
        '- [x] ship the outer thing\n  - [ ] the inner thing\n  - [ ] the other inner thing\n',
      ),
    );

    const checkboxes = rendered.querySelectorAll('.task-list-item input[type="checkbox"]');
    expect(checkboxes).toHaveLength(3);
    expect(checkboxes[0]?.getAttribute('aria-label')).toBe('ship the outer thing');
    // NEGATIVE: the nested text is absent from the outer name, and each inner
    // task still gets its own.
    expect(checkboxes[0]?.getAttribute('aria-label')).not.toContain('inner');
    expect(checkboxes[1]?.getAttribute('aria-label')).toBe('the inner thing');
    expect(checkboxes[2]?.getAttribute('aria-label')).toBe('the other inner thing');
  });

  it('cuts an over-long task name rather than announcing a paragraph before the control', async () => {
    // An accessible name is read in full BEFORE anything else about the control,
    // so an unbounded one turns a checkbox into a minute of speech. Cut with an
    // ellipsis, because the item's own text follows immediately and carries the
    // rest.
    const long = 'x'.repeat(200);
    const rendered = await renderMarkdown(document, bytesOf(`- [ ] ${long}\n`));

    const label = rendered
      .querySelector('.task-list-item input[type="checkbox"]')
      ?.getAttribute('aria-label');
    // 120 characters plus the one-character ellipsis. Asserted as a length and a
    // suffix rather than as the whole string, so the bound is what is pinned.
    expect(label).toHaveLength(121);
    expect(label?.endsWith('\u2026')).toBe(true);
    expect(label?.startsWith('xxx')).toBe(true);
  });

  it('falls back to a constant for a checkbox whose item has nothing to name it', async () => {
    // Reachable two ways: an item that is only a marker, and any `<input>` the
    // sanitizer neutralised into a checkbox outside a list. Without the
    // fallback the attribute would be present and EMPTY, which axe grades
    // exactly as harshly as a missing one — and which would have passed a test
    // that only asserted the attribute exists.
    const rendered = await renderMarkdown(
      document,
      bytesOf('<ul><li><input type="checkbox"></li></ul>\n\n<input name="loose">\n'),
    );

    const labels = [...rendered.querySelectorAll('input')].map((input) =>
      input.getAttribute('aria-label'),
    );
    expect(labels).toHaveLength(2);
    for (const label of labels) expect(label).toBe('Checkbox in this document');
  });

  it('tells the reader that remote images are not loaded, rather than showing a broken one', async () => {
    const rendered = await renderMarkdown(document, corpus('hostile.md'));
    expect(rendered.textContent).toContain(REMOTE_CONTENT_NOTICE);
    // The element itself survives sanitisation; what stops the request is the
    // policy, which is asserted where the policy lives.
    expect(
      [...rendered.querySelectorAll('img')].some((i) =>
        (i.getAttribute('src') ?? '').startsWith('https://'),
      ),
    ).toBe(true);
    // The corpus's second remote vector, and the one an `img[src]` sweep cannot
    // see: `<picture><source srcset>` survives whole, because the default schema
    // allows `source: ['srcSet']` and filters no protocol on it.
    const candidates = rendered.querySelector('picture source')?.getAttribute('srcset') ?? '';
    expect(candidates).toContain('https://example.invalid/wide.png');
    expect(candidates.startsWith('https://')).toBe(false);
  });

  it('tells the reader about a <picture> whose only remote reference is a srcset candidate', async () => {
    // The sweep used to read `img[src]` and nothing else, so this document —
    // whose every `src` is relative — produced a broken image and no sentence
    // explaining it, which is the exact outcome the notice exists to prevent.
    //
    // The remote candidate is deliberately SECOND. `srcset` is a list, and
    // testing the whole attribute value instead of each candidate finds nothing
    // here, which is the mistake the descriptor syntax invites.
    const rendered = await renderMarkdown(
      document,
      bytesOf(
        '<picture><source srcset="local-narrow.png 1x, https://example.invalid/wide.png 2x">' +
          '<img src="local-narrow.png" alt="a responsive image"></picture>\n',
      ),
    );

    expect(rendered.textContent).toContain(REMOTE_CONTENT_NOTICE);
    // Nothing here is a remote `img[src]`, which is what makes the case
    // discriminate rather than ride on the corpus's tracking pixel.
    expect(
      [...rendered.querySelectorAll('img')].every(
        (image) => !(image.getAttribute('src') ?? '').startsWith('http'),
      ),
    ).toBe(true);
    // The URL survives sanitisation with its descriptor intact: the default
    // schema allows `source: ['srcSet']` and lists no protocol filter for
    // `srcSet` at all. What refuses the request is `img-src`, which names no
    // host — pinned in `packages/server/tests/sandbox-document.test.ts`. Telling
    // the reader is the whole of the fix; widening the policy would BE the leak.
    expect(rendered.querySelector('source')?.getAttribute('srcset')).toContain(
      'https://example.invalid/wide.png 2x',
    );
  });

  it('recognises every spelling of a remote reference the sanitizer lets through', async () => {
    // The prefix test this replaces read `//`, `http://` and `https://` and
    // nothing else, which is not what the URL parser does. A special scheme
    // followed by ANY two slash-or-backslash characters enters the authority,
    // whichever the document's own scheme is — so every one of these resolves
    // to a third-party host (measured with `new URL(value, base)`), and every
    // one survives `hast-util-sanitize`, whose protocol check reads only up to
    // the colon (measured against the installed library).
    //
    // Nothing here is fetched — `img-src` names no host — so this is entirely
    // about whether the reader is told. Being told for the wrong reason costs a
    // banner; not being told costs the explanation the notice exists to give.
    for (const src of [
      '//example.invalid/p.png',
      'http://example.invalid/p.png',
      'https://example.invalid/p.png',
      String.raw`https:\\example.invalid/p.png`,
      String.raw`https:/\example.invalid/p.png`,
      String.raw`https:\/example.invalid/p.png`,
    ]) {
      const rendered = await renderMarkdown(document, bytesOf(`<img src="${src}" alt="x">\n`));
      expect(rendered.textContent, src).toContain(REMOTE_CONTENT_NOTICE);
    }
  });

  it('says nothing for the references that reach no third party', async () => {
    // The negatives that keep the notice meaningful, and the ones the fix could
    // most easily break. A relative path is this document's own; a scheme with no
    // host is not a request at all; and a `data:` src reaches nobody either.
    //
    // Say WHICH mechanism spares the `data:` one, because it is not the obvious
    // one and the obvious one is what the first draft of this comment claimed.
    // `hast-util-sanitize`'s default schema pins `protocols.src = ['http','https']`
    // (measured against the installed library), so the ATTRIBUTE is stripped and
    // that image never renders at all — `img-src data:` never comes into it. The
    // case where a `data:` value really does survive and really does render is a
    // `srcSet` candidate, which the schema applies no protocol filter to, and it
    // is the case below.
    for (const src of [
      'local.png',
      './nested/local.png',
      '/rooted.png',
      'data:image/gif;base64,R0lGODlhAQABAAAAACw=',
      // A scheme with no host at all. The sanitizer passes it (its check stops
      // at the colon) and `URL` refuses it — which must read as "no request",
      // never as an exception out of the sweep.
      'http://',
    ]) {
      const rendered = await renderMarkdown(document, bytesOf(`<img src="${src}" alt="x">\n`));
      expect(rendered.textContent, src).not.toContain(REMOTE_CONTENT_NOTICE);
    }
  });

  it('reads ONE slash after the document’s own scheme as a relative path', async () => {
    // The boundary the two-slash spellings above sit a single character from,
    // and the case that makes resolving the right answer rather than a tidier
    // one: `scheme:` plus ONE slash-or-backslash is an authority when the scheme
    // DIFFERS from the document's and a relative path when it matches, so no
    // hard-coded fixture is correct both in a frame served over http and in one
    // served over https. Taking the scheme from the document is what makes the
    // case stable — and a list of prefixes could not have expressed it at all,
    // which is the whole argument for the change.
    const own = new URL(document.baseURI).protocol;
    const rendered = await renderMarkdown(
      document,
      bytesOf(`<img src="${own}\\relative.png" alt="x">\n`),
    );

    expect(rendered.textContent).not.toContain(REMOTE_CONTENT_NOTICE);
    expect(rendered.querySelector('img')?.getAttribute('src')).toBe(`${own}\\relative.png`);
  });

  it('splits srcset candidates on a bare comma, which needs no space after it', async () => {
    // `srcset="a.png 1x,https://…/b.png 2x"` is valid and common, and the
    // separator is the comma rather than the whitespace: a split on whitespace
    // alone leaves `1x,https://…/b.png` as one token, which begins with neither
    // a scheme nor a slash and is therefore invisible.
    const rendered = await renderMarkdown(
      document,
      bytesOf(
        '<picture><source srcset="local.png 1x,https://example.invalid/wide.png 2x">' +
          '<img src="local.png" alt="a responsive image"></picture>\n',
      ),
    );

    expect(rendered.textContent).toContain(REMOTE_CONTENT_NOTICE);
  });

  it('says nothing about a srcset candidate that renders without reaching anyone', async () => {
    // The `data:` case that DOES survive sanitization, unlike the `img src` one
    // above: the default schema names no protocols for `srcSet`, so the candidate
    // is kept, and `img-src` (`server/src/config/sandboxCsp.ts`) admits `data:`, so
    // it renders. Announcing it as blocked would therefore be a lie — which is the
    // one thing the sweep must not do — while the remote candidate beside it is
    // still reported.
    const localOnly = await renderMarkdown(
      document,
      bytesOf(
        '<picture><source srcset="data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x"><img src="local.png" alt="x"></picture>\n',
      ),
    );
    expect(localOnly.textContent).not.toContain(REMOTE_CONTENT_NOTICE);

    const mixed = await renderMarkdown(
      document,
      bytesOf(
        '<picture><source srcset="data:image/gif;base64,R0lGODlhAQABAAAAACw= 1x, https://example.invalid/p.png 2x"><img src="local.png" alt="x"></picture>\n',
      ),
    );
    expect(mixed.textContent).toContain(REMOTE_CONTENT_NOTICE);
  });

  it('says nothing about a <picture> whose candidates are all local', async () => {
    // The other side of the same parse: `2x` and `640w` are descriptors, not
    // URLs, and a sweep that flagged either would put the banner on every
    // responsive image in every README.
    const rendered = await renderMarkdown(
      document,
      bytesOf(
        '<picture><source srcset="narrow.png 1x, wide.png 2x, huge.png 640w">' +
          '<img src="narrow.png" alt="a local responsive image"></picture>\n',
      ),
    );

    expect(rendered.textContent).not.toContain(REMOTE_CONTENT_NOTICE);
    expect(rendered.querySelector('source')?.getAttribute('srcset')).toContain('640w');
  });

  it('says nothing about remote content for a document that asks for none', async () => {
    // The negative that keeps the notice meaningful: a banner on every document
    // is a banner nobody reads.
    const rendered = await renderMarkdown(document, bytesOf('# Just a heading\n\nAnd a line.\n'));
    expect(rendered.textContent).not.toContain(REMOTE_CONTENT_NOTICE);
    expect(rendered.querySelector('h1')?.textContent).toBe('Just a heading');
  });

  it('gives every link the three tokens it should already carry', async () => {
    const rendered = await renderMarkdown(document, bytesOf('[x](https://example.com/)\n'));
    expect(rendered.querySelector('a')?.getAttribute('rel')).toBe('noopener noreferrer nofollow');
  });

  it('shows the encoding warning above a markdown document that barely decoded', async () => {
    // The same decoder every text-family renderer starts from, so the reader is
    // told the same thing whichever one they landed in.
    const damaged = new ArrayBuffer(6);
    new Uint8Array(damaged).set([0xff, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9]);
    const rendered = await renderMarkdown(document, damaged);
    expect(rendered.querySelector('.hv-notice')?.textContent).toContain('not valid UTF-8');
  });
});

describe('the HTML renderer', () => {
  it('executes nothing from a stored web page', async () => {
    document.body.append(await renderHtml(document, corpus('hostile.html')));
    expect(canary.__pwned).toBeUndefined();
  });

  it('runs the same sanitizer and shows its own persistent banner', async () => {
    const rendered = await renderHtml(document, corpus('hostile.html'));

    expect(rendered.textContent).toContain(HTML_PREVIEW_NOTICE);
    expect(rendered.querySelector('script')).toBeNull();
    expect(rendered.querySelector('iframe')).toBeNull();
    expect(rendered.querySelector('object')).toBeNull();
    expect(rendered.querySelector('form')).toBeNull();
    expect(rendered.querySelector('svg')).toBeNull();
    expect(rendered.querySelector('[style]')).toBeNull();
    expect(rendered.querySelector('meta')).toBeNull();
    for (const anchor of rendered.querySelectorAll('a')) {
      expect(anchor.getAttribute('href') ?? '').not.toMatch(/^javascript:/i);
    }
    // The document's own prose survives, which is the point of rendering it.
    expect(rendered.querySelector('h1')?.textContent).toBe('Stored page');
    expect(rendered.textContent).toContain('Ordinary text that must survive.');
  });

  it('drops the head rather than unwrapping it into the body', async () => {
    // MEASURED, not theoretical: with `<head>`, `<title>` and `<style>` merely
    // unwrapped, a stored page renders its own title and its whole stylesheet as
    // the first two paragraphs of the document.
    const rendered = await renderHtml(document, corpus('hostile.html'));
    expect(rendered.textContent).not.toContain('this title must not become body text');
    expect(rendered.textContent).not.toContain('this must not be readable text');
    expect(rendered.textContent).not.toContain('--leaked');
  });

  it('highlights a fenced block that names its language', async () => {
    const rendered = await renderHtml(document, corpus('hostile.html'));
    const code = rendered.querySelector('pre code');
    expect(code?.className).toContain('hljs');
    expect(code?.querySelector('.hljs-keyword')).not.toBeNull();
  });

  it('shows the encoding warning above a stored page that barely decoded', async () => {
    const damaged = new ArrayBuffer(6);
    new Uint8Array(damaged).set([0xff, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9]);
    const rendered = await renderHtml(document, damaged);
    const notices = [...rendered.querySelectorAll('.hv-notice')].map((n) => n.textContent ?? '');
    expect(notices.some((text) => text.includes('not valid UTF-8'))).toBe(true);
    // And the persistent banner is still there beside it, because the two say
    // different things and one is not a substitute for the other.
    expect(notices.some((text) => text === HTML_PREVIEW_NOTICE)).toBe(true);
  });

  it('shows a page with no markup at all rather than an empty frame', async () => {
    const rendered = await renderHtml(document, bytesOf('just text, no tags'));
    expect(rendered.textContent).toContain('just text, no tags');
  });
});

// ---------------------------------------------------------------------------
// A document that sanitises down to nothing
// ---------------------------------------------------------------------------

/**
 * The empty page, which is a real document and not an edge case worth shrugging
 * at.
 *
 * `hast-util-to-dom` decides its return type from the tree it was handed, and
 * `fragment: true` does NOT settle it: `lib/index.js:142` sets
 * `rootIsDocument = children.length === 0` and `:168-172` then builds a
 * `Document` without consulting the option at all (measured against the
 * installed copy: `nodeType` 9, an `XMLDocument`). Appending a `Document` to an
 * element throws `HierarchyRequestError`, `sandbox.ts` catches it, and the
 * reader is told "The document could not be displayed." — for a file that is
 * perfectly well-formed and simply has nothing visible in it.
 *
 * Both inputs below are ordinary. Neither is hostile, and that is what makes
 * them worth pinning: the failure looked like a corrupt document.
 */
/** A title string no other text in the rendered page could contain. */
const TITLE_CANARY = 'this-title-must-not-become-body-text';

describe('a document whose sanitized tree is empty', () => {
  it('renders an empty markdown page for a file that is only an HTML comment', async () => {
    // `rehype-sanitize`'s default schema has no `allowComments`, so the one node
    // this document contains is dropped and the root is left with no children.
    const rendered = await renderMarkdown(document, bytesOf('<!-- nothing to see -->\n'));

    const article = rendered.querySelector('article.hv-markdown');
    expect(article).not.toBeNull();
    expect(article?.childNodes).toHaveLength(0);
    // The comment did not survive as text, which is the other way this could
    // have been made to "work".
    expect(rendered.textContent).not.toContain('nothing to see');
  });

  it('renders an empty page for an HTML document with nothing in its body', async () => {
    // `<head>` and `<title>` are removed whole by the raw-text step; `html` and
    // `body` are not in the default schema's tag list and are unwrapped. What
    // reaches `toDom` is a root with no children.
    const rendered = await renderHtml(
      document,
      bytesOf(`<html><head><title>${TITLE_CANARY}</title></head><body></body></html>`),
    );

    const article = rendered.querySelector('article.hv-markdown');
    expect(article).not.toBeNull();
    expect(article?.childNodes).toHaveLength(0);
    // The persistent banner still stands: an empty page is still a stored page,
    // and the reader is still owed the sentence explaining what is disabled.
    expect(rendered.textContent).toContain(HTML_PREVIEW_NOTICE);
    // A DISTINCTIVE canary rather than a one-letter title: `<title>x</title>`
    // would have made this assertion pass because `HTML_PREVIEW_NOTICE` happens
    // to contain no letter `x`, so editing that sentence — which says nothing
    // about `<head>` — could turn this red for a reason nobody cares about.
    expect(rendered.textContent).not.toContain(TITLE_CANARY);
  });
});
