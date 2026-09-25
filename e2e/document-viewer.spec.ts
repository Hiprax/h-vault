import { test, expect } from '@playwright/test';
import {
  PREVIEW_TIMEOUT_MS,
  gotoDocuments,
  openDocument,
  openNext,
  previewFrame,
  registerAndSignInViaUI,
  sandboxFrame,
  uploadDocument,
  waitForRendered,
} from './helpers';

/**
 * The document viewer, and the isolation around it, against a real browser.
 *
 * ## Why this spec exists at all, when the renderers have unit tests
 *
 * Every renderer is covered in jsdom, and none of that coverage can say anything
 * about the thing this file is for. jsdom never loads an iframe's `src`, has no
 * notion of an opaque origin, does not enforce a sandbox attribute and does not
 * run a Content-Security-Policy — so the entire containment story is invisible
 * there. Here the frame is really framed, its origin really is opaque, and the
 * markup a hostile document produced really has been through the sanitizer on its
 * way into a live DOM.
 *
 * ## Reaching INTO the frame
 *
 * `page.frameLocator()` and `Frame.evaluate()` both work against this frame, and
 * that is a fact about PLAYWRIGHT rather than a hole in the isolation: Playwright
 * drives the browser through the DevTools protocol and addresses documents by
 * their place in the frame tree, which is not subject to the same-origin policy
 * at all. `page.evaluate` in the PARENT still cannot reach in — that is the
 * boundary the application depends on — and nothing below uses it for that.
 *
 * ## Two servers run this file
 *
 * `test:e2e` runs it against `npm run dev`. `test:sandbox`
 * (`playwright.sandbox.config.ts`) runs it again against the BUILT artifact in
 * production mode, and `test:deploy` a third time behind the Compose stack's own
 * Nginx — the only runs in which the frame is served under the policy
 * `packages/server/src/config/sandboxCsp.ts` attaches. Nothing below may
 * therefore assume either server; what only the production headers make true is
 * asserted in `sandbox-policy.prod.ts`, which the dev-server run never loads.
 *
 * ## The dependency that will bite first if these fail
 *
 * A module script is fetched in CORS mode unconditionally; the frame's opaque
 * origin sends `Origin: null`. On the dev server, Vite's default `server.cors`
 * allowlist rejects that, and `packages/client/vite.config.ts` adds `'null'` to
 * it for exactly this reason; in production the same permission is the
 * `Access-Control-Allow-Origin: *` scoped to `sandbox-assets/`. Without it, every
 * module the frame imports is refused, the frame is blank, and every assertion
 * here fails for a reason that has nothing to do with a renderer. Check that
 * header before suspecting the sanitizer.
 */

const README = 'README.md';
const PNG = 'checker.png';
const CSV = 'contacts.csv';
const JSON_DOC = 'settings.json';
const PDF = 'handbook.pdf';
const HOSTILE = 'hostile.md';

test.describe('document viewer: rendering inside the isolated frame', () => {
  test('renders each supported format, refuses a PDF, and neutralises a hostile document', async ({
    page,
  }) => {
    // Six uploads and six previews after a sign-in that costs two 600,000-iteration
    // derivations, on a single worker, against a dev server transforming a renderer
    // per format on demand.
    test.setTimeout(600_000);

    await registerAndSignInViaUI(page);
    await gotoDocuments(page);

    for (const fixture of [README, PNG, CSV, JSON_DOC, PDF, HOSTILE]) {
      await uploadDocument(page, fixture);
    }

    await test.step('the markdown README renders as real elements', async () => {
      await openDocument(page, README);
      await waitForRendered(page, 'markdown');
      const frame = previewFrame(page);

      // Elements, not text: `hast-util-to-dom` builds nodes from the sanitized
      // tree, and the whole reason the pipeline never serialises back to a
      // string is that stringify-then-reparse is the mutation-XSS shape. A
      // heading, a table with a real header cell, and a GFM task list are three
      // things a plain-text fallback could not produce.
      await expect(frame.getByRole('heading', { name: 'Field notes', level: 1 })).toBeVisible();
      await expect(frame.locator('table th', { hasText: 'Format' })).toBeVisible();
      await expect(frame.locator('table td', { hasText: 'rehype-sanitize' })).toBeVisible();
      await expect(frame.locator('input[type="checkbox"]')).toHaveCount(3);
      await expect(frame.locator('input[type="checkbox"]').first()).toBeChecked();
      await expect(frame.locator('del')).toHaveText('Struck through');

      // The sandbox attribute, READ BACK off the live element rather than taken
      // from the source. `allow-scripts` and nothing else: with
      // `allow-same-origin` beside it the framed document could remove its own
      // sandbox attribute and the isolation would be worth nothing at all.
      await expect(page.locator('iframe[title^="Preview of "]')).toHaveAttribute(
        'sandbox',
        'allow-scripts',
      );
      await expect(page.locator('iframe[title^="Preview of "]')).toHaveAttribute(
        'referrerpolicy',
        'no-referrer',
      );
    });

    await test.step('full screen enlarges the panel without restarting the preview', async () => {
      const frame = previewFrame(page);
      // A mark set INSIDE the framed document. A remount reloads that document
      // and takes the mark with it; a resize cannot. Deliberately NOT the scroll
      // position, which only moves if the fixture happens to overflow its box —
      // a probe that reads 0 before and 0 after proves nothing and fails anyway.
      await frame.locator('.hv-doc-markdown').evaluate((el) => {
        el.ownerDocument.documentElement.dataset.hvSurvives = 'before-full-screen';
      });

      await page.getByRole('button', { name: 'Full screen' }).click();
      await expect(page.getByRole('dialog', { name: README })).toBeVisible();

      // No fresh handshake, no re-post: the SAME browsing context is still there.
      await expect(frame.locator('.hv-doc-markdown')).toBeVisible({ timeout: 5_000 });
      expect(
        await frame
          .locator('.hv-doc-markdown')
          .evaluate((el) => el.ownerDocument.documentElement.dataset.hvSurvives),
      ).toBe('before-full-screen');

      // The chrome a reader acts on stays OUTSIDE the frame in this state too.
      await expect(page.getByRole('button', { name: /^Download/ })).toBeVisible();
      await page.getByRole('button', { name: 'Exit full screen' }).click();
      await expect(page.getByRole('dialog')).toHaveCount(0);
    });

    await test.step('a link inside the document asks before it opens', async () => {
      const before = page.url();
      await previewFrame(page).getByRole('link', { name: 'link out' }).click();

      // The application's own dialog, drawn OUTSIDE the frame, with the origin
      // on its own line — because a long path with a lookalike host buried in it
      // is exactly what reading a whole URL as one string misses.
      const dialog = page.getByRole('dialog', { name: 'Leave H-Vault?' });
      await expect(dialog).toBeVisible();
      await expect(page.getByTestId('document-link-origin')).toHaveText('https://example.com');

      // NEGATIVES, and they are the substance of this step. The frame withheld
      // `allow-popups` and `allow-top-navigation`, so it opened nothing itself:
      // this page has not moved and no second page exists. A frame that had
      // navigated the top-level document, or opened a tab, would fail here.
      expect(page.url()).toBe(before);
      expect(page.context().pages()).toHaveLength(1);

      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
      expect(page.url()).toBe(before);
      expect(page.context().pages()).toHaveLength(1);
    });

    await test.step('the PNG renders through an img the sandbox minted itself', async () => {
      await openNext(page, PNG);
      await waitForRendered(page, 'image');
      const image = previewFrame(page).locator('img.hv-image');
      await expect(image).toBeVisible();
      // A generic alternative text, never the document's name: the name is one
      // of the things the protocol deliberately does not send into the frame.
      await expect(image).toHaveAttribute('alt', 'The stored image');
      // DECODED, which is the only thing that distinguishes a rendered image
      // from a broken one: a blob URL minted by the application would not
      // resolve in an opaque origin, so a non-zero natural width is evidence the
      // frame minted its own.
      const frame = await sandboxFrame(page);
      const decoded = await frame.evaluate(() => {
        const node = document.querySelector('img.hv-image');
        return node instanceof HTMLImageElement
          ? { width: node.naturalWidth, complete: node.complete }
          : null;
      });
      expect(decoded).toEqual({ width: 8, complete: true });
    });

    await test.step('the CSV renders as a table of text, formula-shaped cells included', async () => {
      await openNext(page, CSV);
      await waitForRendered(page, 'text');
      const frame = previewFrame(page);
      await expect(frame.locator('table th', { hasText: 'role' })).toBeVisible();
      await expect(frame.locator('table td', { hasText: 'Ada Lovelace' })).toBeVisible();
      // VERBATIM, as text. A cell that looks like a spreadsheet formula is shown
      // exactly as it was stored — there is nothing here that evaluates one, and
      // silently rewriting it would be this viewer editing the document.
      await expect(frame.locator('table td', { hasText: '=1+1' })).toHaveText('=1+1');
      // The toggle is inside the frame, which is not an exception to "the app
      // draws the chrome": it switches between two renderings of the same bytes
      // and has nothing to forge.
      await expect(frame.getByRole('button', { name: 'Show raw text' })).toBeVisible();
    });

    await test.step('the JSON document renders formatted, with the original a click away', async () => {
      await openNext(page, JSON_DOC);
      await waitForRendered(page, 'text');
      const frame = previewFrame(page);
      await expect(frame.locator('.hv-source code')).toContainText('"autoLockMinutes": 15');
      await expect(frame.getByRole('button', { name: 'Show original' })).toBeVisible();
    });

    await test.step('the PDF is download-only and gets no frame at all', async () => {
      await openNext(page, PDF);
      const refusal = page.getByTestId('document-download-to-view');
      await expect(refusal).toBeVisible({ timeout: PREVIEW_TIMEOUT_MS });
      await expect(refusal).toContainText('PDF');

      // NEGATIVE, and it is the decision rather than an accident: a PDF renderer
      // is a large third-party parser with a documented history of executing
      // attacker JavaScript in its host page, so `PREVIEW_MODES` names `pdf` as
      // `none` and NO iframe element is created — not a hidden one, not an empty
      // one. The download button beside the reason is the whole offer.
      await expect(page.locator('iframe')).toHaveCount(0);
      await expect(page.getByRole('button', { name: /^Download\b/ })).toBeVisible();
    });

    await test.step('the hostile markdown is rendered with its teeth removed', async () => {
      await openNext(page, HOSTILE);
      await waitForRendered(page, 'markdown');
      // Captured AFTER the render, so the comparison at the end is about what
      // the hostile document did rather than about the navigation that opened it.
      const settled = page.url();
      const frame = previewFrame(page);
      const handle = await sandboxFrame(page);

      // The renderer DID run: the ordinary prose is on screen. Without this the
      // assertions below would pass just as well against a blank frame, which is
      // the failure mode that makes a security test worthless.
      await expect(frame.getByRole('heading', { name: 'Hostile document' })).toBeVisible();
      await expect(frame.getByText('Ordinary prose after the hostile markup')).toBeVisible();

      // The script and the handler are ABSENT FROM THE RENDERED DOCUMENT. This
      // is the assertion with content in it: "no dialog appeared" could not fail
      // here whatever the sanitizer did, because `allow-modals` was never
      // granted.
      //
      // SCOPED TO `#root`, which is the renderer's output target, and the scope
      // is load-bearing rather than tidy. The isolated document has scripts of
      // its OWN — its entry module, plus whatever the dev server injects beside
      // it — so an unscoped `script` count is a fact about the harness and
      // measures nothing about the file (measured: three, none of them from the
      // document). And a `<script>` that DID reach this subtree would really
      // run: `hast-util-to-dom` builds elements with `createElement`, and a
      // script inserted that way executes, unlike one parsed from innerHTML.
      const rendered = frame.locator('#root');
      await expect(rendered.locator('script')).toHaveCount(0);
      await expect(rendered.locator('[onerror]')).toHaveCount(0);
      // The IMG SURVIVED, stripped of its handler rather than dropped whole — so
      // the count above is a statement about the attribute and not about an
      // element the sanitizer happened to delete.
      await expect(rendered.locator('img[alt="broken on purpose"]')).toHaveCount(1);
      // A `javascript:` href is stripped while the anchor's text stays, which is
      // what the sanitizer's URL allowlist does. The link therefore never reaches
      // the host's message boundary, and `isSafeUrl` there would refuse it
      // anyway.
      await expect(rendered.locator('a[href^="javascript:"]')).toHaveCount(0);
      await expect(rendered.getByText('a javascript: link')).toBeVisible();
      // A nested frame is not in the sanitizer's schema, so the whole element is
      // gone: the isolated document cannot embed anything of its own.
      await expect(rendered.locator('iframe')).toHaveCount(0);
      // `<style>` is a RAW-TEXT element, and the pipeline drops those BEFORE the
      // sanitizer runs. The reason is measured rather than theoretical: the
      // sanitizer UNWRAPS a disallowed element, so the rule's text would
      // otherwise land on screen as prose.
      await expect(rendered.locator('style')).toHaveCount(0);
      await expect(rendered.getByText('display: none')).toHaveCount(0);

      // And nothing EXECUTED inside the isolated document either. Asked of the
      // frame itself, because the flags the hostile file tries to set would be
      // set on the frame's own `window` — which the parent cannot read and a DOM
      // locator cannot see.
      const executed = await handle.evaluate(() => ({
        script: '__hvSandboxScriptRan' in window,
        handler: '__hvSandboxHandlerRan' in window,
        javascriptUrl: '__hvSandboxJavascriptUrl' in window,
      }));
      expect(executed).toEqual({ script: false, handler: false, javascriptUrl: false });

      // The document is still where it was: nothing in the hostile file
      // navigated this page, and nothing opened a tab.
      expect(page.url()).toBe(settled);
      await expect(page).toHaveURL(/\/documents\/[0-9a-f]{24}$/);
      expect(page.context().pages()).toHaveLength(1);
    });
  });
});
