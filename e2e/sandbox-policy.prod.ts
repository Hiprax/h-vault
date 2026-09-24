import { test, expect, type Frame, type Page, type Response } from '@playwright/test';
import { SANDBOX_CSP_HEADER } from '../packages/server/src/config/sandboxCsp';
import {
  PREVIEW_TIMEOUT_MS,
  SANDBOX_HOSTILE_CORPUS,
  UNLOCK_SUBMIT_LABEL,
  expectVaultVisible,
  gotoDocuments,
  openDocument,
  openNext,
  previewFrame,
  registerAndSignInViaUI,
  sandboxFrame,
  unlockVault,
  uploadDocument,
  waitForRendered,
} from './helpers';

/**
 * The isolated render document, rendered under the policy a deployment sends.
 *
 * Run ONLY by `playwright.sandbox.config.ts` — against the built artifact in
 * production mode (`test:sandbox`) and behind the Compose stack's Nginx
 * (`test:deploy`) — and never by `test:e2e`, whose dev server sends no policy at
 * all. The name keeps it outside Playwright's default `*.spec.ts` pattern for
 * exactly that reason; the config explains the choice.
 *
 * `document-viewer.spec.ts` runs beside this file in the same gate and already
 * covers markdown, a PNG, CSV and JSON text, the PDF refusal, full screen and the
 * link dialog. This file adds the modes and inputs it does not reach — audio from
 * a `blob:` URL, an SVG through `<img>`, a `data:` image inside a document,
 * highlighted source, a stored web page — plus the committed hostile corpus the
 * unit tier pins in jsdom, and it asserts the three things only a production run
 * can:
 *
 *  1. **The frame is served under the sandbox policy, and exactly one.** Read off
 *     the response the BROWSER received for `/sandbox.html`, not off a separate
 *     request: two policies on one response are intersected, which is how `blob:`
 *     media and `data:` images would both die at once.
 *  2. **The engine refused exactly what the policy is for, and nothing else.**
 *     Every `securitypolicyviolation` the isolated document raises is recorded by
 *     an init script, which Playwright evaluates in each frame before the frame's
 *     own scripts run. A preview of a benign document must raise NONE — a refused
 *     `blob:` source, `data:` image, module or stylesheet is precisely the failure
 *     an HTTP assertion cannot see — and a hostile document's refusals must all be
 *     its remote images, on `img-src`.
 *  3. **The service worker controls the page.** The production build installs one
 *     and the dev server never does, so the previews are opened from a page the
 *     worker controls — the state every returning user is in. State what that
 *     buys precisely, because it was measured rather than assumed: with the
 *     worker in control and its `navigateFallbackDenylist` neutralised in the
 *     built `sw.js`, this spec still passed, because Chromium does not hand a
 *     sandboxed frame's navigation to the embedding page's worker. So on this
 *     engine the denylist is defence in depth, and what this step proves is that
 *     the worker's presence changes nothing about the frame; an engine that did
 *     route that navigation through the worker would have its shell refused here
 *     by (1).
 */

const AUDIO = 'tone.wav';
const SVG = 'badge.svg';
const INLINE_IMAGE = 'inline-image.md';
const SOURCE = 'deploy.sh';
const HOSTILE_MARKDOWN = 'hostile.md';
const HOSTILE_PAGE = 'hostile.html';

/** One refusal, as the engine reported it inside the isolated document. */
interface PolicyViolation {
  blockedURI: string;
  directive: string;
}

declare global {
  interface Window {
    /** Every `securitypolicyviolation` this document raised, in order. */
    __hvPolicyViolations?: PolicyViolation[];
  }
}

/**
 * Registered with `page.addInitScript`, so it runs in EVERY frame — the isolated
 * document included — before any of that frame's own scripts. It observes and
 * changes nothing the application reads.
 */
function recordPolicyViolations(): void {
  const seen: PolicyViolation[] = [];
  window.__hvPolicyViolations = seen;
  document.addEventListener('securitypolicyviolation', (event) => {
    seen.push({ blockedURI: event.blockedURI, directive: event.effectiveDirective });
  });
}

/** The refusals recorded in the isolated document; `null` if the recorder never ran there. */
async function violationsIn(frame: Frame): Promise<PolicyViolation[] | null> {
  return frame.evaluate(() => window.__hvPolicyViolations ?? null);
}

/**
 * (1) The response the browser rendered the frame from carries the sandbox policy,
 * once, verbatim. A second header — Nginx's floor, or helmet's application policy
 * left in place — fails here by count, before its value is even compared.
 */
async function expectSandboxPolicy(response: Response): Promise<void> {
  const policies = (await response.headersArray())
    .filter((header) => header.name.toLowerCase() === 'content-security-policy')
    .map((header) => header.value);
  expect(policies, 'the policy the isolated document was served under').toEqual([
    SANDBOX_CSP_HEADER,
  ]);
}

/**
 * Open a listed document and return its isolated frame once the renderer has put
 * its shell on screen, having checked the policy the frame arrived under.
 *
 * The response listener is armed BEFORE the click: each document gets a fresh
 * frame, so each preview is a fresh navigation to `/sandbox.html`.
 */
async function previewUnderPolicy(
  page: Page,
  fixture: string,
  mode: string,
  open: (page: Page, fixture: string) => Promise<void>,
): Promise<Frame> {
  const served = page.waitForResponse(
    (response) => new URL(response.url()).pathname === '/sandbox.html',
    { timeout: PREVIEW_TIMEOUT_MS },
  );
  await open(page, fixture);
  await expectSandboxPolicy(await served);
  await waitForRendered(page, mode);
  return sandboxFrame(page);
}

/**
 * (2) for a hostile document: at least one refusal (the corpus asks for remote
 * images, so none at all would mean the policy never applied), and every one of
 * them is a remote image on `img-src`. Polled, because the refusal is raised when
 * the image REQUEST starts, which is a moment after the element is inserted.
 */
async function expectOnlyRemoteImagesRefused(frame: Frame): Promise<void> {
  await expect
    .poll(async () => (await violationsIn(frame))?.length ?? 0, { timeout: PREVIEW_TIMEOUT_MS })
    .toBeGreaterThan(0);
  const refused = await violationsIn(frame);
  expect(
    refused?.every((v) => v.directive === 'img-src'),
    JSON.stringify(refused),
  ).toBe(true);
  expect(
    refused?.every((v) => v.blockedURI.startsWith('https://example.invalid/')),
    JSON.stringify(refused),
  ).toBe(true);
}

test.describe('the isolated document under the production policy', () => {
  test('renders every preview mode and the hostile corpus, refusing only what the policy is for', async ({
    page,
  }) => {
    // Six uploads and six previews, after a sign-in and an unlock that cost three
    // 600,000-iteration derivations between them, on a single worker.
    test.setTimeout(600_000);
    await page.addInitScript(recordPolicyViolations);

    const { password } = await registerAndSignInViaUI(page);

    await test.step('the service worker controls the page before any preview opens', async () => {
      // Polled with a deadline rather than awaiting `serviceWorker.ready`, which
      // never settles on a build that registers no worker — this step must fail
      // on that build, not wait out the whole test.
      await expect
        .poll(
          () =>
            page.evaluate(
              async () => (await navigator.serviceWorker.getRegistration())?.active?.state ?? null,
            ),
          { timeout: PREVIEW_TIMEOUT_MS },
        )
        .toBe('activated');
      // A worker controls a page only from its NEXT load, which is the state a
      // returning user is in. The vault key is never persisted, so the reload
      // lands on the unlock screen, which is a real journey of its own.
      await page.reload();
      await expect(
        page.getByRole('button', { name: UNLOCK_SUBMIT_LABEL, exact: true }),
      ).toBeVisible({ timeout: PREVIEW_TIMEOUT_MS });
      await unlockVault(page, password);
      await expectVaultVisible(page);
      expect(await page.evaluate(() => navigator.serviceWorker.controller !== null)).toBe(true);
    });

    await gotoDocuments(page);
    for (const fixture of [AUDIO, SVG, INLINE_IMAGE, SOURCE]) {
      await uploadDocument(page, fixture);
    }
    for (const fixture of [HOSTILE_MARKDOWN, HOSTILE_PAGE]) {
      await uploadDocument(page, fixture, SANDBOX_HOSTILE_CORPUS);
    }

    await test.step('audio plays from a blob: URL the isolated document minted', async () => {
      const frame = await previewUnderPolicy(page, AUDIO, 'media', openDocument);

      // An opaque origin, and the stylesheet admitted across it: `sandbox.css`
      // sets the body's size, and a stylesheet refused by CORS or by CORP leaves
      // the engine's default. Asked once, of the first frame, because every
      // preview loads the same document.
      expect(await frame.evaluate(() => window.origin)).toBe('null');
      expect(await frame.evaluate(() => getComputedStyle(document.body).fontSize)).toBe('14px');

      // METADATA LOADED, which is the one thing a refused `media-src` cannot fake:
      // the element would raise `error`, and the renderer would replace it with
      // its could-not-play notice.
      await expect
        .poll(
          () =>
            frame.evaluate(() => {
              const player = document.querySelector('audio.hv-media');
              if (!(player instanceof HTMLMediaElement)) return null;
              return {
                ready: player.readyState >= HTMLMediaElement.HAVE_METADATA,
                scheme: player.currentSrc.split(':')[0],
                duration: Math.round(player.duration * 100) / 100,
                error: player.error?.code ?? null,
              };
            }),
          { timeout: PREVIEW_TIMEOUT_MS },
        )
        .toEqual({ ready: true, scheme: 'blob', duration: 0.25, error: null });
      await expect(previewFrame(page).getByText(/could not play this file/)).toHaveCount(0);
      expect(await violationsIn(frame)).toEqual([]);
    });

    await test.step('an SVG renders through an img, from a blob: URL, and runs nothing', async () => {
      const frame = await previewUnderPolicy(page, SVG, 'image', openNext);
      await expect
        .poll(
          () =>
            frame.evaluate(() => {
              const image = document.querySelector('img.hv-image');
              return image instanceof HTMLImageElement && image.complete
                ? {
                    width: image.naturalWidth,
                    height: image.naturalHeight,
                    scheme: image.currentSrc.split(':')[0],
                  }
                : null;
            }),
          { timeout: PREVIEW_TIMEOUT_MS },
        )
        .toEqual({ width: 24, height: 12, scheme: 'blob' });
      // The file carries a script. Through `<img>` it is a picture, never a
      // program: nothing inlined the markup into the document.
      expect(await frame.evaluate(() => '__hvSvgScriptRan' in window)).toBe(false);
      await expect(previewFrame(page).locator('#root svg')).toHaveCount(0);
      expect(await violationsIn(frame)).toEqual([]);
    });

    await test.step('a data: image inside a document decodes under img-src', async () => {
      const frame = await previewUnderPolicy(page, INLINE_IMAGE, 'markdown', openNext);
      await expect(previewFrame(page).getByText('Text after the picture')).toBeVisible();
      await expect
        .poll(
          () =>
            frame.evaluate(() => {
              const image = document.querySelector('img[alt="an inline checkerboard"]');
              return image instanceof HTMLImageElement && image.complete
                ? { width: image.naturalWidth, scheme: image.currentSrc.split(':')[0] }
                : null;
            }),
          { timeout: PREVIEW_TIMEOUT_MS },
        )
        .toEqual({ width: 8, scheme: 'data' });
      // Nothing about it is remote, so the reader is told nothing was withheld.
      await expect(previewFrame(page).getByText(/not loaded/)).toHaveCount(0);
      expect(await violationsIn(frame)).toEqual([]);
    });

    await test.step('source code is highlighted by a grammar loaded into the frame', async () => {
      const frame = await previewUnderPolicy(page, SOURCE, 'text', openNext);
      const code = previewFrame(page).locator('.hv-source code.hljs');
      await expect(code).toContainText('deploying to ${target}');
      // A highlighted token is the evidence the grammar chunk — a dynamic import
      // from `sandbox-assets/`, fetched in CORS mode from an opaque origin — was
      // admitted; the plain-text fallback would carry no span at all.
      await expect(code.locator('.hljs-keyword').first()).toBeVisible();
      expect(await violationsIn(frame)).toEqual([]);
    });

    await test.step('the hostile markdown corpus renders with its teeth removed', async () => {
      const frame = await previewUnderPolicy(page, HOSTILE_MARKDOWN, 'markdown', openNext);
      const rendered = previewFrame(page).locator('#root');
      // Captured AFTER the render, so the comparison at the end is about what the
      // hostile document did rather than about the navigation that opened it.
      const settled = page.url();

      // The renderer RAN: the ordinary parts of the corpus are on screen.
      await expect(rendered.getByRole('heading', { name: 'Hostile document' })).toBeVisible();
      await expect(rendered.locator('table td', { hasText: 'second' })).toBeVisible();
      await expect(rendered.locator('.task-list-item input[type="checkbox"]')).toHaveCount(2);

      // And nothing hostile survived into the live document, or ran there.
      for (const selector of [
        'script',
        'iframe',
        'object',
        'form',
        'style',
        '[onerror]',
        '[onload]',
      ]) {
        await expect(rendered.locator(selector), selector).toHaveCount(0);
      }
      await expect(rendered.locator('a[href^="javascript:"]')).toHaveCount(0);
      await expect(rendered.getByText('this must not be readable text')).toHaveCount(0);
      expect(await frame.evaluate(() => '__pwned' in window)).toBe(false);

      // The remote images were refused BY THE ENGINE, on `img-src`, and the reader
      // was told; nothing else was refused.
      await expect(previewFrame(page).getByText(/They are not loaded/)).toBeVisible();
      await expectOnlyRemoteImagesRefused(frame);

      // Nothing navigated this page or opened another.
      expect(page.url()).toBe(settled);
      expect(page.context().pages()).toHaveLength(1);
    });

    await test.step('the hostile web page renders as a stored page and runs nothing', async () => {
      const frame = await previewUnderPolicy(page, HOSTILE_PAGE, 'html', openNext);
      const rendered = previewFrame(page).locator('#root');
      const settled = page.url();

      await expect(rendered.getByRole('heading', { name: 'Stored page' })).toBeVisible();
      await expect(rendered.getByText('Ordinary text that must survive.')).toBeVisible();
      await expect(rendered.getByText(/scripts, styles and remote content disabled/)).toBeVisible();
      // The `<head>` went with its contents: its title is not prose, and its
      // `<meta http-equiv="refresh">` navigated nothing.
      await expect(rendered.getByText('this title must not become body text')).toHaveCount(0);
      for (const selector of ['script', 'iframe', 'object', 'form', 'style', 'meta', '[onload]']) {
        await expect(rendered.locator(selector), selector).toHaveCount(0);
      }
      await expect(rendered.locator('a[href^="javascript:"]')).toHaveCount(0);
      expect(await frame.evaluate(() => '__pwned' in window)).toBe(false);

      await expectOnlyRemoteImagesRefused(frame);
      expect(page.url()).toBe(settled);
      expect(page.context().pages()).toHaveLength(1);
    });
  });
});
