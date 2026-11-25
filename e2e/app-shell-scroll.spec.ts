import { test, expect, type Locator, type Page } from '@playwright/test';
import {
  LAZY_ROUTE_TIMEOUT_MS,
  backToSettings,
  createIdentityWithAddress,
  gotoDocuments,
  gotoFileEncryptionTool,
  gotoTotpImportTool,
  gotoVault,
  openCreateDialog,
  openDocument,
  registerAndSignInViaUI,
  uploadDocument,
} from './helpers';

/**
 * The signed-in shell (`AppLayout`) is a fixed-height frame whose ONE scroller is
 * `<main>`. The document itself must never scroll inside it.
 *
 * It did. An absolutely positioned element with no positioned ancestor takes the
 * initial containing block as its containing block, so it escapes `<main>` (and
 * the `overflow-hidden` shell) and lands in the DOCUMENT's scrollable overflow at
 * its static position. Every `sr-only` element is `position: absolute`. On Backup
 * Settings an always-mounted `sr-only` status line sits ~1,100 px down, so the
 * document became a second scroller under `<main>`: two scrollbars, and once
 * `<main>` reached its end the wheel chained to the document and slid the whole
 * shell up over an empty band.
 *
 * The rule this pins: a scroller that holds an absolutely positioned descendant
 * is that descendant's containing block (`<main>`, the RailLayout pane and the
 * saved-address list are `relative`), so nothing can reach the document.
 *
 * Pseudo-elements are out of the DOM's reach and are not walked. The two that
 * exist are safe by construction: `ReleaseEntry`'s `before:absolute` bullet sits
 * on a `relative` element, and `.release-unseen-dot::after` on an absolute one.
 */

const DESKTOP = { width: 1280, height: 720 } as const;
const PHONE = { width: 390, height: 844 } as const;

/** The document the walk opens: a PDF, whose preview is declined, so no frame loads. */
const DOCUMENT_PDF = 'handbook.pdf';

interface ShellReading {
  /** How far the DOCUMENT can scroll, per axis. Must be 0 inside the shell. */
  readonly overflowX: number;
  readonly overflowY: number;
  /** Every absolutely positioned element inside `<main>` that escapes a scroller. */
  readonly escapees: readonly string[];
}

/**
 * Wait until layout stops moving: the same reading on five consecutive frames.
 *
 * A condition, not a clock. The shell's sidebar has a width/transform transition,
 * and a resize or a scroll settles over a few frames; reading mid-way would
 * measure a state nobody sees. Throws when nothing settles, rather than
 * measuring anyway.
 */
async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const sample = (): string => {
      const root = document.scrollingElement;
      const main = document.querySelector('main');
      const banner = document.querySelector('body header')?.getBoundingClientRect();
      return [
        root?.scrollHeight,
        root?.scrollWidth,
        window.scrollX,
        window.scrollY,
        main?.scrollHeight,
        main?.scrollTop,
        banner?.left,
        banner?.width,
      ].join(',');
    };
    const nextFrame = (): Promise<void> =>
      new Promise((resolve) => {
        requestAnimationFrame(() => resolve());
      });
    let last = sample();
    let unchanged = 0;
    for (let frame = 0; frame < 600 && unchanged < 5; frame += 1) {
      await nextFrame();
      const current = sample();
      unchanged = current === last ? unchanged + 1 : 0;
      last = current;
    }
    if (unchanged < 5) throw new Error(`layout never settled: ${last}`);
  });
}

/**
 * Reads the two facts the shell must hold.
 *
 * The containing block is found by walking ancestors to the first one that
 * establishes one for an absolutely positioned box (CSS Position 3 and the
 * properties that create one: a non-static position, transforms, filters,
 * containment, `will-change` naming one of them). `offsetParent` is NOT used: an
 * SVG element has none, and the absolutely placed icons inside the search fields
 * would read as escapees. Hidden subtrees (`display: none`) have no client rects
 * and are skipped — they occupy no layout and extend nothing.
 */
async function readShell(page: Page): Promise<ShellReading> {
  return page.evaluate(() => {
    const main = document.querySelector('main');
    if (main === null) throw new Error('no <main> on this page');
    const root = document.scrollingElement ?? document.documentElement;

    const CLIPPING = new Set(['auto', 'scroll', 'hidden']);
    const WILL_CHANGE_CB =
      /\b(?:position|transform|translate|rotate|scale|perspective|filter|backdrop-filter|contain)\b/;
    const CONTAIN_CB = /\b(?:layout|paint|strict|content)\b/;

    const isScroller = (el: Element): boolean => {
      const style = getComputedStyle(el);
      return CLIPPING.has(style.overflowX) || CLIPPING.has(style.overflowY);
    };
    const holdsAbsolutes = (el: Element): boolean => {
      const style = getComputedStyle(el);
      return (
        style.position !== 'static' ||
        style.transform !== 'none' ||
        style.translate !== 'none' ||
        style.rotate !== 'none' ||
        style.scale !== 'none' ||
        style.perspective !== 'none' ||
        style.filter !== 'none' ||
        style.backdropFilter !== 'none' ||
        CONTAIN_CB.test(style.contain) ||
        style.containerType !== 'normal' ||
        style.contentVisibility === 'auto' ||
        WILL_CHANGE_CB.test(style.willChange)
      );
    };
    const describe = (el: Element): string => {
      const testId = el.getAttribute('data-testid');
      const label = el.getAttribute('aria-label');
      const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim().slice(0, 60);
      const name = testId ?? label ?? (text === '' ? '(empty)' : `"${text}"`);
      return `<${el.tagName.toLowerCase()}> ${name}`;
    };
    const describeScroller = (el: Element): string => {
      const classes = (el.getAttribute('class') ?? '').split(/\s+/).slice(0, 4).join('.');
      return `<${el.tagName.toLowerCase()}${classes === '' ? '' : `.${classes}`}>`;
    };

    const escapees: string[] = [];
    for (const el of main.querySelectorAll('*')) {
      if (getComputedStyle(el).position !== 'absolute') continue;
      if (el.getClientRects().length === 0) continue;
      for (let ancestor = el.parentElement; ancestor !== null; ancestor = ancestor.parentElement) {
        if (holdsAbsolutes(ancestor)) break;
        if (isScroller(ancestor)) {
          escapees.push(`${describe(el)} escapes ${describeScroller(ancestor)}`);
          break;
        }
      }
    }
    return {
      overflowX: root.scrollWidth - root.clientWidth,
      overflowY: root.scrollHeight - root.clientHeight,
      escapees,
    };
  });
}

/** Resize, wait until the new width is the one laid out, then until it settles. */
async function resizeTo(page: Page, size: { width: number; height: number }): Promise<void> {
  await page.setViewportSize(size);
  await page.waitForFunction((width) => window.innerWidth === width, size.width);
  await settle(page);
}

/**
 * The page on screen, at desktop width and at phone width: the document cannot
 * scroll, and no positioned element escapes the scroller it belongs to. Soft, so
 * one red run reports every page. Ends back at desktop width, where the walk
 * navigates (the sidebar is off-canvas on a phone).
 */
async function expectShellOwnsScrolling(page: Page, where: string): Promise<void> {
  for (const [width, size] of [
    ['desktop', DESKTOP],
    ['phone', PHONE],
  ] as const) {
    await resizeTo(page, size);
    const reading = await readShell(page);
    expect
      .soft(reading.escapees, `${where} at ${width} width: positioned elements escape a scroller`)
      .toEqual([]);
    expect
      .soft(
        { x: reading.overflowX, y: reading.overflowY },
        `${where} at ${width} width: the document itself can scroll`,
      )
      .toEqual({ x: 0, y: 0 });
  }
  await resizeTo(page, DESKTOP);
}

/** Sidebar navigation to a route, ready when the page's own heading is. */
async function gotoBySidebar(page: Page, link: string, heading: string | RegExp): Promise<void> {
  await page.getByRole('link', { name: link, exact: true }).click();
  await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/** One of the pages behind Settings, by its entry on the Settings page. */
async function gotoSettingsPage(page: Page, link: RegExp, heading: string): Promise<void> {
  await page.getByRole('link', { name: link }).click();
  await expect(page.getByRole('heading', { name: heading, level: 1 })).toBeVisible({
    timeout: LAZY_ROUTE_TIMEOUT_MS,
  });
}

/** Whether two boxes share any area. */
function intersects(
  a: { x: number; y: number; width: number; height: number },
  b: { x: number; y: number; width: number; height: number },
): boolean {
  return a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
}

async function box(
  locator: Locator,
): Promise<{ x: number; y: number; width: number; height: number }> {
  const found = await locator.boundingBox();
  if (found === null) throw new Error('element has no box');
  return found;
}

test.describe('app shell scrolling', () => {
  test('no signed-in page lets the document scroll, at desktop and phone width', async ({
    page,
  }, testInfo) => {
    await registerAndSignInViaUI(page);
    // Two 600k-iteration derivations for the sign-in, about twenty SPA
    // navigations (each the first load of a lazy chunk on a dev server), one
    // document through the browser's AES-GCM to the storage engine, and two
    // layout readings per stop. MEASURED at 21 s for the whole walk on an idle
    // machine; the ceiling is the accessibility walk's, for the same reason: a
    // contended machine where one derivation alone has passed 30 s and each
    // first load of a lazy chunk may take up to `LAZY_ROUTE_TIMEOUT_MS`. A
    // CEILING, not a budget: every step waits on a named element or on settled
    // layout, never on the clock.
    testInfo.setTimeout(600_000);
    await resizeTo(page, DESKTOP);

    await test.step('vault, empty: the document cannot scroll', async () => {
      await expect(page.getByRole('heading', { name: 'Vault', level: 1 })).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/vault (empty)');
    });

    await test.step('vault, with an item: the document cannot scroll', async () => {
      await createIdentityWithAddress(page);
      await expect(page.getByTestId('vault-item-name').first()).toBeVisible();
      await expectShellOwnsScrolling(page, '/vault');
    });

    await test.step('item page: the document cannot scroll', async () => {
      await page.getByTestId('vault-item-name').filter({ hasText: 'Home address' }).click();
      await expect(page.getByRole('heading', { name: 'Home address', level: 1 })).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/vault/:id');
    });

    await test.step('create dialog with an applied saved address: nothing escapes the list', async () => {
      await gotoVault(page);
      const dialog = await openCreateDialog(page);
      await dialog.getByRole('tab', { name: 'Card' }).click();
      await dialog.getByText('+ Add billing address').click();
      const picker = dialog.getByRole('button', { name: 'Use a saved address' });
      const list = dialog.getByRole('listbox', { name: 'Saved addresses' });
      await picker.click();
      await list.getByRole('option').first().click();
      // Choosing an address applies it and closes the panel.
      await expect(list).toBeHidden();
      await expect(dialog.locator('#field-billingStreet')).toHaveValue('1 Main St');
      // Reopened, the applied address is listed first with its "Currently
      // applied" mark: an `sr-only` element inside the list's own scroller.
      await picker.click();
      await expect(list.getByText('Currently applied')).toHaveCount(1);
      await expectShellOwnsScrolling(page, 'create dialog, saved-address list');
      await page.keyboard.press('Escape');
      await expect(list).toBeHidden();
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
    });

    await test.step('documents and a document: the document cannot scroll', async () => {
      await gotoDocuments(page);
      await expectShellOwnsScrolling(page, '/documents (empty)');
      await uploadDocument(page, DOCUMENT_PDF);
      await expectShellOwnsScrolling(page, '/documents');
      await openDocument(page, DOCUMENT_PDF);
      await expect(page.getByTestId('document-download-to-view')).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/documents/:id');
    });

    await test.step('tools and health: the document cannot scroll', async () => {
      await gotoBySidebar(page, 'Password Generator', 'Password Generator');
      await expect(page.getByText(/^\d+ bits$/)).toBeVisible({ timeout: LAZY_ROUTE_TIMEOUT_MS });
      await expectShellOwnsScrolling(page, '/generator');

      await gotoFileEncryptionTool(page);
      await expectShellOwnsScrolling(page, '/tools/file-encryption');

      await gotoTotpImportTool(page);
      await expectShellOwnsScrolling(page, '/tools/totp-import');

      await gotoBySidebar(page, 'Vault Health', 'Vault Health');
      await expect(page.getByText('Health Score')).toBeVisible({ timeout: LAZY_ROUTE_TIMEOUT_MS });
      await expectShellOwnsScrolling(page, '/vault/health');
    });

    await test.step('settings and the pages behind it: the document cannot scroll', async () => {
      await gotoBySidebar(page, 'Settings', /^settings$/i);
      await expectShellOwnsScrolling(page, '/settings');

      await gotoSettingsPage(page, /active sessions/i, 'Active Sessions');
      await expectShellOwnsScrolling(page, '/settings/sessions');
      await backToSettings(page);

      await gotoSettingsPage(page, /audit log/i, 'Audit Log');
      await expect(page.getByRole('table', { name: 'Audit log entries' })).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/settings/audit');
      await backToSettings(page);

      await gotoSettingsPage(page, /export to another manager/i, 'Leave H-Vault');
      await expectShellOwnsScrolling(page, '/settings/export-data');
      // The one page behind Settings with no back control of its own.
      await gotoBySidebar(page, 'Settings', /^settings$/i);

      await gotoSettingsPage(page, /^About H-Vault$/, 'About H-Vault');
      await expect(page.getByRole('heading', { name: 'Release history', level: 2 })).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/settings/about');
      await backToSettings(page);

      await gotoSettingsPage(page, /backup settings/i, 'Backup Settings');
      await expect(page.getByText('No backup history')).toBeVisible({
        timeout: LAZY_ROUTE_TIMEOUT_MS,
      });
      await expectShellOwnsScrolling(page, '/settings/backup');
      await page.getByRole('button', { name: 'Restore from File' }).click();
      await expect(page.locator('#restore-password')).toBeVisible();
      await expectShellOwnsScrolling(page, '/settings/backup (restore form open)');
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Restore from File' })).toBeVisible();
    });
  });

  test('past the end of Backup Settings, the window, the sidebar and the bottom edge stay put', async ({
    page,
  }) => {
    await registerAndSignInViaUI(page);
    await resizeTo(page, DESKTOP);
    await gotoBySidebar(page, 'Settings', /^settings$/i);
    await gotoSettingsPage(page, /backup settings/i, 'Backup Settings');
    await expect(page.getByText('No backup history')).toBeVisible({
      timeout: LAZY_ROUTE_TIMEOUT_MS,
    });

    const main = page.locator('main');

    await test.step('no script can scroll the document under the page: there is nothing to scroll', async () => {
      // The page must be long enough for `<main>` to scroll at all, or nothing
      // below would mean anything.
      await main.evaluate((m) => {
        m.scrollTop = 0;
      });
      await settle(page);
      expect(await main.evaluate((m) => m.scrollHeight - m.clientHeight)).toBeGreaterThan(0);
      // Deterministic, whatever the browser does with wheel input.
      const forced = await page.evaluate(() => {
        const root = document.scrollingElement ?? document.documentElement;
        root.scrollTop = 1e9;
        const reached = window.scrollY;
        root.scrollTop = 0;
        return reached;
      });
      expect(forced).toBe(0);
    });

    await test.step("the operator's gesture: keep scrolling down once the page has ended", async () => {
      // `<main>` to its end, the way a finished scroll leaves it: awaiting
      // `scrollend` means no wheel sequence is latched to `<main>` when the next
      // wheel arrives, so that wheel goes wherever the browser chains it.
      await main.evaluate(
        (m) =>
          new Promise<void>((resolve) => {
            m.addEventListener('scrollend', () => resolve(), { once: true });
            m.scrollTop = m.scrollHeight;
          }),
      );
      const centre = await box(main);
      await page.mouse.move(centre.x + centre.width / 2, centre.y + centre.height / 2);
      await page.mouse.wheel(0, 400);
      await settle(page);
      await page.mouse.wheel(0, 400);
      await settle(page);

      const atEnd = await page.evaluate(() => {
        const m = document.querySelector('main');
        const banner = document.querySelector('body header');
        if (m === null || banner === null) throw new Error('shell not found');
        const mainBox = m.getBoundingClientRect();
        const hit = document.elementFromPoint(
          mainBox.left + mainBox.width / 2,
          window.innerHeight - 5,
        );
        return {
          windowScrollY: window.scrollY,
          mainAtItsEnd: m.scrollHeight - m.clientHeight - m.scrollTop <= 1,
          bannerBottom: Math.round(banner.getBoundingClientRect().bottom),
          mainBottom: Math.round(mainBox.bottom),
          viewportBottom: window.innerHeight,
          bottomEdgeIsPage: hit !== null && m.contains(hit),
        };
      });
      expect(atEnd).toEqual({
        windowScrollY: 0,
        mainAtItsEnd: true,
        bannerBottom: DESKTOP.height,
        mainBottom: DESKTOP.height,
        viewportBottom: DESKTOP.height,
        bottomEdgeIsPage: true,
      });

      // Scrolling back up moves the page and nothing else. Polled, because
      // `mouse.wheel` does not wait for the scroll it starts.
      const before = await main.evaluate((m) => m.scrollTop);
      await page.mouse.wheel(0, -400);
      await expect.poll(() => main.evaluate((m) => m.scrollTop)).toBeLessThan(before);
      await settle(page);
      expect(await page.evaluate(() => window.scrollY)).toBe(0);
    });
  });

  test('the folder rail toggle is visible, clickable and overlaps nothing', async ({ page }) => {
    await registerAndSignInViaUI(page);
    await resizeTo(page, DESKTOP);
    await expect(page.getByRole('heading', { name: 'Vault', level: 1 })).toBeVisible({
      timeout: LAZY_ROUTE_TIMEOUT_MS,
    });

    await test.step('collapse and restore the rail from the toolbar', async () => {
      const rail = page.locator('main aside');
      const search = page.getByLabel('Search vault items');
      const allItems = page.getByRole('button', { name: /^All Items/ });
      const toggle = page.getByRole('button', { name: 'Close sidebar' });
      await expect(rail).toBeVisible();
      await expect(toggle).toHaveCount(1);
      await settle(page);

      // Nothing covers it: the point at its centre belongs to the toggle (the
      // hit is its icon, hence `contains`).
      const reachable = await toggle.evaluate((el) => {
        const r = el.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return hit !== null && el.contains(hit);
      });
      expect(reachable, 'something covers the folder rail toggle').toBe(true);

      // In the toolbar row, left of the search field, clear of the rail.
      const open = { toggle: await box(toggle), search: await box(search) };
      expect(open.toggle.x + open.toggle.width).toBeLessThanOrEqual(open.search.x);
      expect(open.toggle.y).toBeLessThan(open.search.y + open.search.height);
      expect(open.search.y).toBeLessThan(open.toggle.y + open.toggle.height);
      expect(intersects(open.toggle, await box(allItems))).toBe(false);
      expect(intersects(open.toggle, await box(rail))).toBe(false);

      await toggle.click();
      await expect(rail).toBeHidden();
      const reopen = page.getByRole('button', { name: 'Open sidebar' });
      await expect(reopen).toHaveCount(1);
      const closed = { toggle: await box(reopen), search: await box(search) };
      expect(intersects(closed.toggle, closed.search)).toBe(false);
      expect(closed.toggle.x + closed.toggle.width).toBeLessThanOrEqual(closed.search.x);

      await reopen.click();
      await expect(rail).toBeVisible();
      await expect(page.getByRole('button', { name: 'Close sidebar' })).toHaveCount(1);
    });
  });
});
