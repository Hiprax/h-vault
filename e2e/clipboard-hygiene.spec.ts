import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

/**
 * Clipboard hygiene, in a real browser.
 *
 * This is the layer that can catch the defect these tests exist for: the app used
 * to erase the OS clipboard on every transition to
 * `visibilityState === 'hidden'`, which is exactly the gesture a user makes to go
 * and paste a password. jsdom cannot see it, because it has no real page
 * visibility, no window focus, and a stubbed clipboard.
 *
 * ## Why these assert on writes rather than on clipboard contents
 *
 * Reading the clipboard back was tried first and is unusably flaky here: headless
 * Chromium intermittently reports an empty `readText()` for several seconds after
 * a `writeText()` that already resolved. Asserting on the calls the app makes to
 * `navigator.clipboard.writeText` is deterministic, and it pins the actual
 * invariant more precisely: an erase must not even be ATTEMPTED when the page is
 * merely hidden. An empty string reaching the clipboard is the whole defect, so
 * "no empty-string write happened" is the property worth guarding.
 */

/**
 * One `writeText` call the application made, and what the PLATFORM did with it.
 *
 * `ok` is the whole point of this shape. The spy used to record the argument
 * alone, which made an ATTEMPTED write indistinguishable from an ACCEPTED one —
 * and those are exactly the two outcomes the guard is built to tell apart. An
 * erase that Gecko refuses for want of transient user activation still shows up
 * as a `''` argument, so "the last thing written was the empty string" passed
 * whether the clipboard had been emptied or the secret was still sitting on it.
 * Both engines here refuse a timer-driven erase (measured), so that turned the
 * assertion this spec exists for into a tautology on every one of them.
 *
 * `null` means the write has not settled yet; `true` and `false` are the
 * promise's own two outcomes.
 */
interface ClipboardWrite {
  text: string;
  ok: boolean | null;
}

interface ClipboardSpyWindow {
  __hvClipboardWrites?: ClipboardWrite[];
}

/**
 * Give the page permission to write to the clipboard, on the engines that have
 * such a permission to give.
 *
 * This is a difference in the PLATFORM, not a difference in what is asserted
 * below: both engines run every line of all three tests. Chromium gates
 * `writeText()` on a Permissions API entry named `clipboard-write`, which is
 * auto-granted to the active tab in a normal browser and has to be granted
 * explicitly to an automated context. Gecko has no such permission at all — it
 * gates the same call on TRANSIENT USER ACTIVATION instead — so the name does
 * not exist there and Playwright rejects it outright with
 * `browserContext.grantPermissions: Unknown permission: clipboard-write`
 * (measured, Playwright 1.61.1 / Firefox 151).
 *
 * Hence the condition, which is on the engine's permission model rather than on
 * a test that is expected to fail: a `try`/`catch` around the grant would have
 * hidden a genuine permission error just as effectively, and skipping the spec
 * on Firefox would have thrown away the only run that exercises the activation
 * rule the guard was written for.
 */
async function grantClipboardWrite(
  context: BrowserContext,
  browserName: 'chromium' | 'firefox' | 'webkit',
): Promise<void> {
  if (browserName === 'chromium') {
    await context.grantPermissions(['clipboard-write']);
  }
}

/**
 * Record every `writeText` the app performs, passing each call through to the real
 * implementation so copying still works. Installed as an init script so it is in
 * place before any application code runs, on every document load.
 */
async function installClipboardSpy(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const spy = window as unknown as ClipboardSpyWindow;
    spy.__hvClipboardWrites = [];
    const original = navigator.clipboard.writeText.bind(navigator.clipboard);
    Object.defineProperty(navigator.clipboard, 'writeText', {
      configurable: true,
      writable: true,
      value: (text: string) => {
        const record: ClipboardWrite = { text, ok: null };
        spy.__hvClipboardWrites?.push(record);
        // The record is returned to the application UNCHANGED — the outcome is
        // observed, never altered. A refusal must still reject exactly as the
        // platform rejected it, or the guard would take the wrong branch.
        const settled = original(text);
        settled.then(
          () => {
            record.ok = true;
          },
          () => {
            record.ok = false;
          },
        );
        return settled;
      },
    });
  });
}

function clipboardWrites(page: Page): Promise<ClipboardWrite[]> {
  return page.evaluate(() => (window as unknown as ClipboardSpyWindow).__hvClipboardWrites ?? []);
}

/**
 * Report `visibilityState` as `state` and fire a real `visibilitychange`, which is
 * precisely what the guard's handler reads.
 *
 * Headless Chromium keeps every page "visible" regardless of which one is in
 * front, so `bringToFront()` cannot background a tab here (verified: the
 * backgrounded page still reports `visible`). Overriding the property is the only
 * way to exercise the transition in this harness.
 */
async function emulateVisibility(page: Page, state: 'hidden' | 'visible'): Promise<void> {
  await page.evaluate((value) => {
    Object.defineProperty(document, 'visibilityState', {
      get: () => value,
      configurable: true,
    });
    document.dispatchEvent(new Event('visibilitychange'));
  }, state);
}

/**
 * The live countdown the guard drives, e.g. "Clipboard will clear in 27s".
 *
 * `useClipboardCountdown` renders it from `subscribeClipboardGuard`, so it is a
 * direct read-out of the guard's own state: it appears when a secret is pending,
 * re-titles once a second from the deadline, and is DISMISSED the moment the
 * erase is confirmed. That makes it the synchronisation signal these tests need.
 */
function countdownToast(page: Page) {
  return page.getByText(/clipboard will clear in \d+s/i);
}

/**
 * The notice the guard shows when the browser REFUSED the erase.
 *
 * `useClipboardCountdown` renders this and nothing else does, so its presence is
 * a direct read-out of `overdue` — the state a refusal produces and a success
 * cannot. The wording is deliberately "on your next action here" rather than
 * "when you return", because on an activation-gated engine the guard cannot
 * promise a moment, only a gesture.
 */
function overdueToast(page: Page) {
  return page.getByText(/clipboard not cleared yet/i);
}

/**
 * Seconds remaining, or `NaN` when no countdown is on screen.
 *
 * The `count()` guard is load-bearing: `textContent()` auto-waits for its
 * element, so on a DISMISSED toast — exactly the state an unwanted erase
 * produces — it would block until the whole test timed out instead of letting
 * the poll below fail with a message that names the countdown.
 */
async function countdownSeconds(page: Page): Promise<number> {
  const toast = countdownToast(page);
  if ((await toast.count()) === 0) return Number.NaN;
  const text = (await toast.first().textContent()) ?? '';
  const match = /clipboard will clear in (\d+)s/i.exec(text);
  return match?.[1] === undefined ? Number.NaN : Number(match[1]);
}

/**
 * Wait for the guard to make observable progress, and assert the deadline is
 * still running while doing it.
 *
 * This replaces a blind 250 ms `waitForTimeout`. Polling for a countdown STRICTLY
 * BELOW the value seen before the transition proves three things a sleep cannot:
 * the guard's handler has run, at least a full second of its deadline has
 * elapsed, and the deadline was neither cancelled nor restarted. An erase would
 * clear `pending` and dismiss the toast entirely, so the poll fails on the very
 * defect these tests exist for instead of silently racing it.
 */
async function expectCountdownStillTicking(page: Page, below: number): Promise<number> {
  await expect.poll(() => countdownSeconds(page), { timeout: 15_000 }).toBeLessThan(below);
  return countdownSeconds(page);
}

/**
 * How long {@link waitForDeadlineErase} will wait in the page for the erase.
 *
 * The deadline itself is `CLIPBOARD_CLEAR_SECONDS` (30 s) from the copy. This is
 * that plus room for a contended machine — a CEILING on a wait for a real event,
 * not a synchronisation delay: the wait ends the instant the erase settles, and a
 * run that reaches this number has found a deadline that never fired, which is a
 * defect worth reporting rather than a slow machine to be tolerated.
 *
 * It is checked BETWEEN animation frames, so it binds only while frames are being
 * served. A page whose frames stopped entirely would be bounded by the test's own
 * timeout instead, and that is deliberate: racing this against a timer would put a
 * `setTimeout` of exactly the shape the integrity scan treats as a sleep back into
 * the file, to guard a case in which the browser has already stopped running the
 * application.
 */
const DEADLINE_ERASE_CAP_MS = 60_000;

/**
 * The enclosing test's budget for the deadline spec.
 *
 * Two key derivations through the UI, plus a real 30-second deadline, plus the
 * ceiling above. Bound by the master-password derivation and by a platform timer,
 * neither of which goes faster on a quiet machine.
 */
const DEADLINE_TEST_TIMEOUT_MS = 300_000;

/**
 * Wait for the guard's DEADLINE erase to settle, without touching the page.
 *
 * This is one `page.evaluate` that returns a promise, and that is the whole
 * technique. MEASURED, on both engines: every Playwright protocol call — an
 * `evaluate`, a locator query, an `expect.poll` iteration — refreshes the
 * document's transient user activation, and `navigator.userActivation.isActive`
 * was never once observed to go false while a poll was running. So polling from
 * the runner does not merely fail to see a refusal; it PREVENTS one, by keeping
 * the page permanently activated. Waiting in the page instead makes exactly one
 * protocol call, at the start, and then stays silent for the whole deadline.
 *
 * `CLIPBOARD_CLEAR_SECONDS` is 30 and Gecko's transient activation lasts 5, so by
 * the time the guard's timer fires the copy's activation has been gone for about
 * twenty-five seconds. That margin is why this is deterministic rather than a
 * race, and it is also why this cannot be done with `page.clock`: the activation
 * deadline is native and is not one of the JS clocks `clock.install()` fakes, so
 * fast-forwarding would fire the erase while the click's activation was still
 * live and quietly reproduce the accepting path instead.
 *
 * `documentFocused` is captured at the moment the erase settles, and it is not
 * decoration: without it, a refusal is indistinguishable from "this headless page
 * happened to be in the background", which is the ONE uninteresting explanation
 * for the whole result. Reading it here rather than from the runner matters for
 * the same reason as everything else in this function — a protocol call to ask
 * would have refreshed the activation the answer is about.
 *
 * Returns the settled record, or `null` if no erase was even attempted — which is
 * a failure of the deadline itself and is reported as one.
 */
interface DeadlineErase extends ClipboardWrite {
  documentFocused: boolean;
}

async function waitForDeadlineErase(page: Page): Promise<DeadlineErase | null> {
  return page.evaluate(async (capMs: number) => {
    const spy = window as unknown as ClipboardSpyWindow;
    const giveUpAt = Date.now() + capMs;
    for (;;) {
      const settled = (spy.__hvClipboardWrites ?? []).find(
        (write) => write.text === '' && write.ok !== null,
      );
      if (settled !== undefined) return { ...settled, documentFocused: document.hasFocus() };
      if (Date.now() >= giveUpAt) return null;
      // One animation frame between checks, not a timer: this is a poll for a
      // condition, and a frame is both the cheapest tick the page has and the one
      // that cannot be mistaken for a wait of a chosen length.
      await new Promise((resolve) => requestAnimationFrame(() => resolve(null)));
    }
  }, DEADLINE_ERASE_CAP_MS);
}

async function copyGeneratedPassword(page: Page): Promise<void> {
  await page.getByRole('link', { name: /password generator/i }).click();
  await expect(page).toHaveURL(/\/generator/);

  const copyButton = page.getByRole('button', { name: 'Copy password' }).first();
  await expect(copyButton).toBeVisible();
  // The first password arrives on a debounced timer; the copy control is disabled
  // until then, so clicking earlier would copy an empty string.
  await expect(copyButton).toBeEnabled();
  await copyButton.click();
  await expect(page.getByText(/password copied to clipboard/i)).toBeVisible();
}

test.describe('clipboard hygiene', () => {
  test('backgrounding the tab never erases a copied password', async ({
    browserName,
    context,
    page,
  }) => {
    await grantClipboardWrite(context, browserName);
    await installClipboardSpy(page);
    await registerAndSignInViaUI(page);
    await copyGeneratedPassword(page);

    // The copy itself wrote the secret, the PLATFORM ACCEPTED it, and nothing has
    // erased it. `ok` is what makes the second of those three an assertion rather
    // than an assumption, and on an activation-gated engine it is the whole claim:
    // `copySecretToClipboard` only arms the deadline after its write RESOLVES, so a
    // copy that Gecko refused would leave no countdown to tick below.
    const afterCopy = await clipboardWrites(page);
    expect(afterCopy).toHaveLength(1);
    expect(afterCopy[0]?.text).not.toBe('');
    expect(afterCopy[0]?.ok).toBe(true);

    // The deadline is running and visible to the user.
    await expect(countdownToast(page)).toBeVisible();
    const started = await countdownSeconds(page);
    expect(started).toBeGreaterThan(0);

    // THE regression: the old implementation erased the clipboard right here, so
    // the password the user was on their way to paste was already gone.
    await emulateVisibility(page, 'hidden');
    const whileHidden = await expectCountdownStillTicking(page, started);
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Returning must not erase it early either. `focus` is the retry path, so this
    // also pins that the retry is a no-op while nothing is due.
    await emulateVisibility(page, 'visible');
    await page.evaluate(() => {
      window.dispatchEvent(new Event('focus'));
    });
    const afterFocus = await expectCountdownStillTicking(page, whileHidden);
    expect(await clipboardWrites(page)).toEqual(afterCopy);

    // Repeated hide/show cycles, still untouched.
    for (let cycle = 0; cycle < 3; cycle++) {
      await emulateVisibility(page, 'hidden');
      await emulateVisibility(page, 'visible');
    }
    await expectCountdownStillTicking(page, afterFocus);
    const writes = await clipboardWrites(page);
    expect(writes).toEqual(afterCopy);
    expect(writes.filter((write) => write.text === '')).toHaveLength(0);
  });

  test('locking the vault erases a copied password', async ({ browserName, context, page }) => {
    await grantClipboardWrite(context, browserName);
    await installClipboardSpy(page);
    await registerAndSignInViaUI(page);
    await copyGeneratedPassword(page);
    expect(await clipboardWrites(page)).toHaveLength(1);

    // Ctrl+L locks the vault, and the erase rides the keypress that requested it.
    // That is why it is worth running twice. The engines do not accept it for the
    // same reason — Gecko accepts because a `keydown` grants transient user
    // activation and the lock's erase is issued inside it — and the test below
    // proves that a write issued OUTSIDE a gesture is refused on both, so a
    // gesture-scoped erase is the only kind either engine will take here. The
    // guarantee SECURITY.md states, that locking erases the clipboard immediately
    // on every engine, had only one engine's evidence behind it before this leg.
    await page.keyboard.press('Control+l');
    await expect(page.getByText('Vault Locked')).toBeVisible({ timeout: 30_000 });

    // `ok: true`, not merely `text: ''`: the empty string is written whether the
    // platform accepts it or refuses it, and a refusal leaves the secret on the
    // clipboard with the guard marking it overdue for the next gesture. Only the
    // settled outcome distinguishes "erased" from "tried to erase".
    await expect
      .poll(async () => (await clipboardWrites(page)).at(-1), { timeout: 10_000 })
      .toEqual({ text: '', ok: true });
  });

  test('an erase the platform refuses is retried at the next gesture, never forgotten', async ({
    browserName,
    context,
    page,
  }) => {
    test.setTimeout(DEADLINE_TEST_TIMEOUT_MS);
    await grantClipboardWrite(context, browserName);
    await installClipboardSpy(page);
    await registerAndSignInViaUI(page);
    await copyGeneratedPassword(page);

    // Nothing touches the page from here until the deadline elapses. See
    // `waitForDeadlineErase`: a poll from the runner would keep the document
    // user-activated and destroy the very condition this test is about.
    const settled = await waitForDeadlineErase(page);
    expect(settled, 'the clipboard deadline must attempt an erase when it elapses').not.toBeNull();

    // BOTH engines refuse it, and that is a MEASUREMENT rather than an assumption —
    // it is also not what this test was first written to expect. Gecko refuses for
    // want of transient user activation, which is its documented rule. Chromium
    // refuses too, with `clipboard-write` granted, so the permission alone does not
    // carry a timer-driven write there either. `documentFocused` is asserted in the
    // same breath because it rules out the one dull explanation: the page was in
    // front on both engines and the write was still refused. That makes this one
    // unbranched assertion rather than two engine arms, and it makes the branch in
    // `services/clipboard/clipboardService.ts` reachable on every engine this suite
    // runs — the opposite of the "Chromium is the permissive case" reading that the
    // unit tests' simulated refusals left standing. If a future engine ever ACCEPTS
    // this write, this line is where it will say so, and that is worth being told:
    // the guard's whole overdue path exists for the engines that do not.
    //
    // Three things must then hold, and all three were once wrong in shipped code:
    //   1. the refusal is not mistaken for success — the secret stays pending;
    //   2. the user is TOLD, rather than being left with a countdown that already
    //      reached zero and a clipboard that still holds a password;
    //   3. nothing re-wrote the secret in the process.
    expect(settled).toEqual({ text: '', ok: false, documentFocused: true });
    await expect(overdueToast(page)).toBeVisible();
    const afterRefusal = await clipboardWrites(page);
    expect(afterRefusal.filter((write) => write.text !== '')).toHaveLength(1);

    // The retry is gesture-scoped because on this engine nothing else can succeed.
    // A keypress is a real trusted event, so it both grants the activation the
    // write needs and is the `keydown` `useClipboardGuard` listens for.
    await page.keyboard.press('Tab');

    await expect
      .poll(async () => (await clipboardWrites(page)).at(-1), { timeout: 15_000 })
      .toEqual({ text: '', ok: true });
    await expect(overdueToast(page)).toHaveCount(0);
    // And the secret was never put back on the clipboard to achieve it.
    expect((await clipboardWrites(page)).filter((write) => write.text !== '')).toHaveLength(1);
  });
});
