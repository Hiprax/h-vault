import { test, expect, type Locator, type Page } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

/**
 * The keyboard and focus invariants automation cannot infer.
 *
 * axe (`a11y.spec.ts`) checks the STATIC properties of a rendered document: does
 * this control have a name, does this text meet the contrast threshold, is this
 * ARIA relationship well formed. It cannot check where focus GOES, whether a
 * keyboard user can get back out of a panel, or whether the dialog they are in
 * still holds them. Every behaviour below is one somebody had to fix once, in a
 * way that is invisible in the markup and would be silently lost by a refactor
 * that "tidied up" an effect.
 *
 * ## Why these live in a real browser rather than in jsdom
 *
 * The component suite already drives each of them
 * (`packages/client/tests/components/SavedAddressPicker.test.tsx`,
 * `coverage-vault-item-form.test.tsx`, `coverage-ui-components.test.tsx`), and
 * that is the right place for the exhaustive matrix. What it cannot do is what
 * makes these three cases interesting:
 *
 *   - jsdom does not implement Tab. A focus trap is a claim about what the
 *     BROWSER does when Tab is pressed, so a jsdom test of one asserts the
 *     handler it wrote rather than the behaviour a user gets.
 *   - jsdom does not focus a button on click, so the component tests have to
 *     `focus()` the control by hand before asserting where focus went — which
 *     means they cannot see a regression that only a real click sequence
 *     produces.
 *   - The Escape case is a claim about EVENT ORDER between two independent
 *     `document` listeners (the picker's capture-phase one and the dialog's
 *     bubble-phase one). The component test simulates the dialog's listener; here
 *     it is the real one, inside the real dialog, with a real half-filled item to
 *     lose.
 *
 * ## The one case that is NOT here, and why
 *
 * `DropdownMenu`'s roving focus (WCAG 2.1.1: focus moves to the first enabled
 * `menuitem` on open, then arrows and Home/End move it) is pinned in
 * `packages/client/tests/coverage-ui-components.test.tsx` and deliberately not
 * duplicated here — because the component has NO MOUNT SITE in the application.
 * Nothing in `packages/client/src` renders it; the only importers are its own
 * tests. There is no page to drive it on, so an end-to-end test of it would have
 * to mount a fixture, which is a component test with a browser attached and a
 * five-minute sign-in in front of it. The phase log records the defect-injection
 * transcript proving those component assertions still fail when the behaviour is
 * removed.
 */

const IDENTITIES = [
  { name: 'Home address', street: '1 Main St', city: 'London' },
  { name: 'Work address', street: '10 Tech Park', city: 'Cambridge' },
] as const;

test.describe('keyboard and focus invariants', () => {
  test('the picker, the billing section and the dialog trap behave under the keyboard', async ({
    page,
  }, testInfo) => {
    // One registration (two 600k-iteration derivations), then three fixtures and
    // a long keyboard walk — the same trade `address-fields.spec.ts` records.
    testInfo.setTimeout(300_000);
    await registerAndSignInViaUI(page);

    for (const identity of IDENTITIES) await createIdentityWithAddress(page, identity);

    // ─── The saved-address picker: an ARIA combobox ─────────────────────────
    let dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Card' }).click();
    await dialog.getByRole('button', { name: 'Use a saved address' }).click();

    const search = dialog.getByRole('combobox', { name: 'Search saved addresses' });
    const listbox = dialog.getByRole('listbox', { name: 'Saved addresses' });
    await expect(search).toBeFocused();
    await expect(listbox).toBeVisible();

    const options = listbox.getByRole('option');
    await expect(options).toHaveCount(IDENTITIES.length);

    // The contract: DOM focus never leaves the input, and `aria-activedescendant`
    // is what moves. A picker that moved real focus onto each option would blur
    // the field the user is still typing into — which is precisely why this is
    // not the shared `DropdownMenu`.
    await expectActiveOption(page, search, options, 0);
    await search.press('ArrowDown');
    await expectActiveOption(page, search, options, 1);
    await search.press('ArrowDown'); // wraps
    await expectActiveOption(page, search, options, 0);
    await search.press('End');
    await expectActiveOption(page, search, options, IDENTITIES.length - 1);
    await search.press('Home');
    await expectActiveOption(page, search, options, 0);

    // ─── Escape belongs to the panel, from every position focus can be in ───
    // All three were reachable when this was a bug, and all three ended the same
    // way: the whole half-filled item was discarded. The fix is a capture-phase
    // `document` listener, and nothing about the markup shows it is there.
    const trigger = dialog.getByRole('button', { name: 'Use a saved address' });

    // (1) focus INSIDE the panel.
    await search.press('Escape');
    await expect(listbox).toBeHidden();
    await expect(dialog).toBeVisible();
    await expect(trigger).toBeFocused();

    // (2) focus on the TRIGGER, which is a SIBLING of the panel — so a React
    // handler on the panel never sees the key.
    await trigger.click();
    await expect(search).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(trigger).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(listbox).toBeHidden();
    await expect(dialog).toBeVisible();

    // (3) focus OUTSIDE the picker entirely: Tab out of the search field lands on
    // the first control below the panel, with the panel still visibly open —
    // there is deliberately no focus-driven close.
    await trigger.click();
    await expect(search).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(search).not.toBeFocused();
    await expect(listbox).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(listbox).toBeHidden();
    await expect(dialog).toBeVisible();

    // ─── Focus is re-homed across every billing-section transition ──────────
    // Both arms of the billing ternary are unkeyed, so React reconciles by
    // position and destroys every fiber from the differing index on — including
    // whichever control the user just activated. Left alone, focus falls to
    // <body>, and the dialog's trap listens on the dialog CONTAINER, so the next
    // Tab escapes the modal entirely. Five transitions, two mechanisms.
    const street = dialog.locator('#field-billingStreet');
    const reveal = dialog.getByRole('button', { name: '+ Add billing address' });

    // (a) the reveal unmounts the button that was clicked.
    await reveal.click();
    await expect(street).toBeFocused();

    // (b) a fill into an already-open section still re-homes.
    await dialog.locator('#field-billingCity').click();
    await expect(dialog.locator('#field-billingCity')).toBeFocused();
    await fillFromPicker(dialog, 'Home address');
    await expect(street).toHaveValue('1 Main St');
    await expect(street).toBeFocused();

    // (c) an Undo that LEAVES the section open withdraws the button holding focus.
    const undo = dialog.getByRole('button', { name: /undo fill/i });
    await undo.click();
    await expect(undo).toBeHidden();
    await expect(street).toBeVisible();
    await expect(street).toBeFocused();

    // (d) Remove collapses the section, so focus goes to the reveal that replaces it.
    await dialog.getByRole('button', { name: 'Remove' }).click();
    await expect(street).toBeHidden();
    await expect(reveal).toBeFocused();

    // (e) an Undo that COLLAPSES the section (the fill is what opened it) goes the
    // same way. This is the other half of `restoreAddBillingFocus`.
    await fillFromPicker(dialog, 'Work address');
    await expect(street).toHaveValue('10 Tech Park');
    await dialog.getByRole('button', { name: /undo fill/i }).click();
    await expect(street).toBeHidden();
    await expect(reveal).toBeFocused();

    // ─── The dialog's focus trap holds ──────────────────────────────────────
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();

    dialog = await openCreateDialog(page);
    await expectFocusTrapped(page, 'Tab');
    await expectFocusTrapped(page, 'Shift+Tab');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
  });
});

// ─── Assertions ──────────────────────────────────────────────────────────────

/**
 * The combobox contract at one position: focus on the INPUT, the active option
 * named by `aria-activedescendant`, and `aria-selected` on that option ALONE.
 *
 * All three are asserted together on purpose. Focus without the pointer is a
 * picker a screen reader cannot follow; the pointer without focus is the
 * behaviour of a menu, which blurs the search field; and `aria-selected` on more
 * than one row tells the user they have selected several addresses.
 */
async function expectActiveOption(
  page: Page,
  search: Locator,
  options: Locator,
  index: number,
): Promise<void> {
  await expect(search).toBeFocused();
  const active = options.nth(index);
  const activeId = await active.getAttribute('id');
  expect(activeId, 'every option needs an id for aria-activedescendant to name it').toBeTruthy();
  await expect(search).toHaveAttribute('aria-activedescendant', activeId!);
  await expect(active).toHaveAttribute('aria-selected', 'true');

  const selected = await options.evaluateAll(
    (nodes) => nodes.filter((node) => node.getAttribute('aria-selected') === 'true').length,
  );
  expect(selected, 'exactly one option may be aria-selected').toBe(1);
  // The active option must be in the DOM: `aria-activedescendant` pointing at an
  // id that is not there names nothing, and the failure is completely silent.
  // `getElementById` inside the page rather than a CSS selector here, because
  // React's generated ids carry characters a selector would have to escape and
  // `CSS.escape` does not exist in the Node process the spec runs in.
  const activeIsInDocument = await page.evaluate(
    (id) => document.getElementById(id) !== null,
    activeId!,
  );
  expect(activeIsInDocument, 'aria-activedescendant names an element that is not there').toBe(true);
}

/**
 * Presses `key` far enough to cycle the dialog and requires focus to stay inside
 * it the whole way.
 *
 * The count is what makes this a trap test rather than a tab-order test: the
 * create dialog has fewer focusable controls than this, so the walk necessarily
 * runs off the end and has to be sent back to the other side. Focus is checked
 * after EVERY press — checking only at the end would pass if focus left the
 * dialog and happened to come back through the browser's own tab cycle.
 */
async function expectFocusTrapped(page: Page, key: 'Tab' | 'Shift+Tab'): Promise<void> {
  const PRESSES = 45;
  const seen: string[] = [];
  for (let i = 0; i < PRESSES; i++) {
    await page.keyboard.press(key);
    const where = await page.evaluate(() => {
      const active = document.activeElement;
      if (!(active instanceof HTMLElement)) return 'not-an-element';
      if (active.closest('[role="dialog"]') === null) return `escaped:${active.tagName}`;
      return active.id || active.getAttribute('aria-label') || active.textContent?.trim() || 'anon';
    });
    expect(where, `${key} #${String(i + 1)} left the dialog`).not.toMatch(
      /^escaped:|not-an-element/,
    );
    seen.push(where);
  }
  // Having stayed inside is necessary but not sufficient: focus parked on one
  // element would also never leave. A cycle proves it was still MOVING.
  expect(new Set(seen).size, `${key} never moved focus`).toBeGreaterThan(1);
  expect(seen.length, 'focus must return to somewhere it has already been').toBeGreaterThan(
    new Set(seen).size,
  );
}

// ─── Fixture helpers ─────────────────────────────────────────────────────────

/** Opens the create dialog (see `address-fields.spec.ts` for the alternation). */
async function openCreateDialog(page: Page): Promise<Locator> {
  await page
    .getByRole('button', { name: /^create (new )?item$/i })
    .first()
    .click();
  const dialog = page.getByRole('dialog', { name: /create new vault item/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

/** An identity carrying an address, so the picker has something to offer. */
async function createIdentityWithAddress(
  page: Page,
  identity: { name: string; street: string; city: string },
): Promise<void> {
  const dialog = await openCreateDialog(page);
  await dialog.getByRole('tab', { name: 'Identity' }).click();
  await dialog.getByPlaceholder('Item name').fill(identity.name);
  // Both name controls: the identity form requires a last name.
  await dialog.getByPlaceholder('First name').fill('Ada');
  await dialog.getByPlaceholder('Last name').fill('Lovelace');
  await dialog.locator('#field-street').fill(identity.street);
  await dialog.locator('#field-city').fill(identity.city);
  await dialog.getByRole('button', { name: 'Create' }).click();
  await expect(dialog).toBeHidden();
}

/** Opens the picker and chooses one option by its item name. */
async function fillFromPicker(dialog: Locator, name: string): Promise<void> {
  await dialog.getByRole('button', { name: 'Use a saved address' }).click();
  const listbox = dialog.getByRole('listbox', { name: 'Saved addresses' });
  await expect(listbox).toBeVisible();
  await listbox.getByRole('option', { name: new RegExp(name) }).click();
  await expect(listbox).toBeHidden();
}
