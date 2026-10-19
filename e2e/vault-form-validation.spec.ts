import { test, expect, type Locator, type Page } from '@playwright/test';
import { describeA11y, registerAndSignInViaUI, scanA11y } from './helpers';

/**
 * The 0.18.0 editor, card-expiry, custom-field and Settings-help behaviour, end to
 * end in a real Chromium.
 *
 * What only this layer can establish:
 *
 * 1. the identity email no longer blocks the save SILENTLY. The defect lived in the
 *    browser's own constraint validation, which jsdom only approximates: Chromium
 *    is what showed the focus-without-a-message the report described. Likewise a
 *    half-typed date: only a real date control reads as empty while it holds
 *    typed parts, and only a real one would wipe them if the form wrote to it.
 * 2. a card whose expiry has passed is warned about everywhere it appears (the
 *    editor, the vault list, the item view, the vault reminder), after a real save,
 *    a real encryption and a real decrypt, and those states pass axe.
 * 3. a note made of nothing but a custom field survives the round trip.
 * 4. a Settings help popover opens on hover and closes on Escape in a real layout.
 * 5. an import over the custom-field limit (`CUSTOM_FIELDS_LIMIT`, the default 30
 *    pinned by e2e/start-server.ts) shows what it will cut BEFORE sending, and the
 *    report after.
 *
 * One test and one registration on purpose: PBKDF2 at 600k dominates the wall
 * clock, and every step below needs nothing a fresh account would add.
 *
 * Locators prefer roles, test ids and `#field-*` ids: Playwright's text and label
 * matchers are substring matchers, and several labels here are prefixes of others.
 * Navigation is SPA-only (link clicks): a full load locks the vault.
 */

async function openCreateDialog(page: Page): Promise<Locator> {
  await page
    .getByRole('button', { name: /^create (new )?item$/i })
    .first()
    .click();
  const dialog = page.getByRole('dialog', { name: /create new vault item/i });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function goToVault(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Vault', exact: true }).click();
  await expect(page).toHaveURL(/\/vault$/);
}

async function goToSettings(page: Page): Promise<void> {
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await expect(page).toHaveURL(/\/settings/);
}

/** A Bitwarden JSON login with `textCount` text fields and two hidden ones after them. */
function overLimitBitwardenExport(textCount: number): string {
  return JSON.stringify({
    items: [
      {
        type: 1,
        name: 'Over the limit',
        login: { username: 'many', password: 'many-pass', uris: [] },
        fields: [
          ...Array.from({ length: textCount }, (_, i) => ({
            name: `Field ${String(i + 1)}`,
            value: `value ${String(i + 1)}`,
            type: 0,
          })),
          { name: 'Hidden one', value: 'E2E-HIDDEN-VALUE-ONE', type: 1 },
          { name: 'Hidden two', value: 'E2E-HIDDEN-VALUE-TWO', type: 1 },
        ],
      },
    ],
  });
}

test('validates as it should, warns about expired cards, and explains itself', async ({ page }) => {
  test.setTimeout(240_000);
  await registerAndSignInViaUI(page);

  await test.step('an invalid identity email is reported, with every other problem', async () => {
    const dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Identity' }).click();
    await dialog.locator('#field-email').fill('not-an-email');
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();

    await expect(
      dialog.getByText('Enter a valid email address, like name@example.com'),
    ).toBeVisible();
    await expect(dialog.getByText('Name is required', { exact: true })).toBeVisible();
    await expect(dialog.getByText('First name is required', { exact: true })).toBeVisible();
    await expect(dialog.getByText('Last name is required', { exact: true })).toBeVisible();
    // Focus is on the first problem on screen, and the dialog did not close.
    await expect(dialog.locator('#field-name')).toBeFocused();
    await expect(dialog).toBeVisible();

    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(dialog).toBeHidden();
  });

  await test.step('a half-typed expiry date is refused on every save, and stays as typed', async () => {
    const dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Secret' }).click();
    await dialog.locator('#field-name').fill('API key');
    await dialog.getByPlaceholder('Secret value (API key, token, etc.)').fill('sk-123');
    const date = dialog.locator('#field-expiryDate');
    // Month only: the control holds a value script reads as empty.
    await date.focus();
    await page.keyboard.type('12');
    await expect
      .poll(() => date.evaluate((el: HTMLInputElement) => el.validity.badInput))
      .toBe(true);

    // A person's press, held: the button keeps focus where it is, so leaving the
    // date shows nothing between the press and the release that could move Create
    // away from under the pointer. The save itself then runs, and refuses.
    const create = dialog.getByRole('button', { name: 'Create', exact: true });
    await create.scrollIntoViewIfNeeded();
    const box = await create.boundingBox();
    if (box === null) throw new Error('the Create button has no box');
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await expect(date).toBeFocused();
    await expect(dialog.getByText('Enter a complete date, or clear it')).toHaveCount(0);
    await page.mouse.up();
    await expect(dialog.getByText('Enter a complete date, or clear it')).toBeVisible();
    await expect(dialog.getByText('1 field needs your attention', { exact: false })).toBeVisible();

    // What was typed is still there, so the next save is refused too.
    expect(await date.evaluate((el: HTMLInputElement) => el.validity.badInput)).toBe(true);
    await create.click();
    await expect(dialog.getByText('Enter a complete date, or clear it')).toBeVisible();
    expect(await date.evaluate((el: HTMLInputElement) => el.validity.badInput)).toBe(true);
    await expect(dialog).toBeVisible();

    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(dialog).toBeHidden();
  });

  await test.step('an expired card is warned about in the editor, the list, the item and the vault', async () => {
    const dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Card' }).click();
    await dialog.locator('#field-name').fill('Old Visa');
    await dialog.locator('#field-cardholderName').fill('Ada Lovelace');
    await dialog.locator('#field-number').fill('4111111111111111');
    await dialog.locator('#field-expMonth').fill('1');
    await dialog.locator('#field-expYear').fill('20');
    await dialog.locator('#field-expYear').blur();
    // A two-digit year is said back as 20YY as soon as it is left.
    await expect(dialog.locator('#field-expYear')).toHaveValue('2020');
    await expect(dialog.getByTestId('card-expiry-hint')).toContainText(
      'This card expired at the end of January 2020. You can still save it.',
    );
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(dialog).toBeHidden();

    const row = page.getByTestId('vault-item-row').filter({ hasText: 'Old Visa' });
    await expect(row.getByTestId('card-expiry-badge')).toHaveText('Expired');

    const reminder = page.getByTestId('expiring-cards-reminder');
    await expect(reminder).toContainText('1 card has expired.');
    const vaultScan = await scanA11y(page, 'vault with an expired card');
    expect(vaultScan.blocking, describeA11y(vaultScan)).toEqual([]);

    await reminder.getByRole('link', { name: /Old Visa/ }).click();
    await expect(page.getByTestId('card-expiry-notice')).toContainText('This card has expired');
    const itemScan = await scanA11y(page, 'expired card item view');
    expect(itemScan.blocking, describeA11y(itemScan)).toEqual([]);

    await goToVault(page);
    await page.getByRole('button', { name: 'Hide card expiry reminder' }).click();
    await expect(page.getByTestId('expiring-cards-reminder')).toHaveCount(0);
    await expect(page.getByRole('heading', { level: 1, name: 'Vault' })).toBeFocused();
  });

  await test.step('a note made only of a custom field round-trips', async () => {
    const dialog = await openCreateDialog(page);
    await dialog.getByRole('tab', { name: 'Note' }).click();
    await dialog.locator('#field-name').fill('Wi-Fi');
    await expect(dialog.getByText('(0 of 30)')).toBeVisible();
    await dialog.getByRole('button', { name: '+ Add Field' }).click();
    await dialog.getByLabel('Custom field 1 name').fill('Network');
    await dialog.getByLabel('Custom field 1 value').fill('home-5g');
    // A yes/no field: its checkbox keeps focus where it is when pressed, and must
    // still switch on.
    await dialog.getByRole('button', { name: '+ Add Field' }).click();
    await dialog.getByLabel('Custom field 2 name').fill('Guests allowed');
    await dialog.getByLabel('Custom field 2 type').selectOption('boolean');
    await dialog.getByRole('checkbox').click();
    await expect(dialog.getByRole('checkbox')).toBeChecked();
    await dialog.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(dialog).toBeHidden();

    await page.getByTestId('vault-item-name').filter({ hasText: 'Wi-Fi' }).click();
    await expect(page.getByText('Network', { exact: true })).toBeVisible();
    await expect(page.getByText('home-5g', { exact: true })).toBeVisible();
    await expect(page.getByText('Guests allowed', { exact: true })).toBeVisible();
    await goToVault(page);
  });

  await test.step('a Settings help popover opens on hover and closes on Escape', async () => {
    await goToSettings(page);
    const trigger = page.getByRole('button', { name: 'Help: what rotating the vault key does' });
    await trigger.hover();
    const panel = page.getByRole('dialog', { name: 'Vault key rotation, explained' });
    await expect(panel).toBeVisible();
    await expect(
      panel.getByRole('heading', { level: 3, name: 'What happens when you rotate' }),
    ).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(panel).toBeHidden();

    // Pinned by a click, Tab leaves the panel for the control after the trigger.
    await trigger.click();
    await expect(panel).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(panel).toBeHidden();
    await expect(trigger).not.toBeFocused();
  });

  await test.step('an import over the custom-field limit says what it cuts, before and after', async () => {
    await page.getByRole('button', { name: 'Import Vault' }).click();
    const format = page
      .locator('select')
      .filter({ has: page.locator('option[value="bitwarden"]') });
    await format.selectOption('bitwarden');
    await page.getByPlaceholder('Paste exported data here...').fill(overLimitBitwardenExport(31));
    await page.getByRole('button', { name: 'Import', exact: true }).click();

    const confirm = page.getByRole('dialog', { name: 'Confirm import changes' });
    await expect(confirm).toBeVisible();
    const cuts = confirm.getByRole('region', {
      name: 'Custom fields this import will move or leave out',
    });
    await expect(cuts).toContainText(
      'In 1 entry, some custom fields are moved or left out. The limit is 30 custom fields per entry.',
    );
    await expect(cuts).toContainText('moved to its notes: Field 31');
    await expect(cuts).toContainText('hidden, not imported: Hidden one, Hidden two');
    await expect(confirm).not.toContainText('E2E-HIDDEN-VALUE');
    await confirm.getByRole('button', { name: 'Apply Changes' }).click();

    const report = page.getByRole('region', { name: 'Import report' });
    await expect(report).toContainText('hidden, not imported: Hidden one, Hidden two');
    await expect(report).not.toContainText('E2E-HIDDEN-VALUE');
  });
});
