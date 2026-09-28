/**
 * `dark:` utilities follow the APP's theme, not the operating system's.
 *
 * The colour tokens switch on the `.dark` class the app puts on `<html>` from
 * the theme setting, and the Tailwind `dark:` variant must switch on the same
 * thing. By default Tailwind v4 compiles `dark:` into a `prefers-color-scheme`
 * media query instead, so with the app set to dark on a light system (or the
 * other way round) half of a component followed one theme and half the other.
 * This measures a real computed colour, which only a browser can: jsdom
 * computes no styles at all. Every element eases its colour over 0.2s
 * (`globals.css`), so each reading waits for the transitions a theme switch
 * starts to finish; read at once, the colour is caught half-way between the
 * two themes.
 */
import { test, expect } from '@playwright/test';
import { registerAndSignInViaUI } from './helpers';

test('the dark variant follows the dark class, whatever the system asks for', async ({ page }) => {
  await registerAndSignInViaUI(page);
  // The connection indicator is `text-green-800 dark:text-green-400`.
  const indicator = page.getByText('Online', { exact: true });
  await expect(indicator).toBeVisible();
  const colourWith = async (scheme: 'light' | 'dark', darkClass: boolean) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.evaluate((on) => {
      document.documentElement.classList.toggle('dark', on);
    }, darkClass);
    return indicator.evaluate(async (node) => {
      // `getAnimations()` flushes the pending style change, so the transitions
      // the switch starts exist by now; a cancelled one rejects, which is fine.
      const transitions = document
        .getAnimations()
        .filter((animation) => animation instanceof CSSTransition);
      await Promise.all(transitions.map((animation) => animation.finished.catch(() => undefined)));
      return getComputedStyle(node.parentElement ?? node).color;
    });
  };

  const lightApp = await colourWith('light', false);
  const darkAppOnLightSystem = await colourWith('light', true);
  const lightAppOnDarkSystem = await colourWith('dark', false);
  const darkApp = await colourWith('dark', true);

  // The app's own setting decides, in both directions.
  expect(darkAppOnLightSystem).not.toBe(lightApp);
  expect(darkAppOnLightSystem).toBe(darkApp);
  expect(lightAppOnDarkSystem).toBe(lightApp);
});
