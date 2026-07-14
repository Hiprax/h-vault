/**
 * Dynamic favicon reflecting vault state.
 *
 * The browser-tab icon signals whether the vault is currently accessible:
 *   - `unlocked` (authenticated AND unlocked) -> green background, open padlock
 *   - `locked`   (logged out OR locked)       -> red background, closed padlock
 *
 * The icons are shipped as static SVG files in `public/` so the correct default
 * (`locked`) is shown on first paint before any script runs (index.html points
 * at `/favicon.svg`). At runtime `setFaviconState` swaps the `<link rel="icon">`
 * href as the auth state changes.
 */

export type FaviconState = 'locked' | 'unlocked';

/**
 * Public paths for each state. `locked` reuses `/favicon.svg` (the static
 * default declared in index.html), so the logged-out/first-load icon and the
 * runtime `locked` icon are one and the same file.
 */
export const FAVICON_HREFS: Record<FaviconState, string> = {
  locked: '/favicon.svg',
  unlocked: '/favicon-unlocked.svg',
};

/**
 * Map auth state to a favicon state. The vault is only "unlocked" (green, open)
 * when the user is both authenticated and not locked; every other combination
 * (logged out, or locked whether automatically or by choice) is "locked".
 */
export function faviconStateFor(isAuthenticated: boolean, isLocked: boolean): FaviconState {
  return isAuthenticated && !isLocked ? 'unlocked' : 'locked';
}

// Remember the last applied state so repeated calls with the same state are
// no-ops (avoids redundant DOM writes / favicon refetches).
let appliedState: FaviconState | null = null;

/**
 * Point the document's `<link rel="icon">` at the SVG for the given state,
 * creating the link element if the document has none. No-op outside a DOM
 * environment (e.g. SSR / unit tests without jsdom).
 */
export function setFaviconState(state: FaviconState): void {
  if (typeof document === 'undefined') return;
  if (state === appliedState) return;
  appliedState = state;

  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.setAttribute('rel', 'icon');
    document.head.appendChild(link);
  }
  link.setAttribute('type', 'image/svg+xml');
  link.setAttribute('href', FAVICON_HREFS[state]);
}

/** Test-only: clear the memoised applied state between test cases. */
export function resetFaviconStateForTests(): void {
  appliedState = null;
}
