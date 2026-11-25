/**
 * `RailLayout` — the two-pane shell `/vault` and `/documents` share.
 *
 * Extracted rather than copied, so it is tested once rather than through two
 * pages that each happen to exercise half of it. The cases below are the parts
 * no page test reaches: the desktop collapse toggle, the mobile drawer's four
 * ways to close, and the toolbar bar's own layout.
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RailLayout } from '../../src/components/layout/RailLayout';

function renderLayout(toolbar?: React.ReactNode) {
  const close = vi.fn();
  const view = render(
    <RailLayout
      rail={(closeDrawer) => (
        <button type="button" onClick={closeDrawer} data-testid="rail-close">
          rail
        </button>
      )}
      {...(toolbar === undefined ? {} : { toolbar })}
    >
      <p>pane</p>
    </RailLayout>,
  );
  return { ...view, close };
}

const aside = (): HTMLElement => document.querySelector('aside')!;

/**
 * The bar above the pane, found while the rail is OPEN: the drawer trigger is
 * then the only control named "Open sidebar" (the desktop toggle reads "Close
 * sidebar"). Callers take it once, before collapsing, because a collapsed rail
 * names both controls "Open sidebar".
 */
const topBar = (): HTMLElement =>
  screen.getByRole('button', { name: 'Open sidebar' }).parentElement!;

/**
 * The DESKTOP collapse toggle: the top bar's FIRST control, by position rather
 * than by name.
 *
 * Several controls carry "Close sidebar" or "Open sidebar": this one, the drawer
 * trigger beside it, the mobile overlay and the drawer's X. They are never
 * exposed together — this one is `hidden lg:inline-flex`, the others are
 * `lg:hidden`, and `display: none` keeps an element out of the accessibility
 * tree — but jsdom applies no CSS, so a query by name here would match several.
 */
const desktopToggle = (bar: HTMLElement): HTMLElement => bar.querySelector('button')!;

/** The icon drawn in a control, by its exact lucide class (one name prefixes the other). */
function expectIcon(control: HTMLElement, icon: 'lucide-panel-left-close' | 'lucide-panel-left') {
  const svg = control.querySelector('svg')!;
  const other = icon === 'lucide-panel-left' ? 'lucide-panel-left-close' : 'lucide-panel-left';
  expect(svg.classList.contains(icon)).toBe(true);
  expect(svg.classList.contains(other)).toBe(false);
}

/** The full-screen overlay behind the mobile drawer. */
const overlay = (): HTMLElement | null =>
  document.querySelector('button.fixed.inset-0[aria-label="Close sidebar"]');

describe('RailLayout', () => {
  it('collapses and restores the desktop rail, and says and shows which it will do', () => {
    renderLayout();
    const toggle = desktopToggle(topBar());

    // Open: the rail is drawn on large screens, and the control offers to close
    // it — in its name, in the tooltip a pointer user reads, and in its icon.
    expect(aside().className).toContain('lg:block');
    expect(toggle).toHaveAttribute('aria-label', 'Close sidebar');
    expect(toggle).toHaveAttribute('title', 'Close sidebar');
    expectIcon(toggle, 'lucide-panel-left-close');

    fireEvent.click(toggle);

    // Collapsed: hidden at EVERY width, and the control now offers the reverse.
    expect(aside().className).not.toContain('lg:block');
    expect(toggle).toHaveAttribute('aria-label', 'Open sidebar');
    expect(toggle).toHaveAttribute('title', 'Open sidebar');
    expectIcon(toggle, 'lucide-panel-left');

    fireEvent.click(toggle);
    expect(aside().className).toContain('lg:block');
    expect(toggle).toHaveAttribute('aria-label', 'Close sidebar');
    expectIcon(toggle, 'lucide-panel-left-close');
  });

  it('opens the mobile drawer and closes it from the overlay, the X, and the rail', () => {
    renderLayout();
    // The trigger that is only drawn on small screens, distinct from the desktop
    // collapse toggle before it in the same bar.
    const open = () =>
      fireEvent.click(
        screen.getAllByRole('button', { name: 'Open sidebar' }).at(-1) as HTMLElement,
      );

    // The overlay behind the drawer.
    open();
    expect(aside().className).toContain('fixed');
    expect(overlay()).not.toBeNull();
    fireEvent.click(overlay()!);
    expect(aside().className).not.toContain('fixed');

    // Escape, on that same overlay.
    open();
    fireEvent.keyDown(overlay()!, { key: 'Escape' });
    expect(aside().className).not.toContain('fixed');

    // The rail's own callback, which is what a selection uses: the layout owns
    // the drawer, so no scope hook has to know one exists.
    open();
    expect(aside().className).toContain('fixed');
    fireEvent.click(screen.getByTestId('rail-close'));
    expect(aside().className).not.toContain('fixed');
  });

  it('draws the top bar at every width: the rail toggle first, then the drawer trigger, then the toolbar', () => {
    // The bar carries the rail's control at EVERY width — the collapse toggle on
    // a large screen, the drawer trigger on a small one — so it is never an empty
    // strip and is never hidden, with or without a toolbar. The toggle sits in
    // the bar's flow rather than over the rail: placed absolutely it resolved
    // against the viewport and sat hidden under the application sidebar.
    const { unmount } = renderLayout();
    let bar = topBar();
    expect(bar.className).not.toContain('hidden');
    expect([...bar.children].map((child) => child.getAttribute('aria-label'))).toEqual([
      'Close sidebar',
      'Open sidebar',
    ]);
    unmount();

    renderLayout(<input aria-label="search" />);
    bar = topBar();
    expect(bar.className).not.toContain('hidden');
    const [toggle, trigger, toolbar, ...rest] = [...bar.children];
    expect(toggle).toBe(desktopToggle(bar));
    expect(toggle).toHaveAttribute('aria-label', 'Close sidebar');
    expect(trigger).toHaveAttribute('aria-label', 'Open sidebar');
    expect(toolbar).toBe(screen.getByLabelText('search'));
    expect(rest).toEqual([]);
    // Each control is drawn at one size only, so the two never show together.
    expect(toggle?.className).toContain('hidden');
    expect(toggle?.className).toContain('lg:inline-flex');
    expect(trigger?.className).toContain('lg:hidden');
  });
});
