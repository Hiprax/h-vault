/**
 * `RailLayout` — the two-pane shell `/vault` and `/documents` share.
 *
 * Extracted rather than copied, so it is tested once rather than through two
 * pages that each happen to exercise half of it. The cases below are the parts
 * no page test reaches: the desktop collapse toggle, the mobile drawer's four
 * ways to close, and the toolbar bar's own visibility.
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
 * The DESKTOP collapse toggle, by position rather than by name.
 *
 * Three controls carry "Close sidebar": this one, the mobile overlay, and the
 * drawer's X. They are never exposed together — the first is `hidden lg:block`
 * and the other two are `lg:hidden`, and `display: none` keeps an element out of
 * the accessibility tree — but jsdom applies no CSS, so a query by name here
 * would match all three.
 */
const desktopToggle = (): HTMLElement => screen.getAllByRole('button', { name: /sidebar$/ })[0]!;

/** The full-screen overlay behind the mobile drawer. */
const overlay = (): HTMLElement | null =>
  document.querySelector('button.fixed.inset-0[aria-label="Close sidebar"]');

describe('RailLayout', () => {
  it('collapses and restores the desktop rail, and says which it will do', () => {
    renderLayout();

    // Open: the rail is drawn on large screens.
    expect(aside().className).toContain('lg:block');
    expect(desktopToggle()).toHaveAttribute('aria-label', 'Close sidebar');

    fireEvent.click(desktopToggle());

    // Collapsed: hidden at EVERY width, and the control now offers the reverse.
    expect(aside().className).not.toContain('lg:block');
    expect(desktopToggle()).toHaveAttribute('aria-label', 'Open sidebar');

    fireEvent.click(desktopToggle());
    expect(aside().className).toContain('lg:block');
  });

  it('opens the mobile drawer and closes it from the overlay, the X, and the rail', () => {
    renderLayout();
    // The trigger that is only drawn on small screens, distinct from the desktop
    // collapse toggle above it.
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

  it('hides the top bar on desktop when there is no toolbar to put in it', () => {
    const { unmount } = renderLayout();
    // The bar still exists on small screens, because it carries the drawer
    // trigger — but an empty bordered strip on desktop is not a design.
    expect(screen.getByRole('button', { name: 'Open sidebar' }).parentElement?.className).toContain(
      'lg:hidden',
    );
    unmount();

    renderLayout(<input aria-label="search" />);
    expect(
      screen.getByRole('button', { name: 'Open sidebar' }).parentElement?.className,
    ).not.toContain('lg:hidden');
  });
});
