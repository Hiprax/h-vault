/**
 * The first open of an `InfoTip`, while its panel chunk (`InfoTipPanel`) is
 * still on its way.
 *
 * A file of its own, with ONE test, because a lazy component resolves once per
 * module instance: in `InfoTip.test.tsx` a `beforeAll` warms it so every other
 * behaviour is pinned without waiting, and here nothing has, so this test is the
 * only thing that ever loads the panel. Splitting the steps into several tests
 * would make each one's starting state depend on the order the runner picks.
 *
 * The panel module is wrapped only to COUNT its loads; what it exports is the
 * real module, unchanged.
 */
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { InfoTip } from '../../src/components/ui/InfoTip';

const panelModule = vi.hoisted(() => ({ loads: 0 }));

vi.mock('../../src/components/ui/InfoTipPanel', async (importOriginal) => {
  panelModule.loads += 1;
  return importOriginal<typeof import('../../src/components/ui/InfoTipPanel')>();
});

describe('InfoTip: the first open', () => {
  it('fetches the panel on the first approach, survives a press and a cancel before it arrives, and then opens it', async () => {
    const onPreload = vi.fn();
    render(
      <>
        <button type="button">Before</button>
        <InfoTip
          label="Help: the first open"
          title="The first open, explained"
          onPreload={onPreload}
        >
          <p>Plain words.</p>
        </InfoTip>
      </>,
    );
    const trigger = screen.getByRole('button', { name: 'Help: the first open' });
    const before = screen.getByRole('button', { name: 'Before' });
    before.focus();
    expect(panelModule.loads).toBe(0);

    // Focus alone starts both fetches, the caller's body and the panel, and opens nothing.
    fireEvent.focus(trigger);
    await vi.dynamicImportSettled();
    expect(onPreload).toHaveBeenCalledTimes(1);
    expect(panelModule.loads).toBe(1);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(trigger.getAttribute('aria-expanded')).toBe('false');

    // A press before the panel has rendered is already "open" to assistive
    // technology; a second press cancels it, and focus stays where it was.
    fireEvent.click(trigger);
    expect(trigger.getAttribute('aria-expanded')).toBe('true');
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.click(trigger);
    expect(trigger.getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(before);

    // The cancelled press's request for focus is gone: a hover then opens the
    // panel without taking focus from where it is.
    fireEvent.pointerEnter(trigger, { pointerType: 'mouse' });
    const dialog = await screen.findByRole('dialog', { name: 'The first open, explained' });
    expect(document.activeElement).toBe(before);

    // And a press now pins it and moves focus in, as on every later open.
    fireEvent.click(trigger);
    expect(document.activeElement).toBe(dialog);
    expect(panelModule.loads).toBe(1);
    expect(onPreload).toHaveBeenCalledTimes(1);
  });
});
