import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import {
  SavedAddressPicker,
  MAX_VISIBLE_ADDRESS_OPTIONS,
  type SavedAddressOption,
} from '../../src/components/vault/SavedAddressPicker';
import { addressSearchText, formatAddressSummary, type BaseAddress } from '../../src/lib/address';

/**
 * The searchable picker over addresses saved on identity items.
 *
 * What this file pins:
 *
 * 1. **The WAI-ARIA combobox contract.** DOM focus stays on the `role="combobox"`
 *    input, the active option is named by `aria-activedescendant`, and
 *    `aria-selected` is on that option ALONE (selection follows focus). Getting
 *    this wrong makes the control unusable with a screen reader while looking
 *    perfect on screen, which is the failure mode that never gets noticed.
 * 2. **Escape and Enter do not reach the form.** The item form mounts inside a
 *    dialog that closes itself from a `document`-level Escape listener, and the
 *    picker's search field sits inside a `<form>` where a bare Enter submits. An
 *    unstopped key here discards or prematurely saves a half-filled item — so
 *    both are asserted against a real listener and a real form.
 * 3. **The visible-option cap is stated, never silent.** A truncated list that
 *    says nothing reads as "that is all of them".
 *
 * Selection payloads are asserted by identity (`toBe`) rather than by value, so
 * a future change cannot start handing the caller a copy that has been through a
 * lossy transformation.
 */

function makeAddress(overrides: Partial<BaseAddress> = {}): BaseAddress {
  return { street: '', street2: '', city: '', state: '', zip: '', country: '', ...overrides };
}

function makeOption(
  id: string,
  title: string,
  subtitle: string,
  address: Partial<BaseAddress>,
): SavedAddressOption {
  const full = makeAddress(address);
  const summary = formatAddressSummary(full);
  return {
    id,
    title,
    subtitle,
    address: full,
    summary,
    searchText: addressSearchText([title, subtitle, summary]),
  };
}

const HOME = makeOption('id-home', 'Home address', 'Ada Lovelace', {
  street: '1 Main St',
  city: 'London',
  country: 'United Kingdom',
});
const WORK = makeOption('id-work', 'Work address', 'Ada Lovelace', {
  street: '10 Tech Park',
  city: 'Cambridge',
  country: 'United Kingdom',
});
const PARIS = makeOption('id-paris', 'Paris pied-à-terre', 'Marie Curie', {
  street: '5 Rue Cuvier',
  city: 'Paris',
  country: 'France',
});

const DEFAULT_OPTIONS = [HOME, WORK, PARIS];

const onSelect = vi.fn();

function renderPicker(props: Partial<React.ComponentProps<typeof SavedAddressPicker>> = {}) {
  return render(<SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} {...props} />);
}

function openPicker() {
  fireEvent.click(screen.getByRole('button', { name: /use a saved address/i }));
  return screen.getByRole('combobox');
}

function optionTitles(): string[] {
  return screen
    .getAllByRole('option')
    .map((option) => within(option).getByTestId('saved-address-option-title').textContent ?? '');
}

/** The option the combobox currently points `aria-activedescendant` at. */
function activeOption(): HTMLElement | null {
  const id = screen.getByRole('combobox').getAttribute('aria-activedescendant');
  return id === null ? null : document.getElementById(id);
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('SavedAddressPicker — opening and closing', () => {
  it('renders only a collapsed trigger until it is opened', () => {
    renderPicker();

    const trigger = screen.getByRole('button', { name: /use a saved address/i });
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
  });

  it('is a type="button" so it cannot submit the form it lives in', () => {
    renderPicker();

    expect(screen.getByRole('button', { name: /use a saved address/i })).toHaveAttribute(
      'type',
      'button',
    );
  });

  it('opens on click, moves focus to the search field and lists every option', () => {
    renderPicker();

    const input = openPicker();

    expect(screen.getByRole('button', { name: /use a saved address/i })).toHaveAttribute(
      'aria-expanded',
      'true',
    );
    expect(document.activeElement).toBe(input);
    expect(screen.getAllByRole('option')).toHaveLength(3);
  });

  it('closes again when the trigger is pressed a second time, restoring focus', () => {
    renderPicker();
    const trigger = screen.getByRole('button', { name: /use a saved address/i });

    fireEvent.click(trigger);
    expect(screen.getByRole('listbox')).toBeInTheDocument();

    fireEvent.click(trigger);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);
  });

  it('closes on a click outside itself, without stealing focus back', () => {
    render(
      <div>
        <SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} />
        <button type="button">elsewhere</button>
      </div>,
    );
    openPicker();

    fireEvent.click(screen.getByRole('button', { name: 'elsewhere' }));

    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(document.activeElement).not.toBe(
      screen.getByRole('button', { name: /use a saved address/i }),
    );
  });

  it('stays open for a click inside its own panel', () => {
    renderPicker();
    openPicker();

    fireEvent.click(screen.getByRole('listbox'));

    expect(screen.getByRole('listbox')).toBeInTheDocument();
  });

  /**
   * The panel is IN FLOW and ~300px tall, so closing it between the press and
   * the release of one click yanks everything below it upwards and the pressed
   * control never receives its `click`. Dismissal therefore happens on `click`,
   * and there is deliberately no focus-driven close (`focusout` fires during the
   * very mousedown that moves focus to a button below).
   */
  it('does NOT close on mousedown, so a control below keeps its click', () => {
    render(
      <div>
        <SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} />
        <button type="button">below</button>
      </div>,
    );
    openPicker();

    fireEvent.mouseDown(screen.getByRole('button', { name: 'below' }));

    expect(screen.getByRole('listbox')).toBeInTheDocument();
  });

  it('does not close merely because focus left it', () => {
    render(
      <div>
        <SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} />
        <button type="button">below</button>
      </div>,
    );
    const input = openPicker();

    fireEvent.blur(input, { relatedTarget: screen.getByRole('button', { name: 'below' }) });

    expect(screen.getByRole('listbox')).toBeInTheDocument();
  });

  /**
   * Pressing a non-focusable `<li>` moves focus off the search field in a real
   * browser. The ARIA combobox pattern requires DOM focus to stay on the input,
   * and suppressing the shift also keeps a press on a row from disturbing the
   * caret in the field the user is still typing into.
   */
  it('suppresses the focus shift that a press on an option would otherwise cause', () => {
    renderPicker();
    openPicker();

    const notPrevented = fireEvent.mouseDown(screen.getByRole('option', { name: /Home address/ }));

    // fireEvent returns false when a handler called preventDefault.
    expect(notPrevented).toBe(false);
    expect(screen.getByRole('listbox')).toBeInTheDocument();
  });

  it('forgets the previous search when reopened', () => {
    renderPicker();
    const input = openPicker();
    fireEvent.change(input, { target: { value: 'paris' } });
    expect(screen.getAllByRole('option')).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: /use a saved address/i }));
    const reopened = openPicker();

    expect(reopened).toHaveValue('');
    expect(screen.getAllByRole('option')).toHaveLength(3);
  });
});

describe('SavedAddressPicker — ARIA combobox contract', () => {
  it('ties the disclosure trigger to the panel it reveals', () => {
    renderPicker();
    const trigger = screen.getByRole('button', { name: /use a saved address/i });
    const controls = trigger.getAttribute('aria-controls');

    expect(controls).toBeTruthy();
    expect(document.getElementById(controls ?? '')).toBeNull();

    openPicker();
    expect(document.getElementById(controls ?? '')).not.toBeNull();
  });

  it('wires the input to the listbox and to the active option', () => {
    renderPicker();
    const input = openPicker();

    expect(input).toHaveAttribute('aria-expanded', 'true');
    expect(input).toHaveAttribute('aria-autocomplete', 'list');
    const listbox = screen.getByRole('listbox');
    expect(input.getAttribute('aria-controls')).toBe(listbox.getAttribute('id'));
    expect(activeOption()).toBe(screen.getAllByRole('option')[0]);
  });

  it('marks aria-selected on the active option ONLY', () => {
    renderPicker();
    const input = openPicker();

    const selected = () =>
      screen.getAllByRole('option').map((o) => o.getAttribute('aria-selected'));
    expect(selected()).toEqual(['true', 'false', 'false']);

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(selected()).toEqual(['false', 'true', 'false']);
  });

  it('keeps DOM focus on the input while arrowing through options', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'ArrowDown' });

    expect(document.activeElement).toBe(input);
  });

  it('drops aria-activedescendant when nothing matches', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'nothing-matches-this' } });

    expect(input).not.toHaveAttribute('aria-activedescendant');
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('announces the result count in a live region', () => {
    renderPicker();
    const input = openPicker();

    expect(screen.getByRole('status')).toHaveTextContent('3 saved addresses available');

    fireEvent.change(input, { target: { value: 'paris' } });
    expect(screen.getByRole('status')).toHaveTextContent('1 saved address available');

    fireEvent.change(input, { target: { value: 'zzz' } });
    expect(screen.getByRole('status')).toHaveTextContent('No matching saved addresses');
  });
});

describe('SavedAddressPicker — keyboard navigation', () => {
  it('wraps at both ends with the arrow keys', () => {
    renderPicker();
    const input = openPicker();
    const options = screen.getAllByRole('option');

    fireEvent.keyDown(input, { key: 'ArrowUp' });
    expect(activeOption()).toBe(options[2]);

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(activeOption()).toBe(options[0]);
  });

  it('jumps to the ends with Home and End', () => {
    renderPicker();
    const input = openPicker();
    const options = screen.getAllByRole('option');

    fireEvent.keyDown(input, { key: 'End' });
    expect(activeOption()).toBe(options[2]);

    fireEvent.keyDown(input, { key: 'Home' });
    expect(activeOption()).toBe(options[0]);
  });

  it('selects the active option with Enter and closes, restoring focus', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect).toHaveBeenCalledWith(WORK);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: /use a saved address/i }),
    );
  });

  it('closes on Escape without selecting anything', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.keyDown(input, { key: 'Escape' });

    expect(onSelect).not.toHaveBeenCalled();
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(
      screen.getByRole('button', { name: /use a saved address/i }),
    );
  });

  it('leaves an unhandled key alone so typing still reaches the field', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.keyDown(input, { key: 'a' });

    expect(screen.getByRole('listbox')).toBeInTheDocument();
    expect(activeOption()).toBe(screen.getAllByRole('option')[0]);
  });

  it('survives Enter, the arrows and Home/End with an empty result set', () => {
    renderPicker();
    const input = openPicker();
    fireEvent.change(input, { target: { value: 'zzz' } });

    for (const key of ['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter']) {
      fireEvent.keyDown(input, { key });
    }

    expect(onSelect).not.toHaveBeenCalled();
    expect(screen.getByRole('listbox')).toBeInTheDocument();
  });
});

describe('SavedAddressPicker — keys must not escape to the form or dialog', () => {
  /**
   * Both mount sites of the item form wrap it in a dialog that closes from a
   * `document`-level keydown listener. React dispatches its synthetic events at
   * a container BELOW `document`, so stopping propagation there is what keeps an
   * Escape inside this panel from discarding a half-filled item.
   */
  it('stops Escape from reaching a document-level listener', () => {
    const documentEscape = vi.fn();
    document.addEventListener('keydown', documentEscape);
    try {
      renderPicker();
      const input = openPicker();

      fireEvent.keyDown(input, { key: 'Escape' });

      expect(documentEscape).not.toHaveBeenCalled();
    } finally {
      document.removeEventListener('keydown', documentEscape);
    }
  });

  it('stops Escape only while it is open, leaving the dialog reachable when closed', () => {
    const documentEscape = vi.fn();
    document.addEventListener('keydown', documentEscape);
    try {
      renderPicker();
      const trigger = screen.getByRole('button', { name: /use a saved address/i });

      fireEvent.keyDown(trigger, { key: 'Escape' });

      expect(documentEscape).toHaveBeenCalledTimes(1);
    } finally {
      document.removeEventListener('keydown', documentEscape);
    }
  });

  /**
   * Asserted through `defaultPrevented`, NOT through an `onSubmit` spy. jsdom
   * does not implement a form's native implicit submission, so a synthetic Enter
   * never reaches `onSubmit` there — a spy would stay silent even with
   * `preventDefault()` deleted, and the regression would ship. `fireEvent`
   * returns false exactly when a handler prevented the default, which is the
   * thing that actually stops the browser submitting the half-filled item.
   */
  it('prevents the default on Enter, which is what stops the form submitting', () => {
    render(
      <form onSubmit={(event) => event.preventDefault()}>
        <SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} />
      </form>,
    );

    const input = openPicker();
    const notPrevented = fireEvent.keyDown(input, { key: 'Enter' });

    expect(notPrevented).toBe(false);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  /**
   * Shift+Tab out of the search field lands on the trigger — still inside the
   * picker, so the panel stays open — and the panel's own handler is a SIBLING
   * of that button, so it never sees the key. Before the container-level
   * interceptor, Escape from there closed the whole create dialog.
   */
  it('stops Escape reaching the document when focus is on the trigger and the panel is open', () => {
    const documentEscape = vi.fn();
    document.addEventListener('keydown', documentEscape);
    try {
      renderPicker();
      openPicker();
      const trigger = screen.getByRole('button', { name: /use a saved address/i });

      fireEvent.keyDown(trigger, { key: 'Escape' });

      expect(documentEscape).not.toHaveBeenCalled();
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
      expect(document.activeElement).toBe(trigger);
    } finally {
      document.removeEventListener('keydown', documentEscape);
    }
  });

  /**
   * There is deliberately no focus-driven close, so Tab out of the search field
   * leaves the panel visibly open with focus on a control OUTSIDE the picker —
   * and that is exactly the state in which a user presses Escape expecting the
   * list to close. Escape must still be the panel's, not the dialog's.
   */
  it('stops Escape reaching the document even when focus has left the picker', () => {
    const documentEscape = vi.fn();
    document.addEventListener('keydown', documentEscape);
    try {
      render(
        <div>
          <SavedAddressPicker options={DEFAULT_OPTIONS} onSelect={onSelect} />
          <input aria-label="outside field" />
        </div>,
      );
      openPicker();
      const outside = screen.getByLabelText('outside field');
      outside.focus();

      fireEvent.keyDown(outside, { key: 'Escape' });

      expect(documentEscape).not.toHaveBeenCalled();
      expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    } finally {
      document.removeEventListener('keydown', documentEscape);
    }
  });

  it('leaves Enter on the trigger alone, so it still toggles rather than selecting', () => {
    renderPicker();
    openPicker();
    const trigger = screen.getByRole('button', { name: /use a saved address/i });

    const notPrevented = fireEvent.keyDown(trigger, { key: 'Enter' });

    // Untouched by the container interceptor: the browser turns it into a click
    // on the button, which is what a disclosure trigger should do.
    expect(notPrevented).toBe(true);
    expect(onSelect).not.toHaveBeenCalled();
  });
});

describe('SavedAddressPicker — search', () => {
  it('filters on the item name, the person label and the address itself', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'work' } });
    expect(optionTitles()).toEqual(['Work address']);

    fireEvent.change(input, { target: { value: 'marie' } });
    expect(optionTitles()).toEqual(['Paris pied-à-terre']);

    fireEvent.change(input, { target: { value: 'cambridge' } });
    expect(optionTitles()).toEqual(['Work address']);
  });

  it('requires every term, drawn from any part of the row', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'ada london' } });
    expect(optionTitles()).toEqual(['Home address']);

    fireEvent.change(input, { target: { value: 'ada paris' } });
    expect(screen.queryAllByRole('option')).toHaveLength(0);
  });

  it('explains an empty result rather than showing a blank panel', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'zzz' } });

    expect(screen.getByText('No saved address matches that search.')).toBeInTheDocument();
  });

  it('resets the active option to the top when the filter shortens the list', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.keyDown(input, { key: 'End' });
    expect(activeOption()).toBe(screen.getAllByRole('option')[2]);

    fireEvent.change(input, { target: { value: 'ada' } });

    // Two matches remain; the previously active index (2) is past the end, so it
    // must fall back rather than strand aria-activedescendant on a removed id.
    expect(screen.getAllByRole('option')).toHaveLength(2);
    expect(activeOption()).toBe(screen.getAllByRole('option')[0]);
  });

  it('ignores surrounding whitespace in the query', () => {
    renderPicker();
    const input = openPicker();

    fireEvent.change(input, { target: { value: '   ' } });

    expect(screen.getAllByRole('option')).toHaveLength(3);
  });
});

describe('SavedAddressPicker — selection by pointer', () => {
  it('hands the caller the exact option object and closes', () => {
    renderPicker();
    openPicker();

    fireEvent.click(screen.getByRole('option', { name: /Paris pied-à-terre/ }));

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0]?.[0]).toBe(PARIS);
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });

  it('follows the pointer with the active option, so hover and keyboard agree', () => {
    renderPicker();
    openPicker();
    const options = screen.getAllByRole('option');

    fireEvent.mouseEnter(options[2]!);

    expect(activeOption()).toBe(options[2]);
  });
});

describe('SavedAddressPicker — the option row', () => {
  it('shows the item name, the person label and the address summary', () => {
    renderPicker();
    openPicker();

    const row = screen.getByRole('option', { name: /Home address/ });
    expect(within(row).getByText('Home address')).toBeInTheDocument();
    expect(within(row).getByText('Ada Lovelace')).toBeInTheDocument();
    expect(within(row).getByText('1 Main St · London · United Kingdom')).toBeInTheDocument();
  });

  it('omits the person label when there is none', () => {
    const anonymous = makeOption('id-anon', 'Storage unit', '', { city: 'Leeds' });
    renderPicker({ options: [anonymous] });
    openPicker();

    const row = screen.getByRole('option', { name: /Storage unit/ });
    expect(within(row).getByText('Leeds')).toBeInTheDocument();
    expect(row.textContent).toBe('Storage unitLeeds');
  });

  it('marks the currently applied option, and only that one', () => {
    renderPicker({ appliedOptionId: 'id-work' });
    openPicker();

    expect(
      within(screen.getByRole('option', { name: /Work address/ })).getByText('Currently applied'),
    ).toBeInTheDocument();
    expect(
      within(screen.getByRole('option', { name: /Home address/ })).queryByText('Currently applied'),
    ).not.toBeInTheDocument();
  });

  it('marks nothing when no option is applied', () => {
    renderPicker({ appliedOptionId: null });
    openPicker();

    expect(screen.queryByText('Currently applied')).not.toBeInTheDocument();
  });
});

describe('SavedAddressPicker — the visible-option cap', () => {
  const many = Array.from({ length: MAX_VISIBLE_ADDRESS_OPTIONS + 7 }, (_, index) =>
    makeOption(`id-${String(index)}`, `Address ${String(index).padStart(3, '0')}`, '', {
      city: `City ${String(index)}`,
    }),
  );

  it('renders at most the cap and says how many were left out', () => {
    renderPicker({ options: many });
    openPicker();

    expect(screen.getAllByRole('option')).toHaveLength(MAX_VISIBLE_ADDRESS_OPTIONS);
    expect(
      screen.getByText(
        `Showing ${String(MAX_VISIBLE_ADDRESS_OPTIONS)} of ${String(many.length)} — keep typing to narrow the list.`,
      ),
    ).toBeInTheDocument();
  });

  it('drops the notice once the search brings the list under the cap', () => {
    renderPicker({ options: many });
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'address 003' } });

    expect(screen.getAllByRole('option')).toHaveLength(1);
    expect(screen.queryByText(/keep typing to narrow the list/)).not.toBeInTheDocument();
  });

  it('keeps the applied option visible even when it sorts past the cap', () => {
    const appliedId = `id-${String(MAX_VISIBLE_ADDRESS_OPTIONS + 3)}`;
    renderPicker({ options: many, appliedOptionId: appliedId });
    openPicker();

    // Pinned first, so the check mark and the form's Undo button cannot disagree
    // about whether a saved address is currently applied.
    expect(screen.getAllByRole('option')).toHaveLength(MAX_VISIBLE_ADDRESS_OPTIONS);
    expect(screen.getByText('Currently applied')).toBeInTheDocument();
    expect(optionTitles()[0]).toBe(
      `Address ${String(MAX_VISIBLE_ADDRESS_OPTIONS + 3).padStart(3, '0')}`,
    );
  });

  it('does not force the applied option back into results the search excluded', () => {
    renderPicker({
      options: many,
      appliedOptionId: `id-${String(MAX_VISIBLE_ADDRESS_OPTIONS + 3)}`,
    });
    const input = openPicker();

    fireEvent.change(input, { target: { value: 'address 001' } });

    // Pinning exists so a truncated list still shows what is applied — not so a
    // row the user filtered away reappears and claims to match.
    expect(optionTitles()).toEqual(['Address 001']);
    expect(screen.queryByText('Currently applied')).not.toBeInTheDocument();
  });

  it('leaves the order alone when the applied option is already inside the cap', () => {
    renderPicker({ options: many, appliedOptionId: 'id-2' });
    openPicker();

    expect(optionTitles()[0]).toBe('Address 000');
    expect(screen.getByText('Currently applied')).toBeInTheDocument();
  });

  it('keeps the count in the live region honest about the full match set', () => {
    renderPicker({ options: many });
    openPicker();

    expect(screen.getByRole('status')).toHaveTextContent(
      `${String(many.length)} saved addresses available`,
    );
  });
});

describe('SavedAddressPicker — degenerate inputs', () => {
  it('renders an empty listbox rather than crashing when given no options', () => {
    renderPicker({ options: [] });
    const input = openPicker();

    expect(screen.queryAllByRole('option')).toHaveLength(0);
    expect(input).not.toHaveAttribute('aria-activedescendant');
    expect(screen.getByRole('status')).toHaveTextContent('No matching saved addresses');
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
