import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent } from 'react';
import { Check, ChevronDown, MapPin, Search } from 'lucide-react';
import { cn } from '../../lib/utils';
import { inputClass } from './formStyles';
import type { BaseAddress } from '../../lib/address';
import { matchesSearchQuery } from '../../lib/address';

/**
 * A searchable picker over the postal addresses already saved on the vault's
 * IDENTITY items, used to fill a card's billing address without retyping it.
 *
 * ## Why this is not the shared `DropdownMenu`
 *
 * `DropdownMenu` is a menu: it moves REAL DOM focus onto each `role="menuitem"`
 * as you arrow through it. That is correct for a menu and wrong here — a search
 * field is not a valid child of `role="menu"`, and moving focus onto an option
 * would blur the field the user is still typing into. This follows the WAI-ARIA
 * combobox pattern instead: DOM focus stays on the `role="combobox"` input and
 * the active option is named by `aria-activedescendant`, with `aria-selected`
 * on that one option only (selection follows focus).
 *
 * ## Why the list is an INLINE panel rather than a floating popover
 *
 * Both mount sites of the item form put it inside a scroll container — the
 * create dialog's overlay is `fixed inset-0 overflow-y-auto` and the item page
 * scrolls the document — and neither gives the form a fixed height. An
 * absolutely-positioned list would be clipped by that overlay exactly when the
 * card form is long enough to matter, which is always. A panel that expands in
 * flow cannot be clipped, needs no portal, no positioning maths and no resize
 * observer, and is what makes this behave identically on a phone.
 *
 * ## Escape must not escape
 *
 * The create dialog closes itself from a `document`-level `keydown` listener
 * (`useInlineDialog`), so an unhandled Escape inside this panel would discard
 * the entire half-filled item. {@link handleKeyDown} therefore calls
 * `stopPropagation()` on the keys it handles: React dispatches the synthetic
 * event at its root container, which is BELOW `document` on the bubble path, so
 * stopping there is what keeps the dialog open. This is asserted by a test.
 *
 * ## What is never shown, searched or copied
 *
 * An identity's `deliveryNotes` — see the `lib/address` module docblock. Nothing
 * here reads any other identity field either: no SSN, passport, email-only
 * fallback beyond the subtitle the vault list already shows, and no secret of
 * any kind. The haystack is built from the rendered strings, so the two cannot
 * drift apart.
 */

/** One identity's saved address, pre-flattened for rendering and matching. */
export interface SavedAddressOption {
  /** The source identity item's id. Stable across a re-filter. */
  id: string;
  /** The identity item's decrypted name. */
  title: string;
  /** The identity's full name or email — `getItemSubtitle`'s value, or `''`. */
  subtitle: string;
  /** The six base fields, VERBATIM, exactly as they will be written. */
  address: BaseAddress;
  /** The address on one line, exactly as this row renders it. */
  summary: string;
  /** Lower-cased haystack: precisely `title`, `subtitle` and `summary`. */
  searchText: string;
}

/**
 * How many matching addresses are rendered at once.
 *
 * A bound rather than virtualisation: `aria-activedescendant` requires the
 * active option to be in the DOM, and combining that with a windowed list is a
 * meaningful amount of machinery for a list that is a handful of rows in every
 * realistic vault. The cap only binds for someone with hundreds of addressed
 * identities, and when it does the overflow is STATED in the panel rather than
 * silently dropped — a silent truncation reads as "that is all of them".
 */
export const MAX_VISIBLE_ADDRESS_OPTIONS = 50;

interface SavedAddressPickerProps {
  /** Every identity address on offer, already filtered to the non-empty ones. */
  options: readonly SavedAddressOption[];
  /** Called with the chosen option; the panel closes and focus returns. */
  onSelect: (option: SavedAddressOption) => void;
  /** The option whose values are currently in the form, if any. */
  appliedOptionId?: string | null | undefined;
  /** Extra classes for the picker's block-level root. */
  className?: string | undefined;
}

export function SavedAddressPicker({
  options,
  onSelect,
  appliedOptionId = null,
  className,
}: SavedAddressPickerProps) {
  const baseId = useId();
  const listboxId = `${baseId}-listbox`;
  const panelId = `${baseId}-panel`;
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);

  const matches = useMemo(() => {
    const trimmed = query.trim();
    if (!trimmed) return options;
    return options.filter((option) => matchesSearchQuery(option.searchText, trimmed));
  }, [options, query]);

  /**
   * The rows actually rendered: the first {@link MAX_VISIBLE_ADDRESS_OPTIONS}
   * matches, except that the CURRENTLY APPLIED option is pulled in when the cap
   * would otherwise hide it.
   *
   * Without that exception the picker and the form disagree in a corner that is
   * reachable: with more than 50 addressed identities, filling from one that
   * sorts past position 50 leaves the Undo button offered while no row carries
   * the "Currently applied" mark, so the user gets no confirmation of which
   * address is in the form. The applied row is pinned FIRST rather than sorted
   * into place — it is the one row that has a reason to lead, and hoisting only
   * when it would be invisible keeps the ordinary list in plain alphabetical
   * order.
   */
  const visible = useMemo(() => {
    const window = matches.slice(0, MAX_VISIBLE_ADDRESS_OPTIONS);
    if (appliedOptionId === null || window.some((option) => option.id === appliedOptionId)) {
      return window;
    }
    const applied = matches.find((option) => option.id === appliedOptionId);
    if (applied === undefined) return window;
    return [applied, ...window.slice(0, MAX_VISIBLE_ADDRESS_OPTIONS - 1)];
  }, [matches, appliedOptionId]);
  const hiddenCount = matches.length - visible.length;

  const optionId = useCallback((index: number) => `${baseId}-option-${String(index)}`, [baseId]);

  const close = useCallback((restoreFocus: boolean) => {
    setOpen(false);
    setQuery('');
    setActiveIndex(0);
    if (restoreFocus) triggerRef.current?.focus();
  }, []);

  // Focus the search field as the panel appears. The trigger and the panel are
  // siblings, so without this focus would sit on the trigger and the first
  // keystroke would go nowhere.
  useEffect(() => {
    if (!open) return;
    inputRef.current?.focus();
  }, [open]);

  // Keep the active option inside the scrollport. jsdom implements no layout and
  // therefore no `scrollIntoView`; the test setup polyfills it as a no-op rather
  // than making production code defend against a missing DOM method.
  useEffect(() => {
    if (!open) return;
    const active = listRef.current?.children[activeIndex];
    if (active instanceof HTMLElement) active.scrollIntoView({ block: 'nearest' });
  }, [open, activeIndex]);

  // A filter that shortens the list must not leave the active index past its
  // end, which would strand `aria-activedescendant` on an id no longer in the
  // document and make Enter a no-op.
  useEffect(() => {
    setActiveIndex((current) => (current < visible.length ? current : 0));
  }, [visible.length]);

  /**
   * Dismiss on an outside press — on `click`, NOT on `mousedown`.
   *
   * `DropdownMenu` uses `mousedown`, and it can: its content is absolutely
   * positioned, so removing it moves nothing. This panel is deliberately IN
   * FLOW and is ~300px tall, so closing it between the press and the release of
   * a single click yanks everything below it upwards mid-gesture. Per UI Events,
   * a `click` is then dispatched at the nearest common ancestor of the differing
   * mousedown/mouseup targets — so the button the user actually pressed (Cancel,
   * Create, Remove, a type tab) never receives one, and the first click silently
   * does nothing. Closing on `click` lets the press land first.
   *
   * There is deliberately no focus-driven close to go with it. `focusout` fires
   * during the same mousedown that moves focus to a button below, which would
   * reintroduce exactly the layout shift this avoids. The panel is an inline
   * disclosure rather than a floating popover: leaving it open until something
   * is clicked or Escape is pressed is what an expanded section does.
   */
  useEffect(() => {
    if (!open) return;
    const handleOutsideClick = (event: MouseEvent) => {
      const target = event.target as Node | null;
      if (target && containerRef.current?.contains(target) === true) return;
      // No focus restoration: the user is on their way somewhere else, and
      // yanking focus back to the trigger would fight that.
      close(false);
    };
    document.addEventListener('click', handleOutsideClick);
    return () => document.removeEventListener('click', handleOutsideClick);
  }, [open, close]);

  /**
   * While the panel is open, ESCAPE BELONGS TO IT — wherever focus happens to be.
   *
   * A `document` listener in the CAPTURE phase, which is the only placement that
   * holds. React handlers on the panel cover only focus inside it, and the two
   * ways out are both reachable: Shift+Tab lands on the trigger (a SIBLING of the
   * panel, so the panel's handler never sees the key), and Tab lands on the
   * street control, which is outside the picker entirely while the panel is still
   * visibly open — there is deliberately no focus-driven close (see the dismissal
   * effect below). In both cases the key reached `document`, where
   * `useInlineDialog`'s BUBBLE-phase listener closed the whole create dialog and
   * discarded a half-filled item.
   *
   * Capture runs before that bubble listener, and `stopPropagation()` set during
   * the capture phase at `document` also suppresses the bubble-phase invocation
   * on the same node — so the panel wins, and only the panel closes.
   *
   * Enter is deliberately NOT intercepted here: with focus on the trigger it must
   * keep doing what a button does, and inside the panel {@link handleKeyDown}
   * already owns it.
   */
  useEffect(() => {
    if (!open) return;
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      event.stopPropagation();
      close(true);
    };
    document.addEventListener('keydown', handleEscape, true);
    return () => document.removeEventListener('keydown', handleEscape, true);
  }, [open, close]);

  const select = useCallback(
    (option: SavedAddressOption) => {
      onSelect(option);
      close(true);
    },
    [onSelect, close],
  );

  /**
   * Every key this panel understands is also handled by something ABOVE it —
   * Enter submits the form, Escape closes the dialog, the arrows scroll the
   * page — so each handled key is stopped as well as defaulted. Enter in
   * particular is unconditional: a bare text input inside a `<form>` makes
   * Enter submit it, which would create a half-filled item.
   */
  const handleKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLDivElement>) => {
      switch (event.key) {
        // No 'Escape' case: the capture-phase document listener above owns it and
        // stops propagation before this handler could ever run.
        case 'Enter': {
          event.preventDefault();
          event.stopPropagation();
          const option = visible[activeIndex];
          if (option) select(option);
          return;
        }
        case 'ArrowDown':
          event.preventDefault();
          event.stopPropagation();
          setActiveIndex((current) => (visible.length === 0 ? 0 : (current + 1) % visible.length));
          return;
        case 'ArrowUp':
          event.preventDefault();
          event.stopPropagation();
          setActiveIndex((current) =>
            visible.length === 0 ? 0 : (current - 1 + visible.length) % visible.length,
          );
          return;
        case 'Home':
          event.preventDefault();
          event.stopPropagation();
          setActiveIndex(0);
          return;
        case 'End':
          event.preventDefault();
          event.stopPropagation();
          setActiveIndex(visible.length === 0 ? 0 : visible.length - 1);
          return;
        default:
          return;
      }
    },
    [visible, activeIndex, select],
  );

  const activeOptionId =
    visible.length > 0 && activeIndex < visible.length ? optionId(activeIndex) : undefined;

  // A plain BLOCK root, deliberately not `relative`: the panel below is in normal
  // flow, so it inherits this element's width and there is nothing to position
  // against. Callers give it a full-width slot of its own rather than dropping it
  // into a flex row, where a shrink-to-fit item would squeeze the panel to the
  // width of the trigger's label.
  return (
    <div ref={containerRef} className={className}>
      <button
        type="button"
        ref={triggerRef}
        onClick={() => {
          if (open) {
            close(true);
            return;
          }
          setQuery('');
          setActiveIndex(0);
          setOpen(true);
        }}
        aria-expanded={open}
        // The APG's Disclosure pattern calls always including `aria-controls`
        // best practice, so assistive tech can report WHAT expanded rather than
        // only that something did.
        aria-controls={panelId}
        className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs font-medium text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))]"
      >
        <MapPin className="h-3.5 w-3.5 text-[hsl(var(--muted-foreground))]" aria-hidden="true" />
        Use a saved address
        <ChevronDown
          className={cn('h-3.5 w-3.5 transition-transform', open && 'rotate-180')}
          aria-hidden="true"
        />
      </button>

      {/*
        The result count, announced rather than only drawn: filtering happens on
        every keystroke and a screen-reader user gets no other signal that the
        list under the field changed size.

        Mounted UNCONDITIONALLY, outside the `open` guard. A live region that
        appears already populated is generally not announced — screen readers
        report MUTATIONS of a region that was already in the accessibility tree —
        so a region created together with its first content would silently skip
        the opening count and only start speaking from the second keystroke.
      */}
      <div role="status" aria-live="polite" className="sr-only">
        {!open
          ? ''
          : matches.length === 0
            ? 'No matching saved addresses'
            : `${String(matches.length)} saved ${matches.length === 1 ? 'address' : 'addresses'} available`}
      </div>

      {open && (
        <div
          id={panelId}
          onKeyDown={handleKeyDown}
          // `animate-in` is a hand-written class in `styles/globals.css`, not a
          // Tailwind utility, so a `motion-safe:` variant of it is never
          // generated and would silently mean NO animation. The reduced-motion
          // guard lives on the class itself, in that same file.
          className="mt-2 overflow-hidden rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--popover))] text-[hsl(var(--popover-foreground))] shadow-md animate-in"
        >
          <div className="relative border-b border-[hsl(var(--border))] p-2">
            <Search
              className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]"
              aria-hidden="true"
            />
            <input
              ref={inputRef}
              type="text"
              role="combobox"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search saved addresses"
              aria-label="Search saved addresses"
              aria-expanded="true"
              aria-controls={listboxId}
              aria-autocomplete="list"
              aria-activedescendant={activeOptionId}
              autoComplete="off"
              spellCheck={false}
              className={cn(inputClass, 'pl-9')}
            />
          </div>

          <ul
            ref={listRef}
            id={listboxId}
            role="listbox"
            aria-label="Saved addresses"
            // Pressing a non-focusable element moves focus off the search
            // field. The ARIA combobox pattern requires DOM focus to STAY on the
            // input while `aria-activedescendant` names the active option, so the
            // default focus shift is suppressed rather than chased — which also
            // means a press on a row cannot disturb the caret in the field the
            // user is still typing into.
            onMouseDown={(event) => event.preventDefault()}
            className="max-h-64 space-y-0.5 overflow-y-auto p-1"
          >
            {visible.map((option, index) => {
              const isActive = index === activeIndex;
              const isApplied = option.id === appliedOptionId;
              return (
                <li
                  key={option.id}
                  id={optionId(index)}
                  role="option"
                  aria-selected={isActive}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => select(option)}
                  className={cn(
                    'flex cursor-pointer items-start gap-2.5 rounded-md px-2.5 py-2 transition-colors',
                    isActive && 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]',
                  )}
                >
                  <MapPin
                    className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--muted-foreground))]"
                    aria-hidden="true"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-baseline gap-1.5">
                      <span
                        data-testid="saved-address-option-title"
                        className="truncate text-sm font-medium"
                      >
                        {option.title}
                      </span>
                      {option.subtitle && (
                        <span className="truncate text-xs text-[hsl(var(--muted-foreground))]">
                          {option.subtitle}
                        </span>
                      )}
                    </span>
                    <span className="mt-0.5 block truncate text-xs text-[hsl(var(--muted-foreground))]">
                      {option.summary}
                    </span>
                  </span>
                  {isApplied && (
                    <>
                      <Check
                        className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]"
                        aria-hidden="true"
                      />
                      <span className="sr-only">Currently applied</span>
                    </>
                  )}
                </li>
              );
            })}
          </ul>

          {matches.length === 0 && (
            <p className="px-3 pb-3 pt-1 text-xs text-[hsl(var(--muted-foreground))]">
              No saved address matches that search.
            </p>
          )}

          {hiddenCount > 0 && (
            <p className="border-t border-[hsl(var(--border))] px-3 py-2 text-xs text-[hsl(var(--muted-foreground))]">
              Showing {String(MAX_VISIBLE_ADDRESS_OPTIONS)} of {String(matches.length)} — keep
              typing to narrow the list.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
