import { CheckSquare, Square } from 'lucide-react';
import { cn } from '../../lib/utils';

interface SelectionCheckboxProps {
  readonly checked: boolean;
  readonly onChange: () => void;
  /** The control's accessible name ("Select item", "Select report.pdf", "Select all"). */
  readonly label: string;
  /**
   * `row` dims the box until it is ticked; `all` (the selection bar's select-all)
   * is always drawn in the primary colour, as the bar it sits in is.
   */
  readonly tone?: 'row' | 'all';
}

/**
 * The selection checkbox of the vault and document lists: a real checkbox, kept
 * in the accessibility tree and the tab order but visually replaced by an icon.
 *
 * It is always a SIBLING of a row's activator, never inside it: a checkbox nested
 * in an element with `role="button"` (or in a link) is stripped from the
 * accessibility tree, which made multi-select unreachable for a screen reader
 * once. The icon carries a ring while the hidden input has keyboard focus,
 * because `sr-only` would otherwise leave a tab stop nobody can see.
 */
export function SelectionCheckbox({
  checked,
  onChange,
  label,
  tone = 'row',
}: SelectionCheckboxProps) {
  return (
    <label className="shrink-0 relative flex items-center cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        className="peer sr-only"
        aria-label={label}
      />
      <span
        className={cn(
          'flex rounded-sm peer-focus-visible:ring-2',
          tone === 'all'
            ? 'text-[hsl(var(--primary))]'
            : 'text-[hsl(var(--muted-foreground))] peer-checked:text-[hsl(var(--primary))] hover:text-[hsl(var(--foreground))] transition-colors',
        )}
      >
        {checked ? <CheckSquare className="h-5 w-5" /> : <Square className="h-5 w-5" />}
      </span>
    </label>
  );
}
