import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '../../lib/utils';

interface PaginationProps {
  /** The current page, one-based. */
  page: number;
  /** Total pages; 1 even when there are no rows at all. */
  totalPages: number;
  /**
   * What the pages are OF, lower-case — "audit log entries", "backup history
   * entries".
   *
   * REQUIRED, and not decoration: this renders a `<nav>`, which is a landmark,
   * and two landmarks sharing a role AND an accessible name is a `landmark-unique`
   * violation. AppLayout's sidebar `<nav>` is unnamed, so any named one here is
   * distinct from it.
   */
  label: string;
  onPageChange: (page: number) => void;
  /** Total row count, folded into the counter when the caller knows it. */
  total?: number;
  className?: string;
}

/**
 * Previous / next page controls.
 *
 * Extracted so the audit log and the backup history cannot drift into two
 * different pagers — and so the accessibility below is written once rather than
 * being wrong twice. The clamping lives here too, so no caller can page past
 * either end by wiring its own arithmetic.
 */
export function Pagination({
  page,
  totalPages,
  label,
  onPageChange,
  total,
  className,
}: PaginationProps) {
  const atStart = page <= 1;
  const atEnd = page >= totalPages;
  const buttonClass =
    'inline-flex items-center gap-1 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm text-[hsl(var(--foreground))] transition-colors hover:bg-[hsl(var(--accent))] aria-disabled:cursor-default aria-disabled:opacity-50 aria-disabled:hover:bg-transparent';

  return (
    <nav
      aria-label={`${label} pagination`}
      className={cn('flex items-center justify-between gap-3', className)}
    >
      {/* A live region, because pressing Next leaves focus on Next, that button's
          label does not change, and the rows behind it are replaced in silence —
          so a screen-reader user gets no signal that anything happened at all.
          `aria-atomic` so the whole sentence is re-read rather than the digit. */}
      <p
        aria-live="polite"
        aria-atomic="true"
        className="text-sm text-[hsl(var(--muted-foreground))]"
      >
        Page {page} of {totalPages}
        {total !== undefined && ` · ${String(total)} ${total === 1 ? 'entry' : 'entries'}`}
      </p>
      <div className="flex gap-2">
        {/* `aria-disabled` rather than `disabled`, which is this project's idiom
            for a control that cannot act (see `VaultItemDetail`'s and
            `DocumentDetail`'s Edit buttons). A `disabled` element leaves the tab
            order, so paging to the last entry disables the very button under the
            reader's focus and drops that focus to `<body>` — Tab then restarts
            from the top of the document, which is a poor reward for reaching the
            end of a list. Keeping it focusable costs nothing here because the
            clamp below already makes the handler a no-op at both ends: it asks
            for the page the reader is already on, so no request is made. */}
        <button
          type="button"
          aria-label={`Previous page of ${label}`}
          aria-disabled={atStart || undefined}
          onClick={() => onPageChange(Math.max(1, page - 1))}
          className={buttonClass}
        >
          <ChevronLeft className="h-4 w-4" /> Prev
        </button>
        <button
          type="button"
          aria-label={`Next page of ${label}`}
          aria-disabled={atEnd || undefined}
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          className={buttonClass}
        >
          Next <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </nav>
  );
}
