import { useState } from 'react';
import { Tag } from 'lucide-react';
import { MAX_TAG_LENGTH } from '@hvault/shared';

interface BulkTagPopoverProps {
  /** A bulk action is running: the trigger and Apply wait for it. */
  readonly disabled: boolean;
  /**
   * Adds the tag to the selection. Resolves `true` when it was applied, which
   * clears the typed tag; on `false` the tag stays typed for another try.
   */
  readonly onApply: (tag: string) => Promise<boolean>;
}

/**
 * The selection bar's Tag action, shared by the vault and document lists: a
 * small popover with one input that adds a single tag to every selected row.
 *
 * The popover closes when focus leaves it and as soon as a tag is applied; the
 * action itself (and its report) belongs to the list that owns the selection.
 * Enter applies, as Apply does.
 */
export function BulkTagPopover({ disabled, onApply }: BulkTagPopoverProps) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState('');

  const apply = (): void => {
    const tag = draft.trim();
    if (!tag || disabled) return;
    setOpen(false);
    void onApply(tag).then((applied) => {
      if (applied) setDraft('');
    });
  };

  return (
    <div
      className="relative"
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) setOpen(false);
      }}
    >
      <button
        type="button"
        disabled={disabled}
        onClick={() => setOpen((p) => !p)}
        aria-haspopup="true"
        aria-expanded={open}
        className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors disabled:opacity-50"
      >
        <Tag className="h-4 w-4" />
        Tag
      </button>
      {open && (
        <div className="absolute right-0 top-full z-20 mt-1 w-64 rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--popover))] p-3 shadow-lg">
          <div className="space-y-2">
            <input
              type="text"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
                  e.preventDefault();
                  apply();
                }
              }}
              aria-label="Tag to add to the selection"
              placeholder="Enter tag name"
              maxLength={MAX_TAG_LENGTH}
              className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-2 py-1.5 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-1 focus:ring-[hsl(var(--ring))]"
            />
            <button
              type="button"
              disabled={!draft.trim() || disabled}
              onClick={apply}
              className="w-full rounded-md bg-[hsl(var(--primary))] px-3 py-1.5 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 disabled:opacity-50"
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
