import { useCallback, useEffect, useRef, useState } from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '../../lib/utils';

/** ID used to link the search input's aria-controls to the vault results list. */
export const VAULT_SEARCH_RESULTS_ID = 'vault-search-results';

/** ID used to link the search input's aria-controls to the documents results list. */
export const DOCUMENT_SEARCH_RESULTS_ID = 'document-search-results';

interface SearchBarProps {
  /** The COMMITTED query — what the store holds, not what is being typed. */
  query: string;
  onQueryChange: (query: string) => void;
  /** How many rows currently match, or `null` when the caller cannot say. */
  resultCount: number | null;
  placeholder: string;
  /** The input's accessible name. */
  label: string;
  /** The id of the list this input filters. */
  controlsId: string;
  className?: string;
}

/**
 * The search field, rendered on both `/vault` and `/documents`.
 *
 * Everything route-specific arrives as a prop rather than being read from a
 * store, for the reason the folder rail records: one component with two callers
 * cannot reach for one caller's store. The debounce, the Ctrl+K shortcut and the
 * external-clear sync are the same in both places and stay here.
 *
 * Only one instance is ever mounted, because the two routes are two pages, so
 * the document-level Ctrl+K listener cannot collide with itself.
 */
export function SearchBar({
  query,
  onQueryChange,
  resultCount,
  placeholder,
  label,
  controlsId,
  className,
}: SearchBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const setSearchQuery = onQueryChange;
  const searchQuery = query;
  const [localQuery, setLocalQuery] = useState(searchQuery);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Debounced sync to store
  const handleChange = useCallback(
    (value: string) => {
      setLocalQuery(value);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => {
        setSearchQuery(value);
      }, 300);
    },
    [setSearchQuery],
  );

  // Clear on unmount
  useEffect(() => {
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, []);

  // Keyboard shortcut: Ctrl+K / Cmd+K to focus
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Keep local in sync when store clears externally (but not while the user
  // is actively typing — the debounce ref being set means a local change is
  // pending, so we skip the store→local sync to avoid eating keystrokes).
  useEffect(() => {
    if (searchQuery === '' && localQuery !== '' && !debounceRef.current) {
      setLocalQuery('');
    }
  }, [searchQuery, localQuery]);

  const handleClear = useCallback(() => {
    setLocalQuery('');
    setSearchQuery('');
    inputRef.current?.focus();
  }, [setSearchQuery]);

  return (
    <div className={cn('relative', className)}>
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
      <input
        ref={inputRef}
        type="search"
        placeholder={placeholder}
        value={localQuery}
        onChange={(e) => handleChange(e.target.value)}
        maxLength={200}
        className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] py-2 pl-9 pr-20 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2"
        autoComplete="off"
        aria-label={label}
        aria-autocomplete="list"
        aria-controls={controlsId}
      />

      <div className="absolute right-3 top-1/2 flex -translate-y-1/2 items-center gap-2">
        {resultCount !== null && (
          <span className="text-xs text-[hsl(var(--muted-foreground))]">
            {resultCount} result{resultCount !== 1 ? 's' : ''}
          </span>
        )}
        {localQuery.length > 0 && (
          <button
            type="button"
            onClick={handleClear}
            className="rounded p-0.5 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] transition-colors"
            aria-label="Clear search"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>
    </div>
  );
}
