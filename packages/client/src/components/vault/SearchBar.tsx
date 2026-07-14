import { useCallback, useEffect, useRef, useState } from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { useVaultStore } from '../../stores/vaultStore';

/** ID used to link the search input's aria-controls to the vault results list. */
export const VAULT_SEARCH_RESULTS_ID = 'vault-search-results';

interface SearchBarProps {
  className?: string;
}

export function SearchBar({ className }: SearchBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const setSearchQuery = useVaultStore((s) => s.setSearchQuery);
  const searchQuery = useVaultStore((s) => s.searchQuery);
  const filteredItemCount = useVaultStore((s) => s.filteredItemCount);
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

  // Read filtered count from the store (set by VaultList) to avoid
  // duplicating the filtering logic.
  const resultCount = filteredItemCount;

  return (
    <div className={cn('relative', className)}>
      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]" />
      <input
        ref={inputRef}
        type="search"
        placeholder="Search vault... (Ctrl+K)"
        value={localQuery}
        onChange={(e) => handleChange(e.target.value)}
        maxLength={200}
        className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] py-2 pl-9 pr-20 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus:outline-none focus:ring-2 focus:ring-[hsl(var(--ring))] focus:ring-offset-2"
        autoComplete="off"
        aria-label="Search vault items"
        aria-autocomplete="list"
        aria-controls={VAULT_SEARCH_RESULTS_ID}
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
