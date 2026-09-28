import { useId, useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { RELEASE_CHANGE_KINDS, type ReleaseNoteView } from '@hvault/shared';
import { cn } from '../../lib/utils';
import { ReleaseEntry } from './ReleaseEntry';
import { releaseKindFor } from './releaseVisuals';

/** Every text of a release, lower-cased once, for the search box. */
function searchableText(release: ReleaseNoteView): string {
  return [
    release.version,
    release.title,
    release.summary,
    ...release.highlights.flatMap((highlight) => [highlight.title, highlight.body]),
    ...release.changes.map((change) => change.text),
  ]
    .join('\n')
    .toLowerCase();
}

interface ReleaseHistoryProps {
  releases: readonly ReleaseNoteView[];
}

/**
 * Every release, newest first, with a filter by kind of change and a search box.
 *
 * Filtering by a kind keeps the releases that have such a change and shows only
 * those changes, opened; searching keeps the releases whose notes mention the
 * words anywhere. The count of what is left is announced politely, so a
 * screen-reader user hears the effect of each keystroke without losing their
 * place.
 */
export function ReleaseHistory({ releases }: ReleaseHistoryProps) {
  const [kind, setKind] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const searchId = useId();

  const indexed = useMemo(
    () => releases.map((release) => ({ release, text: searchableText(release) })),
    [releases],
  );
  const presentKinds = RELEASE_CHANGE_KINDS.filter((candidate) =>
    releases.some((release) => release.changes.some((change) => change.kind === candidate)),
  );
  const words = query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((word) => word !== '');
  const kinds = kind === null ? undefined : new Set([kind]);
  const shown = indexed
    .filter(
      ({ release }) => kind === null || release.changes.some((change) => change.kind === kind),
    )
    .filter(({ text }) => words.every((word) => text.includes(word)))
    .map(({ release }) => release);
  const narrowed = kind !== null || words.length > 0;

  const filterButton = (value: string | null, label: string) => (
    <button
      key={value ?? 'all'}
      type="button"
      aria-pressed={kind === value}
      onClick={() => setKind(value)}
      className={cn(
        'min-h-8 rounded-full border px-3 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]',
        kind === value
          ? 'border-[hsl(var(--primary))] bg-[hsl(var(--sidebar-accent))] text-[hsl(var(--sidebar-accent-foreground))]'
          : 'border-[hsl(var(--border))] text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
      )}
    >
      {label}
    </button>
  );

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="relative">
          <label htmlFor={searchId} className="sr-only">
            Search the release notes
          </label>
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[hsl(var(--muted-foreground))]"
            aria-hidden="true"
          />
          <input
            id={searchId}
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search the release notes"
            className="h-10 w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] pl-9 pr-3 text-sm text-[hsl(var(--foreground))] placeholder:text-[hsl(var(--muted-foreground))] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]"
          />
        </div>
        <div role="group" aria-label="Show changes of one kind" className="flex flex-wrap gap-2">
          {filterButton(null, 'All')}
          {presentKinds.map((candidate) =>
            filterButton(candidate, releaseKindFor(candidate).label),
          )}
        </div>
        <p aria-live="polite" className="text-xs text-[hsl(var(--muted-foreground))]">
          {shown.length === 1 ? '1 release' : `${String(shown.length)} releases`}
          {narrowed ? (shown.length === 1 ? ' matches' : ' match') : ''}
        </p>
      </div>

      {shown.length === 0 ? (
        <p className="text-sm text-[hsl(var(--muted-foreground))]">
          No release notes match. Try fewer words, or show all kinds of change.
        </p>
      ) : (
        <div className="space-y-6">
          {shown.map((release) => (
            <ReleaseEntry
              // Re-mounted when the filter changes, so its details open to show the matches.
              key={`${release.version}:${kind ?? ''}:${words.join(' ')}`}
              release={release}
              heading="h3"
              variant="row"
              {...(kinds === undefined ? {} : { kinds })}
              defaultOpen={release.isNew || narrowed}
            />
          ))}
        </div>
      )}
    </div>
  );
}
