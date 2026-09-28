import { useId, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { RELEASE_CHANGE_KINDS, type ReleaseNoteView } from '@hvault/shared';
import { cn } from '../../lib/utils';
import { formatReleaseDate, releaseAnchorId } from '../../lib/releaseFormat';
import { releaseIconFor, releaseKindFor } from './releaseVisuals';

type Heading = 'h3' | 'h4';

/** The change groups in reading order: the known kinds, then anything unknown. */
function groupChanges(changes: ReleaseNoteView['changes'], kinds: ReadonlySet<string> | undefined) {
  const known: readonly string[] = RELEASE_CHANGE_KINDS;
  const order = [
    ...known,
    ...changes.map((change) => change.kind).filter((kind) => !known.includes(kind)),
  ];
  const groups: { kind: string; items: ReleaseNoteView['changes'] }[] = [];
  for (const kind of new Set(order)) {
    if (kinds !== undefined && !kinds.has(kind)) continue;
    const items = changes.filter((change) => change.kind === kind);
    if (items.length > 0) groups.push({ kind, items });
  }
  return groups;
}

function AdministratorTag() {
  return (
    <span className="ml-2 inline-flex items-center rounded-full border border-[hsl(var(--border))] px-2 py-0.5 align-middle text-xs font-medium text-[hsl(var(--muted-foreground))]">
      For administrators
    </span>
  );
}

interface ReleaseDetailsProps {
  release: ReleaseNoteView;
  kinds: ReadonlySet<string> | undefined;
  showHighlights: boolean;
}

/** A release's highlights and grouped changes. */
function ReleaseDetails({ release, kinds, showHighlights }: ReleaseDetailsProps) {
  const groups = groupChanges(release.changes, kinds);
  return (
    <div className="space-y-5">
      {showHighlights && (
        <ul className="grid gap-3 sm:grid-cols-2">
          {release.highlights.map((highlight, index) => {
            const Icon = releaseIconFor(highlight.icon);
            return (
              <li
                key={`${highlight.title}-${String(index)}`}
                className="flex gap-3 rounded-lg border border-[hsl(var(--border))] p-3"
              >
                <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-[hsl(var(--primary)/0.1)] text-[hsl(var(--primary))]">
                  <Icon className="h-4 w-4" aria-hidden="true" />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-[hsl(var(--foreground))]">
                    {highlight.title}
                    {highlight.audience === 'administrators' && <AdministratorTag />}
                  </p>
                  <p className="mt-1 text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">
                    {highlight.body}
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {groups.map((group) => {
        const visual = releaseKindFor(group.kind);
        const KindIcon = visual.icon;
        return (
          <div key={group.kind}>
            <p
              className={cn(
                'release-chip inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold',
                visual.className,
              )}
            >
              <KindIcon className="h-3.5 w-3.5" aria-hidden="true" />
              {visual.label}
            </p>
            <ul className="mt-2 space-y-1.5 pl-1">
              {group.items.map((change, index) => (
                <li
                  key={`${change.text}-${String(index)}`}
                  className="relative max-w-prose pl-4 text-sm leading-relaxed text-[hsl(var(--foreground)/0.9)] before:absolute before:left-0 before:top-2.5 before:h-1 before:w-1 before:rounded-full before:bg-[hsl(var(--muted-foreground))]"
                >
                  {change.text}
                  {change.audience === 'administrators' && <AdministratorTag />}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

interface ReleaseEntryProps {
  release: ReleaseNoteView;
  heading: Heading;
  /** `hero` shows everything; `row` is a ledger line whose details open on request. */
  variant: 'hero' | 'row';
  /** Only changes of these kinds; every kind when undefined. */
  kinds?: ReadonlySet<string>;
  /** Whether a `row` starts open. */
  defaultOpen?: boolean;
}

/** One release, either as the focus of the dialog or as a line of the history. */
export function ReleaseEntry({
  release,
  heading,
  variant,
  kinds,
  defaultOpen = false,
}: ReleaseEntryProps) {
  const [open, setOpen] = useState(defaultOpen);
  const detailsId = useId();
  const HeadingTag = heading;
  const date = formatReleaseDate(release.date);

  if (variant === 'hero') {
    return (
      <article className="space-y-4" aria-label={`Release ${release.version}`}>
        <div>
          <HeadingTag className="text-xl font-semibold tracking-tight text-[hsl(var(--foreground))]">
            {release.title}
          </HeadingTag>
          <p className="mt-2 max-w-prose text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">
            {release.summary}
          </p>
        </div>
        <ReleaseDetails release={release} kinds={kinds} showHighlights />
      </article>
    );
  }

  return (
    <article
      id={releaseAnchorId(release.version)}
      aria-label={`Release ${release.version}`}
      // A link to one release lands focus here; Tab never stops on it.
      tabIndex={-1}
      className="grid scroll-mt-24 gap-x-6 gap-y-2 focus:outline-none sm:grid-cols-[6.5rem_1fr]"
    >
      <div className="flex items-baseline gap-3 sm:flex-col sm:gap-1">
        <span className="flex items-center gap-2 text-2xl font-semibold tabular-nums tracking-tight text-[hsl(var(--foreground))]">
          <span
            aria-hidden="true"
            className={cn(
              'h-2.5 w-2.5 shrink-0 rounded-full border-2',
              release.isNew
                ? 'border-[hsl(var(--primary))] bg-[hsl(var(--primary))]'
                : 'border-[hsl(var(--muted-foreground)/0.6)] bg-transparent',
            )}
          />
          {release.version}
        </span>
        <span className="text-xs text-[hsl(var(--muted-foreground))]">{date}</span>
      </div>
      <div className="min-w-0 border-b border-[hsl(var(--border))] pb-5">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <HeadingTag className="text-base font-semibold text-[hsl(var(--foreground))]">
            {release.title}
          </HeadingTag>
          {release.isNew && (
            <span className="rounded-full bg-[hsl(var(--sidebar-accent))] px-2 py-0.5 text-xs font-semibold text-[hsl(var(--sidebar-accent-foreground))]">
              New for you
            </span>
          )}
        </div>
        <p className="mt-1 max-w-prose text-sm leading-relaxed text-[hsl(var(--muted-foreground))]">
          {release.summary}
        </p>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={detailsId}
          onClick={() => setOpen((value) => !value)}
          className="mt-2 inline-flex min-h-6 items-center gap-1 rounded-md text-sm font-medium text-[hsl(var(--primary))] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))]"
        >
          {open ? 'Hide details' : 'Show details'}
          <ChevronDown
            aria-hidden="true"
            className={cn('h-4 w-4 transition-transform', open && 'rotate-180')}
          />
        </button>
        <div id={detailsId} hidden={!open} className="mt-4">
          {open && (
            <ReleaseDetails release={release} kinds={kinds} showHighlights={kinds === undefined} />
          )}
        </div>
      </div>
    </article>
  );
}
