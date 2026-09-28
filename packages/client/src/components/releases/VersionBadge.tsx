import { Sparkles } from 'lucide-react';
import type { ReleaseStatus } from '@hvault/shared';
import { cn } from '../../lib/utils';

interface VersionBadgeProps {
  /** Whether the sidebar is showing labels (see `AppLayout`). */
  expanded: boolean;
  /** The status for the signed-in account, or `null` before it has loaded. */
  status: ReleaseStatus | null;
  onOpen: () => void;
}

/** What the badge says to a screen reader, and in the tooltip of a collapsed sidebar. */
export function versionBadgeLabel(status: ReleaseStatus): string {
  const unseen = status.releaseNotes.unseenCount;
  const newer = status.update?.state === 'available' ? status.update.latestVersion : null;
  return [
    `H-Vault ${status.version}.`,
    unseen > 0 ? `${String(unseen)} new ${unseen === 1 ? 'release' : 'releases'} to read.` : null,
    newer === null ? null : `Version ${newer} is available.`,
    "Open what's new",
  ]
    .filter((part) => part !== null)
    .join(' ');
}

/**
 * The running version, at the foot of the sidebar. Opens "What's new". A dot
 * with a slow ring marks unread release notes; administrators also see "New
 * release" while GitHub has a newer version than this server runs.
 *
 * Before the status has loaded it holds its place with an empty row of the same
 * height, so the sidebar does not shift when the answer arrives.
 */
export function VersionBadge({ expanded, status, onOpen }: VersionBadgeProps) {
  if (status === null) {
    return <div className="h-9" aria-hidden="true" />;
  }
  const unseen = status.releaseNotes.unseenCount > 0;
  const newer = status.update?.state === 'available' && status.update.latestVersion !== null;
  const label = versionBadgeLabel(status);

  return (
    <button
      type="button"
      onClick={onOpen}
      aria-label={label}
      title={expanded ? undefined : label}
      className={cn(
        'flex min-h-9 w-full cursor-pointer items-center rounded-md px-3 py-2 text-xs text-[hsl(var(--sidebar-foreground))] transition-colors hover:bg-[hsl(var(--sidebar-accent))] hover:text-[hsl(var(--sidebar-accent-foreground))]',
        expanded ? 'gap-3' : 'justify-center',
      )}
    >
      <span className="relative flex h-4 w-4 shrink-0 items-center justify-center">
        <Sparkles className="h-4 w-4 opacity-70" aria-hidden="true" />
        {unseen && (
          <span
            data-testid="release-unseen-dot"
            aria-hidden="true"
            className="release-unseen-dot absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-[hsl(var(--primary))]"
          />
        )}
      </span>
      <span
        className={cn(
          'flex min-w-0 items-center gap-2 whitespace-nowrap transition-opacity duration-200',
          expanded ? 'opacity-100' : 'w-0 overflow-hidden opacity-0',
        )}
      >
        <span className="tabular-nums">v{status.version}</span>
        {newer && (
          <span className="rounded-full bg-[hsl(var(--sidebar-accent))] px-2 py-0.5 text-[11px] font-semibold text-[hsl(var(--sidebar-accent-foreground))]">
            New release
          </span>
        )}
      </span>
    </button>
  );
}
