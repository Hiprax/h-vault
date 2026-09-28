import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import type { ReleaseNotesList } from '@hvault/shared';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/Dialog';
import { Button } from '../ui/Button';
import { useReleaseStore } from '../../stores/releaseStore';
import { getReleaseNotesApi } from '../../services/api/releaseNotesApi';
import { formatReleaseDate } from '../../lib/releaseFormat';
import { ReleaseEntry } from './ReleaseEntry';
import { VaultDial } from './VaultDial';

type NotesState =
  { phase: 'loading' } | { phase: 'ready'; notes: ReleaseNotesList } | { phase: 'failed' };

interface WhatsNewDialogProps {
  userId: string;
  /** The version the server runs, known before the notes arrive. */
  version: string;
}

/** "Released 27 September 2026", plus how many releases are new when more than one is. */
function describeRelease(notes: ReleaseNotesList): string {
  const newest = notes.releases[0];
  const released = newest ? `Released ${formatReleaseDate(newest.date)}.` : '';
  const unseen = notes.releases.filter((release) => release.isNew).length;
  return unseen > 1 ? `${released} ${String(unseen)} updates since you last looked.` : released;
}

/**
 * "What's new": the release notes, opened by itself on the first visit after an
 * update and from the version in the sidebar at any time.
 *
 * Loaded lazily and only while open, so neither it nor the notes are part of the
 * initial page. The scroll region is the first thing that can take focus, so the
 * dialog's initial focus lands there and the arrow keys scroll the notes at once
 * (and a stray Enter cannot dismiss them). Every way of closing (Done, the close
 * button, Escape, the backdrop) acknowledges the notes, but only once they have
 * actually been shown.
 */
export default function WhatsNewDialog({ userId, version }: WhatsNewDialogProps) {
  const closeDialog = useReleaseStore((state) => state.closeDialog);
  const [state, setState] = useState<NotesState>({ phase: 'loading' });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    getReleaseNotesApi().then(
      (notes) => {
        if (active) setState({ phase: 'ready', notes });
      },
      () => {
        if (active) setState({ phase: 'failed' });
      },
    );
    return () => {
      active = false;
    };
  }, [attempt]);

  const shownVersion = state.phase === 'ready' ? state.notes.version : undefined;
  const close = useCallback(() => {
    closeDialog(userId, shownVersion);
  }, [closeDialog, userId, shownVersion]);

  const [hero, ...earlier] = state.phase === 'ready' ? state.notes.releases : [];

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) close();
      }}
    >
      <DialogContent
        onClose={close}
        className="flex h-[100dvh] max-w-3xl flex-col gap-0 overflow-hidden rounded-none p-0 sm:h-auto sm:max-h-[85vh] sm:rounded-xl"
      >
        <DialogHeader className="flex-row items-center gap-5 space-y-0 border-b border-[hsl(var(--border))] px-6 py-5 text-left sm:text-left">
          <VaultDial version={version} />
          <div className="min-w-0 pr-6">
            <DialogTitle className="text-xl leading-tight">
              What&apos;s new in H-Vault {version}
            </DialogTitle>
            <DialogDescription className="mt-1.5">
              {state.phase === 'ready'
                ? describeRelease(state.notes)
                : 'The release notes for this server.'}
            </DialogDescription>
          </div>
        </DialogHeader>

        <div
          role="region"
          aria-label="Release notes"
          tabIndex={0}
          className="flex-1 overflow-y-auto px-6 py-6 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[hsl(var(--ring))]"
        >
          {state.phase === 'loading' && (
            <div className="space-y-3" aria-busy="true">
              <p className="sr-only">Loading the release notes</p>
              <div className="h-6 w-2/3 animate-pulse rounded bg-[hsl(var(--muted))]" />
              <div className="h-4 w-full animate-pulse rounded bg-[hsl(var(--muted))]" />
              <div className="h-4 w-5/6 animate-pulse rounded bg-[hsl(var(--muted))]" />
            </div>
          )}
          {state.phase === 'failed' && (
            <div className="space-y-3">
              <p className="text-sm text-[hsl(var(--foreground))]">
                The release notes could not be loaded. Check your connection and try again.
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setState({ phase: 'loading' });
                  setAttempt((value) => value + 1);
                }}
              >
                Try again
              </Button>
            </div>
          )}
          {state.phase === 'ready' && hero === undefined && (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">
              There are no release notes for this version yet.
            </p>
          )}
          {hero !== undefined && (
            <div className="space-y-10">
              <ReleaseEntry release={hero} heading="h3" variant="hero" />
              {earlier.length > 0 && (
                <div className="space-y-6">
                  <h3 className="text-sm font-semibold text-[hsl(var(--muted-foreground))]">
                    Earlier releases
                  </h3>
                  {earlier.map((release) => (
                    <ReleaseEntry
                      key={release.version}
                      release={release}
                      heading="h4"
                      variant="row"
                      defaultOpen={release.isNew}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <DialogFooter className="items-center gap-2 border-t border-[hsl(var(--border))] px-6 py-4 sm:justify-between sm:space-x-0">
          <Link
            to="/settings/about#release-history"
            onClick={close}
            className="text-sm font-medium text-[hsl(var(--primary))] hover:underline"
          >
            See full history
          </Link>
          <Button onClick={close}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
