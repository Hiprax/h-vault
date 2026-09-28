import { useEffect, useId, useState } from 'react';
import { useLocation, useNavigate } from 'react-router';
import { ArrowLeft, ExternalLink, Sparkles } from 'lucide-react';
import type { ReleaseNotesList } from '@hvault/shared';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { useToast } from '../components/ui/Toast';
import { VaultDial } from '../components/releases/VaultDial';
import { ReleaseHistory } from '../components/releases/ReleaseHistory';
import { UpdateStatusCard } from '../components/releases/UpdateStatusCard';
import { useAuthStore } from '../stores/authStore';
import { releaseStatusFor, useReleaseStore } from '../stores/releaseStore';
import { getReleaseNotesApi } from '../services/api/releaseNotesApi';
import { updateSettingsApi } from '../services/api/userApi';
import { clearSettingsCache } from '../hooks/useUserSettings';
import { formatReleaseDate, isGithubReleaseUrl } from '../lib/releaseFormat';
import { getApiErrorMessage } from '../lib/utils';

type NotesState =
  { phase: 'loading' } | { phase: 'ready'; notes: ReleaseNotesList } | { phase: 'failed' };

/**
 * About H-Vault: the version this server runs, whether a newer one exists (for
 * its administrators), the "What's new" preference, and every release's notes.
 */
export default function AboutPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const userId = useAuthStore((state) => state.user?.userId);
  const status = useReleaseStore((state) => releaseStatusFor(state, userId));
  const [notes, setNotes] = useState<NotesState>({ phase: 'loading' });
  const [savingPreference, setSavingPreference] = useState(false);
  const preferenceId = useId();
  const historyTitleId = useId();

  useEffect(() => {
    if (userId !== undefined) void useReleaseStore.getState().loadStatus(userId);
  }, [userId]);

  useEffect(() => {
    let active = true;
    getReleaseNotesApi().then(
      (list) => {
        if (active) setNotes({ phase: 'ready', notes: list });
      },
      () => {
        if (active) setNotes({ phase: 'failed' });
      },
    );
    return () => {
      active = false;
    };
  }, []);

  // A link such as `/settings/about#release-history` or `#v0-15-0` lands on its
  // target once the notes it points into have rendered. Focus goes there as
  // well, so the next Tab continues from the history rather than from wherever
  // the link was (the dialog that opened this page has already closed).
  useEffect(() => {
    if (notes.phase !== 'ready' || location.hash.length < 2) return;
    const target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (target === null) return;
    target.scrollIntoView();
    target.focus({ preventScroll: true });
  }, [notes.phase, location.hash]);

  const savePreference = async (showReleaseNotes: boolean) => {
    if (userId === undefined) return;
    setSavingPreference(true);
    try {
      await updateSettingsApi({ showReleaseNotes });
      clearSettingsCache();
      await useReleaseStore.getState().loadStatus(userId);
      toast({
        title: showReleaseNotes
          ? "What's new will open after each update"
          : "What's new will stay behind the version in the sidebar",
        type: 'success',
      });
    } catch (error: unknown) {
      toast({
        title: 'Could not save the preference',
        description: getApiErrorMessage(error),
        type: 'error',
      });
    } finally {
      setSavingPreference(false);
    }
  };

  const newest = notes.phase === 'ready' ? notes.notes.releases[0] : undefined;
  const releaseLink =
    status !== null && isGithubReleaseUrl(status.releaseUrl) ? status.releaseUrl : null;

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="flex items-center gap-4">
        <button
          type="button"
          onClick={() => void navigate('/settings')}
          className="rounded-md p-2 text-[hsl(var(--muted-foreground))] transition-colors hover:bg-[hsl(var(--accent))]"
          aria-label="Back to settings"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <h1 className="text-2xl font-bold text-[hsl(var(--foreground))]">About H-Vault</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>This installation</CardTitle>
          <CardDescription>The version of H-Vault this server runs.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {status === null ? (
            <p className="text-sm text-[hsl(var(--muted-foreground))]">Reading the version…</p>
          ) : (
            <div className="flex flex-wrap items-center gap-6">
              <VaultDial version={status.version} />
              <div className="space-y-1">
                <p className="text-3xl font-semibold tabular-nums tracking-tight text-[hsl(var(--foreground))]">
                  {status.version}
                </p>
                {newest?.version === status.version && (
                  <p className="text-sm text-[hsl(var(--muted-foreground))]">
                    Released {formatReleaseDate(newest.date)}
                  </p>
                )}
                {releaseLink !== null && (
                  <a
                    href={releaseLink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
                  >
                    Release notes on GitHub
                    <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                    <span className="sr-only">(opens in a new tab)</span>
                  </a>
                )}
              </div>
            </div>
          )}
          {status?.update && userId !== undefined && (
            <UpdateStatusCard userId={userId} current={status.version} update={status.update} />
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>What&apos;s new</CardTitle>
          <CardDescription>
            After the server is updated, H-Vault shows what changed the first time you sign in.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <label htmlFor={preferenceId} className="text-sm text-[hsl(var(--foreground))]">
              Show what&apos;s new after an update
            </label>
            <input
              id={preferenceId}
              type="checkbox"
              checked={status?.releaseNotes.showOnUpdate ?? true}
              disabled={status === null || savingPreference}
              onChange={(event) => void savePreference(event.target.checked)}
              className="h-4 w-4 rounded border-[hsl(var(--input))] accent-[hsl(var(--primary))]"
            />
          </div>
          <p className="text-xs text-[hsl(var(--muted-foreground))]">
            When this is off, the notes stay one click away, behind the version in the sidebar.
          </p>
          <Button
            variant="outline"
            size="sm"
            disabled={status === null}
            onClick={() => useReleaseStore.getState().openDialog()}
          >
            <Sparkles className="h-4 w-4" aria-hidden="true" />
            Open what&apos;s new
          </Button>
        </CardContent>
      </Card>

      <section
        id="release-history"
        aria-labelledby={historyTitleId}
        // Focusable from a link to it, never from Tab.
        tabIndex={-1}
        className="scroll-mt-6 space-y-4 focus:outline-none"
      >
        <h2 id={historyTitleId} className="text-lg font-semibold text-[hsl(var(--foreground))]">
          Release history
        </h2>
        {notes.phase === 'loading' && (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">Loading the release notes…</p>
        )}
        {notes.phase === 'failed' && (
          <p className="text-sm text-[hsl(var(--foreground))]">
            The release notes could not be loaded. Check your connection and reload the page.
          </p>
        )}
        {notes.phase === 'ready' && <ReleaseHistory releases={notes.notes.releases} />}
      </section>
    </div>
  );
}
