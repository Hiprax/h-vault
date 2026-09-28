import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import { useAuthStore } from '../../stores/authStore';
import { useUIStore } from '../../stores/uiStore';
import {
  markReleaseNotesOffered,
  releaseStatusFor,
  shouldAutoOpenReleaseNotes,
  useReleaseStore,
} from '../../stores/releaseStore';
import { dismissUpdateNotice, isUpdateNoticeDismissed } from '../../lib/updateNoticeDismissal';
import { ErrorBoundary } from '../layout/ErrorBoundary';

const WhatsNewDialog = lazy(() => import('./WhatsNewDialog'));
const UpdateAvailableBanner = lazy(() => import('./UpdateAvailableBanner'));

/** The shortest gap between two status reads caused by the tab becoming visible again. */
const VISIBILITY_REFRESH_MS = 5 * 60 * 1000;

/**
 * What a failed dialog load leaves behind: nothing on screen, and the dialog
 * marked closed WITHOUT acknowledging notes that were never shown, so the badge
 * can open it again.
 */
function DialogLoadFailed({ userId }: { userId: string }) {
  useEffect(() => {
    useReleaseStore.getState().closeDialog(userId, undefined);
  }, [userId]);
  return null;
}

/** Whether some other modal is already open, in which case the notes wait. */
function anotherModalIsOpen(): boolean {
  return document.querySelector('[aria-modal="true"]') !== null;
}

/**
 * Everything release-related the app shell shows besides the version badge: it
 * reads the release status when the shell mounts (every unlock), opens "What's
 * new" by itself when there is something to read, and shows administrators the
 * notice about a newer release.
 *
 * The dialog opens by itself at most ONCE per mount, from the first status read,
 * and never over another modal or while the first-run guide is on screen (it
 * waits for the guide to close). A later refresh, when the tab becomes visible
 * again, only updates the badge and the notice: opening a dialog over whatever
 * the user came back to would take over a screen they were using.
 *
 * The dialog and the notice are loaded on demand and each sits inside its own
 * error boundary, so a failure in either leaves the shell exactly as it was.
 */
export function ReleaseNotesHost() {
  const userId = useAuthStore((state) => state.user?.userId);
  const status = useReleaseStore((state) => releaseStatusFor(state, userId));
  const dialogOpen = useReleaseStore((state) => state.dialogOpen);
  const dialogSession = useReleaseStore((state) => state.dialogSession);
  const onboardingActive = useUIStore((state) => state.onboardingActive);
  const [dismissedUpdate, setDismissedUpdate] = useState<string | null>(null);
  // Armed until the first status of this mount has been judged.
  const autoOpenPending = useRef(true);
  // Whether THIS mount's read has settled. The store may still hold the status
  // from before a lock; judging that one would decide on stale information and
  // disarm before the fresh answer arrives.
  const [loadedThisMount, setLoadedThisMount] = useState(false);

  // The dialog belongs to this shell, and the shell goes away on every lock and
  // sign-out. It closes with it, acknowledging nothing, so it can never reappear
  // over the next unlock or in front of the next account to sign in.
  useEffect(
    () => () => {
      useReleaseStore.setState({ dialogOpen: false });
    },
    [],
  );

  useEffect(() => {
    if (userId === undefined) return;
    let active = true;
    void useReleaseStore
      .getState()
      .loadStatus(userId)
      .then(() => {
        if (active) setLoadedThisMount(true);
      });
    return () => {
      active = false;
    };
  }, [userId]);

  useEffect(() => {
    if (userId === undefined) return;
    const onVisibility = () => {
      if (document.visibilityState !== 'visible') return;
      if (Date.now() - useReleaseStore.getState().statusLoadedAt < VISIBILITY_REFRESH_MS) return;
      void useReleaseStore.getState().loadStatus(userId);
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [userId]);

  useEffect(() => {
    if (!autoOpenPending.current || !loadedThisMount || status === null || userId === undefined) {
      return;
    }
    if (onboardingActive) return;
    autoOpenPending.current = false;
    if (!shouldAutoOpenReleaseNotes(status, userId) || anotherModalIsOpen()) return;
    markReleaseNotesOffered(userId, status.version);
    useReleaseStore.getState().openDialog();
  }, [status, userId, onboardingActive, loadedThisMount]);

  const update = status?.update;
  const newer =
    update?.state === 'available' &&
    update.latestVersion !== null &&
    update.latestVersion !== dismissedUpdate &&
    !isUpdateNoticeDismissed(update.latestVersion)
      ? update.latestVersion
      : null;

  return (
    <>
      {status !== null && newer !== null && (
        <ErrorBoundary key={`notice-${newer}`} fallback={null}>
          <Suspense fallback={null}>
            <UpdateAvailableBanner
              current={status.version}
              latest={newer}
              releaseUrl={update?.releaseUrl ?? null}
              onDismiss={() => {
                dismissUpdateNotice(newer);
                setDismissedUpdate(newer);
              }}
            />
          </Suspense>
        </ErrorBoundary>
      )}
      {dialogOpen && status !== null && userId !== undefined && (
        <ErrorBoundary
          // A fresh boundary per opening, so one failed load cannot disable the dialog.
          key={`dialog-${String(dialogSession)}`}
          fallback={<DialogLoadFailed userId={userId} />}
        >
          <Suspense fallback={null}>
            <WhatsNewDialog userId={userId} version={status.version} />
          </Suspense>
        </ErrorBoundary>
      )}
    </>
  );
}
