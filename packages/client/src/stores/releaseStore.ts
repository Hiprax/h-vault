/**
 * Release store: what the server says about the version it runs, this account's
 * release-notes state and (for its administrators) newer releases, plus whether
 * the "What's new" dialog is open.
 *
 * Not persisted: every value here is the server's to state, and it is re-read
 * each time the app shell mounts (which it does on every unlock).
 *
 * The status is TAGGED with the account it was fetched for, and readers compare
 * that tag with the signed-in account. So a sign-out needs no hook into this
 * store: another account's status is simply never shown. A late answer from a
 * superseded request is dropped by a generation counter rather than allowed to
 * overwrite a newer one.
 */

import { create } from 'zustand';
import type { ReleaseStatus, UpdateStatus } from '@hvault/shared';
import { getReleaseStatusApi, markReleaseNotesSeenApi } from '../services/api/releaseStatusApi';
import { requestServiceWorkerUpdate } from '../lib/serviceWorkerUpdate';

interface ReleaseState {
  status: ReleaseStatus | null;
  /** The account `status` belongs to. */
  statusUserId: string | null;
  /** When `status` was last read (epoch ms), for the visibility refresh. */
  statusLoadedAt: number;
  dialogOpen: boolean;
  /** Counts openings, so each one gets a fresh error boundary (see `ReleaseNotesHost`). */
  dialogSession: number;
  /**
   * The version the server moved to while this page was open, or `null` while it
   * still runs the version it ran when the page first asked. A page built for the
   * old version is then out of date, and the update prompt says which version is
   * waiting.
   */
  serverUpdatedTo: string | null;

  /** Reads the status for `userId`. Never rejects: a failure keeps what was shown. */
  loadStatus: (userId: string) => Promise<void>;
  openDialog: () => void;
  /**
   * Closes the dialog. `shownVersion` is the newest release whose notes it
   * DISPLAYED, or `undefined` when they never loaded; only a shown release is
   * acknowledged, so notes that failed to appear are offered again.
   */
  closeDialog: (userId: string, shownVersion: string | undefined) => void;
  /** Replaces the update block after a "Check now". */
  applyUpdateStatus: (userId: string, update: UpdateStatus) => void;
}

// ── Module state: one per page, like the registration it drives ──────

const inFlight = new Map<string, Promise<void>>();
let generation = 0;
/** `userId:version` pairs already offered this session, so a failed save cannot re-open the dialog. */
const handled = new Set<string>();
/** The version the server reported the first time this page asked. */
let firstVersion: string | null = null;

const handledKey = (userId: string, version: string): string => `${userId}:${version}`;

/**
 * Whether the dialog should open by itself for this status: there are notes the
 * account has not read, the account wants them shown, and this session has not
 * already offered this release.
 */
export function shouldAutoOpenReleaseNotes(status: ReleaseStatus, userId: string): boolean {
  return (
    status.releaseNotes.unseenCount > 0 &&
    status.releaseNotes.showOnUpdate &&
    !handled.has(handledKey(userId, status.version))
  );
}

/** Records that this session offered `version` to `userId`. */
export function markReleaseNotesOffered(userId: string, version: string): void {
  handled.add(handledKey(userId, version));
}

export const useReleaseStore = create<ReleaseState>()((set, get) => ({
  status: null,
  statusUserId: null,
  statusLoadedAt: 0,
  dialogOpen: false,
  dialogSession: 0,
  serverUpdatedTo: null,

  loadStatus: (userId: string): Promise<void> => {
    const pending = inFlight.get(userId);
    if (pending) return pending;
    generation += 1;
    const mine = generation;
    const request = getReleaseStatusApi()
      .then(
        (status) => {
          if (mine !== generation) return;
          // The server now runs a different version than it did when this page
          // first asked, so a newer build is waiting: ask the browser to fetch it
          // now, and the update prompt appears on its own.
          let serverUpdatedTo = get().serverUpdatedTo;
          if (firstVersion === null) {
            firstVersion = status.version;
          } else if (status.version !== firstVersion) {
            serverUpdatedTo = status.version;
            requestServiceWorkerUpdate();
          }
          set({ status, statusUserId: userId, statusLoadedAt: Date.now(), serverUpdatedTo });
        },
        // A failed read keeps whatever was already shown; the next mount or
        // visibility refresh asks again.
        () => undefined,
      )
      .finally(() => {
        inFlight.delete(userId);
      });
    inFlight.set(userId, request);
    return request;
  },

  openDialog: (): void => {
    if (get().dialogOpen) return;
    set((state) => ({ dialogOpen: true, dialogSession: state.dialogSession + 1 }));
  },

  closeDialog: (userId: string, shownVersion: string | undefined): void => {
    set({ dialogOpen: false });
    const { status, statusUserId } = get();
    if (shownVersion === undefined || status === null || statusUserId !== userId) return;
    markReleaseNotesOffered(userId, status.version);
    if (status.releaseNotes.unseenCount === 0) return;
    // Shown as read at once; the server's answer then states what it stored.
    set({
      status: {
        ...status,
        releaseNotes: { ...status.releaseNotes, seenVersion: shownVersion, unseenCount: 0 },
      },
    });
    markReleaseNotesSeenApi(shownVersion).then(
      (seen) => {
        const current = get();
        if (current.status === null || current.statusUserId !== userId) return;
        set({
          status: {
            ...current.status,
            releaseNotes: { ...current.status.releaseNotes, ...seen },
          },
        });
      },
      // Not retried: `handled` keeps this session from asking again, and the next
      // session re-reads the server, which still holds the old watermark, so the
      // notes are offered once more rather than lost.
      () => undefined,
    );
  },

  applyUpdateStatus: (userId: string, update: UpdateStatus): void => {
    const { status, statusUserId } = get();
    if (status === null || statusUserId !== userId) return;
    set({ status: { ...status, update } });
  },
}));

/** The status, when it belongs to `userId`; `null` otherwise. */
export function releaseStatusFor(
  state: Pick<ReleaseState, 'status' | 'statusUserId'>,
  userId: string | undefined,
): ReleaseStatus | null {
  return userId !== undefined && state.statusUserId === userId ? state.status : null;
}

/** Test seam: forget the module state between cases. */
export function _resetReleaseStoreForTests(): void {
  inFlight.clear();
  handled.clear();
  generation = 0;
  firstVersion = null;
  useReleaseStore.setState({
    status: null,
    statusUserId: null,
    statusLoadedAt: 0,
    dialogOpen: false,
    dialogSession: 0,
    serverUpdatedTo: null,
  });
}
