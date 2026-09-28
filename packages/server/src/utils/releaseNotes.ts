import {
  APP_VERSION,
  compareReleaseVersions,
  isReleaseVersion,
  type ReleaseAudience,
  type ReleaseNote,
  type ReleaseNoteView,
} from '@hvault/shared';
import { config } from '../config/index.js';
import { RELEASE_NOTES_BASELINE_VERSION } from '../constants/index.js';

/**
 * The release an account's notes are caught up to.
 *
 * A stored value that is not a release version (absent on an account created
 * before the watermark existed, or anything malformed) reads as
 * `RELEASE_NOTES_BASELINE_VERSION`, so such an account is shown what changed
 * since the notes shipped rather than either nothing or the whole history.
 */
export function effectiveSeenVersion(stored: unknown): string {
  return isReleaseVersion(stored) ? stored : RELEASE_NOTES_BASELINE_VERSION;
}

/**
 * Whether this account is one of the server's administrators for release news:
 * it sees update information and the administrator-only notes.
 *
 * With no `UPDATE_NOTIFY_EMAILS` configured every account qualifies, which on a
 * typical self-hosted install means the one person who runs it. Both sides are
 * compared lower-cased, as account emails are stored.
 */
export function isUpdateAudience(email: string): boolean {
  const administrators = config.UPDATE_NOTIFY_EMAILS;
  return administrators.length === 0 || administrators.includes(email.toLowerCase());
}

/**
 * The public release page for `version`, built from configuration and a
 * validated version. Nothing a network response said ever becomes a link.
 */
export function releaseUrlFor(version: string): string {
  return `https://github.com/${config.UPDATE_CHECK_REPOSITORY}/releases/tag/v${version}`;
}

interface Viewer {
  /** Whether the viewer is in the update audience (sees administrator-only items). */
  isAudience: boolean;
  /** The release the viewer's notes are caught up to (see {@link effectiveSeenVersion}). */
  seenVersion: string;
}

/**
 * The release notes as one viewer receives them, newest first.
 *
 * - Administrator-only items are removed for a viewer outside the audience, and a
 *   release left with no highlight is removed altogether. The content test
 *   guarantees a release never has user-facing changes without a user-facing
 *   highlight, so no change a user should read is dropped this way; it removes a
 *   purely operational release from the view of people it does not concern.
 * - An entry newer than the running version is never shown: notes describe what
 *   this server runs, not what it might run next.
 * - `isNew` marks every release newer than the viewer's watermark.
 */
export function notesForViewer(notes: readonly ReleaseNote[], viewer: Viewer): ReleaseNoteView[] {
  const visible = (audience: ReleaseAudience | undefined): boolean =>
    viewer.isAudience || audience !== 'administrators';
  const views: ReleaseNoteView[] = [];
  for (const note of notes) {
    if (compareReleaseVersions(note.version, APP_VERSION) > 0) continue;
    const highlights = note.highlights.filter((highlight) => visible(highlight.audience));
    if (highlights.length === 0) continue;
    views.push({
      version: note.version,
      date: note.date,
      title: note.title,
      summary: note.summary,
      highlights: highlights.map((highlight) => ({ ...highlight })),
      changes: note.changes
        .filter((change) => visible(change.audience))
        .map((change) => ({ ...change })),
      isNew: compareReleaseVersions(note.version, viewer.seenVersion) > 0,
    });
  }
  return views;
}

/** How many releases in the viewer's notes are newer than their watermark. */
export function countUnseen(notes: readonly ReleaseNote[], viewer: Viewer): number {
  return notesForViewer(notes, viewer).filter((view) => view.isNew).length;
}
