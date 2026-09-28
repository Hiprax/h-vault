import type { Request, Response } from 'express';
import { catchAsync, httpErrors } from '@hiprax/errors';
import {
  APP_VERSION,
  SHOW_RELEASE_NOTES_DEFAULT,
  compareReleaseVersions,
  type MarkReleaseNotesSeenInput,
  type ReleaseNotesList,
  type ReleaseNotesSeen,
  type ReleaseStatus,
  type UpdateCheckResult,
} from '@hvault/shared';
import { config } from '../config/index.js';
import { RELEASE_NOTES } from '../content/releaseNotes.js';
import { User, type IUserSettings } from '../models/User.js';
import { getUserId } from '../utils/controllerHelpers.js';
import {
  countUnseen,
  effectiveSeenVersion,
  isUpdateAudience,
  notesForViewer,
  releaseUrlFor,
} from '../utils/releaseNotes.js';
import { checkForUpdateNow, readUpdateStatus } from '../utils/updateCheck.js';

/**
 * How many times `POST /releases/seen` re-reads and retries when another request
 * moved the watermark between its read and its write. Only the same account's
 * own tabs can race it, so a third collision in a row is not worth a fourth try:
 * the answer is then whatever the winner stored.
 */
const SEEN_WRITE_ATTEMPTS = 3;

interface ViewerRecord {
  /** The raw stored watermark, exactly as the conditional write must match it. */
  stored: unknown;
  seenVersion: string;
  isAudience: boolean;
  showOnUpdate: boolean;
}

/**
 * What the release endpoints need to know about the caller, read from the
 * PRIMARY: the seen write compares against this value, and a lagging secondary
 * would make that comparison fail every time.
 */
async function loadViewer(userId: string): Promise<ViewerRecord> {
  const user = await User.findById(userId)
    .read('primary')
    .select('email settings.showReleaseNotes +releaseNotesSeenVersion')
    .lean();
  if (!user) {
    throw httpErrors.notFound('User not found');
  }
  // A lean read of an account created before the setting existed has no value
  // for it; the declared type is what this line makes true.
  const settings = user.settings as Partial<IUserSettings> | undefined;
  return {
    stored: user.releaseNotesSeenVersion,
    seenVersion: effectiveSeenVersion(user.releaseNotesSeenVersion),
    isAudience: isUpdateAudience(user.email),
    showOnUpdate: settings?.showReleaseNotes ?? SHOW_RELEASE_NOTES_DEFAULT,
  };
}

/** `GET /releases/status`: the running version, the caller's notes state, and update news. */
export const getReleaseStatus = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const viewer = await loadViewer(getUserId(req));
  const data: ReleaseStatus = {
    version: APP_VERSION,
    releaseUrl: releaseUrlFor(APP_VERSION),
    releaseNotes: {
      seenVersion: viewer.seenVersion,
      unseenCount: countUnseen(RELEASE_NOTES, viewer),
      showOnUpdate: viewer.showOnUpdate,
    },
    // Only the update audience learns what GitHub has; everyone else is told
    // nothing rather than a status that depends on who they are.
    update: viewer.isAudience ? await readUpdateStatus() : null,
  };
  res.status(200).json({ success: true, data });
});

/** `GET /releases/notes`: every release's notes, as this caller may read them. */
export const listReleaseNotes = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const viewer = await loadViewer(getUserId(req));
  const data: ReleaseNotesList = {
    version: APP_VERSION,
    seenVersion: viewer.seenVersion,
    releases: notesForViewer(RELEASE_NOTES, viewer),
  };
  res.status(200).json({ success: true, data });
});

/**
 * `POST /releases/seen`: the caller acknowledged the notes up to `version`.
 *
 * The version comes from the client because only the client knows what it
 * SHOWED: a tab still running an older build must not mark notes it never
 * displayed as seen. It is clamped to the running version (nothing newer exists
 * to have been seen) and only ever moves the watermark forward, through a write
 * conditioned on the value just read, so two tabs finishing at once cannot move
 * it backwards.
 */
export const markReleaseNotesSeen = catchAsync(
  async (req: Request, res: Response): Promise<void> => {
    const userId = getUserId(req);
    const { version } = req.body as MarkReleaseNotesSeenInput;
    const target = compareReleaseVersions(version, APP_VERSION) > 0 ? APP_VERSION : version;

    let viewer = await loadViewer(userId);
    for (let attempt = 0; attempt < SEEN_WRITE_ATTEMPTS; attempt += 1) {
      if (compareReleaseVersions(target, viewer.seenVersion) <= 0) break;
      const write = await User.updateOne(
        // `null` matches a missing field as well as a null one, so an account
        // with no watermark yet is matched by the same filter.
        { _id: userId, releaseNotesSeenVersion: viewer.stored ?? null },
        { $set: { releaseNotesSeenVersion: target } },
      );
      if (write.matchedCount === 1) {
        viewer = { ...viewer, stored: target, seenVersion: target };
        break;
      }
      viewer = await loadViewer(userId);
    }

    const data: ReleaseNotesSeen = {
      seenVersion: viewer.seenVersion,
      unseenCount: countUnseen(RELEASE_NOTES, viewer),
    };
    res.status(200).json({ success: true, data });
  },
);

/**
 * `POST /releases/update-check`: "Check now", for the update audience only.
 * Answers from the stored state inside the cooldown, so it can never spend the
 * server's GitHub budget however often it is pressed.
 */
export const checkForUpdate = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const viewer = await loadViewer(getUserId(req));
  if (!viewer.isAudience) {
    throw httpErrors.forbidden("Only this server's administrators can check for updates.");
  }
  if (!config.UPDATE_CHECK_ENABLED) {
    throw httpErrors.conflict('Update checks are turned off on this server.');
  }
  const data: UpdateCheckResult = await checkForUpdateNow();
  res.status(200).json({ success: true, data });
});
