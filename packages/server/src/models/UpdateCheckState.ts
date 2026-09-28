import mongoose, { Schema, type Model } from 'mongoose';
import { MAX_RELEASE_VERSION_LENGTH } from '@hvault/shared';

/** How the most recent request to GitHub ended. */
const UPDATE_CHECK_OUTCOMES = ['ok', 'no_release', 'rate_limited', 'unavailable'] as const;
export type UpdateCheckOutcome = (typeof UPDATE_CHECK_OUTCOMES)[number];

/** The `_id` of the one document this collection holds. */
export const UPDATE_CHECK_STATE_ID = 'github-latest';

/**
 * What the release check last learned, shared by every worker.
 *
 * ONE document, keyed by a fixed string id. It lives in the database rather than
 * in process memory because only the primary PM2 worker runs the check, while any
 * worker may answer `GET /releases/status`; an in-memory result would make the
 * answer depend on which worker a request reached.
 *
 * A failed check updates `lastCheckedAt` and `lastCheckStatus` and leaves the
 * last known release in place, so a temporary outage does not erase what a
 * previous check found. `lastSuccessAt` is what decides whether any of it is
 * still trusted (`UPDATE_CHECK_FRESHNESS_MS`).
 */
export interface IUpdateCheckState {
  _id: string;
  /** The `owner/name` the stored release belongs to; a different configured repository discards it. */
  repository: string;
  latestVersion?: string | undefined;
  latestPublishedAt?: Date | undefined;
  lastCheckedAt: Date;
  lastCheckStatus: UpdateCheckOutcome;
  lastSuccessAt?: Date | undefined;
  /** The newest release the administrators were emailed about; moves forward only. */
  notifiedVersion?: string | undefined;
}

const updateCheckStateSchema = new Schema<IUpdateCheckState>(
  {
    _id: { type: String, required: true },
    repository: { type: String, required: true, maxlength: 140 },
    latestVersion: { type: String, maxlength: MAX_RELEASE_VERSION_LENGTH, default: undefined },
    latestPublishedAt: { type: Date, default: undefined },
    lastCheckedAt: { type: Date, required: true },
    lastCheckStatus: { type: String, enum: UPDATE_CHECK_OUTCOMES, required: true },
    lastSuccessAt: { type: Date, default: undefined },
    notifiedVersion: { type: String, maxlength: MAX_RELEASE_VERSION_LENGTH, default: undefined },
  },
  {
    collection: 'update_check_state',
    // A single operational record: no `__v`, and no timestamps beyond the ones
    // the check writes itself.
    versionKey: false,
  },
);

export const UpdateCheckState: Model<IUpdateCheckState> = mongoose.model<IUpdateCheckState>(
  'UpdateCheckState',
  updateCheckStateSchema,
);
