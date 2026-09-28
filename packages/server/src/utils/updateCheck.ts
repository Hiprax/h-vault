import axios, { type AxiosResponse } from 'axios';
import { z } from 'zod';
import {
  APP_VERSION,
  compareReleaseVersions,
  isReleaseVersion,
  type UpdateState,
  type UpdateStatus,
} from '@hvault/shared';
import { config } from '../config/index.js';
import {
  UPDATE_CHECK_API_BASE_URL,
  UPDATE_CHECK_API_VERSION,
  UPDATE_CHECK_FRESHNESS_MS,
  UPDATE_CHECK_LOCK_TTL_MS,
  UPDATE_CHECK_MAX_RESPONSE_BYTES,
  UPDATE_CHECK_MIN_INTERVAL_MS,
  UPDATE_CHECK_SOCKET_TIMEOUT_MS,
  UPDATE_CHECK_TOTAL_TIMEOUT_MS,
  UPDATE_CHECK_USER_AGENT,
} from '../constants/index.js';
import {
  UPDATE_CHECK_STATE_ID,
  UpdateCheckState,
  type IUpdateCheckState,
  type UpdateCheckOutcome,
} from '../models/UpdateCheckState.js';
import { isEmailConfigured, sendUpdateAvailableEmail } from './email.js';
import { acquireJobLock, releaseJobLock } from './jobLock.js';
import { trackJob } from './jobTracker.js';
import { createModuleLogger, errorMessage } from './logger.js';
import { releaseUrlFor } from './releaseNotes.js';

/**
 * The release check: "is a newer H-Vault published than the one this server runs?"
 *
 * It is one of the two outbound HTTP calls the server makes (the other is the
 * HIBP range lookup), and it is hardened the same way: a fixed host, no
 * redirects, a size cap, and time limits. The request carries a fixed
 * User-Agent and nothing about the server, its users or its version; the
 * answer is reduced to a version number and a date before anything stores it.
 */

const logger = createModuleLogger('update-check');

/** The JobLock that makes one check at a time, across every worker and instance. */
export const UPDATE_CHECK_LOCK_NAME = 'update-check';

/** What one request to GitHub established. */
export type FetchedRelease =
  | { outcome: 'ok'; version: string; publishedAt: Date | null }
  | { outcome: Exclude<UpdateCheckOutcome, 'ok'> };

/** The only fields of a GitHub release document this code reads. */
const githubReleaseSchema = z.object({
  tag_name: z.string().max(64),
  draft: z.boolean(),
  prerelease: z.boolean(),
  published_at: z.string().max(64).nullable(),
});

/** Overrides for tests: a loopback stub in place of GitHub, and shorter deadlines. */
export interface FetchOptions {
  baseUrl?: string;
  socketTimeoutMs?: number;
  totalTimeoutMs?: number;
}

const UNAVAILABLE = { outcome: 'unavailable' } as const;

/**
 * A publication time as GitHub may write it: an ISO timestamp with a four-digit
 * year, in UTC or with an offset. `Date.parse` also accepts extended years
 * (`+275760-…`), whose ISO form no client schema accepts, so one such answer
 * would make every status unreadable.
 */
const publicationTimeSchema = z.iso.datetime({ offset: true });
/** What the status re-emits it as, and what the client's schema accepts: UTC, four-digit year. */
const emittedTimeSchema = z.iso.datetime();

/**
 * The publication time to store, or `null`. The date must survive the round
 * trip: an offset can carry a four-digit year across 9999 or below 0000 once
 * converted to UTC, and `toISOString()` then writes the extended form.
 */
function readPublicationTime(value: string | null): Date | null {
  const parsed = publicationTimeSchema.safeParse(value);
  if (!parsed.success) return null;
  const date = new Date(parsed.data);
  return emittedTimeSchema.safeParse(date.toISOString()).success ? date : null;
}

/**
 * Asks GitHub for the newest published release of `repository`. Never throws:
 * every failure is reduced to an outcome, because the caller's only question is
 * what to record.
 */
export async function fetchLatestRelease(
  repository: string,
  options: FetchOptions = {},
): Promise<FetchedRelease> {
  let response: AxiosResponse<string>;
  try {
    response = await axios.get<string>(
      `${options.baseUrl ?? UPDATE_CHECK_API_BASE_URL}/repos/${repository}/releases/latest`,
      {
        headers: {
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': UPDATE_CHECK_API_VERSION,
          'User-Agent': UPDATE_CHECK_USER_AGENT,
        },
        timeout: options.socketTimeoutMs ?? UPDATE_CHECK_SOCKET_TIMEOUT_MS,
        signal: AbortSignal.timeout(options.totalTimeoutMs ?? UPDATE_CHECK_TOTAL_TIMEOUT_MS),
        responseType: 'text',
        // A renamed repository answers with a redirect. Following it would let
        // the answer choose where the next request goes, so it is reported
        // instead and the operator updates UPDATE_CHECK_REPOSITORY.
        maxRedirects: 0,
        maxContentLength: UPDATE_CHECK_MAX_RESPONSE_BYTES,
        maxBodyLength: UPDATE_CHECK_MAX_RESPONSE_BYTES,
        // Every status is classified below; none is an exception.
        validateStatus: () => true,
      },
    );
  } catch (error: unknown) {
    logger.warn('Release check request failed', { repository, error: errorMessage(error) });
    return UNAVAILABLE;
  }

  const { status } = response;
  if (status === 200) {
    return parseRelease(response.data, repository);
  }
  if (status === 404) {
    logger.info('The repository has no published release', { repository });
    return { outcome: 'no_release' };
  }
  if (status === 429 || (status === 403 && isRateLimitReply(response))) {
    logger.warn('GitHub rate limit reached; the next scheduled check will try again', {
      repository,
    });
    return { outcome: 'rate_limited' };
  }
  if (status >= 300 && status < 400) {
    logger.warn(
      'Release check was redirected: the repository may have moved; set UPDATE_CHECK_REPOSITORY',
      {
        repository,
        status,
      },
    );
    return UNAVAILABLE;
  }
  if (status === 410) {
    // GitHub's documented answer to an API version it no longer supports. A
    // version stays supported for at least 24 months after its successor ships,
    // so this is an installation that has not been updated in that long.
    logger.warn(
      'Release check was refused as gone: GitHub may no longer support the API version this H-Vault asks for; updating H-Vault fixes it',
      { repository, status, apiVersion: UPDATE_CHECK_API_VERSION },
    );
    return UNAVAILABLE;
  }
  logger.warn('Release check got an unexpected answer', { repository, status });
  return UNAVAILABLE;
}

/**
 * A 403 is a rate limit only when GitHub says so; without these headers it is a
 * refusal of another kind, and calling it a rate limit would misdirect the
 * operator reading the log.
 */
function isRateLimitReply(response: AxiosResponse<string>): boolean {
  const headers = response.headers as Record<string, unknown>;
  return headers['x-ratelimit-remaining'] === '0' || headers['retry-after'] !== undefined;
}

function parseRelease(body: string, repository: string): FetchedRelease {
  let document: unknown;
  try {
    document = JSON.parse(body);
  } catch (error: unknown) {
    logger.warn('Release check answer is not JSON', { repository, error: errorMessage(error) });
    return UNAVAILABLE;
  }
  const parsed = githubReleaseSchema.safeParse(document);
  if (!parsed.success) {
    logger.warn('Release check answer is not a release document', { repository });
    return UNAVAILABLE;
  }
  const release = parsed.data;
  const version = release.tag_name.startsWith('v') ? release.tag_name.slice(1) : '';
  if (release.draft || release.prerelease || !isReleaseVersion(version)) {
    logger.warn('The latest release is not a release version this server can compare', {
      repository,
    });
    return UNAVAILABLE;
  }
  return { outcome: 'ok', version, publishedAt: readPublicationTime(release.published_at) };
}

/** Overrides for tests: the fetch options and the clock. */
export interface CheckOptions {
  fetch?: FetchOptions;
  now?: () => Date;
}

/**
 * Runs one check and records it, returning the stored state.
 *
 * A failed check records WHEN and HOW it failed and keeps the release a previous
 * check found; a check against a different repository than the stored one
 * discards that repository's findings first. The caller holds
 * {@link UPDATE_CHECK_LOCK_NAME}.
 */
export async function runUpdateCheck(options: CheckOptions = {}): Promise<IUpdateCheckState> {
  const repository = config.UPDATE_CHECK_REPOSITORY;
  const result = await fetchLatestRelease(repository, options.fetch);
  const now = options.now?.() ?? new Date();
  const previous = await UpdateCheckState.findById(UPDATE_CHECK_STATE_ID).lean();
  const sameRepository = previous?.repository === repository;

  const set: Record<string, unknown> = {
    repository,
    lastCheckedAt: now,
    lastCheckStatus: result.outcome,
  };
  const unset: Record<string, ''> = {};
  if (!sameRepository) {
    unset.notifiedVersion = '';
  }
  if (result.outcome === 'ok') {
    set.latestVersion = result.version;
    set.lastSuccessAt = now;
    if (result.publishedAt === null) {
      unset.latestPublishedAt = '';
    } else {
      set.latestPublishedAt = result.publishedAt;
    }
  } else if (result.outcome === 'no_release') {
    // A definite answer, so a success: nothing is published, hence nothing newer.
    set.lastSuccessAt = now;
    unset.latestVersion = '';
    unset.latestPublishedAt = '';
  } else if (!sameRepository) {
    unset.latestVersion = '';
    unset.latestPublishedAt = '';
    unset.lastSuccessAt = '';
  }

  const state = await UpdateCheckState.findOneAndUpdate(
    { _id: UPDATE_CHECK_STATE_ID },
    Object.keys(unset).length === 0 ? { $set: set } : { $set: set, $unset: unset },
    { upsert: true, returnDocument: 'after' },
  )
    .lean()
    .orFail();

  if (result.outcome === 'ok' && compareReleaseVersions(result.version, APP_VERSION) > 0) {
    logger.warn('A newer H-Vault release is available', {
      running: APP_VERSION,
      latest: result.version,
      releaseUrl: releaseUrlFor(result.version),
    });
  }
  return state;
}

/**
 * Emails the administrators once about a newer release, if there is one they
 * have not been told about.
 *
 * Sent only when `UPDATE_NOTIFY_EMAILS` lists someone and email is configured.
 * "Told about" is `notifiedVersion`, which moves FORWARD only: a release the
 * administrators were already told about, or an older one (a latest release that
 * was withdrawn), sends nothing. The claim is a conditional write on the value
 * just read, so two checks racing each other send once. If every address fails,
 * the claim is handed back so the next check tries again.
 */
export async function notifyAdministrators(state: IUpdateCheckState): Promise<void> {
  const latest = state.latestVersion;
  if (!isReleaseVersion(latest) || compareReleaseVersions(latest, APP_VERSION) <= 0) return;
  const recipients = config.UPDATE_NOTIFY_EMAILS;
  if (recipients.length === 0 || !isEmailConfigured()) return;
  const previous = state.notifiedVersion;
  if (isReleaseVersion(previous) && compareReleaseVersions(latest, previous) <= 0) return;

  // `null` in a filter matches a missing field AND one stored as null.
  const claim = await UpdateCheckState.updateOne(
    { _id: UPDATE_CHECK_STATE_ID, notifiedVersion: previous ?? null },
    { $set: { notifiedVersion: latest } },
  );
  if (claim.modifiedCount !== 1) return;

  const email = {
    current: APP_VERSION,
    latest,
    publishedAt: state.latestPublishedAt ?? null,
    releaseUrl: releaseUrlFor(latest),
  };
  let delivered = 0;
  for (const recipient of recipients) {
    if (await deliveredTo(recipient, email)) delivered += 1;
  }
  if (delivered > 0) {
    logger.info('Administrators told about a newer release', { latest, delivered });
    return;
  }
  await UpdateCheckState.updateOne(
    { _id: UPDATE_CHECK_STATE_ID, notifiedVersion: latest },
    previous === undefined
      ? { $unset: { notifiedVersion: '' } }
      : { $set: { notifiedVersion: previous } },
  );
  logger.warn('No administrator could be emailed about a newer release; the next check retries', {
    latest,
  });
}

/**
 * Whether one notification reached `recipient`. A send that THROWS is a failed
 * send like any other: letting it escape would skip handing the claim back, and
 * that release would never be emailed. (The error itself is not logged: it may
 * quote the address, and the summary warning above says what matters.)
 */
async function deliveredTo(
  recipient: string,
  email: Parameters<typeof sendUpdateAvailableEmail>[1],
): Promise<boolean> {
  try {
    return (await sendUpdateAvailableEmail(recipient, email)).success;
  } catch {
    return false;
  }
}

/**
 * Runs one check under the lock, then the email step. What the scheduled and
 * boot checks call. Returns whether it ran (false when another holder had the
 * lock). Never throws: a background job's failure is logged, not escalated.
 */
export async function performUpdateCheck(options: CheckOptions = {}): Promise<boolean> {
  let lockId: string | null = null;
  try {
    lockId = await acquireJobLock(UPDATE_CHECK_LOCK_NAME, UPDATE_CHECK_LOCK_TTL_MS);
    if (lockId === null) return false;
    const state = await runUpdateCheck(options);
    await notifyAdministrators(state);
    return true;
  } catch (error: unknown) {
    logger.error('Release check failed', { error: errorMessage(error) });
    return false;
  } finally {
    if (lockId !== null) await releaseUpdateCheckLock(lockId);
  }
}

async function releaseUpdateCheckLock(lockId: string): Promise<void> {
  try {
    await releaseJobLock(UPDATE_CHECK_LOCK_NAME, lockId);
  } catch (error: unknown) {
    logger.error('Could not release the release-check lock', { error: errorMessage(error) });
  }
}

/** The stored state, when it belongs to the configured repository. */
async function readState(): Promise<IUpdateCheckState | null> {
  const state = await UpdateCheckState.findById(UPDATE_CHECK_STATE_ID).lean();
  return state?.repository === config.UPDATE_CHECK_REPOSITORY ? state : null;
}

/**
 * What to tell the update audience, derived from the stored state.
 *
 * `current` needs a SUCCESSFUL check within `UPDATE_CHECK_FRESHNESS_MS`;
 * anything older, or no success at all, is `unknown`, however recently a check
 * FAILED. A known newer release is still reported under `unknown`, so the app
 * can say what it last knew and since when.
 */
export function deriveUpdateStatus(state: IUpdateCheckState | null, now: Date): UpdateStatus {
  if (!config.UPDATE_CHECK_ENABLED) {
    return {
      state: 'disabled',
      latestVersion: null,
      publishedAt: null,
      releaseUrl: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      canCheckNow: false,
    };
  }
  const latest = isReleaseVersion(state?.latestVersion) ? state.latestVersion : null;
  const lastSuccessAt = state?.lastSuccessAt ?? null;
  const fresh =
    lastSuccessAt !== null && now.getTime() - lastSuccessAt.getTime() <= UPDATE_CHECK_FRESHNESS_MS;
  let derived: UpdateState = 'unknown';
  if (fresh) {
    derived =
      latest !== null && compareReleaseVersions(latest, APP_VERSION) > 0 ? 'available' : 'current';
  }
  return {
    state: derived,
    latestVersion: latest,
    publishedAt: latest === null ? null : (state?.latestPublishedAt?.toISOString() ?? null),
    releaseUrl: latest === null ? null : releaseUrlFor(latest),
    lastCheckedAt: state?.lastCheckedAt.toISOString() ?? null,
    lastSuccessAt: lastSuccessAt?.toISOString() ?? null,
    canCheckNow: true,
  };
}

/** The update status for `GET /releases/status`. */
export async function readUpdateStatus(now: Date = new Date()): Promise<UpdateStatus> {
  return deriveUpdateStatus(config.UPDATE_CHECK_ENABLED ? await readState() : null, now);
}

/** Whether the last request to GitHub, of any outcome, is inside the "Check now" cooldown. */
function checkedRecently(state: IUpdateCheckState | null, now: Date): state is IUpdateCheckState {
  return (
    state !== null && now.getTime() - state.lastCheckedAt.getTime() < UPDATE_CHECK_MIN_INTERVAL_MS
  );
}

/**
 * "Check now", for `POST /releases/update-check`.
 *
 * Asks GitHub only when the last request of any outcome is older than
 * `UPDATE_CHECK_MIN_INTERVAL_MS` and no other check holds the lock; otherwise
 * it answers from the stored state (`fetched: false`). The email step runs
 * after the answer, so the request does not wait on mail delivery. The caller
 * has already refused the request when checks are turned off.
 */
export async function checkForUpdateNow(
  options: CheckOptions = {},
): Promise<{ update: UpdateStatus; fetched: boolean }> {
  const now = options.now?.() ?? new Date();
  const stored = await readState();
  if (checkedRecently(stored, now)) {
    return { update: deriveUpdateStatus(stored, now), fetched: false };
  }
  const lockId = await acquireJobLock(UPDATE_CHECK_LOCK_NAME, UPDATE_CHECK_LOCK_TTL_MS);
  if (lockId === null) {
    return { update: deriveUpdateStatus(stored, now), fetched: false };
  }
  try {
    // Read again under the lock: a check that finished while this request waited
    // for it has already asked, and the cooldown covers that request too.
    const current = await readState();
    if (checkedRecently(current, now)) {
      return { update: deriveUpdateStatus(current, now), fetched: false };
    }
    const state = await runUpdateCheck(options);
    trackJob(
      notifyAdministrators(state).catch((error: unknown) => {
        logger.error('Release notification failed', { error: errorMessage(error) });
      }),
    );
    return { update: deriveUpdateStatus(state, options.now?.() ?? new Date()), fetched: true };
  } finally {
    await releaseUpdateCheckLock(lockId);
  }
}
