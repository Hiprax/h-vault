/**
 * The small release endpoints the app shell calls on every visit: the running
 * version with the caller's release-notes state, acknowledging the notes, and the
 * administrators' "Check now". The notes themselves are fetched by
 * `releaseNotesApi.ts`, which only the lazily loaded dialog and About page import,
 * so their schema stays out of the initial bundle.
 *
 * Every response is PARSED, not cast: this module feeds a badge that is always on
 * screen, and a malformed answer must become "nothing to show" rather than a
 * crash in the shell.
 */

import {
  releaseNotesSeenResponseSchema,
  releaseStatusResponseSchema,
  updateCheckResponseSchema,
  type ReleaseNotesSeen,
  type ReleaseStatus,
  type UpdateCheckResult,
} from '@hvault/shared';
import { api } from './client.js';

export async function getReleaseStatusApi(): Promise<ReleaseStatus> {
  const res = await api.get('/releases/status');
  return releaseStatusResponseSchema.parse(res.data).data;
}

export async function markReleaseNotesSeenApi(version: string): Promise<ReleaseNotesSeen> {
  const res = await api.post('/releases/seen', { version });
  return releaseNotesSeenResponseSchema.parse(res.data).data;
}

export async function checkForUpdateNowApi(): Promise<UpdateCheckResult> {
  const res = await api.post('/releases/update-check');
  return updateCheckResponseSchema.parse(res.data).data;
}
