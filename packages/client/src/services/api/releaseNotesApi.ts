/**
 * The release notes. Imported only by the lazily loaded dialog and About page, so
 * the notes schema never reaches the initial bundle.
 */

import { releaseNotesResponseSchema, type ReleaseNotesList } from '@hvault/shared';
import { api } from './client.js';

export async function getReleaseNotesApi(): Promise<ReleaseNotesList> {
  const res = await api.get('/releases/notes');
  return releaseNotesResponseSchema.parse(res.data).data;
}
