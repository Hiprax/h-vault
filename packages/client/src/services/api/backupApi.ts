import type { AxiosResponse } from 'axios';
import type { IBackupLogEntry, PaginatedResponse } from '@hvault/shared';
import { api } from './client';

/**
 * The backup endpoints, as typed wrappers.
 *
 * DELIBERATELY INCOMPLETE, and this note is the record of that. Only the history
 * read lives here today; `/backup/setup`, `/backup/settings`, `/backup/trigger`,
 * `/backup/download`, `/backup/restore` and `/backup/change-password` are still
 * inline `api.*` calls inside `BackupSettingsPage`, with two more in
 * `SettingsPage`. They belong here too — `api-contract.test.ts` pins the exact
 * verb, URL and parameter shape for the modules in this directory against a
 * mirror of the real route table, and an inline call gets none of that — but
 * moving seven of them inside a pagination fix would be seven more blocks of
 * changed code to justify for no user-visible gain. Move them when you next have
 * a reason to touch one.
 *
 * The history read is here BECAUSE its inline form was the bug: it was typed as
 * `api.get<{ data: IBackupLogEntry[] }>`, a hand-written shape that simply
 * omitted `pagination` — so the compiler could never have pointed out that the
 * page was discarding it, and the section silently showed only its first page for
 * as long as it has existed.
 */
export interface BackupHistoryParams {
  page?: number;
  limit?: number;
}

export function getBackupHistoryApi(
  params?: BackupHistoryParams,
): Promise<AxiosResponse<PaginatedResponse<IBackupLogEntry>>> {
  return api.get('/backup/history', { params });
}
