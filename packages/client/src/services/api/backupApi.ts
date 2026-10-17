import type { AxiosResponse } from 'axios';
import type {
  ApiResponse,
  IBackupLogEntry,
  IBackupRecipient,
  PaginatedResponse,
} from '@hvault/shared';
import { api } from './client';

/**
 * The backup endpoints, as typed wrappers.
 *
 * DELIBERATELY INCOMPLETE, and this note is the record of that. The history read
 * and the two recipient calls live here; `/backup/setup`, `/backup/settings`, `/backup/trigger`,
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

/** What `PUT /backup/recipients` answers with. */
export interface BackupRecipientsResult {
  recipients: IBackupRecipient[];
  /** Confirmation emails sent by this request. */
  confirmationsSent: number;
  /** Confirmations still owed (the daily email limit, or the mail relay); the server sends them later. */
  confirmationsPending: number;
}

/**
 * Replaces where mailed backups go. `authHash` is the master-password proof the
 * server requires for this change; every address other than the account's own is
 * stored unconfirmed and is emailed a confirmation link.
 */
export function updateBackupRecipientsApi(data: {
  authHash: string;
  backupEmails: string[];
}): Promise<AxiosResponse<ApiResponse<BackupRecipientsResult>>> {
  return api.put('/backup/recipients', data);
}

/** A recipient confirming its address with the token from its link. Needs no session. */
export function confirmBackupRecipientApi(data: {
  token: string;
}): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/backup/recipients/confirm', data);
}
