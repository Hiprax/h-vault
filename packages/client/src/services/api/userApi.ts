/**
 * User, Settings, Tools & Session API service.
 *
 * All endpoints are relative to the Axios base URL (/api/v1).
 */

import type { AxiosResponse } from 'axios';
import type {
  ApiResponse,
  PaginatedResponse,
  IUserProfile,
  ISessionInfo,
  ITrustedDeviceInfo,
  IAuditLogEntry,
  TwoFactorSetupResponse,
  UpdateSettingsInput,
  ChangePasswordInput,
  ExportInput,
  ExportResponse,
  ImportInput,
} from '@hvault/shared';
import { api } from './client.js';

// ---------------------------------------------------------------------------
// Query parameter types
// ---------------------------------------------------------------------------

export interface AuditLogParams {
  page?: number;
  limit?: number;
  action?: string;
}

// ---------------------------------------------------------------------------
// Profile & Settings
// ---------------------------------------------------------------------------

export function getProfileApi(): Promise<AxiosResponse<ApiResponse<IUserProfile>>> {
  return api.get('/user/profile');
}

export function updateSettingsApi(
  data: UpdateSettingsInput,
): Promise<AxiosResponse<ApiResponse<IUserProfile>>> {
  return api.put('/user/settings', data);
}

export function changePasswordApi(
  data: ChangePasswordInput,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.put('/user/change-password', data);
}

// ---------------------------------------------------------------------------
// Two-Factor Authentication
// ---------------------------------------------------------------------------

export function setup2faApi(data: {
  password: string;
}): Promise<AxiosResponse<ApiResponse<TwoFactorSetupResponse>>> {
  return api.post('/user/2fa/setup', data);
}

export function verify2faApi(data: {
  code: string;
}): Promise<AxiosResponse<ApiResponse<{ backupCodes: string[] }>>> {
  return api.post('/user/2fa/verify', data);
}

export function disable2faApi(data: {
  code: string;
  password: string;
}): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete('/user/2fa', { data });
}

export function regenerateBackupCodesApi(data: {
  password: string;
  code?: string;
}): Promise<AxiosResponse<ApiResponse<{ backupCodes: string[] }>>> {
  return api.post('/user/2fa/regenerate-backup-codes', data);
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export function listSessionsApi(): Promise<AxiosResponse<ApiResponse<ISessionInfo[]>>> {
  return api.get('/user/sessions');
}

export function revokeSessionApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/user/sessions/${id}`);
}

// ---------------------------------------------------------------------------
// Trusted Devices
// ---------------------------------------------------------------------------

export function listTrustedDevicesApi(): Promise<AxiosResponse<ApiResponse<ITrustedDeviceInfo[]>>> {
  return api.get('/user/trusted-devices');
}

export function revokeTrustedDeviceApi(id: string): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete(`/user/trusted-devices/${id}`);
}

export function revokeAllTrustedDevicesApi(): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.delete('/user/trusted-devices');
}

// ---------------------------------------------------------------------------
// Audit Log
// ---------------------------------------------------------------------------

export function getAuditLogApi(
  params?: AuditLogParams,
): Promise<AxiosResponse<PaginatedResponse<IAuditLogEntry>>> {
  return api.get('/user/audit-log', { params });
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export function checkBreachApi(hashPrefix: string): Promise<AxiosResponse<ApiResponse<string>>> {
  return api.post('/tools/check-password-breach', { hashPrefix });
}

/**
 * Server envelope for the batched breach check. `data` maps each 5-char hash
 * prefix to its raw HIBP range text; `errors` lists prefixes whose upstream
 * lookup failed (reported explicitly so the client marks those passwords
 * not-checked rather than not-breached).
 */
export interface BreachBatchResponse {
  success: boolean;
  data: Record<string, string>;
  errors: string[];
}

/**
 * Check several password hash prefixes in one request (k-anonymity: only the
 * first 5 hex chars of each SHA-1 hash are sent; the client deduplicates first).
 * Accepts an optional AbortSignal so an in-flight scan can be cancelled.
 */
export function checkBreachBatchApi(
  hashPrefixes: string[],
  signal?: AbortSignal,
): Promise<AxiosResponse<BreachBatchResponse>> {
  if (signal) {
    return api.post('/tools/check-password-breach/batch', { hashPrefixes }, { signal });
  }
  return api.post('/tools/check-password-breach/batch', { hashPrefixes });
}

export function exportVaultApi(
  data?: ExportInput,
): Promise<AxiosResponse<ApiResponse<ExportResponse>>> {
  return api.post('/tools/export', data);
}

/**
 * Execute one batch of resolved import operations.
 *
 * The server is a validated EXECUTOR, not a matcher: conflict resolution ran
 * client-side (the match key lives inside the encrypted blob, so the server
 * cannot compute it), and this request carries explicit `inserts` and `updates`
 * with each update naming the `_id` it targets. The response therefore reports
 * only what the server itself did — `insertedCount` / `updatedCount`; every
 * other outcome (duplicates skipped, intra-file duplicates, unconvertible rows)
 * is known only to the client and is accounted for there.
 *
 * A large import is split into several of these requests by
 * `chunkImportOperations`; batching is transport only and cannot change the
 * outcome.
 */
export function importVaultApi(
  data: ImportInput,
): Promise<AxiosResponse<ApiResponse<{ insertedCount: number; updatedCount: number }>>> {
  return api.post('/tools/import', data);
}
