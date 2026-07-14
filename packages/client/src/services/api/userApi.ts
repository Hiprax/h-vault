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

export function exportVaultApi(
  data?: ExportInput,
): Promise<AxiosResponse<ApiResponse<ExportResponse>>> {
  return api.post('/tools/export', data);
}

export function importVaultApi(
  data: ImportInput,
): Promise<AxiosResponse<ApiResponse<{ importedCount: number; skippedCount: number }>>> {
  return api.post('/tools/import', data);
}
