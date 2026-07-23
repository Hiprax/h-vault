/**
 * Authentication API service.
 *
 * All endpoints are relative to the base URL configured on the Axios instance
 * (/api/v1), so paths here start from /auth/...
 */

import type { AxiosResponse } from 'axios';
import type {
  ApiResponse,
  LoginResponse,
  SuccessfulLoginResponse,
  RegisterResponse,
  EmailStatusResponse,
} from '@hvault/shared';
import { api, withRefreshLock } from './client.js';

// ---------------------------------------------------------------------------
// Request payload types
// ---------------------------------------------------------------------------

export interface RegisterPayload {
  email: string;
  authHash: string;
  encryptedVaultKey: string;
  vaultKeyIv: string;
  vaultKeyTag: string;
  kdfIterations: number;
  kdfAlgorithm: string;
  encryptionVersion: number;
}

export interface LoginPayload {
  email: string;
  authHash: string;
  // Hand-mirrored from the shared `loginSchema` (`rememberMe: z.boolean().default(false)`).
  // Optional on the wire because the server defaults an absent field to false;
  // the UI always sends it explicitly. Carried into the signed 2FA temp token
  // server-side, so it can never be injected at the 2FA step.
  rememberMe?: boolean;
  deviceInfo?: {
    userAgent: string;
    fingerprint: string;
  };
}

export interface Login2faPayload {
  tempToken: string;
  code: string;
  deviceInfo?: {
    userAgent: string;
    fingerprint: string;
  };
}

export interface VerifyEmailPayload {
  token: string;
}

export interface ForgotPasswordPayload {
  email: string;
}

export interface ResetPasswordPayload {
  token: string;
  email: string;
  newAuthHash: string;
  newEncryptedVaultKey: string;
  newVaultKeyIv: string;
  newVaultKeyTag: string;
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

export function registerApi(
  data: RegisterPayload,
): Promise<AxiosResponse<ApiResponse<RegisterResponse>>> {
  return api.post('/auth/register', data);
}

export function loginApi(data: LoginPayload): Promise<AxiosResponse<ApiResponse<LoginResponse>>> {
  return api.post('/auth/login', data);
}

export function login2faApi(
  data: Login2faPayload,
): Promise<AxiosResponse<ApiResponse<SuccessfulLoginResponse>>> {
  return api.post('/auth/login/2fa', data);
}

export function refreshTokenApi(): Promise<AxiosResponse<ApiResponse<{ accessToken: string }>>> {
  // Held under the cross-tab refresh lock: this POST rotates the refresh-token
  // cookie that every tab of the origin shares, and a sibling presenting the
  // same pre-rotation token would trip the server's reuse detection and revoke
  // the whole token family. Every refresh call site must take the lock.
  return withRefreshLock(() => api.post('/auth/refresh'));
}

/**
 * Revoke the current session server-side.
 *
 * @param timeoutMs Optional per-call timeout (ms). Bounds how long the caller
 *   blocks on this best-effort request so a stalled/black-holed connection
 *   cannot delay local session teardown indefinitely. A per-call timeout is
 *   used deliberately instead of a global Axios timeout, which would risk
 *   aborting the legitimately-long backup-restore / vault-key-rotation calls.
 */
export function logoutApi(timeoutMs?: number): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/logout', undefined, timeoutMs !== undefined ? { timeout: timeoutMs } : {});
}

/**
 * Record a `vault_lock` audit entry server-side (session stays alive).
 *
 * @param timeoutMs Optional per-call timeout (ms) — see {@link logoutApi}.
 */
export function lockApi(timeoutMs?: number): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/lock', undefined, timeoutMs !== undefined ? { timeout: timeoutMs } : {});
}

export function logoutAllApi(): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/logout-all');
}

export function verifyEmailApi(
  data: VerifyEmailPayload,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/verify-email', data);
}

export function forgotPasswordApi(
  data: ForgotPasswordPayload,
): Promise<AxiosResponse<ApiResponse<EmailStatusResponse>>> {
  return api.post('/auth/forgot-password', data);
}

export function resetPasswordApi(
  data: ResetPasswordPayload,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/reset-password', data);
}

export interface UnlockAccountPayload {
  token: string;
}

export function unlockAccountApi(
  data: UnlockAccountPayload,
): Promise<AxiosResponse<ApiResponse<null>>> {
  return api.post('/auth/unlock-account', data);
}
