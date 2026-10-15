/**
 * Request helpers for the vault byte quota suites (F-24): drive the API as an
 * account would, and hold the counter to the database's own total
 * (`vaultBytes.ts`) rather than to anything the implementation computes.
 */
import { expect } from 'vitest';
import request from 'supertest';
import app from '../../src/app.js';
import { config } from '../../src/config/index.js';
import { authHeader, getCsrf, sampleVaultItem, type TestUser } from '../helpers.js';
import { rowCounters, storedRowCounts, storedVaultBytes, vaultBytesCounter } from './vaultBytes.js';

const API = '/api/v1';
const MB = 1024 * 1024;
const mutableConfig = config as unknown as Record<string, unknown>;

type Method = 'get' | 'post' | 'put' | 'delete';

/** One authenticated, CSRF-carrying request as `user`. */
export async function apiCall(
  user: TestUser,
  method: Method,
  path: string,
  body?: Record<string, unknown>,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  const req = agent[method](`${API}${path}`)
    .set('Authorization', authHeader(user.accessToken))
    .set('Cookie', csrf.cookie)
    .set('x-csrf-token', csrf.token);
  return body === undefined ? req : req.send(body);
}

/** An item create body whose ciphertext is `dataBytes` characters long. */
export function quotaItemBody(
  dataBytes: number,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return sampleVaultItem({ encryptedData: 'd'.repeat(dataBytes), ...extra });
}

/** Creates an item through the API and returns its id. */
export async function createQuotaItem(
  user: TestUser,
  dataBytes: number,
  extra: Record<string, unknown> = {},
): Promise<string> {
  const res = await apiCall(user, 'post', '/vault/items', quotaItemBody(dataBytes, extra));
  expect(res.status).toBe(201);
  return String(res.body.data._id);
}

/** Moves an item to the trash through the API. */
export async function trashQuotaItem(user: TestUser, id: string): Promise<void> {
  expect((await apiCall(user, 'delete', `/vault/items/${id}`)).status).toBe(200);
}

/**
 * Asserts the counters equal what the database says the account stores, and
 * returns the bytes: the byte counter, and (F-15) the two row counters behind
 * the per-user caps, which every reservation installs together with it. A
 * path that wrote or removed rows without counting them fails here as surely as
 * one that miscounted bytes.
 */
export async function expectCounterExact(user: TestUser): Promise<number> {
  const stored = await storedVaultBytes(user.id);
  expect(await vaultBytesCounter(user.id)).toBe(stored);
  expect(await rowCounters(user.id)).toEqual(await storedRowCounts(user.id));
  return stored;
}

/** Sets the quota, in bytes, for the rest of the test (`restoreQuota` puts it back). */
export function setQuotaBytes(bytes: number): void {
  mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER = bytes / MB;
}

/** The configured quota, to hand back to {@link restoreQuota}. */
export function savedQuota(): unknown {
  return mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER;
}

/** Restores the quota {@link savedQuota} returned. */
export function restoreQuota(value: unknown): void {
  mutableConfig.VAULT_STORAGE_QUOTA_MB_PER_USER = value;
}
