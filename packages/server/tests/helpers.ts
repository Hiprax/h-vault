import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import type request from 'supertest';
import { User } from '../src/models/User.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { Folder } from '../src/models/Folder.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { hashToken, derivePurposeKey } from '../src/utils/token.js';

export const JWT_SECRET =
  process.env['JWT_ACCESS_SECRET'] ?? 'test-access-secret-for-testing-only-32chars!';
/** Secret used for purpose-specific JWTs (email verification, password reset, 2FA temp, account unlock). */
export const JWT_PURPOSE_SECRET =
  process.env['JWT_REFRESH_SECRET'] ?? 'test-refresh-secret-for-testing-only-32chars!';

/**
 * Derives a purpose-specific signing key from the base secret.
 * Mirrors the production derivePurposeKey logic for use in tests.
 */
export function deriveTestPurposeKey(purpose: string): string {
  return derivePurposeKey(JWT_PURPOSE_SECRET, purpose);
}
const BCRYPT_ROUNDS = 4;

export interface TestUser {
  id: string;
  email: string;
  authHash: string;
  rawPassword: string;
  accessToken: string;
  refreshToken: string;
}

/**
 * Creates a test user in the database and returns auth tokens.
 */
export async function createTestUser(
  overrides: Partial<{
    email: string;
    password: string;
    emailVerified: boolean;
    twoFactorEnabled: boolean;
  }> = {},
): Promise<TestUser> {
  const email = overrides.email ?? `test-${crypto.randomUUID()}@example.com`;
  const rawPassword = overrides.password ?? 'test-auth-hash-value';
  const authHash = await bcrypt.hash(rawPassword, BCRYPT_ROUNDS);

  const user = await User.create({
    email,
    authHash,
    emailVerified: overrides.emailVerified ?? true,
    encryptedVaultKey: 'test-encrypted-vault-key',
    vaultKeyIv: 'test-vault-key-iv',
    vaultKeyTag: 'test-vault-key-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    twoFactorEnabled: overrides.twoFactorEnabled ?? false,
  });

  const userId = user._id.toString();
  const accessToken = jwt.sign({ userId }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: userId,
    expiresIn: '15m',
  });

  // Create a refresh token
  const refreshTokenRaw = crypto.randomBytes(64).toString('hex');
  const refreshTokenHash = hashToken(refreshTokenRaw);
  const familyId = crypto.randomUUID();

  await RefreshToken.create({
    userId: user._id,
    tokenHash: refreshTokenHash,
    familyId,
    deviceInfo: {
      userAgent: 'test-agent',
      ip: '127.0.0.1',
      fingerprint: 'test-fingerprint',
    },
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  return {
    id: userId,
    email,
    authHash: rawPassword,
    rawPassword,
    accessToken,
    refreshToken: refreshTokenRaw,
  };
}

/**
 * Generates a SHA-256 state hash for JWT token binding (mirrors authController.generateStateHash).
 */
export function generateStateHash(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Generates a valid access token for a given user ID.
 */
export function generateAccessToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: userId,
    expiresIn: '15m',
  });
}

/**
 * Generates an expired access token for testing.
 */
export function generateExpiredToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, { algorithm: 'HS256', subject: userId, expiresIn: '0s' });
}

/**
 * Returns authorization header value.
 */
export function authHeader(token: string): string {
  return `Bearer ${token}`;
}

/**
 * Sample vault item data for creating test items.
 */
export function sampleVaultItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    itemType: 'login',
    encryptedData: 'test-encrypted-data-base64',
    dataIv: 'test-data-iv',
    dataTag: 'test-data-tag',
    encryptedName: 'test-encrypted-name',
    nameIv: 'test-name-iv',
    nameTag: 'test-name-tag',
    tags: [],
    favorite: false,
    ...overrides,
  };
}

/**
 * Sample folder data for creating test folders.
 */
export function sampleFolder(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    encryptedName: 'test-encrypted-folder-name',
    nameIv: 'test-folder-name-iv',
    nameTag: 'test-folder-name-tag',
    ...overrides,
  };
}

export interface CsrfPair {
  token: string;
  cookie: string;
}

/**
 * Fetches a real CSRF token from the server and extracts the cookie + header
 * values needed for state-changing requests (POST, PUT, DELETE).
 *
 * Optionally accepts `extraCookies` to include additional cookies (e.g. a
 * refresh token cookie) alongside the CSRF cookie on the initial request.
 */
export async function getCsrf(agent: request.Agent, extraCookies?: string): Promise<CsrfPair> {
  const req = agent.get('/api/v1/csrf-token');
  if (extraCookies) {
    req.set('Cookie', extraCookies);
  }
  const res = await req;
  const token: string = res.body.data.csrfToken;

  const setCookieHeader = res.headers['set-cookie'] as string | string[] | undefined;
  const cookies = Array.isArray(setCookieHeader)
    ? setCookieHeader
    : setCookieHeader
      ? [setCookieHeader]
      : [];
  const csrfCookie = cookies.find((c: string) => c.startsWith('__csrf='));
  const cookie = csrfCookie ? csrfCookie.split(';')[0]! : '';

  return { token, cookie };
}

// ── Direct-DB seeding + read helpers (used by cross-account restore tests) ──

/**
 * Seeds a folder directly in the DB for a user. `overrides` may include an
 * explicit `_id`, `parentId`, `searchHash`, `encryptedName`, etc. Returns the
 * created document as a plain object (with its real `_id`).
 */
export async function seedFolder(
  userId: string,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const folder = await Folder.create({ userId, ...sampleFolder(overrides) });
  return folder.toObject() as unknown as Record<string, unknown>;
}

/**
 * Seeds a vault item directly in the DB for a user. `overrides` may include an
 * explicit `_id`, `folderId`, `deletedAt`, `encryptedName`, etc. Returns the
 * created document as a plain object (with its real `_id`).
 */
export async function seedItem(
  userId: string,
  overrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
  const item = await VaultItem.create({ userId, ...sampleVaultItem(overrides) });
  return item.toObject() as unknown as Record<string, unknown>;
}

/**
 * Reads a user's live folders and non-trashed items straight from the DB with
 * their `_id`/`parentId`/`folderId` intact — reproducing exactly what the
 * backup download endpoint emits and what the real client forwards verbatim to
 * `POST /backup/restore`. Use this to build a cross-account restore payload.
 */
export async function dbBackupPayload(
  userId: string,
): Promise<{ items: Record<string, unknown>[]; folders: Record<string, unknown>[] }> {
  const folders = await Folder.find({ userId }).lean();
  const items = await VaultItem.find({ userId, deletedAt: { $exists: false } }).lean();
  return {
    items: items as unknown as Record<string, unknown>[],
    folders: folders as unknown as Record<string, unknown>[],
  };
}

/** Reads all folders for a user (lean), for per-user DB assertions. */
export async function rawFolders(userId: string): Promise<Record<string, unknown>[]> {
  return (await Folder.find({ userId }).lean()) as unknown as Record<string, unknown>[];
}

/** Reads all items (including trashed) for a user (lean), for per-user DB assertions. */
export async function rawItems(userId: string): Promise<Record<string, unknown>[]> {
  return (await VaultItem.find({ userId }).lean()) as unknown as Record<string, unknown>[];
}

/** Collects the stringified `_id`s of a list of docs into a Set. */
export function idSet(docs: { _id: unknown }[]): Set<string> {
  return new Set(docs.map((d) => String(d._id)));
}
