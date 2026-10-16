/**
 * A tenant write whose account is gone, or being erased, is a dead session (I-08).
 *
 * Passport proves the account exists on every authenticated request, but a request
 * that passed that check a moment before the account was erased is still in
 * flight, and the two guards every ciphertext-creating write reads first,
 * `assertVaultNotRotating` and `assertVaultKeyVersion`, used to read a missing
 * user as "not rotating" and "generation 0": the write then went ahead and stored
 * a row for an account that no longer existed, which no erasure would ever find
 * again. Both guards now answer such a request exactly as Passport answers a dead
 * session, 401, and they treat an account marked `deletionPending` (the erasure's
 * first write) the same way, since every row written after that mark is one the
 * erasure has to catch.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import { DOCUMENT_PLAINTEXT_CHUNK_BYTES } from '@hvault/shared';

vi.mock('../src/config/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/config/index.js')>();
  return { ...actual, storageConfigured: true };
});

const { storageRef } = vi.hoisted(() => ({
  storageRef: { current: undefined as ReturnType<typeof createInMemoryStorage> | undefined },
}));

vi.mock('../src/services/storage/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/storage/index.js')>();
  return { ...actual, getStorage: () => storageRef.current! };
});

import app from '../src/app.js';
import { DocumentUpload } from '../src/models/DocumentUpload.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { User } from '../src/models/User.js';
import { Folder } from '../src/models/Folder.js';
import { assertVaultKeyVersion, assertVaultNotRotating } from '../src/utils/controllerHelpers.js';
import { authHeader, createTestUser, getCsrf, sampleFolder, type TestUser } from './helpers.js';

const ABSENT_ID = '507f1f77bcf86cd799439011';

beforeEach(() => {
  storageRef.current = createInMemoryStorage();
});

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Lets the NEXT `User.findById` (Passport's, at the start of the request) see the
 * account, then erases the account before the handler runs: the window of a
 * request that authenticated a moment before the erasure.
 */
function eraseAccountAfterAuthentication(user: TestUser): void {
  const original = User.findById.bind(User);
  vi.spyOn(User, 'findById').mockImplementationOnce(((...args: Parameters<typeof original>) => {
    const query = original(...args);
    const exec = query.exec.bind(query);
    query.exec = (async () => {
      const result = await exec();
      await mongoose.connection
        .collection('users')
        .deleteOne({ _id: new mongoose.Types.ObjectId(user.id) });
      return result;
    }) as typeof query.exec;
    return query;
  }) as typeof User.findById);
}

describe('I-08: a write for an account erased mid-request', () => {
  it('opens no document transfer for it: 401, no staging row, no engine upload (it used to answer 201)', async () => {
    const user = await createTestUser({ emailVerified: true });
    const agent = request(app);
    const csrf = await getCsrf(agent);
    eraseAccountAfterAuthentication(user);

    const res = await agent
      .post('/api/v1/documents/uploads')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        encryptedDek: 'ZGVrLWNpcGhlcnRleHQtYmFzZTY0',
        dekIv: 'ZGVrLWl2LWJhc2U2NA==',
        dekTag: 'ZGVrLXRhZy1iYXNlNjQ=',
        streamSalt: Buffer.alloc(32, 7).toString('base64'),
        noncePrefix: Buffer.alloc(7, 3).toString('base64'),
        // Two segments, so a transfer that opened would also have opened an
        // engine-side multipart upload: the negative below can then fail.
        declaredPlaintextBytes: DOCUMENT_PLAINTEXT_CHUNK_BYTES + 1,
        declaredChunkCount: 2,
      });

    expect(res.status, JSON.stringify(res.body)).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
    expect(await DocumentUpload.countDocuments({ userId: user.id })).toBe(0);
    expect(await storageRef.current!.listMultipartUploads()).toEqual([]);
  });

  it('creates no folder for it either, and says so as a dead session', async () => {
    const user = await createTestUser({ emailVerified: true });
    const agent = request(app);
    const csrf = await getCsrf(agent);
    eraseAccountAfterAuthentication(user);

    const res = await agent
      .post('/api/v1/folders')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send(sampleFolder());

    expect(res.status, JSON.stringify(res.body)).toBe(401);
    expect(res.body.message).toBe('Invalid or expired token');
    expect(await Folder.countDocuments({ userId: user.id })).toBe(0);
    expect(await User.exists({ _id: user.id })).toBeNull();
  });
});

describe('I-08: assertVaultNotRotating', () => {
  it('answers 401 for an id with no account behind it', async () => {
    await expect(assertVaultNotRotating(ABSENT_ID)).rejects.toMatchObject({
      statusCode: 401,
      message: 'Invalid or expired token',
    });
  });

  it('answers 401 for an account being erased', async () => {
    const user = await createTestUser({ emailVerified: true });
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    await expect(assertVaultNotRotating(user.id)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('still lets a live account through, and still answers 409 while it rotates', async () => {
    const user = await createTestUser({ emailVerified: true });
    await expect(assertVaultNotRotating(user.id)).resolves.toBeUndefined();

    await User.updateOne({ _id: user.id }, { $set: { rotationInProgress: true } });
    await expect(assertVaultNotRotating(user.id)).rejects.toMatchObject({ statusCode: 409 });
  });
});

describe('I-08: assertVaultKeyVersion', () => {
  it('answers 401 for an id with no account behind it, whatever generation is claimed', async () => {
    for (const supplied of [undefined, 0, 1]) {
      await expect(assertVaultKeyVersion(ABSENT_ID, supplied)).rejects.toMatchObject({
        statusCode: 401,
        message: 'Invalid or expired token',
      });
    }
    // No row invented by the read.
    expect(await User.exists({ _id: ABSENT_ID })).toBeNull();
  });

  it('answers 401 for an account being erased', async () => {
    const user = await createTestUser({ emailVerified: true });
    await User.updateOne({ _id: user.id }, { $set: { deletionPending: true } });

    await expect(assertVaultKeyVersion(user.id, 0)).rejects.toMatchObject({ statusCode: 401 });
  });

  it('still resolves a live account at generation 0', async () => {
    const user = await createTestUser({ emailVerified: true });
    await expect(assertVaultKeyVersion(user.id, 0)).resolves.toBe(0);
  });
});
