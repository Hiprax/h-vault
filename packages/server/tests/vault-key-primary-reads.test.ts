/**
 * Every read that decides a vault-key write, or hands a session the wrapper it
 * derives its key from, is read from the PRIMARY.
 *
 * A deployment whose connection string prefers secondaries would otherwise answer
 * these from a node that has not yet seen a rotation's commit: the fence as
 * lowered, the superseded generation as current, the pre-rotation wrapper as live,
 * or a rotation as not committed when its rollback is deciding whether to run.
 * Each read is identified by the projection it selects (`support/primaryReads.ts`),
 * so removing any single `.read('primary')` turns its assertion red. The two-factor
 * sign-in, the document uploads and the stale-generation diagnoses are held in the
 * suites that already drive those paths.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../src/app.js';
import { createTestUser, getCsrf, sampleVaultItem } from './helpers.js';
import { apiCall, createQuotaItem } from './support/vaultQuotaApi.js';
import { expectReadFromPrimary, recordReads } from './support/primaryReads.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** A rotation payload re-sealing exactly `ids`. */
function rotationOf(
  user: { rawPassword: string },
  ids: string[],
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    authHash: user.rawPassword,
    items: ids.map((id) => ({
      id,
      encryptedName: 'rotated-name',
      nameIv: `rot-name-iv-${id.slice(-4)}`,
      nameTag: 'rot-name-tag',
      encryptedData: 'rotated-data',
      dataIv: `rot-data-iv-${id.slice(-4)}`,
      dataTag: 'rot-data-tag',
    })),
    folders: [],
    documents: [],
    newEncryptedVaultKey: 'rotated-wrapper',
    newVaultKeyIv: 'rotated-wrapper-iv',
    newVaultKeyTag: 'rotated-wrapper-tag',
    vaultKeyVersion: 0,
    vaultFieldFormat: 2,
    ...extra,
  };
}

describe('the vault-key guards read from the primary', () => {
  it('reads the fence, the generation, and both again after the insert, on an item create', async () => {
    const user = await createTestUser();
    const reads = recordReads();

    const res = await apiCall(
      user,
      'post',
      '/vault/items',
      sampleVaultItem({ vaultKeyVersion: 0 }),
    );

    expect(res.status).toBe(201);
    expectReadFromPrimary(reads, 'User', 'rotationInProgress deletionPending');
    expectReadFromPrimary(reads, 'User', 'vaultKeyVersion deletionPending');
    expectReadFromPrimary(reads, 'User', 'rotationInProgress vaultKeyVersion deletionPending');
  });

  it('reads both again after the measure on an item update', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 50);
    const reads = recordReads();

    const res = await apiCall(user, 'put', `/vault/items/${id}`, {
      encryptedData: 'edited',
      dataIv: 'edited-iv',
      dataTag: 'edited-tag',
      vaultKeyVersion: 0,
    });

    expect(res.status).toBe(200);
    expectReadFromPrimary(reads, 'User', 'rotationInProgress vaultKeyVersion deletionPending');
  });
});

describe('a rotation reads the account and its snapshots from the primary', () => {
  it('reads the credential, the idempotency key, the wrapper, the generation and the outstanding wrapper', async () => {
    const user = await createTestUser();
    const id = await createQuotaItem(user, 50);
    const reads = recordReads();

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, [id], { idempotencyKey: '00000000-0000-4000-8000-000000000099' }),
    );

    expect(res.status).toBe(200);
    expectReadFromPrimary(reads, 'User', '+authHash');
    expectReadFromPrimary(reads, 'User', 'lastRotationKey');
    expectReadFromPrimary(reads, 'User', 'encryptedVaultKey vaultKeyIv vaultKeyTag');
    expectReadFromPrimary(reads, 'User', 'vaultKeyVersion deletionPending');
    expectReadFromPrimary(reads, 'User', 'pendingEncryptedVaultKey');
    expectReadFromPrimary(reads, 'Document', '_id encryptedDek dekIv dekTag');
  });

  it('asks the primary whether a failed rotation committed before rolling it back', async () => {
    const user = await createTestUser();
    const a = await createQuotaItem(user, 50);
    const b = await createQuotaItem(user, 50);
    // The rotation's write of the SECOND row is refused, so the first is rolled
    // back, and the rollback first asks whether the commit landed.
    const real = mongoose.mongo.Collection.prototype.updateOne;
    let rotationWrites = 0;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'updateOne').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      const update = args[1] as { $set?: { encryptedName?: unknown } };
      if (this.collectionName === 'vault_items' && update.$set?.encryptedName === 'rotated-name') {
        rotationWrites += 1;
        if (rotationWrites === 2) {
          return Promise.reject(
            new mongoose.mongo.MongoServerError({
              message: 'Document failed validation',
              code: 121,
            }),
          );
        }
      }
      return real.apply(this, args);
    } as never);
    const reads = recordReads();

    const res = await apiCall(
      user,
      'post',
      '/vault/items/bulk-reencrypt',
      rotationOf(user, [a, b]),
    );

    expect(res.status).toBe(409);
    expect(rotationWrites).toBe(2);
    expectReadFromPrimary(reads, 'User', 'encryptedVaultKey');
  });
});

describe('a master-password change reads the account from the primary', () => {
  it('reads the credential and the outstanding wrapper from the primary', async () => {
    const user = await createTestUser();
    const reads = recordReads();

    const res = await apiCall(user, 'put', '/user/change-password', {
      currentAuthHash: user.rawPassword,
      newAuthHash: 'a-brand-new-auth-hash',
      newEncryptedVaultKey: 'rewrapped-under-the-new-password',
      newVaultKeyIv: 'rewrap-iv',
      newVaultKeyTag: 'rewrap-tag',
      vaultKeyVersion: 0,
    });

    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expectReadFromPrimary(reads, 'User', '+authHash');
    expectReadFromPrimary(reads, 'User', 'pendingEncryptedVaultKey');
  });
});

describe('sign-in reads the account it hands a wrapper from from the primary', () => {
  it('reads the account by address from the primary', async () => {
    const user = await createTestUser();
    const reads = recordReads();
    const agent = request(app);
    const csrf = await getCsrf(agent);

    const res = await agent
      .post('/api/v1/auth/login')
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ email: user.email, authHash: user.authHash });

    expect(res.status).toBe(200);
    expectReadFromPrimary(
      reads,
      'User',
      '+authHash +twoFactorSecret +backupCodes +secondFactorLockout',
    );
  });
});
