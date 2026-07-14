import { describe, it, expect, vi, beforeEach } from 'vitest';
import crypto from 'node:crypto';
import mongoose from 'mongoose';

/**
 * Phase 5 / #9 — the zombie-user cleanup in `tokenCleanup` must never clear
 * `deletionPending` before the erasure it guards is durable.
 *
 * `deletionPending` is the ONLY durable record that a user's data still needs
 * erasing. The loop used to "claim" each zombie by flipping the flag to false
 * before calling the cascade; a hard crash between that claim and a committed
 * cascade left the user with `deletionPending: false` and their vault data
 * intact — invisible to every future cleanup cycle (a GDPR erasure failure).
 *
 * The cascade is now invoked directly. Every outcome keeps the user retryable:
 *   - success        → the User document (flag included) is deleted outright
 *   - handled error  → the cascade re-asserts the flag
 *   - hard crash     → the flag was never touched
 *
 * `cascadeDeleteUser` is mocked so the cascade's failure/crash behaviour — and
 * crucially the DB state VISIBLE TO IT at invocation time — can be observed.
 */

const { mockCascade } = vi.hoisted(() => ({ mockCascade: vi.fn() }));

vi.mock('../src/utils/cascadeDelete.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../src/utils/cascadeDelete.js')>();
  return { ...original, cascadeDeleteUser: mockCascade };
});

// Mock node-cron so the scheduled callback can be invoked directly.
vi.mock('node-cron', () => ({
  default: {
    schedule: vi.fn().mockReturnValue({ stop: vi.fn() }),
  },
}));

import cron from 'node-cron';
import { startTokenCleanupJob } from '../src/jobs/tokenCleanup.js';
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { JobLock } from '../src/models/JobLock.js';

const mockedSchedule = vi.mocked(cron.schedule);

function getScheduledCallback(): () => Promise<void> {
  const calls = mockedSchedule.mock.calls;
  return calls[calls.length - 1]![1] as () => Promise<void>;
}

async function createZombieUser() {
  return User.create({
    email: `zombie-${crypto.randomUUID()}@example.com`,
    authHash: '$2a$04$fakehashfakehashfakehashfakehashfakehashfakehashfake',
    emailVerified: true,
    encryptedVaultKey: 'test-encrypted-vault-key',
    vaultKeyIv: 'test-vault-key-iv',
    vaultKeyTag: 'test-vault-key-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    deletionPending: true,
  });
}

async function createVaultItem(userId: mongoose.Types.ObjectId) {
  return VaultItem.create({
    userId,
    itemType: 'login',
    encryptedData: 'test-encrypted-data',
    dataIv: 'test-data-iv',
    dataTag: 'test-data-tag',
    encryptedName: 'test-encrypted-name',
    nameIv: 'test-name-iv',
    nameTag: 'test-name-tag',
  });
}

describe('zombie cleanup crash safety (tokenCleanup)', () => {
  beforeEach(() => {
    mockCascade.mockReset();
  });

  it('invokes the cascade with deletionPending still set (no pre-clearing claim)', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();

    // Observe the flag exactly as the cascade sees it — i.e. AFTER the loop has
    // selected the zombie and BEFORE any erasure has happened.
    let flagAtCascadeTime: boolean | undefined;
    mockCascade.mockImplementation(async () => {
      const seen = await User.findById(zombie._id).lean();
      flagAtCascadeTime = seen?.deletionPending;
      return true;
    });

    await callback();

    expect(mockCascade).toHaveBeenCalledTimes(1);
    expect(flagAtCascadeTime).toBe(true);
  });

  it('leaves deletionPending set when the cascade throws mid-deletion (hard crash)', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();
    await createVaultItem(zombie._id);

    mockCascade.mockRejectedValue(new Error('connection reset mid-cascade'));

    // The job must contain the failure (never reject) — a rejected job promise
    // escalates to `process.exit(1)` via the server's unhandledRejection hook.
    await expect(callback()).resolves.toBeUndefined();

    const user = await User.findById(zombie._id);
    expect(user).not.toBeNull();
    expect(user!.deletionPending).toBe(true);

    // The data that still needs erasing is untouched, and the retry signal
    // survives — the next cycle can finish the job.
    const items = await VaultItem.find({ userId: zombie._id });
    expect(items).toHaveLength(1);
  });

  it('leaves deletionPending set when the cascade reports a handled failure', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();

    // A handled failure: the real cascade re-asserts the flag itself; the mock
    // simply does not clear it. Either way the loop must not have cleared it.
    mockCascade.mockResolvedValue(false);

    await callback();

    const user = await User.findById(zombie._id);
    expect(user).not.toBeNull();
    expect(user!.deletionPending).toBe(true);
  });

  it('retries a previously-crashed zombie on the next cycle and completes the deletion', async () => {
    startTokenCleanupJob();
    const callback = getScheduledCallback();

    const zombie = await createZombieUser();
    await createVaultItem(zombie._id);

    // Cycle 1: hard crash mid-cascade.
    mockCascade.mockRejectedValueOnce(new Error('process died mid-cascade'));
    await callback();

    expect(await User.findById(zombie._id)).not.toBeNull();

    // The lock must be free again for the next cycle to run at all.
    expect(await JobLock.findOne({ jobName: 'token-cleanup' })).toBeNull();

    // Cycle 2: the real cascade runs and the user is finally erased.
    const actual = await vi.importActual<typeof import('../src/utils/cascadeDelete.js')>(
      '../src/utils/cascadeDelete.js',
    );
    mockCascade.mockImplementation(actual.cascadeDeleteUser);

    await callback();

    expect(await User.findById(zombie._id)).toBeNull();
    expect(await VaultItem.find({ userId: zombie._id })).toHaveLength(0);
  });
});
