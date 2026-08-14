/**
 * A full-vault rotation that cannot complete changes NOTHING.
 *
 * The sibling file measures the success path. This is the failure path at the
 * same volume, and it is the one whose regression is unrecoverable: a rotation
 * that writes some rows with the new key and then abandons the vault key at its
 * old value leaves those rows permanently undecryptable by their owner. The
 * sequential fallback guards that by snapshotting every targeted row and
 * refusing BEFORE the first write when any requested id is missing — which is
 * only interesting when "every targeted row" is ten thousand of them.
 *
 * Not a measured scenario (no memory or time budget), so it shares no file with
 * one: it is here for the negative assertions, and every one of them is a
 * "nothing happened" claim about a request that touched the whole vault.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../../src/app.js';
import { MAX_ITEMS_PER_USER } from '@hvault/shared';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { createTestUser, authHeader, getCsrf, type TestUser } from '../helpers.js';
import { seedVault } from './fixtures.js';
import { recordScenarioCase } from './measure.js';

const DATA_BYTES = 1_600;

/** The ciphertext the refused rotation tried to write. No row may end up with it. */
const ABORTED_DATA = 'x'.repeat(DATA_BYTES);

describe('a full-vault rotation that names an unknown item', () => {
  let user: TestUser;
  let itemIds: string[];

  beforeAll(async () => {
    user = await createTestUser();
    await seedVault(user.id, { count: MAX_ITEMS_PER_USER, dataBytes: DATA_BYTES });
    const rows = await VaultItem.find({ userId: user.id }).select('_id').lean();
    itemIds = rows.map((row) => String(row._id));
  }, 300_000);

  it('refuses with 409 and leaves every row and the vault key untouched', async () => {
    const before = await User.findById(user.id).lean();
    const stranger = new mongoose.Types.ObjectId().toString();

    const { token, cookie } = await getCsrf(request(app));
    const res = await request(app)
      .post('/api/v1/vault/items/bulk-reencrypt')
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', token)
      .set('Cookie', cookie)
      .send({
        authHash: user.authHash,
        // The vault's own ids with the LAST one swapped for an unknown, rather
        // than appended to them: `bulkReEncryptSchema` caps `items` at 10,000, so
        // a full vault plus one stranger is 10,001 entries and Zod refuses it
        // with a 400 before the controller's snapshot-and-abort is reached at
        // all. Swapping keeps the request at exactly the cap, which is the shape
        // a real client sends.
        items: [...itemIds.slice(0, -1), stranger].map((id) => ({
          id,
          encryptedName: 'aborted-name',
          nameIv: 'n'.repeat(16),
          nameTag: 'n'.repeat(22),
          encryptedData: ABORTED_DATA,
          dataIv: 'v'.repeat(16),
          dataTag: 'g'.repeat(22),
        })),
        folders: [],
        newEncryptedVaultKey: 'must-not-be-stored',
        newVaultKeyIv: 'k'.repeat(16),
        newVaultKeyTag: 'k'.repeat(22),
      });

    const afterRows = await VaultItem.countDocuments({
      userId: user.id,
      encryptedData: ABORTED_DATA,
    });
    const after = await User.findById(user.id).lean();

    recordScenarioCase('rotation-atomicity', 'unknown-id-changes-nothing', {
      invariant:
        'a full-vault rotation naming one unknown id is refused with 409 and writes nothing: no row takes the new ciphertext and the stored vault key is unchanged',
      items: itemIds.length,
      status: res.status,
      rowsTakingNewCiphertext: afterRows,
      vaultKeyChanged: after?.encryptedVaultKey !== before?.encryptedVaultKey,
    });

    expect(res.status).toBe(409);
    expect(res.body).toMatchObject({ success: false, statusCode: 409 });

    // Not one of the 9,999 real rows took the new ciphertext...
    expect(afterRows).toBe(0);
    // ...and the key that decrypts them is exactly what it was.
    expect(after?.encryptedVaultKey).toBe(before?.encryptedVaultKey);
    expect(after?.vaultKeyIv).toBe(before?.vaultKeyIv);
    expect(after?.vaultKeyTag).toBe(before?.vaultKeyTag);
    // The fence is lowered on the way out, so the refusal costs the account
    // nothing beyond the failed request.
    expect(after?.rotationInProgress).not.toBe(true);
  }, 300_000);
});
