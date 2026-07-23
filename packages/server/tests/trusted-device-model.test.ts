import { describe, it, expect } from 'vitest';
import mongoose, { Types } from 'mongoose';
import { TrustedDevice } from '../src/models/TrustedDevice.js';

/**
 * TrustedDevice records let a device skip the 2FA step. Their security rests on
 * three schema-level guarantees, each asserted here:
 *   1. `tokenHash` is UNIQUE — two devices can never collide on one lookup key.
 *   2. `expiresAt` carries a TTL so a lapsed grant is evicted, not consumable.
 *   3. `toJSON` strips `tokenHash` so a listing endpoint never leaks the secret
 *      a stolen cookie must hash to.
 * The dual registration (indexedModels + config/database) is asserted in
 * migrations.test.ts, not here.
 */
describe('TrustedDevice model', () => {
  const makeDoc = (overrides: Record<string, unknown> = {}) => ({
    userId: new Types.ObjectId(),
    tokenHash: 'a'.repeat(64),
    deviceInfo: { userAgent: 'ua', ip: '203.0.113.1', fingerprint: 'fp' },
    // Far future so the TTL reaper can never race this short test.
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    ...overrides,
  });

  describe('indexes', () => {
    it('has a UNIQUE index on tokenHash', async () => {
      await TrustedDevice.ensureIndexes();
      const indexes = (await TrustedDevice.collection.indexes()) as {
        key: Record<string, number>;
        unique?: boolean;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['tokenHash'] === 1);
      expect(index).toBeDefined();
      expect(index!.unique).toBe(true);
    });

    it('has a TTL index on expiresAt (expireAfterSeconds: 0)', async () => {
      await TrustedDevice.ensureIndexes();
      const indexes = (await TrustedDevice.collection.indexes()) as {
        key: Record<string, number>;
        expireAfterSeconds?: number;
        [k: string]: unknown;
      }[];

      const ttlIndex = indexes.find(
        (idx) => idx.key['expiresAt'] === 1 && idx.expireAfterSeconds === 0,
      );
      expect(ttlIndex).toBeDefined();
    });

    it('has a compound (userId, createdAt desc) index for listing and eviction', async () => {
      await TrustedDevice.ensureIndexes();
      const indexes = (await TrustedDevice.collection.indexes()) as {
        key: Record<string, number>;
        [k: string]: unknown;
      }[];

      const index = indexes.find((idx) => idx.key['userId'] === 1 && idx.key['createdAt'] === -1);
      expect(index).toBeDefined();
    });
  });

  describe('unique tokenHash constraint', () => {
    it('rejects a second record with a duplicate tokenHash', async () => {
      await TrustedDevice.ensureIndexes();
      await TrustedDevice.create(makeDoc({ tokenHash: 'b'.repeat(64) }));

      let error: unknown;
      try {
        await TrustedDevice.create(
          makeDoc({ tokenHash: 'b'.repeat(64), userId: new Types.ObjectId() }),
        );
      } catch (err: unknown) {
        error = err;
      }

      expect(error).toBeDefined();
      expect((error as { code?: number }).code).toBe(11000);
    });

    it('allows the same user to hold multiple distinct trusted devices', async () => {
      await TrustedDevice.ensureIndexes();
      const userId = new Types.ObjectId();
      await TrustedDevice.create(makeDoc({ userId, tokenHash: 'c'.repeat(64) }));
      await TrustedDevice.create(makeDoc({ userId, tokenHash: 'd'.repeat(64) }));

      const count = await TrustedDevice.countDocuments({ userId });
      expect(count).toBe(2);
    });
  });

  describe('toJSON', () => {
    it('strips tokenHash and __v while keeping the safe fields', async () => {
      const doc = await TrustedDevice.create(makeDoc({ tokenHash: 'e'.repeat(64) }));
      const json = doc.toJSON() as Record<string, unknown>;

      expect(json['tokenHash']).toBeUndefined();
      expect(json['__v']).toBeUndefined();
      // Everything a listing endpoint legitimately shows must survive the strip.
      expect(json['_id']).toBeDefined();
      expect(json['userId']).toBeDefined();
      expect(json['deviceInfo']).toBeDefined();
      expect(json['expiresAt']).toBeDefined();
      expect(json['createdAt']).toBeDefined();
    });
  });

  describe('schema shape', () => {
    it('persists the shared deviceInfo sub-schema without its own _id', async () => {
      const doc = await TrustedDevice.create(makeDoc({ tokenHash: 'f'.repeat(64) }));
      const raw = await TrustedDevice.collection.findOne({ _id: doc._id });

      expect(raw).not.toBeNull();
      const deviceInfo = raw!['deviceInfo'] as Record<string, unknown>;
      expect(deviceInfo['userAgent']).toBe('ua');
      expect(deviceInfo['ip']).toBe('203.0.113.1');
      expect(deviceInfo['fingerprint']).toBe('fp');
      // `{ _id: false }` on the shared sub-schema — no nested id.
      expect(deviceInfo['_id']).toBeUndefined();
    });

    it('uses the trusted_devices collection', () => {
      expect(TrustedDevice.collection.collectionName).toBe('trusted_devices');
    });

    it('requires tokenHash, userId and expiresAt', async () => {
      const doc = new TrustedDevice({});
      let error: mongoose.Error.ValidationError | undefined;
      try {
        await doc.validate();
      } catch (err: unknown) {
        error = err as mongoose.Error.ValidationError;
      }
      expect(error).toBeDefined();
      expect(error!.errors['tokenHash']).toBeDefined();
      expect(error!.errors['userId']).toBeDefined();
      expect(error!.errors['expiresAt']).toBeDefined();
    });
  });

  // Guard the harness assumption above: the model is registered on the shared
  // mongoose instance so setup.ts's createIndexes() pass builds its indexes.
  it('is registered on the shared mongoose instance', () => {
    expect(mongoose.models['TrustedDevice']).toBeDefined();
  });
});
