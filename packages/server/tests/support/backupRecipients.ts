import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { User } from '../../src/models/User.js';

/**
 * Stores `emails` as CONFIRMED backup recipients of `userId`, the state an address
 * reaches by following its confirmation link (F-05). For suites that exercise what
 * happens AFTER recipients exist (delivery outcomes, logging), not how they got
 * there: `tests/backup-recipients.test.ts` covers the route and the confirmation.
 */
export async function seedConfirmedRecipients(
  userId: string | mongoose.Types.ObjectId,
  emails: readonly string[],
): Promise<void> {
  const now = new Date();
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(String(userId)) },
    {
      $set: {
        'settings.backup.backupRecipients': emails.map((email) => ({
          email,
          state: 'confirmed',
          confirmedAt: now,
          approvedAt: now,
          confirmationDue: false,
          confirmationSentAt: null,
          confirmationAttempts: 0,
          nonce: crypto.randomBytes(32).toString('hex'),
        })),
        'settings.backup.recipientsRevision': 1,
      },
    },
  );
}
