import type mongoose from 'mongoose';
import { config } from '../config/index.js';
import { User } from '../models/User.js';
import { VaultItem } from '../models/VaultItem.js';
import { Folder } from '../models/Folder.js';
import { Document } from '../models/Document.js';
import { DocumentUpload } from '../models/DocumentUpload.js';
import { cascadeDeleteUser } from './cascadeDelete.js';
import { createModuleLogger, errorMessage } from './logger.js';

const logger = createModuleLogger('unverified-accounts');

const DAY_MS = 24 * 60 * 60 * 1000;

/** How many candidates one read returns; the run reads page after page. */
const REAP_PAGE_SIZE = 500;

/**
 * How long the reaper keeps going, counted from when IT starts (the token deletes
 * and the zombie loop before it are not counted, so the whole job can outlast its
 * ten-minute lock; that is harmless, because every claim below is conditional and
 * an overlapping run simply finds nothing left to claim). Whatever is left is
 * reaped six hours later.
 */
const REAP_BUDGET_MS = 5 * 60 * 1000;

/** And the most one candidate read may take. */
const REAP_PAGE_MAX_TIME_MS = 10_000;

/**
 * The collections whose rows make an account more than provisional. An account
 * that cannot sign in can create none of them, so one that owns any did so while
 * it could (verified, then something cleared the flag) or was planted by hand,
 * and either way it is not the reaper's to erase.
 */
const OWNED_ROW_MODELS = [VaultItem, Folder, Document, DocumentUpload] as const;

async function ownsRows(userId: mongoose.Types.ObjectId): Promise<boolean> {
  for (const model of OWNED_ROW_MODELS) {
    // From the PRIMARY: a lagging secondary that has not seen a row yet would
    // answer "owns nothing" for an account that does.
    const row = await model.collection.findOne(
      { userId },
      { projection: { _id: 1 }, readPreference: 'primary' },
    );
    if (row !== null) return true;
  }
  return false;
}

/**
 * Erases every account whose address was never verified within
 * `UNVERIFIED_ACCOUNT_TTL_DAYS` of its creation (F-21), oldest first, a page of
 * {@link REAP_PAGE_SIZE} at a time, for at most {@link REAP_BUDGET_MS} per run.
 * Returns how many it erased.
 *
 * ## What counts as provisional
 *
 * `emailVerified` EXACTLY `false`. The sign-in check reads a missing field as
 * unverified, which is the safe answer for a door; for an erasure the safe answer
 * is the opposite, so a legacy row without the field is left alone. And no owned
 * vault, folder, document or upload row (see {@link OWNED_ROW_MODELS}).
 *
 * ## Why every account is CLAIMED before it is erased
 *
 * `cascadeDeleteUser` deletes by id, unconditionally. The verification link stays
 * valid for a day, so its owner can follow it at any moment, including the one in
 * which the reaper has picked the account. So each account is claimed first with
 * ONE conditional write that sets `deletionPending` only while the account is still
 * provisional and nobody else is erasing it, and the cascade runs only for a claim
 * that landed. `verifyEmail` writes `emailVerified` under the opposite condition
 * (`deletionPending` not set). The two writes are on the same document, so exactly
 * one of them wins: either the address is verified and the claim matches nothing,
 * or the claim lands and the verification is refused. A pending account cannot sign
 * in, so nothing it could do can follow the claim.
 *
 * The ownership check runs BEFORE the claim and is not repeated after it: an
 * account that cannot authenticate cannot create a row in between.
 *
 * A cascade that fails leaves `deletionPending` set, and the zombie loop of the
 * next run finishes it (its system row then says `deletion_cleanup`).
 */
export async function reapUnverifiedAccounts(now: Date = new Date()): Promise<number> {
  const startedAt = Date.now();
  const cutoff = new Date(now.getTime() - config.UNVERIFIED_ACCOUNT_TTL_DAYS * DAY_MS);
  const provisional = {
    emailVerified: false,
    createdAt: { $lt: cutoff },
    deletionPending: { $ne: true },
  };

  let reaped = 0;
  // A cursor on `_id`, so an account skipped below (it owns data) is passed over
  // and never read again by this run: re-reading from the start would let enough
  // of them fill every page and stall the reaper for good.
  let after: mongoose.Types.ObjectId | undefined;
  for (;;) {
    // `_id` order is creation order, so the oldest go first.
    const page = await User.find({
      ...provisional,
      ...(after === undefined ? {} : { _id: { $gt: after } }),
    })
      .select('_id')
      .sort({ _id: 1 })
      // The unverified accounts only, from their own index, then a bounded top-k
      // sort: left alone the planner may walk EVERY account in `_id` order instead.
      .hint({ emailVerified: 1 })
      .limit(REAP_PAGE_SIZE)
      .maxTimeMS(REAP_PAGE_MAX_TIME_MS)
      .read('primary')
      .lean();
    if (page.length === 0) break;

    for (const { _id } of page) {
      if (Date.now() - startedAt >= REAP_BUDGET_MS) {
        logger.info('Unverified-account reaping paused at the time budget', { reaped });
        return reaped;
      }
      after = _id;
      try {
        if (await ownsRows(_id)) {
          logger.warn('An unverified account owns data and was not reaped', {
            userId: _id.toString(),
          });
          continue;
        }
        const claimed = await User.findOneAndUpdate(
          { _id, ...provisional },
          { $set: { deletionPending: true } },
          { projection: { email: 1 } },
        ).lean();
        // Verified, or claimed by another erasure, since it was read.
        if (!claimed) continue;

        const erased = await cascadeDeleteUser({
          userId: _id,
          userEmail: claimed.email,
          ip: 'system',
          userAgent: 'system/token-cleanup-job',
          auditAction: 'unverified_account_reaped',
        });
        if (erased) {
          reaped += 1;
        } else {
          logger.warn('Reaping an unverified account failed; it stays pending for the next run', {
            userId: _id.toString(),
          });
        }
      } catch (err: unknown) {
        logger.error('Reaping an unverified account failed', {
          userId: _id.toString(),
          error: errorMessage(err),
        });
      }
    }
    if (page.length < REAP_PAGE_SIZE) break;
  }
  if (reaped > 0) logger.info('Reaped never-verified accounts', { reaped });
  return reaped;
}
