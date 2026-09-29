import type { Types } from 'mongoose';
import { MAX_BACKUP_MAILS_PER_USER_PER_DAY } from '@hvault/shared';
import { User } from '../models/User.js';

/**
 * The daily budget of emails the backup feature sends on behalf of one account
 * (F-05): every mailed backup, one per recipient; every recipient confirmation;
 * every "backup not sent" notice to the owner.
 *
 * A request-rate limiter bounds a burst, not a day: the trigger alone allows ten
 * backups per quarter hour, each to up to ten addresses, which is a mail relay by
 * the day. This counter is what bounds the day, and it is a counter on the account
 * rather than a count of `BackupLog` rows, because a confirmation or a notice is
 * not a backup and must not appear in the backup history the owner reads.
 *
 * The day is the UTC calendar day, stored as `YYYY-MM-DD` on `User.outboundMail`
 * (`select: false`). ABSENT means nothing was sent today.
 */

/** The UTC calendar day `now` falls on, as the counter stores it. */
function outboundMailDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}

/**
 * Claims `count` messages of today's budget for `userId`, BEFORE they are sent.
 * True when claimed; false when they would take the day past
 * {@link MAX_BACKUP_MAILS_PER_USER_PER_DAY} (then nothing is claimed and nothing
 * may be sent).
 *
 * ONE conditional update, so concurrent claims cannot both read a count that fits
 * and both spend it: the filter admits the write only while a stored count for
 * today leaves room for `count` more, or while the stored day is another day (or
 * absent), in which case the pipeline starts today's count at `count`. A claimed
 * message that then fails to send is NOT handed back: it was an attempt, and a
 * relay that keeps refusing is exactly what the budget must not let a caller
 * retry without bound.
 */
export async function claimOutboundMail(
  userId: string | Types.ObjectId,
  count: number,
  now: Date = new Date(),
): Promise<boolean> {
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_BACKUP_MAILS_PER_USER_PER_DAY) {
    return false;
  }
  const today = outboundMailDay(now);
  const result = await User.updateOne(
    {
      _id: userId,
      $or: [
        { 'outboundMail.day': { $ne: today } },
        {
          'outboundMail.day': today,
          'outboundMail.count': { $lte: MAX_BACKUP_MAILS_PER_USER_PER_DAY - count },
        },
      ],
    },
    [
      {
        $set: {
          outboundMail: {
            $cond: [
              { $eq: ['$outboundMail.day', today] },
              { day: today, count: { $add: ['$outboundMail.count', count] } },
              { day: today, count },
            ],
          },
        },
      },
    ],
    // Mongoose refuses an update PIPELINE unless it is asked for by name; the
    // lockout episode write in `utils/lockout.ts` documents the same option.
    { updatePipeline: true, timestamps: false },
  );
  return result.matchedCount === 1;
}
