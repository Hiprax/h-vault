import mongoose from 'mongoose';
import { Document } from '../models/Document.js';

/**
 * The breadcrumb a backup carries about the documents it does NOT contain.
 *
 * ## Why a backup says anything about documents at all
 *
 * Documents are deliberately absent from the backup payload: their bytes cannot
 * fit a ~25 MiB JSON document, and metadata without bytes would restore rows
 * pointing at objects that do not exist. The failure mode that creates is quiet
 * and expensive — a user restores into a fresh account, sees every item and every
 * folder come back, and concludes the restore was complete. This summary is what
 * makes the boundary visible, so the restore can say "this backup was taken from
 * an account holding N documents; documents are not part of a backup".
 *
 * ## One definition, because there are two payload builders
 *
 * `backupController.collectBackupData` builds the payload for the manual trigger
 * and the download; `backupScheduler.processUserBackup` builds its own, differently
 * shaped one for the scheduled email. A breadcrumb on only one of them would leave
 * the backup most users actually have silently incomplete, and two copies of the
 * count would be two chances to disagree about what it counts.
 *
 * ## What it counts, and what it deliberately does not
 *
 * ACTIVE documents only — `deletedAt` absent — which is exactly the rule the
 * backup already applies to vault items (`deletedAt: { $exists: false }`). The
 * number therefore answers "how much of what I can see is not in this file",
 * which is the question a user restoring is actually asking. A trashed document
 * is no more in the backup than an active one, but counting it would report a
 * figure that matches nothing on screen.
 *
 * `totalBytes` is PLAINTEXT bytes, the same figure the quota and the UI use, not
 * the stored ciphertext length.
 */
export interface DocumentSummary {
  count: number;
  totalBytes: number;
}

/**
 * Counts one user's active documents and their total plaintext size.
 *
 * The `$match` casts `userId` itself: an aggregation pipeline is NOT run through
 * Mongoose's schema casting the way a query filter is, so a string id here would
 * match nothing and report a confident, permanent zero.
 *
 * A user with no documents produces no group at all, hence the zeroed fallback —
 * which is the value a backup from an account that has never uploaded anything
 * carries, rather than an absent field. Absent means "taken by a server that
 * predates this feature"; zero means "taken by a server that has it, from an
 * account with nothing to report", and a restore should not conflate the two.
 */
export async function collectDocumentSummary(userId: string): Promise<DocumentSummary> {
  const [summary] = await Document.aggregate<DocumentSummary>([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        deletedAt: { $exists: false },
      },
    },
    {
      $group: {
        _id: null,
        count: { $sum: 1 },
        totalBytes: { $sum: '$plaintextBytes' },
      },
    },
  ]);

  return { count: summary?.count ?? 0, totalBytes: summary?.totalBytes ?? 0 };
}
