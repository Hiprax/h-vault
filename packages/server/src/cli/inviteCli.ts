import mongoose from 'mongoose';
import { emailSchema } from '@hvault/shared';
import { config } from '../config/index.js';
import { Invitation } from '../models/Invitation.js';
import { mintInvitation } from '../utils/invitations.js';
import { createIndexesWithCurrentRetention } from '../utils/ttlIndexReconcile.js';

/**
 * `npm run invite -w packages/server -- someone@example.com` (inside the
 * production image: `node packages/server/dist/cli/invite.js someone@example.com`).
 *
 * The operator's way to let one address register while `REGISTRATION_MODE` is
 * `invite`. It prints the invitation link ONCE and stores only a keyed hash of the
 * token, so the output of this command is the only copy there will ever be: the
 * operator hands it over, H-Vault never mails it.
 *
 * Kept apart from the two-line entry point (`cli/invite.ts`) so every branch is
 * exercised by the suite against a real database instead of being excluded from
 * coverage as an entry point.
 */

/** Where the command writes: the link to `log`, everything that went wrong to `error`. */
export interface InviteCliIo {
  log: (message: string) => void;
  error: (message: string) => void;
}

/** The terminal: the link to stdout, everything that went wrong to stderr. */
export const consoleIo: InviteCliIo = {
  log: (message) => {
    console.log(message);
  },
  error: (message) => {
    console.error(message);
  },
};

const USAGE = [
  'Usage: invite <email>',
  '',
  'Mints a single-use invitation for <email>, valid for 7 days, and prints its link once.',
  'Hand the link over yourself: H-Vault never mails an invitation.',
  'Takes effect while REGISTRATION_MODE=invite.',
].join('\n');

/**
 * Runs the command and returns its exit code: 0 on success and for `--help`, 1 for
 * a usage error or a refusal. Connects to MongoDB only when the process is not
 * connected already, and disconnects only a connection it opened.
 */
export async function runInviteCli(argv: readonly string[], io: InviteCliIo): Promise<number> {
  if (argv.includes('--help') || argv.includes('-h')) {
    io.log(USAGE);
    return 0;
  }
  if (argv.length !== 1) {
    io.error(USAGE);
    return 1;
  }

  const parsed = emailSchema.safeParse(argv[0]);
  if (!parsed.success) {
    io.error(`Not an e-mail address: ${String(argv[0])}`);
    return 1;
  }
  const email = parsed.data;

  if (config.REGISTRATION_MODE !== 'invite') {
    io.error(
      `Warning: REGISTRATION_MODE is ${config.REGISTRATION_MODE}, so this invitation is not ` +
        'needed (open) or cannot be used (closed) until it is set to invite.',
    );
  }

  const openedHere = mongoose.connection.readyState !== mongoose.ConnectionStates.connected;
  if (openedHere) {
    await mongoose.connect(config.MONGODB_URI, { serverSelectionTimeoutMS: 10_000 });
  }
  try {
    // The unique token index and the expiry index, in case this runs before the
    // index bootstrap has on an upgraded deployment (production turns autoIndex off).
    await createIndexesWithCurrentRetention(Invitation);
    const minted = await mintInvitation(email, null);
    io.log(`Invitation for ${email}, valid until ${minted.expiresAt.toISOString()}:`);
    io.log(minted.link);
    io.log('This link is shown once. H-Vault does not keep it and will not mail it.');
    return 0;
  } catch (err: unknown) {
    io.error(
      `Could not create the invitation: ${err instanceof Error ? err.message : String(err)}`,
    );
    return 1;
  } finally {
    if (openedHere) await mongoose.disconnect();
  }
}
