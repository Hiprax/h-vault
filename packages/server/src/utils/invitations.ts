import crypto from 'node:crypto';
import mongoose from 'mongoose';
import { httpErrors } from '@hiprax/errors';
import {
  INVITATION_TOKEN_BYTES,
  INVITATION_TTL_DAYS,
  MAX_INVITATIONS_PER_INVITER_PER_DAY,
} from '@hvault/shared';
import { config } from '../config/index.js';
import { Invitation } from '../models/Invitation.js';
import { acquireJobLock, releaseJobLock } from './jobLock.js';
import { derivePurposeKey } from './token.js';

/**
 * Invitations to register (F-24), in one place: how a token is hashed, who may
 * mint one, which addresses a server admits, and the single-use claim.
 *
 * Minting has two callers — the operator's CLI (`cli/invite.ts`) and
 * `POST /auth/invitations` — and spending one has one, `register`. None of them
 * handles a token or a hash on its own: a second hashing site is a second key
 * that has to agree with this one.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/** How long the per-inviter minting lock is held at most. */
const MINT_LOCK_TTL_MS = 30 * 1000;

/** The fixed refusal a closed server gives every registration. */
export const REGISTRATION_CLOSED_MESSAGE = 'Registration is closed on this server.';

/**
 * The fixed refusal for a registration whose invitation does not admit it:
 * missing, unknown, for another address, expired or already spent. One sentence
 * for all five, because telling them apart would tell a guesser which part of a
 * token it held was right.
 */
export const INVITATION_INVALID_MESSAGE =
  'This invitation is not valid for this address, or it has expired or been used.';

/**
 * The stored form of a token: an HMAC under a key derived for this purpose alone.
 * Keyed, so a copy of the collection cannot be used to test guesses, and
 * purpose-derived like every other token key here, so it shares nothing with the
 * signing keys beside it.
 */
export function hashInvitationToken(token: string): string {
  return crypto
    .createHmac('sha256', derivePurposeKey(config.JWT_REFRESH_SECRET, 'invitation'))
    .update(token)
    .digest('hex');
}

/** The domain part of an address, lower-cased. */
function domainOf(email: string): string {
  return email.slice(email.lastIndexOf('@') + 1).toLowerCase();
}

/**
 * Whether `REGISTRATION_ALLOWED_DOMAINS` admits this address: an EXACT domain
 * match, so neither a subdomain nor a look-alike suffix passes. An empty list
 * admits every domain.
 */
export function isAllowedRegistrationDomain(email: string): boolean {
  const allowed = config.REGISTRATION_ALLOWED_DOMAINS;
  return allowed.length === 0 || allowed.includes(domainOf(email));
}

/**
 * Whether this account may mint invitations from the app: the server registers
 * by invitation AND the account's address is listed in `REGISTRATION_INVITERS`.
 * Never "any account", because an account that could invite anyone would let
 * every invitee invite others in turn.
 */
export function canInvite(email: string): boolean {
  return (
    config.REGISTRATION_MODE === 'invite' &&
    config.REGISTRATION_INVITERS.includes(email.toLowerCase())
  );
}

/** What a minted invitation hands back: the link, once, and when it stops working. */
export interface MintedInvitation {
  link: string;
  expiresAt: Date;
}

/**
 * Mints one invitation for `email`, stores its hash, and returns the link that
 * carries the token. The link is the only place the token ever exists outside
 * this call: nothing mails it, and the row keeps only the hash.
 *
 * The token rides in the FRAGMENT (`#invite=`), which a browser never sends to a
 * server, so it stays out of every access log a query string would reach.
 *
 * An inviting account (`inviterId` set) is held to
 * `MAX_INVITATIONS_PER_INVITER_PER_DAY`, counted and inserted under a lock held
 * per inviter: a count and an insert made separately let concurrent requests
 * each read a total that fits. The operator's CLI (`inviterId` null) is not
 * capped; the operator can create accounts directly anyway.
 *
 * @throws 400 when the address is outside the domain allowlist, 409 when another
 *   mint for the same inviter holds the lock, 429 when the inviter's daily cap is
 *   spent.
 */
export async function mintInvitation(
  email: string,
  inviterId: string | null,
): Promise<MintedInvitation> {
  const address = email.trim().toLowerCase();
  if (!isAllowedRegistrationDomain(address)) {
    throw httpErrors.badRequest(
      'This server only registers addresses in the domains its operator has allowed.',
    );
  }

  const lockName = inviterId === null ? null : `invitation-mint:${inviterId}`;
  const lockId = lockName === null ? null : await acquireJobLock(lockName, MINT_LOCK_TTL_MS);
  if (lockName !== null && lockId === null) {
    throw httpErrors.conflict('Another invitation is being created. Try again in a moment.');
  }

  try {
    if (inviterId !== null) {
      const mintedToday = await Invitation.countDocuments({
        userId: new mongoose.Types.ObjectId(inviterId),
        createdAt: { $gte: new Date(Date.now() - DAY_MS) },
      });
      if (mintedToday >= MAX_INVITATIONS_PER_INVITER_PER_DAY) {
        throw httpErrors.tooManyRequests(
          `You can create at most ${String(MAX_INVITATIONS_PER_INVITER_PER_DAY)} invitations a day. Try again tomorrow.`,
        );
      }
    }

    const token = crypto.randomBytes(INVITATION_TOKEN_BYTES).toString('base64url');
    const expiresAt = new Date(Date.now() + INVITATION_TTL_DAYS * DAY_MS);
    await Invitation.create({
      tokenHash: hashInvitationToken(token),
      email: address,
      userId: inviterId === null ? null : new mongoose.Types.ObjectId(inviterId),
      expiresAt,
    });
    return { link: `${config.APP_URL}/register#invite=${token}`, expiresAt };
  } finally {
    if (lockName !== null && lockId !== null) await releaseJobLock(lockName, lockId);
  }
}

/** The filter an invitation matches while it can still admit `email`. */
function usableInvitation(token: string, email: string): Record<string, unknown> {
  return {
    tokenHash: hashInvitationToken(token),
    email: email.toLowerCase(),
    consumedAt: null,
    expiresAt: { $gt: new Date() },
  };
}

/**
 * Whether `token` is an invitation that can admit `email` right now. A READ: it
 * spends nothing, because the registration it guards may still turn out to be
 * for an address that is already registered, and that answer must not cost the
 * invitee the invitation.
 */
export async function invitationAdmits(token: string, email: string): Promise<boolean> {
  return (await Invitation.exists(usableInvitation(token, email))) !== null;
}

/**
 * Spends the invitation for `email`, atomically: of two registrations presenting
 * it, exactly one gets the claim. Returns the claim's time, which
 * {@link returnInvitationClaim} needs, or `null` when it was already spent (or
 * has expired since it was checked).
 */
export async function claimInvitation(token: string, email: string): Promise<Date | null> {
  const claimedAt = new Date();
  const claimed = await Invitation.findOneAndUpdate(usableInvitation(token, email), {
    $set: { consumedAt: claimedAt },
  })
    .select('_id')
    .lean();
  return claimed === null ? null : claimedAt;
}

/**
 * Hands a claim back when the account it was spent on could not be created, so
 * the invitee is not left holding a spent invitation for an account that does
 * not exist. Conditioned on the claim's own time, so it can only undo itself.
 */
export async function returnInvitationClaim(
  token: string,
  email: string,
  claimedAt: Date,
): Promise<void> {
  await Invitation.updateOne(
    { tokenHash: hashInvitationToken(token), email: email.toLowerCase(), consumedAt: claimedAt },
    { $unset: { consumedAt: 1 } },
  );
}
