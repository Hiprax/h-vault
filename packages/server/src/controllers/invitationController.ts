import type { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { catchAsync, httpErrors } from '@hiprax/errors';
import { maskEmail } from '@hvault/shared';
import type { CreateInvitationInput, CreatedInvitation } from '@hvault/shared';
import { config } from '../config/index.js';
import { User } from '../models/User.js';
import { createAuditLog } from '../services/auditService.js';
import { getRequestContext, getUserId } from '../utils/controllerHelpers.js';
import { canInvite, mintInvitation } from '../utils/invitations.js';
import { createModuleLogger } from '../utils/logger.js';

const logger = createModuleLogger('invitations');

/**
 * `POST /auth/invitations` — an inviting account mints an invitation for one
 * address and gets the link back in the response body, to hand over itself.
 *
 * The order is the control:
 *
 *   1. the server must register by invitation (409 otherwise: there is nothing to
 *      invite anyone to, and a link minted now would be dead on arrival);
 *   2. the caller must be listed in `REGISTRATION_INVITERS` (403), never merely
 *      signed in, because an account that could invite would let every invitee
 *      invite others in turn;
 *   3. the master-password proof (401, audited like every other failed proof), so
 *      a stolen session cannot let anyone in;
 *   4. then `mintInvitation`, which owns the domain allowlist and the daily cap.
 *
 * The app sends no invitation mail. A mail would be one more link carrying a
 * token, and a way to make the server write to any address on request.
 */
export const createInvitation = catchAsync(async (req: Request, res: Response): Promise<void> => {
  const userId = getUserId(req);
  const { authHash, email } = req.body as CreateInvitationInput;

  if (config.REGISTRATION_MODE !== 'invite') {
    throw httpErrors.conflict('This server does not register accounts by invitation.');
  }

  const user = await User.findById(userId).select('+authHash email').lean();
  if (!user) {
    throw httpErrors.notFound('User not found');
  }
  if (!canInvite(user.email)) {
    throw httpErrors.forbidden('This account is not allowed to create invitations.');
  }

  if (!(await bcrypt.compare(authHash, user.authHash))) {
    const failCtx = getRequestContext(req);
    await createAuditLog(
      userId,
      'password_verification_failed',
      { endpoint: 'invitation_create' },
      failCtx.ip,
      failCtx.userAgent,
    );
    throw httpErrors.unauthorized('Password verification failed');
  }

  const minted = await mintInvitation(email, userId);

  const ctx = getRequestContext(req);
  await createAuditLog(
    userId,
    'invitation_create',
    { invitee: maskEmail(email), expiresAt: minted.expiresAt.toISOString() },
    ctx.ip,
    ctx.userAgent,
  );
  logger.info('Invitation created', { userId, invitee: maskEmail(email) });

  const data: CreatedInvitation = {
    link: minted.link,
    expiresAt: minted.expiresAt.toISOString(),
  };
  // The link IS the invitation: nothing between here and the inviter may keep it.
  res.setHeader('Cache-Control', 'no-store');
  res.status(201).json({ success: true, data });
});
