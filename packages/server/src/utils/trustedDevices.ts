import type mongoose from 'mongoose';
import { TrustedDevice } from '../models/TrustedDevice.js';

/**
 * Revoke ALL of a user's trusted-device records, forcing that user to complete
 * the 2FA step again on their next login from every previously-trusted device.
 *
 * This is the single choke point every trusted-device revocation trigger calls
 * (§1.5 of the remember-me plan). The non-endpoint triggers are: password reset,
 * change-password, 2FA enable, 2FA disable, regenerate-backup-codes, logout-all,
 * the `refresh` reuse-detection branch, and BOTH branches of `cascadeDeleteUser`;
 * the explicit "revoke all trusted devices" endpoint is the ninth. Centralising
 * the delete here means a second construction path can never silently skip the
 * hook — a class of bug this codebase has repeatedly been bitten by.
 *
 * Ordinary `logout` deliberately does NOT call this: logging out one session on
 * a trusted device must not force 2FA on that device's next login — that is the
 * whole point of the feature.
 *
 * Pass the active `session` when the caller runs inside a MongoDB transaction so
 * the revocation commits or aborts atomically with the rest of the operation
 * (e.g. the transactional cascade delete or change-password); omit it otherwise.
 *
 * @returns the number of trusted-device records removed.
 */
export async function revokeTrustedDevices(
  userId: mongoose.Types.ObjectId | string,
  session?: mongoose.ClientSession,
): Promise<number> {
  const result = await TrustedDevice.deleteMany({ userId }, session ? { session } : {});
  return result.deletedCount;
}
