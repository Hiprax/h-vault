/**
 * The `__hv_device` proof cookie: minting, recognising, charging and revoking it,
 * in ONE module. See `models/DeviceProof.ts` for what a proof is and why a
 * password lockout never brakes a login that presents one.
 *
 * Every construction path of a proof is here — a completed sign-in
 * ({@link issueDeviceProof}) and the unlock link ({@link issueUnlockProof}) — and
 * so is every destruction path the application drives: the failure budget
 * ({@link recordProofFailure}) and the revocations ({@link revokeDeviceProofs},
 * called by reset, change-password, log-out-everywhere, refresh-token reuse and
 * both branches of the account-deletion cascade). The raw token is written only
 * into `Set-Cookie`; it is never logged, returned in a body or stored.
 */
import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import type mongoose from 'mongoose';
import {
  DEVICE_PROOF_DAYS,
  DEVICE_PROOF_FAILURE_WINDOW_MINUTES,
  MAX_DEVICE_PROOF_FAILURES,
  MAX_DEVICE_PROOFS_PER_USER,
  UNLOCK_DEVICE_PROOF_MINUTES,
} from '@hvault/shared';
import { isProduction } from '../config/index.js';
import { DEVICE_PROOF_COOKIE_NAME } from '../constants/index.js';
import { DeviceProof, type IDeviceProof } from '../models/DeviceProof.js';
import { createAuditLog } from '../services/auditService.js';
import { readStringCookie } from './cookies.js';
import { createModuleLogger, errorMessage } from './logger.js';
import { hashToken } from './token.js';

const logger = createModuleLogger('device-proofs');

const DAY_MS = 24 * 60 * 60 * 1000;
const DEVICE_PROOF_MS = DEVICE_PROOF_DAYS * DAY_MS;
const UNLOCK_PROOF_MS = UNLOCK_DEVICE_PROOF_MINUTES * 60 * 1000;
const FAILURE_WINDOW_MS = DEVICE_PROOF_FAILURE_WINDOW_MINUTES * 60 * 1000;

/** What a request presented: the raw value and the live row it names, if any. */
export interface PresentedDeviceProof {
  raw: string;
  /** `null` when the value names no live proof (forged, spent, revoked or expired). */
  proof: IDeviceProof | null;
}

function cookieOptions(): {
  httpOnly: true;
  secure: boolean;
  sameSite: 'strict' | 'lax';
  path: string;
} {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/v1/auth',
  };
}

function setDeviceProofCookie(res: Response, raw: string, maxAgeMs: number): void {
  // At most one `__hv_device` directive per response (RFC 6265 4.1.1): a clear
  // queued earlier in the request (a dead value was presented) is dropped when
  // the same response goes on to set a fresh proof.
  // Node stores ONE queued cookie as a bare string and two or more as an array,
  // so both shapes are normalised before filtering.
  const queued = res.getHeader('Set-Cookie');
  const lines = typeof queued === 'string' ? [queued] : Array.isArray(queued) ? queued : [];
  const kept = lines.filter((line) => !line.startsWith(`${DEVICE_PROOF_COOKIE_NAME}=`));
  if (kept.length !== lines.length) {
    res.removeHeader('Set-Cookie');
    if (kept.length > 0) res.setHeader('Set-Cookie', kept);
  }
  res.cookie(DEVICE_PROOF_COOKIE_NAME, raw, { ...cookieOptions(), maxAge: maxAgeMs });
}

/** Tells the browser to drop its proof. Same attributes as the set, or it is another cookie. */
export function clearDeviceProofCookie(res: Response): void {
  res.clearCookie(DEVICE_PROOF_COOKIE_NAME, cookieOptions());
}

/**
 * Reads the proof a request presented, or `null` when it presented none.
 *
 * Looked up by the hash of the cookie ALONE, before any account is known, so the
 * lookup costs the same whether or not the e-mail beside it is registered: an
 * existence check made only for real accounts would itself be an oracle.
 */
export async function findPresentedDeviceProof(req: Request): Promise<PresentedDeviceProof | null> {
  const raw = readStringCookie(req, DEVICE_PROOF_COOKIE_NAME);
  if (raw === undefined) return null;
  // From the primary: a replica lagging behind a just-minted proof (the unlock
  // link's) would clear a valid cookie, and one lagging behind a revocation would
  // honour a revoked proof.
  const proof = await DeviceProof.findOne({
    tokenHash: hashToken(raw),
    expiresAt: { $gt: new Date() },
  })
    .read('primary')
    .lean();
  return { raw, proof };
}

/** Whether `presented` proves a prior authentication for exactly `userId`. */
export function provesAccount(
  presented: PresentedDeviceProof | null,
  userId: mongoose.Types.ObjectId,
): presented is PresentedDeviceProof & { proof: IDeviceProof } {
  return presented?.proof?.userId.equals(userId) === true;
}

async function enforceDeviceProofCap(userId: mongoose.Types.ObjectId): Promise<void> {
  const count = await DeviceProof.countDocuments({ userId });
  if (count <= MAX_DEVICE_PROOFS_PER_USER) return;
  const oldest = await DeviceProof.find({ userId })
    .sort({ createdAt: 1 })
    .limit(count - MAX_DEVICE_PROOFS_PER_USER)
    .select('_id')
    .lean();
  await DeviceProof.deleteMany({ userId, _id: { $in: oldest.map((row) => row._id) } });
}

async function mint(
  res: Response,
  userId: mongoose.Types.ObjectId,
  lifetimeMs: number,
  singleUse: boolean,
): Promise<void> {
  const raw = crypto.randomBytes(32).toString('hex');
  await DeviceProof.create({
    userId,
    tokenHash: hashToken(raw),
    expiresAt: new Date(Date.now() + lifetimeMs),
    singleUse,
  });
  // After the new row exists, so it is the newest and never the one evicted.
  await enforceDeviceProofCap(userId);
  setDeviceProofCookie(res, raw, lifetimeMs);
}

/**
 * Deletes one proof, spent (single use) or replaced (rotation), and reports
 * whether THIS call deleted it: of two requests racing to spend one single-use
 * proof, exactly one wins.
 */
export async function consumeDeviceProof(proof: IDeviceProof): Promise<boolean> {
  const result = await DeviceProof.deleteOne({ _id: proof._id });
  return result.deletedCount === 1;
}

/**
 * Slides the expiry of the proof a request presented for `userId` forward by the
 * full proof lifetime, for a browser that is using its session: a proof minted at
 * sign-in must not lapse while the owner keeps a remembered or sliding session for
 * weeks (such a session never passes through the sign-in step again), because the
 * day it is needed is the day that session ends. Only a proof the browser already
 * holds for this account is extended, never a single-use one, and nothing is ever
 * minted here: a refresh token alone does not earn a proof. Best effort: it runs
 * after the session has been rotated, so it never throws.
 */
export async function extendPresentedDeviceProof(
  req: Request,
  res: Response,
  userId: mongoose.Types.ObjectId,
): Promise<void> {
  try {
    const presented = await findPresentedDeviceProof(req);
    if (!provesAccount(presented, userId) || presented.proof.singleUse) return;
    const extended = await DeviceProof.updateOne(
      { _id: presented.proof._id },
      { $set: { expiresAt: new Date(Date.now() + DEVICE_PROOF_MS) } },
    );
    // Revoked or reaped in the meantime: nothing to extend, and a dead value is
    // not re-sent.
    if (extended.matchedCount === 1) {
      setDeviceProofCookie(res, presented.raw, DEVICE_PROOF_MS);
    }
  } catch (err: unknown) {
    logger.error('Failed to extend a device proof', {
      userId: userId.toString(),
      error: errorMessage(err),
    });
  }
}

/**
 * Mints the proof a COMPLETED authentication earns, rotating the one presented.
 *
 * A proof the request presented for this same account is consumed (deleted)
 * first, so a copied cookie stops working the moment its owner signs in again
 * and a proof's failure count starts over. A proof for ANOTHER account is not
 * deleted (it lapses at its own expiry, and the browser's cookie is replaced by
 * this one).
 *
 * Best effort, and it never throws: it runs after the session has been created
 * and its cookie queued, so a datastore failure here must not turn a completed
 * sign-in (which may already have spent a TOTP step or a backup code) into a 500.
 * The cost of a failure is only that this browser is not proven next time.
 */
export async function issueDeviceProof(
  res: Response,
  userId: mongoose.Types.ObjectId,
  presented: PresentedDeviceProof | null,
): Promise<void> {
  try {
    if (provesAccount(presented, userId)) {
      await consumeDeviceProof(presented.proof);
    }
    await mint(res, userId, DEVICE_PROOF_MS, false);
  } catch (err: unknown) {
    logger.error('Failed to issue a device proof', {
      userId: userId.toString(),
      error: errorMessage(err),
    });
  }
}

/**
 * Hands the browser that followed an unlock link a SINGLE-USE proof for ten
 * minutes. Without it a stranger's next ten guesses re-lock the account within
 * seconds of the link being used, and an owner with no session and no proof would
 * be locked out of every new sign-in for as long as the guessing went on.
 *
 * Best effort, and it never throws, like {@link issueDeviceProof}: both of its
 * callers run it AFTER a step that cannot be undone (the unlock link is already
 * spent; log-out-everywhere has already revoked every proof), and what follows it
 * there (the unlock's audit row; the suspension of every third-party backup
 * recipient and the audit row) must still happen. The cost of a failure is only
 * that this browser is not proven next time.
 */
export async function issueUnlockProof(
  res: Response,
  userId: mongoose.Types.ObjectId,
): Promise<void> {
  try {
    await mint(res, userId, UNLOCK_PROOF_MS, true);
  } catch (err: unknown) {
    logger.error('Failed to issue an unlock proof', {
      userId: userId.toString(),
      error: errorMessage(err),
    });
  }
}

/**
 * Charges one wrong password to the proof it was presented with, and revokes the
 * proof when the failure reaches {@link MAX_DEVICE_PROOF_FAILURES} inside the
 * window. The account's own counter is not touched: the OWASP device-cookie
 * protocol locks the device cookie, not the account, so a typo on the owner's
 * browser never locks the owner's other new devices.
 *
 * Two conditional writes rather than a read: the first opens a fresh window when
 * none is running (or the last one lapsed), the second counts inside a running
 * one, and a race between them can only open a window early. The revocation is a
 * `deleteOne` whose count decides who audits it, so it is recorded exactly once.
 */
export async function recordProofFailure(
  res: Response,
  proof: IDeviceProof,
  context: { ip: string; userAgent: string },
): Promise<void> {
  const now = new Date();
  const windowStart = new Date(now.getTime() - FAILURE_WINDOW_MS);
  const opened = await DeviceProof.updateOne(
    {
      _id: proof._id,
      $or: [{ failuresSince: null }, { failuresSince: { $lte: windowStart } }],
    },
    { $set: { failures: 1, failuresSince: now } },
  );
  let failures = 1;
  if (opened.modifiedCount === 0) {
    const counted = await DeviceProof.findOneAndUpdate(
      { _id: proof._id },
      { $inc: { failures: 1 } },
      { returnDocument: 'after' },
    ).lean();
    // Gone in between (revoked by a concurrent request, or reaped): nothing to charge.
    if (!counted) return;
    failures = counted.failures;
  }
  if (failures < MAX_DEVICE_PROOF_FAILURES) return;

  const revoked = await DeviceProof.deleteOne({ _id: proof._id });
  clearDeviceProofCookie(res);
  if (revoked.deletedCount === 1) {
    await createAuditLog(
      proof.userId.toString(),
      'device_proof_revoked',
      { reason: 'failure_budget' },
      context.ip,
      context.userAgent,
    );
  }
}

/**
 * Revokes EVERY proof an account holds. Pass `session` inside a transaction so the
 * revocation commits or aborts with the rest. Log-out-everywhere revokes the
 * caller's own proof too (a stolen copy of it is what that action exists to cut
 * off) and then re-proves the caller with a fresh one.
 */
export async function revokeDeviceProofs(
  userId: mongoose.Types.ObjectId | string,
  options: { session?: mongoose.ClientSession } = {},
): Promise<number> {
  const result = await DeviceProof.deleteMany(
    { userId },
    options.session ? { session: options.session } : {},
  );
  return result.deletedCount;
}
