/**
 * Invitations (F-24, task 5.1): the edges the request-level suite cannot reach.
 *
 * - The stored row never serialises its token hash.
 * - Two mints by one inviter at once: the second is refused while the first holds
 *   the per-inviter lock that keeps the daily cap a count of committed rows.
 * - An inviter whose account is gone between authentication and the handler is
 *   told so (404), and nothing is minted.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import mongoose from 'mongoose';
import { config } from '../src/config/index.js';
import { Invitation } from '../src/models/Invitation.js';
import { acquireJobLock, releaseJobLock } from '../src/utils/jobLock.js';
import { mintInvitation } from '../src/utils/invitations.js';
import { createInvitation } from '../src/controllers/invitationController.js';
import { createTestUser } from './helpers.js';

const mutableConfig = config as unknown as Record<string, unknown>;
let savedMode: unknown;

beforeEach(() => {
  savedMode = mutableConfig.REGISTRATION_MODE;
});

afterEach(() => {
  mutableConfig.REGISTRATION_MODE = savedMode;
  vi.restoreAllMocks();
});

describe('an invitation row', () => {
  it('serialises without its token hash or version key', () => {
    const json = new Invitation({
      tokenHash: 'f'.repeat(64),
      email: 'invitee@example.com',
      userId: null,
      expiresAt: new Date('2026-10-20T00:00:00Z'),
    }).toJSON() as unknown as Record<string, unknown>;

    expect(json).not.toHaveProperty('tokenHash');
    expect(json).not.toHaveProperty('__v');
    expect(json['email']).toBe('invitee@example.com');
  });
});

describe('minting by one inviter', () => {
  it('is refused with 409 while another mint by the same inviter holds the lock, and writes nothing', async () => {
    const inviter = await createTestUser();
    const held = await acquireJobLock(`invitation-mint:${inviter.id}`, 60_000);
    expect(held).not.toBeNull();
    try {
      await expect(mintInvitation('invitee@example.com', inviter.id)).rejects.toMatchObject({
        statusCode: 409,
        message: 'Another invitation is being created. Try again in a moment.',
      });
      expect(await Invitation.countDocuments({})).toBe(0);
    } finally {
      await releaseJobLock(`invitation-mint:${inviter.id}`, held!);
    }

    // Negative: with the lock free, the same mint succeeds and stores one row.
    const minted = await mintInvitation('invitee@example.com', inviter.id);
    expect(minted.link).toContain('#invite=');
    expect(await Invitation.countDocuments({ email: 'invitee@example.com' })).toBe(1);
  });
});

describe('the invitation endpoint', () => {
  it('answers 404 for an inviter whose account is gone, and mints nothing', async () => {
    mutableConfig.REGISTRATION_MODE = 'invite';
    const next = vi.fn<(err?: unknown) => void>();
    const req = {
      user: { _id: new mongoose.Types.ObjectId().toString() },
      body: { authHash: 'irrelevant', email: 'invitee@example.com' },
    } as unknown as Request;

    await createInvitation(req, {} as Response, next as unknown as NextFunction);

    expect(next).toHaveBeenCalledTimes(1);
    expect(next.mock.calls[0]![0]).toMatchObject({ statusCode: 404, message: 'User not found' });
    expect(await Invitation.countDocuments({})).toBe(0);
  });
});
