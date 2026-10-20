/**
 * F-24: who may create an account on this server.
 *
 * Registration used to be open to anyone who could reach the API, with no way
 * for an operator to close it, restrict it to a domain or make it invite-only.
 * These tests pin the three modes and the domain allowlist from the outside, by
 * the rows a registration writes and the mail it sends:
 *
 *   - `closed` refuses honestly with a fixed 403 and writes nothing;
 *   - an address outside `REGISTRATION_ALLOWED_DOMAINS` gets the same generic
 *     201 a registered address gets, and nothing is written or mailed;
 *   - `invite` admits exactly the invited address, once per invitation, and an
 *     invitation is minted only by an account in `REGISTRATION_INVITERS` proving
 *     its master password (the operator CLI is the other minting path).
 *
 * Config is mutated in place and restored, the pattern the rest of the suite
 * uses; the mail senders are spied so "nothing is mailed" is an assertion.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    sendVerificationEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
    sendRegistrationAttemptEmail: vi.fn().mockResolvedValue({ success: true, message: 'sent' }),
  };
});

import request from 'supertest';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import { MASTER_PASSWORD_PROOF_REFUSED_MESSAGE } from '@hvault/shared';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { User } from '../src/models/User.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { sendRegistrationAttemptEmail, sendVerificationEmail } from '../src/utils/email.js';
import { authHeader, createTestUser, getCsrf, type CsrfPair, type TestUser } from './helpers.js';

const API = '/api/v1';

const mutableConfig = config as unknown as Record<string, unknown>;
const CONFIG_KEYS = [
  'REGISTRATION_MODE',
  'REGISTRATION_ALLOWED_DOMAINS',
  'REGISTRATION_INVITERS',
] as const;

let savedConfig: Record<string, unknown>;

function setRegistration(settings: {
  mode?: 'open' | 'invite' | 'closed';
  domains?: string[];
  inviters?: string[];
}): void {
  mutableConfig.REGISTRATION_MODE = settings.mode ?? 'open';
  mutableConfig.REGISTRATION_ALLOWED_DOMAINS = settings.domains ?? [];
  mutableConfig.REGISTRATION_INVITERS = settings.inviters ?? [];
}

function registrationBody(email: string, extra: Record<string, unknown> = {}) {
  return {
    email,
    authHash: 'registration-auth-hash',
    encryptedVaultKey: 'enc-vault-key',
    vaultKeyIv: 'vault-iv',
    vaultKeyTag: 'vault-tag',
    kdfIterations: 600_000,
    kdfAlgorithm: 'PBKDF2-SHA256',
    encryptionVersion: 1,
    ...extra,
  };
}

async function register(body: Record<string, unknown>): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/auth/register`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(body);
}

async function mint(
  inviter: TestUser,
  email: string,
  authHash: string = inviter.rawPassword,
): Promise<request.Response> {
  const agent = request.agent(app);
  const csrf: CsrfPair = await getCsrf(agent);
  return agent
    .post(`${API}/auth/invitations`)
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .set('Authorization', authHeader(inviter.accessToken))
    .send({ authHash, email });
}

/** The token a minted link carries after `#invite=`. */
function tokenOf(link: unknown): string {
  expect(typeof link).toBe('string');
  const match = /#invite=([A-Za-z0-9_-]+)$/.exec(link as string);
  expect(match).not.toBeNull();
  return match![1]!;
}

const invitations = () => mongoose.connection.collection('invitations');

const GENERIC_SUCCESS = {
  success: true,
  message: 'Registration successful. Please check your email to verify your account.',
  data: { emailSent: true },
};

beforeEach(() => {
  savedConfig = Object.fromEntries(CONFIG_KEYS.map((key) => [key, mutableConfig[key]]));
  vi.mocked(sendVerificationEmail).mockClear();
  vi.mocked(sendRegistrationAttemptEmail).mockClear();
});

afterEach(() => {
  for (const key of CONFIG_KEYS) mutableConfig[key] = savedConfig[key];
});

describe('REGISTRATION_MODE=closed', () => {
  it('refuses every registration with a fixed 403 and writes no row, no audit entry and no mail', async () => {
    setRegistration({ mode: 'closed' });

    const res = await register(registrationBody('closed-mode@example.com'));

    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe('Registration is closed on this server.');
    expect(await User.countDocuments({})).toBe(0);
    expect(await AuditLog.countDocuments({ action: 'registration' })).toBe(0);
    expect(sendVerificationEmail).not.toHaveBeenCalled();
    expect(sendRegistrationAttemptEmail).not.toHaveBeenCalled();
  });

  it('answers a registered address with the same 403, so a closed server says nothing about who is registered', async () => {
    setRegistration({ mode: 'closed' });
    const existing = await createTestUser({ email: 'already-here@example.com' });

    const res = await register(registrationBody(existing.email));

    expect(res.status).toBe(403);
    expect(res.body.message).toBe('Registration is closed on this server.');
    expect(sendRegistrationAttemptEmail).not.toHaveBeenCalled();
  });

  it('is published on GET /config so the client can say so before the form is filled', async () => {
    setRegistration({ mode: 'closed' });
    const res = await request(app).get(`${API}/config`);
    expect(res.status).toBe(200);
    expect(res.body.data.registration).toEqual({ mode: 'closed' });
  });
});

describe('REGISTRATION_ALLOWED_DOMAINS', () => {
  it('answers an address outside the allowlist with the generic 201 and writes no row and sends no mail', async () => {
    setRegistration({ mode: 'open', domains: ['example.org'] });

    const res = await register(registrationBody('outsider@example.com'));

    expect(res.status).toBe(201);
    expect(res.body).toEqual(GENERIC_SUCCESS);
    expect(await User.countDocuments({})).toBe(0);
    expect(await AuditLog.countDocuments({})).toBe(0);
    expect(sendVerificationEmail).not.toHaveBeenCalled();
    expect(sendRegistrationAttemptEmail).not.toHaveBeenCalled();
  });

  it('matches the domain exactly and case-insensitively, never as a suffix', async () => {
    setRegistration({ mode: 'open', domains: ['example.org'] });

    const lookalike = await register(registrationBody('someone@notexample.org'));
    const subdomain = await register(registrationBody('someone@mail.example.org'));

    expect(lookalike.status).toBe(201);
    expect(subdomain.status).toBe(201);
    expect(await User.countDocuments({})).toBe(0);

    const allowed = await register(registrationBody('Someone@EXAMPLE.ORG'));
    expect(allowed.status).toBe(201);
    expect(await User.countDocuments({ email: 'someone@example.org' })).toBe(1);
    expect(sendVerificationEmail).toHaveBeenCalledTimes(1);
  });

  it('with an empty allowlist admits any domain (the default is unchanged)', async () => {
    setRegistration({ mode: 'open', domains: [] });
    const res = await register(registrationBody('anyone@anywhere.test'));
    expect(res.status).toBe(201);
    expect(await User.countDocuments({ email: 'anyone@anywhere.test' })).toBe(1);
  });
});

describe('REGISTRATION_MODE=open', () => {
  it('registers exactly as before and publishes the mode', async () => {
    setRegistration({ mode: 'open' });
    const res = await register(registrationBody('open-mode@example.com'));
    expect(res.status).toBe(201);
    expect(res.body).toEqual(GENERIC_SUCCESS);
    expect(await User.countDocuments({ email: 'open-mode@example.com' })).toBe(1);

    const cfg = await request(app).get(`${API}/config`);
    expect(cfg.body.data.registration).toEqual({ mode: 'open' });
  });

  it('ignores an invitation token it does not need', async () => {
    setRegistration({ mode: 'open' });
    const res = await register(
      registrationBody('open-with-token@example.com', { invitationToken: 'x'.repeat(43) }),
    );
    expect(res.status).toBe(201);
    expect(await User.countDocuments({ email: 'open-with-token@example.com' })).toBe(1);
  });
});

describe('REGISTRATION_MODE=invite', () => {
  let inviter: TestUser;

  beforeEach(async () => {
    inviter = await createTestUser({ email: 'inviter@example.com' });
    setRegistration({ mode: 'invite', inviters: ['inviter@example.com'] });
  });

  it('refuses a registration without an invitation with a fixed 403 and no row', async () => {
    const res = await register(registrationBody('uninvited@example.com'));
    expect(res.status).toBe(403);
    expect(res.body.message).toBe(
      'This invitation is not valid for this address, or it has expired or been used.',
    );
    expect(await User.countDocuments({ email: 'uninvited@example.com' })).toBe(0);
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('admits exactly the invited address, exactly once', async () => {
    const minted = await mint(inviter, 'invitee@example.com');
    expect(minted.status).toBe(201);
    const token = tokenOf(minted.body.data.link);

    const first = await register(
      registrationBody('invitee@example.com', { invitationToken: token }),
    );
    expect(first.status).toBe(201);
    expect(first.body).toEqual(GENERIC_SUCCESS);
    expect(await User.countDocuments({ email: 'invitee@example.com' })).toBe(1);

    const stored = await invitations().findOne({ email: 'invitee@example.com' });
    expect(stored?.consumedAt).toBeInstanceOf(Date);

    // The same invitation a second time, for the same address and for another.
    const again = await register(
      registrationBody('invitee@example.com', { invitationToken: token }),
    );
    expect(again.status).toBe(403);
    const other = await register(
      registrationBody('second@example.com', { invitationToken: token }),
    );
    expect(other.status).toBe(403);
    expect(await User.countDocuments({ email: 'second@example.com' })).toBe(0);
    expect(await User.countDocuments({ email: 'invitee@example.com' })).toBe(1);
  });

  it('refuses an invitation presented for another address and leaves it usable by the invitee', async () => {
    const token = tokenOf((await mint(inviter, 'invitee@example.com')).body.data.link);

    const stolen = await register(
      registrationBody('thief@example.com', { invitationToken: token }),
    );
    expect(stolen.status).toBe(403);
    expect(await User.countDocuments({ email: 'thief@example.com' })).toBe(0);
    expect((await invitations().findOne({ email: 'invitee@example.com' }))?.consumedAt).toBeFalsy();

    const rightful = await register(
      registrationBody('invitee@example.com', { invitationToken: token }),
    );
    expect(rightful.status).toBe(201);
    expect(await User.countDocuments({ email: 'invitee@example.com' })).toBe(1);
  });

  it('refuses an expired invitation', async () => {
    const token = tokenOf((await mint(inviter, 'late@example.com')).body.data.link);
    await invitations().updateOne(
      { email: 'late@example.com' },
      { $set: { expiresAt: new Date(Date.now() - 1_000) } },
    );

    const res = await register(registrationBody('late@example.com', { invitationToken: token }));
    expect(res.status).toBe(403);
    expect(await User.countDocuments({ email: 'late@example.com' })).toBe(0);
  });

  it('lets exactly one of two concurrent registrations spend one invitation', async () => {
    const token = tokenOf((await mint(inviter, 'race@example.com')).body.data.link);

    const results = await Promise.all([
      register(registrationBody('race@example.com', { invitationToken: token })),
      register(registrationBody('race@example.com', { invitationToken: token })),
    ]);

    expect(results.map((r) => r.status).sort()).toEqual([201, 403]);
    expect(await User.countDocuments({ email: 'race@example.com' })).toBe(1);
  });

  it('answers an invited address that is already registered with the generic 201 and leaves the invitation unspent', async () => {
    const existing = await createTestUser({ email: 'known@example.com' });
    const token = tokenOf((await mint(inviter, existing.email)).body.data.link);

    const res = await register(registrationBody(existing.email, { invitationToken: token }));

    expect(res.status).toBe(201);
    expect(res.body).toEqual(GENERIC_SUCCESS);
    expect(await User.countDocuments({ email: existing.email })).toBe(1);
    expect(sendRegistrationAttemptEmail).toHaveBeenCalledTimes(1);
    expect((await invitations().findOne({ email: existing.email }))?.consumedAt).toBeFalsy();
  });

  it('hands the invitation back when the account could not be created', async () => {
    const token = tokenOf((await mint(inviter, 'unlucky@example.com')).body.data.link);
    const create = vi.spyOn(User, 'create').mockRejectedValueOnce(new Error('storage refused'));
    try {
      const failed = await register(
        registrationBody('unlucky@example.com', { invitationToken: token }),
      );
      expect(failed.status).toBe(500);
    } finally {
      create.mockRestore();
    }
    expect(await User.countDocuments({ email: 'unlucky@example.com' })).toBe(0);
    expect((await invitations().findOne({ email: 'unlucky@example.com' }))?.consumedAt).toBeFalsy();

    // Still usable, by exactly that address.
    const retry = await register(
      registrationBody('unlucky@example.com', { invitationToken: token }),
    );
    expect(retry.status).toBe(201);
    expect(await User.countDocuments({ email: 'unlucky@example.com' })).toBe(1);
  });

  it('refuses an invited address outside the allowlist with the generic answer, without spending the invitation', async () => {
    const token = tokenOf((await mint(inviter, 'invitee@example.com')).body.data.link);
    mutableConfig.REGISTRATION_ALLOWED_DOMAINS = ['example.org'];

    const res = await register(registrationBody('invitee@example.com', { invitationToken: token }));

    expect(res.status).toBe(201);
    expect(res.body).toEqual(GENERIC_SUCCESS);
    expect(await User.countDocuments({ email: 'invitee@example.com' })).toBe(0);
    expect((await invitations().findOne({ email: 'invitee@example.com' }))?.consumedAt).toBeFalsy();
  });
});

describe('refusals keep their shape: no answer depends on the allowlist or on the address (F-24)', () => {
  it('invite mode: a missing invitation is the same 403 inside and outside the allowlist', async () => {
    // Checking the domain first answered an outside address with the generic 201
    // and an inside one with the invitation 403: one guess at a time, the
    // allowlist was readable from the status alone.
    setRegistration({ mode: 'invite', domains: ['corp.example'] });

    const inside = await register(registrationBody('someone@corp.example'));
    const outside = await register(registrationBody('someone@guess.example'));

    expect(inside.status).toBe(403);
    expect(outside.status).toBe(403);
    expect(outside.body).toEqual(inside.body);
    // Negative: neither wrote a row.
    expect(await User.countDocuments({})).toBe(0);
  });

  it('open mode: an address outside the allowlist costs the same bcrypt work as one that registers', async () => {
    setRegistration({ mode: 'open', domains: ['example.org'] });
    const hash = vi.spyOn(bcrypt, 'hash');

    const refused = await register(registrationBody('outsider@example.com'));
    const refusedHashes = hash.mock.calls.length;
    hash.mockClear();
    const admitted = await register(registrationBody('insider@example.org'));

    expect(refused.status).toBe(201);
    expect(admitted.status).toBe(201);
    expect(refused.body).toEqual(admitted.body);
    // Exactly the one hash a real registration makes: deleting the equalising hash
    // makes the refusal measurably faster than an admission.
    expect(refusedHashes).toBe(1);
    expect(hash).toHaveBeenCalledTimes(1);
  });

  it('closed mode refuses before any bcrypt work, the same for every address', async () => {
    setRegistration({ mode: 'closed' });
    const hash = vi.spyOn(bcrypt, 'hash');

    const res = await register(registrationBody('anyone@example.com'));

    expect(res.status).toBe(403);
    expect(hash).not.toHaveBeenCalled();
  });
});

describe('POST /auth/invitations', () => {
  let inviter: TestUser;

  beforeEach(async () => {
    inviter = await createTestUser({ email: 'inviter@example.com' });
    setRegistration({ mode: 'invite', inviters: ['inviter@example.com'] });
  });

  it('mints a fragment link for an inviter proving the master password, stores only a hash and audits it', async () => {
    const res = await mint(inviter, 'Friend@Example.com');

    expect(res.status).toBe(201);
    const link = res.body.data.link as string;
    expect(link.startsWith(`${config.APP_URL}/register#invite=`)).toBe(true);
    const token = tokenOf(link);
    expect(token.length).toBeGreaterThanOrEqual(43);
    expect(new Date(res.body.data.expiresAt as string).getTime()).toBeGreaterThan(Date.now());

    const rows = await invitations().find({}).toArray();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.email).toBe('friend@example.com');
    expect(String(rows[0]?.userId)).toBe(inviter.id);
    expect(rows[0]?.tokenHash).not.toBe(token);
    expect(JSON.stringify(rows[0])).not.toContain(token);

    const audit = await AuditLog.findOne({
      userId: inviter.id,
      action: 'invitation_create',
    }).lean();
    expect(audit).not.toBeNull();
    expect(JSON.stringify(audit?.metadata)).not.toContain('friend@example.com');
    // No invitation mail: delivery is out of band.
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it('refuses an account that is not a configured inviter with 403 and mints nothing', async () => {
    const stranger = await createTestUser({ email: 'stranger@example.com' });
    const res = await mint(stranger, 'friend@example.com');
    expect(res.status).toBe(403);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('refuses a wrong master-password proof with 401, audits the failure and mints nothing', async () => {
    const res = await mint(inviter, 'friend@example.com', 'not-the-password');
    expect(res.status).toBe(401);
    // The one refusal sentence every proof route shares, which the client matches
    // exactly so a typo is reported without being refreshed and sent twice.
    expect((res.body as { message: string }).message).toBe(MASTER_PASSWORD_PROOF_REFUSED_MESSAGE);
    expect(await invitations().countDocuments({})).toBe(0);
    const failed = await AuditLog.findOne({
      userId: inviter.id,
      action: 'password_verification_failed',
    }).lean();
    expect(failed?.metadata).toMatchObject({ endpoint: 'invitation_create' });
  });

  it('refuses a request without the proof with 400 and mints nothing', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/invitations`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .set('Authorization', authHeader(inviter.accessToken))
      .send({ email: 'friend@example.com' });
    expect(res.status).toBe(400);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('refuses an unauthenticated request with 401', async () => {
    const agent = request.agent(app);
    const csrf = await getCsrf(agent);
    const res = await agent
      .post(`${API}/auth/invitations`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ authHash: 'x', email: 'friend@example.com' });
    expect(res.status).toBe(401);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('refuses with 409 when the server does not register by invitation', async () => {
    mutableConfig.REGISTRATION_MODE = 'open';
    const res = await mint(inviter, 'friend@example.com');
    expect(res.status).toBe(409);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('refuses an address outside the domain allowlist with 400', async () => {
    mutableConfig.REGISTRATION_ALLOWED_DOMAINS = ['example.org'];
    const res = await mint(inviter, 'friend@example.com');
    expect(res.status).toBe(400);
    expect(await invitations().countDocuments({})).toBe(0);
  });

  it('caps what one inviter can mint in a day', async () => {
    const { MAX_INVITATIONS_PER_INVITER_PER_DAY } = await import('@hvault/shared');
    for (let i = 0; i < MAX_INVITATIONS_PER_INVITER_PER_DAY; i += 1) {
      const res = await mint(inviter, `friend-${String(i)}@example.com`);
      expect(res.status).toBe(201);
    }
    const over = await mint(inviter, 'one-too-many@example.com');
    expect(over.status).toBe(429);
    expect(await invitations().countDocuments({})).toBe(MAX_INVITATIONS_PER_INVITER_PER_DAY);
  });
});

describe('the per-inviter daily cap counts from the primary (F-24)', () => {
  it('reads the count it decides on from the primary, under the mint lock', async () => {
    // Read then written under a lock; on a URI asking for `secondaryPreferred`, a
    // lagging secondary would undercount a burst of mints and let it pass the cap.
    const inviter = await createTestUser({ email: 'inviter@example.com' });
    setRegistration({ mode: 'invite', inviters: ['inviter@example.com'] });
    const counts: unknown[] = [];
    const real = mongoose.mongo.Collection.prototype.countDocuments;
    vi.spyOn(mongoose.mongo.Collection.prototype, 'countDocuments').mockImplementation(function (
      this: mongoose.mongo.Collection,
      ...args: Parameters<typeof real>
    ) {
      if (this.collectionName === 'invitations') {
        const preference = (args[1] as { readPreference?: string | { mode?: string } } | undefined)
          ?.readPreference;
        counts.push(typeof preference === 'string' ? preference : preference?.mode);
      }
      return real.apply(this, args);
    } as never);

    const res = await mint(inviter, 'invitee@example.com');

    expect(res.status).toBe(201);
    expect(counts).toEqual(['primary']);
  });
});

describe('invitation claims', () => {
  it('hands back only the claim it made, never a later one', async () => {
    const { mintInvitation, claimInvitation, returnInvitationClaim } =
      await import('../src/utils/invitations.js');
    const minted = await mintInvitation('claimed@example.com', null);
    const token = tokenOf(minted.link);

    const claimedAt = await claimInvitation(token, 'claimed@example.com');
    expect(claimedAt).toBeInstanceOf(Date);
    // A second claim loses: the invitation is spent.
    expect(await claimInvitation(token, 'claimed@example.com')).toBeNull();

    // A hand-back naming another moment undoes nothing.
    await returnInvitationClaim(token, 'claimed@example.com', new Date(claimedAt!.getTime() + 1));
    expect((await invitations().findOne({ email: 'claimed@example.com' }))?.consumedAt).toEqual(
      claimedAt,
    );

    await returnInvitationClaim(token, 'claimed@example.com', claimedAt!);
    expect((await invitations().findOne({ email: 'claimed@example.com' }))?.consumedAt).toBeFalsy();
  });
});
