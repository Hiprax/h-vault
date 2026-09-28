/**
 * The release-notes API: `GET /releases/status`, `GET /releases/notes`,
 * `POST /releases/seen` and `POST /releases/update-check`, end to end against a
 * real database.
 *
 * What would go wrong without each group below:
 *  - authentication: the running version would reach an anonymous caller, the
 *    exact disclosure `healthController` refuses in production;
 *  - the watermark: a new account would be shown history it never lived through,
 *    an older account would be shown nothing, and a stale tab or a race between
 *    two tabs could move the watermark BACKWARDS and replay notes already read;
 *  - the audience: update news and administrator-only notes would reach accounts
 *    the operator did not list.
 *
 * Every version used as a fixture is read from `RELEASE_NOTES` rather than
 * written out, so the suite holds as releases are added.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';
import axios from 'axios';
import mongoose from 'mongoose';
import { APP_VERSION, compareReleaseVersions } from '@hvault/shared';
import app from '../src/app.js';
import { config } from '../src/config/index.js';
import { User } from '../src/models/User.js';
import { UPDATE_CHECK_STATE_ID, UpdateCheckState } from '../src/models/UpdateCheckState.js';
import { RELEASE_NOTES } from '../src/content/releaseNotes.js';
import { RELEASE_NOTES_BASELINE_VERSION } from '../src/constants/index.js';
import { authHeader, createTestUser, getCsrf, type TestUser } from './helpers.js';

const API = '/api/v1';
const agent = request.agent(app);

const mutableConfig = config as unknown as {
  UPDATE_NOTIFY_EMAILS: string[];
  UPDATE_CHECK_ENABLED: boolean;
};
const originalAudience = mutableConfig.UPDATE_NOTIFY_EMAILS;
const originalEnabled = mutableConfig.UPDATE_CHECK_ENABLED;

const newest = RELEASE_NOTES[0]!.version;
const previous = RELEASE_NOTES[1]!.version;
const older = RELEASE_NOTES[2]!.version;

beforeEach(() => {
  mutableConfig.UPDATE_NOTIFY_EMAILS = [];
  mutableConfig.UPDATE_CHECK_ENABLED = true;
});

afterEach(() => {
  mutableConfig.UPDATE_NOTIFY_EMAILS = originalAudience;
  mutableConfig.UPDATE_CHECK_ENABLED = originalEnabled;
  vi.restoreAllMocks();
});

async function setWatermark(userId: string, version: string | undefined): Promise<void> {
  await User.collection.updateOne(
    { _id: new mongoose.Types.ObjectId(userId) },
    version === undefined
      ? { $unset: { releaseNotesSeenVersion: '' } }
      : { $set: { releaseNotesSeenVersion: version } },
  );
}

async function storedWatermark(userId: string): Promise<unknown> {
  const doc = await User.collection.findOne({ _id: new mongoose.Types.ObjectId(userId) });
  return doc?.releaseNotesSeenVersion;
}

function getStatus(user: TestUser) {
  return agent.get(`${API}/releases/status`).set('Authorization', authHeader(user.accessToken));
}

function getNotes(user: TestUser) {
  return agent.get(`${API}/releases/notes`).set('Authorization', authHeader(user.accessToken));
}

async function postSeen(user: TestUser, body: unknown) {
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/releases/seen`)
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie)
    .send(body as object);
}

async function postCheck(user: TestUser) {
  const csrf = await getCsrf(agent);
  return agent
    .post(`${API}/releases/update-check`)
    .set('Authorization', authHeader(user.accessToken))
    .set('x-csrf-token', csrf.token)
    .set('Cookie', csrf.cookie);
}

/** The number of entries above `version` in the newest-first content. */
function entriesAbove(version: string): number {
  return RELEASE_NOTES.filter((note) => compareReleaseVersions(note.version, version) > 0).length;
}

describe('the content the API serves', () => {
  it('starts at the running version and has at least three releases to use as fixtures', () => {
    expect(newest).toBe(APP_VERSION);
    expect(compareReleaseVersions(previous, newest)).toBe(-1);
    expect(compareReleaseVersions(older, previous)).toBe(-1);
  });
});

describe('authentication and CSRF', () => {
  it.each([
    ['get', '/releases/status'],
    ['get', '/releases/notes'],
    ['post', '/releases/seen'],
    ['post', '/releases/update-check'],
  ] as const)(
    'refuses %s %s without a session, never revealing the version',
    async (method, path) => {
      const csrf = await getCsrf(agent);
      const res = await agent[method](`${API}${path}`)
        .set('x-csrf-token', csrf.token)
        .set('Cookie', csrf.cookie)
        .send({ version: newest });
      expect(res.status).toBe(401);
      expect(JSON.stringify(res.body)).not.toContain(APP_VERSION);
    },
  );

  it('refuses a seen write without a CSRF token and leaves the watermark alone', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const res = await agent
      .post(`${API}/releases/seen`)
      .set('Authorization', authHeader(user.accessToken))
      .send({ version: newest });
    expect(res.status).toBe(403);
    expect(await storedWatermark(user.id)).toBe(older);
  });
});

describe('GET /releases/status', () => {
  it('reports the running version and its release page', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, newest);
    const res = await getStatus(user).expect(200);
    expect(res.body.success).toBe(true);
    expect(res.body.data.version).toBe(APP_VERSION);
    expect(res.body.data.releaseUrl).toBe(
      `https://github.com/Hiprax/h-vault/releases/tag/v${APP_VERSION}`,
    );
    expect(res.body.data.releaseNotes).toEqual({
      seenVersion: newest,
      unseenCount: 0,
      showOnUpdate: true,
    });
  });

  it('treats an account with no watermark as caught up to the baseline, without writing one', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, undefined);
    const res = await getStatus(user).expect(200);
    expect(res.body.data.releaseNotes.seenVersion).toBe(RELEASE_NOTES_BASELINE_VERSION);
    expect(res.body.data.releaseNotes.unseenCount).toBe(
      entriesAbove(RELEASE_NOTES_BASELINE_VERSION),
    );
    expect(await storedWatermark(user.id)).toBeUndefined();
  });

  it('treats a malformed stored watermark like a missing one', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, 'not-a-version');
    const res = await getStatus(user).expect(200);
    expect(res.body.data.releaseNotes.seenVersion).toBe(RELEASE_NOTES_BASELINE_VERSION);
  });

  it('counts every release newer than the watermark', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const res = await getStatus(user).expect(200);
    expect(res.body.data.releaseNotes.unseenCount).toBe(entriesAbove(older));
    expect(entriesAbove(older)).toBeGreaterThanOrEqual(2);
  });

  it('includes update information for the audience, and only for it', async () => {
    const user = await createTestUser();
    const outsider = await createTestUser();

    // No administrator list: every account is in the audience.
    const everyone = await getStatus(outsider).expect(200);
    expect(everyone.body.data.update).toMatchObject({ state: 'unknown', canCheckNow: true });

    // A list naming `user`. The configuration lower-cases the list when it loads
    // and the audience check lower-cases the account's address, which
    // release-notes-viewer.test.ts pins with a mixed-case address.
    mutableConfig.UPDATE_NOTIFY_EMAILS = [user.email.toLowerCase()];
    const listed = await getStatus(user).expect(200);
    expect(listed.body.data.update).not.toBeNull();
    const unlisted = await getStatus(outsider).expect(200);
    expect(unlisted.body.data.update).toBeNull();
  });

  it('reads the stored result only: the status never asks GitHub and never writes it', async () => {
    const user = await createTestUser();
    const get = vi.spyOn(axios, 'get');
    const response = await getStatus(user).expect(200);
    expect(response.body.data.update).toMatchObject({ state: 'unknown', lastCheckedAt: null });
    expect(get).not.toHaveBeenCalled();
    expect(await UpdateCheckState.countDocuments()).toBe(0);
  });

  it('reports update checks as turned off when the operator disabled them', async () => {
    mutableConfig.UPDATE_CHECK_ENABLED = false;
    const user = await createTestUser();
    const res = await getStatus(user).expect(200);
    expect(res.body.data.update).toEqual({
      state: 'disabled',
      latestVersion: null,
      publishedAt: null,
      releaseUrl: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      canCheckNow: false,
    });
  });

  it('reads the showReleaseNotes setting, defaulting it on an account that has none', async () => {
    const user = await createTestUser();
    await User.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(user.id) },
      { $unset: { 'settings.showReleaseNotes': '' } },
    );
    expect((await getStatus(user).expect(200)).body.data.releaseNotes.showOnUpdate).toBe(true);

    const csrf = await getCsrf(agent);
    const put = await agent
      .put(`${API}/user/settings`)
      .set('Authorization', authHeader(user.accessToken))
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({ showReleaseNotes: false })
      .expect(200);
    expect(put.body.data.showReleaseNotes).toBe(false);
    expect((await getStatus(user).expect(200)).body.data.releaseNotes.showOnUpdate).toBe(false);

    const profile = await agent
      .get(`${API}/user/profile`)
      .set('Authorization', authHeader(user.accessToken))
      .expect(200);
    expect(profile.body.data.settings.showReleaseNotes).toBe(false);
  });

  it('answers 404 when the account disappears between sign-in checks and the read', async () => {
    const user = await createTestUser();
    const realFindById = User.findById.bind(User);
    let calls = 0;
    // The first read is the session check in `authenticate`; the second is the
    // controller's own, which finds the account gone.
    vi.spyOn(User, 'findById').mockImplementation(((id: unknown) => {
      calls += 1;
      if (calls === 1) return realFindById(id as string);
      return { read: () => ({ select: () => ({ lean: () => Promise.resolve(null) }) }) };
    }) as unknown as typeof User.findById);
    const res = await getStatus(user);
    expect(res.status).toBe(404);
    expect(res.body.message).toBe('User not found');
  });

  it('never puts the watermark in the profile', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const profile = await agent
      .get(`${API}/user/profile`)
      .set('Authorization', authHeader(user.accessToken))
      .expect(200);
    expect(profile.body.data).not.toHaveProperty('releaseNotesSeenVersion');
  });
});

describe('GET /releases/notes', () => {
  it('serves every release, newest first, marking those newer than the watermark', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, previous);
    const res = await getNotes(user).expect(200);
    expect(res.body.data.version).toBe(APP_VERSION);
    expect(res.body.data.seenVersion).toBe(previous);
    const releases = res.body.data.releases as { version: string; isNew: boolean }[];
    expect(releases.map((release) => release.version)).toEqual(
      RELEASE_NOTES.map((note) => note.version),
    );
    expect(releases.filter((release) => release.isNew).map((release) => release.version)).toEqual([
      newest,
    ]);
  });

  it('serves the audience the authored content itself', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, newest);
    const res = await getNotes(user).expect(200);
    const releases = res.body.data.releases as Record<string, unknown>[];
    expect(releases.map(({ isNew: _isNew, ...rest }) => rest)).toEqual(
      JSON.parse(JSON.stringify(RELEASE_NOTES)),
    );
  });

  it('withholds administrator-only items, and releases left without a highlight, from others', async () => {
    const user = await createTestUser();
    mutableConfig.UPDATE_NOTIFY_EMAILS = ['someone-else@example.com'];
    const res = await getNotes(user).expect(200);
    const releases = res.body.data.releases as {
      version: string;
      highlights: { audience?: string }[];
      changes: { audience?: string }[];
    }[];
    for (const release of releases) {
      expect(release.highlights.length).toBeGreaterThan(0);
      expect(release.changes.length).toBeGreaterThan(0);
      for (const item of [...release.highlights, ...release.changes]) {
        expect(item.audience).not.toBe('administrators');
      }
    }
    const expectedVersions = RELEASE_NOTES.filter((note) =>
      note.highlights.some((highlight) => highlight.audience !== 'administrators'),
    ).map((note) => note.version);
    expect(releases.map((release) => release.version)).toEqual(expectedVersions);
  });
});

describe('POST /releases/seen', () => {
  it.each<[unknown, string]>([
    ['0.15', 'two parts'],
    ['v1.0.0', 'a tag prefix'],
    ['1.0.0-rc.1', 'a prerelease'],
    ['01.0.0', 'a leading zero'],
    ['1'.repeat(25), 'an over-long value'],
    [15, 'a number'],
  ])('refuses %j (%s) with 400 and writes nothing', async (version) => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const res = await postSeen(user, { version });
    expect(res.status).toBe(400);
    expect(await storedWatermark(user.id)).toBe(older);
  });

  it('refuses a body with no version', async () => {
    const user = await createTestUser();
    expect((await postSeen(user, {})).status).toBe(400);
  });

  it('moves the watermark forward and answers with the new state', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const res = await postSeen(user, { version: previous });
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ seenVersion: previous, unseenCount: entriesAbove(previous) });
    expect(await storedWatermark(user.id)).toBe(previous);
  });

  it('gives an account with no watermark one, once there is a release past the baseline', async () => {
    // Such an account reads as caught up to the baseline, so acknowledging the
    // newest release writes a watermark exactly when that release is newer than
    // the baseline, and writes nothing (not even the baseline) when it is not.
    const user = await createTestUser();
    await setWatermark(user.id, undefined);
    const res = await postSeen(user, { version: newest });
    expect(res.status).toBe(200);
    const advances = compareReleaseVersions(newest, RELEASE_NOTES_BASELINE_VERSION) > 0;
    expect(await storedWatermark(user.id)).toBe(advances ? newest : undefined);
    expect(res.body.data.seenVersion).toBe(advances ? newest : RELEASE_NOTES_BASELINE_VERSION);
  });

  it('never moves the watermark backwards, and a repeat is a no-op', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, previous);
    const back = await postSeen(user, { version: older });
    expect(back.status).toBe(200);
    expect(back.body.data.seenVersion).toBe(previous);
    expect(await storedWatermark(user.id)).toBe(previous);

    const same = await postSeen(user, { version: previous });
    expect(same.body.data.seenVersion).toBe(previous);
    expect(await storedWatermark(user.id)).toBe(previous);
  });

  it('never moves the watermark past the running version', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const res = await postSeen(user, { version: '999999.0.0' });
    expect(res.status).toBe(200);
    expect(res.body.data).toEqual({ seenVersion: APP_VERSION, unseenCount: 0 });
    expect(await storedWatermark(user.id)).toBe(APP_VERSION);
  });

  it('ends at the newest acknowledged version when two tabs finish at once', async () => {
    const user = await createTestUser();
    for (let round = 0; round < 5; round += 1) {
      await setWatermark(user.id, older);
      const csrfA = await getCsrf(agent);
      const csrfB = await getCsrf(agent);
      const send = (version: string, csrf: { token: string; cookie: string }) =>
        agent
          .post(`${API}/releases/seen`)
          .set('Authorization', authHeader(user.accessToken))
          .set('x-csrf-token', csrf.token)
          .set('Cookie', csrf.cookie)
          .send({ version });
      const [a, b] = await Promise.all([send(newest, csrfA), send(previous, csrfB)]);
      expect([a.status, b.status]).toEqual([200, 200]);
      expect(await storedWatermark(user.id)).toBe(newest);
    }
  });

  it('re-reads and retries when another write lands between its read and its write', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    const realUpdateOne = User.updateOne.bind(User);
    let intercepted = false;
    vi.spyOn(User, 'updateOne').mockImplementation(((filter: object, update: object) => {
      if (!intercepted) {
        intercepted = true;
        // Another tab moves the watermark after this request read it.
        return User.collection
          .updateOne(
            { _id: new mongoose.Types.ObjectId(user.id) },
            { $set: { releaseNotesSeenVersion: previous } },
          )
          .then(() => realUpdateOne(filter, update));
      }
      return realUpdateOne(filter, update);
    }) as unknown as typeof User.updateOne);

    const res = await postSeen(user, { version: newest });
    expect(res.status).toBe(200);
    expect(res.body.data.seenVersion).toBe(newest);
    expect(await storedWatermark(user.id)).toBe(newest);
    expect(vi.mocked(User.updateOne)).toHaveBeenCalledTimes(2);
  });

  it('gives up after three collisions and answers with what is stored', async () => {
    const user = await createTestUser();
    await setWatermark(user.id, older);
    vi.spyOn(User, 'updateOne').mockResolvedValue({ matchedCount: 0 } as never);

    const res = await postSeen(user, { version: newest });
    expect(res.status).toBe(200);
    expect(res.body.data.seenVersion).toBe(older);
    expect(vi.mocked(User.updateOne)).toHaveBeenCalledTimes(3);
    expect(await storedWatermark(user.id)).toBe(older);
  });
});

describe('registration', () => {
  it('starts a new account caught up to the running version', async () => {
    const csrf = await getCsrf(agent);
    const email = `release-notes-${String(Date.now())}@example.com`;
    const res = await agent
      .post(`${API}/auth/register`)
      .set('x-csrf-token', csrf.token)
      .set('Cookie', csrf.cookie)
      .send({
        email,
        authHash: 'my-auth-hash-value',
        encryptedVaultKey: 'enc-vault-key',
        vaultKeyIv: 'vault-iv',
        vaultKeyTag: 'vault-tag',
        kdfIterations: 600_000,
        kdfAlgorithm: 'PBKDF2-SHA256',
        encryptionVersion: 1,
        releaseNotesSeenVersion: '0.0.1',
      });
    expect(res.status).toBe(201);
    const stored = await User.collection.findOne({ email });
    // The server's value, not the one smuggled into the body.
    expect(stored?.releaseNotesSeenVersion).toBe(APP_VERSION);
  });
});

describe('POST /releases/update-check', () => {
  it('is refused with 403 to an account outside the audience, without asking GitHub', async () => {
    const user = await createTestUser();
    mutableConfig.UPDATE_NOTIFY_EMAILS = ['someone-else@example.com'];
    const fetch = vi.spyOn(axios, 'get');
    const res = await postCheck(user);
    expect(res.status).toBe(403);
    expect(res.body.message).toBe("Only this server's administrators can check for updates.");
    expect(fetch).not.toHaveBeenCalled();
  });

  it('is refused with 409 while checks are turned off', async () => {
    mutableConfig.UPDATE_CHECK_ENABLED = false;
    const user = await createTestUser();
    const fetch = vi.spyOn(axios, 'get');
    const res = await postCheck(user);
    expect(res.status).toBe(409);
    expect(res.body.message).toBe('Update checks are turned off on this server.');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('asks GitHub and records the answer', async () => {
    const user = await createTestUser();
    const fetch = vi.spyOn(axios, 'get').mockResolvedValue({
      status: 200,
      headers: {},
      data: JSON.stringify({
        tag_name: `v${APP_VERSION}`,
        draft: false,
        prerelease: false,
        published_at: '2026-09-28T09:00:00Z',
      }),
    });
    const res = await postCheck(user);
    expect(res.status).toBe(200);
    expect(res.body.data.fetched).toBe(true);
    expect(res.body.data.update).toMatchObject({ state: 'current', latestVersion: APP_VERSION });
    expect(fetch).toHaveBeenCalledTimes(1);
    const stored = await UpdateCheckState.findById(UPDATE_CHECK_STATE_ID).lean();
    expect(stored?.lastCheckStatus).toBe('ok');
  });

  it('answers from the stored state inside the cooldown', async () => {
    const user = await createTestUser();
    await UpdateCheckState.create({
      _id: UPDATE_CHECK_STATE_ID,
      repository: config.UPDATE_CHECK_REPOSITORY,
      latestVersion: '999999.0.0',
      lastCheckedAt: new Date(),
      lastCheckStatus: 'ok',
      lastSuccessAt: new Date(),
    });
    const fetch = vi.spyOn(axios, 'get');
    const res = await postCheck(user);
    expect(res.status).toBe(200);
    expect(res.body.data.fetched).toBe(false);
    expect(res.body.data.update).toMatchObject({ state: 'available', latestVersion: '999999.0.0' });
    expect(fetch).not.toHaveBeenCalled();
  });
});
