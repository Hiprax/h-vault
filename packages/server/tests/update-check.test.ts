/**
 * The release check (`utils/updateCheck.ts`), against a LOOPBACK stub in place of
 * GitHub and a real database.
 *
 * This is the server's second outbound HTTP call, so the first half pins what it
 * SENDS (a fixed User-Agent and API version, the configured repository, nothing
 * about the server or its users) and how it treats every kind of answer: a
 * redirect is not followed, an oversized or trickling body is abandoned, a 403 is
 * a rate limit only when GitHub says so, and nothing that is not a plain release
 * version is ever recorded as one. The second half pins what it RECORDS and
 * CLAIMS: a failure keeps the last known release, "current" needs a recent
 * success, and the administrators are emailed once per newer release.
 *
 * The egress guard installed by `tests/setup.ts` still blocks every non-loopback
 * host, so a case that forgot the stub records `unavailable` (the check never
 * throws) instead of reaching the internet.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { APP_VERSION, parseReleaseVersion } from '@hvault/shared';

const log = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }));
const mail = vi.hoisted(() => ({ configured: { value: true }, send: vi.fn() }));
const locks = vi.hoisted(() => ({
  failRelease: { value: false },
  // Runs just before a lock is taken: what another check did in the meantime.
  beforeAcquire: { value: null as (() => Promise<void>) | null },
}));

vi.mock('../src/utils/logger.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/logger.js')>();
  return {
    ...actual,
    createModuleLogger: (name: string) =>
      name === 'update-check' ? log : actual.createModuleLogger(name),
  };
});
vi.mock('../src/utils/jobLock.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/jobLock.js')>();
  return {
    ...actual,
    acquireJobLock: async (name: string, ttlMs: number) => {
      await locks.beforeAcquire.value?.();
      return actual.acquireJobLock(name, ttlMs);
    },
    releaseJobLock: (name: string, id: string) =>
      locks.failRelease.value
        ? Promise.reject(new Error('lock store unavailable'))
        : actual.releaseJobLock(name, id),
  };
});
vi.mock('../src/utils/email.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/email.js')>();
  return {
    ...actual,
    isEmailConfigured: () => mail.configured.value,
    sendUpdateAvailableEmail: mail.send,
  };
});

import { config } from '../src/config/index.js';
import {
  UPDATE_CHECK_API_VERSION,
  UPDATE_CHECK_FRESHNESS_MS,
  UPDATE_CHECK_MAX_RESPONSE_BYTES,
  UPDATE_CHECK_MIN_INTERVAL_MS,
} from '../src/constants/index.js';
import {
  UPDATE_CHECK_STATE_ID,
  UpdateCheckState,
  type IUpdateCheckState,
} from '../src/models/UpdateCheckState.js';
import { JobLock } from '../src/models/JobLock.js';
import { acquireJobLock } from '../src/utils/jobLock.js';
import { getRunningJobs } from '../src/utils/jobTracker.js';
import {
  UPDATE_CHECK_LOCK_NAME,
  checkForUpdateNow,
  deriveUpdateStatus,
  fetchLatestRelease,
  notifyAdministrators,
  performUpdateCheck,
  readUpdateStatus,
  runUpdateCheck,
} from '../src/utils/updateCheck.js';

const [major] = parseReleaseVersion(APP_VERSION)!;
const NEWER = `${String(major + 1)}.0.0`;
const NEWEST = `${String(major + 2)}.0.0`;
const OLDER = '0.0.1';
const REPOSITORY = 'Hiprax/h-vault';

const mutableConfig = config as unknown as {
  UPDATE_CHECK_REPOSITORY: string;
  UPDATE_CHECK_ENABLED: boolean;
  UPDATE_NOTIFY_EMAILS: string[];
};
const original = {
  repository: mutableConfig.UPDATE_CHECK_REPOSITORY,
  enabled: mutableConfig.UPDATE_CHECK_ENABLED,
  emails: mutableConfig.UPDATE_NOTIFY_EMAILS,
};

// ── The stub ─────────────────────────────────────────────────────────

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
let handler: Handler = () => undefined;
const seen: { url: string; method: string; headers: http.IncomingHttpHeaders }[] = [];
let server: http.Server;
let baseUrl = '';

function reply(status: number, body: string, headers: Record<string, string> = {}): Handler {
  return (_req, res) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(body);
  };
}

function release(tag: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    tag_name: tag,
    name: tag,
    draft: false,
    prerelease: false,
    published_at: '2026-09-28T09:00:00Z',
    html_url: `https://example.invalid/${tag}`,
    body: '### Added\n- something',
    ...extra,
  });
}

const fast = () => ({ baseUrl, socketTimeoutMs: 2_000, totalTimeoutMs: 3_000 });
const options = (now?: Date) => ({ fetch: fast(), ...(now ? { now: () => now } : {}) });

beforeAll(async () => {
  server = http.createServer((req, res) => {
    seen.push({ url: req.url ?? '', method: req.method ?? '', headers: req.headers });
    handler(req, res);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  baseUrl = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
});

beforeEach(() => {
  seen.length = 0;
  handler = reply(200, release(`v${NEWER}`));
  mutableConfig.UPDATE_CHECK_REPOSITORY = REPOSITORY;
  mutableConfig.UPDATE_CHECK_ENABLED = true;
  mutableConfig.UPDATE_NOTIFY_EMAILS = ['admin@example.com', 'second@example.com'];
  mail.configured.value = true;
  locks.failRelease.value = false;
  locks.beforeAcquire.value = null;
  mail.send.mockReset();
  mail.send.mockResolvedValue({ success: true, message: 'Email sent successfully.' });
  log.info.mockClear();
  log.warn.mockClear();
  log.error.mockClear();
});

afterEach(async () => {
  await Promise.all(getRunningJobs());
  mutableConfig.UPDATE_CHECK_REPOSITORY = original.repository;
  mutableConfig.UPDATE_CHECK_ENABLED = original.enabled;
  mutableConfig.UPDATE_NOTIFY_EMAILS = original.emails;
  vi.restoreAllMocks();
});

async function storedState(): Promise<IUpdateCheckState | null> {
  return UpdateCheckState.findById(UPDATE_CHECK_STATE_ID).lean();
}

function state(overrides: Partial<IUpdateCheckState> = {}): IUpdateCheckState {
  return {
    _id: UPDATE_CHECK_STATE_ID,
    repository: REPOSITORY,
    lastCheckedAt: new Date('2026-09-28T10:00:00Z'),
    lastCheckStatus: 'ok',
    ...overrides,
  };
}

// ── What the request sends ───────────────────────────────────────────

describe('fetchLatestRelease: the request', () => {
  it('asks for the configured repository with a fixed User-Agent and API version, and nothing else', async () => {
    await fetchLatestRelease(REPOSITORY, fast());
    expect(seen).toHaveLength(1);
    const [request] = seen;
    expect(request!.method).toBe('GET');
    expect(request!.url).toBe('/repos/Hiprax/h-vault/releases/latest');
    expect(request!.headers['user-agent']).toBe('H-Vault-Update-Check');
    expect(request!.headers['x-github-api-version']).toBe('2026-03-10');
    expect(request!.headers['accept']).toBe('application/vnd.github+json');
    expect(request!.headers['authorization']).toBeUndefined();
    expect(request!.headers['cookie']).toBeUndefined();
    // The running version is not disclosed anywhere in the request.
    expect(JSON.stringify(request)).not.toContain(APP_VERSION);
  });
});

// ── How each answer is read ─────────────────────────────────────────

describe('fetchLatestRelease: the answer', () => {
  it('reads a release: the version without its v, and the publication time', async () => {
    const result = await fetchLatestRelease(REPOSITORY, fast());
    expect(result).toEqual({
      outcome: 'ok',
      version: NEWER,
      publishedAt: new Date('2026-09-28T09:00:00Z'),
    });
  });

  it.each([
    ['null', null],
    ['unparseable', 'yesterday'],
    // Valid to Date.parse, but its extended-year ISO form is no timestamp the
    // wire schema (or any client) accepts, so storing it would break the status.
    ['beyond year 9999', '+275760-09-13T00:00:00Z'],
    // Four-digit years as written, but outside 0000-9999 once the offset is applied.
    ['one that reaches year 10000 in UTC', '9999-12-31T23:30:00-01:00'],
    ['one that falls before year 0000 in UTC', '0000-01-01T00:00:00+01:00'],
  ])(
    'keeps the release when the publication time is %s, recording no date',
    async (_label, value) => {
      handler = reply(200, release(`v${NEWER}`, { published_at: value }));
      expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({
        outcome: 'ok',
        version: NEWER,
        publishedAt: null,
      });
    },
  );

  it('reads a publication time given with an offset as the same instant', async () => {
    handler = reply(200, release(`v${NEWER}`, { published_at: '2026-09-28T11:00:00+02:00' }));
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({
      outcome: 'ok',
      version: NEWER,
      publishedAt: new Date('2026-09-28T09:00:00Z'),
    });
  });

  it('reports no release on 404', async () => {
    handler = reply(404, '{"message":"Not Found"}');
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'no_release' });
    expect(log.info).toHaveBeenCalledWith('The repository has no published release', {
      repository: REPOSITORY,
    });
  });

  it.each([
    ['429', 429, {}],
    ['403 with no requests remaining', 403, { 'x-ratelimit-remaining': '0' }],
    ['403 with Retry-After', 403, { 'retry-after': '60' }],
  ])('reports a rate limit on %s', async (_label, status, headers) => {
    handler = reply(status, '{"message":"rate limited"}', headers);
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'rate_limited' });
    expect(log.warn).toHaveBeenCalledWith(
      'GitHub rate limit reached; the next scheduled check will try again',
      { repository: REPOSITORY },
    );
  });

  it('does not call a 403 without rate-limit headers a rate limit', async () => {
    handler = reply(403, '{"message":"Forbidden"}', { 'x-ratelimit-remaining': '12' });
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn).toHaveBeenCalledWith('Release check got an unexpected answer', {
      repository: REPOSITORY,
      status: 403,
    });
  });

  it('does not follow a redirect, and says the repository may have moved', async () => {
    handler = reply(301, '', { location: `${baseUrl}/repositories/1/releases/latest` });
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(seen).toHaveLength(1);
    expect(log.warn).toHaveBeenCalledWith(
      'Release check was redirected: the repository may have moved; set UPDATE_CHECK_REPOSITORY',
      { repository: REPOSITORY, status: 301 },
    );
  });

  it.each([400, 500, 502])('reports an unexpected status %d as unavailable', async (status) => {
    handler = reply(status, '{}');
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn).toHaveBeenCalledWith('Release check got an unexpected answer', {
      repository: REPOSITORY,
      status,
    });
  });

  it('says a 410 may mean GitHub no longer supports the API version this server asks for', async () => {
    handler = reply(410, '{"message":"Gone"}');
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn).toHaveBeenCalledWith(
      'Release check was refused as gone: GitHub may no longer support the API version this H-Vault asks for; updating H-Vault fixes it',
      { repository: REPOSITORY, status: 410, apiVersion: UPDATE_CHECK_API_VERSION },
    );
    expect(log.warn).not.toHaveBeenCalledWith(
      'Release check got an unexpected answer',
      expect.anything(),
    );
  });

  it('refuses a body above the size cap', async () => {
    handler = reply(200, 'x'.repeat(UPDATE_CHECK_MAX_RESPONSE_BYTES + 1));
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn.mock.calls[0]?.[0]).toBe('Release check request failed');
  });

  it('abandons a server that trickles its answer, at the total deadline', async () => {
    const timers: NodeJS.Timeout[] = [];
    handler = (_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      timers.push(setInterval(() => res.write(' '), 10));
    };
    const started = Date.now();
    const result = await fetchLatestRelease(REPOSITORY, {
      baseUrl,
      socketTimeoutMs: 5_000,
      totalTimeoutMs: 150,
    });
    for (const timer of timers) clearInterval(timer);
    expect(result).toEqual({ outcome: 'unavailable' });
    // Well before the socket idle timeout, which the trickle keeps resetting.
    expect(Date.now() - started).toBeLessThan(4_000);
  });

  it('reports a connection failure as unavailable, never throwing', async () => {
    const closed = http.createServer();
    await new Promise<void>((resolve) => {
      closed.listen(0, '127.0.0.1', () => resolve());
    });
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => {
      closed.close(() => resolve());
    });
    const result = await fetchLatestRelease(REPOSITORY, {
      baseUrl: `http://127.0.0.1:${String(port)}`,
      socketTimeoutMs: 1_000,
      totalTimeoutMs: 2_000,
    });
    expect(result).toEqual({ outcome: 'unavailable' });
  });

  it('refuses an answer that is not JSON', async () => {
    handler = reply(200, '<html>not json</html>');
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn.mock.calls[0]?.[0]).toBe('Release check answer is not JSON');
  });

  it('refuses JSON that is not a release document', async () => {
    handler = reply(200, JSON.stringify({ tag_name: 42 }));
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn).toHaveBeenCalledWith('Release check answer is not a release document', {
      repository: REPOSITORY,
    });
  });

  it.each([
    ['a draft', release(`v${NEWER}`, { draft: true })],
    ['a prerelease', release(`v${NEWER}`, { prerelease: true })],
    ['a two-part tag', release('v1.2')],
    ['a tag without the v', release(NEWER)],
    ['a tag with a suffix', release(`v${NEWER}-rc.1`)],
  ])('never records %s as a release', async (_label, body) => {
    handler = reply(200, body);
    expect(await fetchLatestRelease(REPOSITORY, fast())).toEqual({ outcome: 'unavailable' });
    expect(log.warn).toHaveBeenCalledWith(
      'The latest release is not a release version this server can compare',
      { repository: REPOSITORY },
    );
  });
});

// ── What a check records ────────────────────────────────────────────

describe('runUpdateCheck', () => {
  const at = new Date('2026-09-28T12:00:00Z');

  it('records a found release and warns when it is newer than this server', async () => {
    const recorded = await runUpdateCheck(options(at));
    expect(recorded).toMatchObject({
      repository: REPOSITORY,
      latestVersion: NEWER,
      latestPublishedAt: new Date('2026-09-28T09:00:00Z'),
      lastCheckedAt: at,
      lastCheckStatus: 'ok',
      lastSuccessAt: at,
    });
    expect(await storedState()).toMatchObject({ latestVersion: NEWER, lastCheckStatus: 'ok' });
    expect(log.warn).toHaveBeenCalledWith('A newer H-Vault release is available', {
      running: APP_VERSION,
      latest: NEWER,
      releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/v${NEWER}`,
    });
  });

  it('does not warn when the latest release is this one', async () => {
    handler = reply(200, release(`v${APP_VERSION}`));
    await runUpdateCheck(options(at));
    expect(log.warn).not.toHaveBeenCalled();
  });

  it('clears the publication time when the new answer has none', async () => {
    await runUpdateCheck(options(at));
    handler = reply(200, release(`v${NEWER}`, { published_at: null }));
    const recorded = await runUpdateCheck(options(at));
    expect(recorded.latestPublishedAt).toBeUndefined();
  });

  it('keeps the last known release through a failed check, recording the failure', async () => {
    await runUpdateCheck(options(new Date('2026-09-27T00:00:00Z')));
    handler = reply(500, '{}');
    const recorded = await runUpdateCheck(options(at));
    expect(recorded).toMatchObject({
      latestVersion: NEWER,
      lastCheckedAt: at,
      lastCheckStatus: 'unavailable',
      lastSuccessAt: new Date('2026-09-27T00:00:00Z'),
    });
  });

  it('records "no release" as a success with nothing newer', async () => {
    await runUpdateCheck(options(new Date('2026-09-27T00:00:00Z')));
    handler = reply(404, '{}');
    const recorded = await runUpdateCheck(options(at));
    expect(recorded.lastCheckStatus).toBe('no_release');
    expect(recorded.lastSuccessAt).toEqual(at);
    expect(recorded.latestVersion).toBeUndefined();
    expect(recorded.latestPublishedAt).toBeUndefined();
  });

  it("discards another repository's findings, including whom it notified", async () => {
    await UpdateCheckState.create(
      state({
        repository: 'someone/fork',
        latestVersion: NEWEST,
        lastSuccessAt: new Date('2026-09-27T00:00:00Z'),
        notifiedVersion: NEWEST,
      }),
    );
    handler = reply(429, '{}');
    const recorded = await runUpdateCheck(options(at));
    expect(recorded.repository).toBe(REPOSITORY);
    expect(recorded.lastCheckStatus).toBe('rate_limited');
    expect(recorded.latestVersion).toBeUndefined();
    expect(recorded.lastSuccessAt).toBeUndefined();
    expect(recorded.notifiedVersion).toBeUndefined();
  });

  it("keeps the same repository's notification record", async () => {
    await UpdateCheckState.create(state({ notifiedVersion: NEWER }));
    const recorded = await runUpdateCheck(options(at));
    expect(recorded.notifiedVersion).toBe(NEWER);
  });
});

// ── What the audience is told ───────────────────────────────────────

describe('deriveUpdateStatus', () => {
  const now = new Date('2026-09-28T12:00:00Z');
  const successAgo = (ms: number) => new Date(now.getTime() - ms);

  it('is disabled, with nothing to report, when the operator turned checks off', () => {
    mutableConfig.UPDATE_CHECK_ENABLED = false;
    expect(deriveUpdateStatus(state({ latestVersion: NEWER, lastSuccessAt: now }), now)).toEqual({
      state: 'disabled',
      latestVersion: null,
      publishedAt: null,
      releaseUrl: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      canCheckNow: false,
    });
  });

  it('is unknown before any check', () => {
    expect(deriveUpdateStatus(null, now)).toEqual({
      state: 'unknown',
      latestVersion: null,
      publishedAt: null,
      releaseUrl: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      canCheckNow: true,
    });
  });

  it('is available after a fresh success that found a newer release', () => {
    const published = new Date('2026-09-26T08:00:00Z');
    expect(
      deriveUpdateStatus(
        state({ latestVersion: NEWER, latestPublishedAt: published, lastSuccessAt: now }),
        now,
      ),
    ).toEqual({
      state: 'available',
      latestVersion: NEWER,
      publishedAt: published.toISOString(),
      releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/v${NEWER}`,
      lastCheckedAt: '2026-09-28T10:00:00.000Z',
      lastSuccessAt: now.toISOString(),
      canCheckNow: true,
    });
  });

  it.each([
    ['the same release', APP_VERSION],
    ['an older release', OLDER],
  ])('is current after a fresh success that found %s', (_label, version) => {
    expect(
      deriveUpdateStatus(state({ latestVersion: version, lastSuccessAt: now }), now).state,
    ).toBe('current');
  });

  it('is current after a fresh success that found no release at all', () => {
    const result = deriveUpdateStatus(state({ lastSuccessAt: now }), now);
    expect(result.state).toBe('current');
    expect(result.latestVersion).toBeNull();
    expect(result.releaseUrl).toBeNull();
    expect(result.publishedAt).toBeNull();
  });

  it('trusts a success for exactly the freshness window, and not a millisecond longer', () => {
    const at = (age: number) =>
      deriveUpdateStatus(state({ latestVersion: NEWER, lastSuccessAt: successAgo(age) }), now)
        .state;
    expect(at(UPDATE_CHECK_FRESHNESS_MS - 1)).toBe('available');
    expect(at(UPDATE_CHECK_FRESHNESS_MS)).toBe('available');
    expect(at(UPDATE_CHECK_FRESHNESS_MS + 1)).toBe('unknown');
  });

  it('still reports the last known release while unknown', () => {
    const result = deriveUpdateStatus(
      state({ latestVersion: NEWER, lastSuccessAt: successAgo(UPDATE_CHECK_FRESHNESS_MS + 1) }),
      now,
    );
    expect(result).toMatchObject({ state: 'unknown', latestVersion: NEWER });
  });

  it('never reports a stored value that is not a release version', () => {
    const result = deriveUpdateStatus(state({ latestVersion: 'garbage', lastSuccessAt: now }), now);
    expect(result).toMatchObject({ state: 'current', latestVersion: null, releaseUrl: null });
  });
});

describe('readUpdateStatus', () => {
  it("ignores another repository's stored state", async () => {
    await UpdateCheckState.create(
      state({ repository: 'someone/fork', latestVersion: NEWER, lastSuccessAt: new Date() }),
    );
    expect((await readUpdateStatus()).state).toBe('unknown');
  });

  it('reads the stored state of the configured repository', async () => {
    await UpdateCheckState.create(state({ latestVersion: NEWER, lastSuccessAt: new Date() }));
    expect((await readUpdateStatus()).state).toBe('available');
  });

  it('reads nothing when checks are turned off', async () => {
    mutableConfig.UPDATE_CHECK_ENABLED = false;
    const findById = vi.spyOn(UpdateCheckState, 'findById');
    expect((await readUpdateStatus()).state).toBe('disabled');
    expect(findById).not.toHaveBeenCalled();
  });
});

// ── Telling the administrators ──────────────────────────────────────

describe('notifyAdministrators', () => {
  const published = new Date('2026-09-26T08:00:00Z');

  async function stored(overrides: Partial<IUpdateCheckState>): Promise<IUpdateCheckState> {
    await UpdateCheckState.create(state({ latestPublishedAt: published, ...overrides }));
    return (await storedState())!;
  }

  it('emails every administrator once about a newer release, and records it', async () => {
    await notifyAdministrators(await stored({ latestVersion: NEWER }));
    expect(mail.send.mock.calls).toEqual([
      [
        'admin@example.com',
        {
          current: APP_VERSION,
          latest: NEWER,
          publishedAt: published,
          releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/v${NEWER}`,
        },
      ],
      [
        'second@example.com',
        {
          current: APP_VERSION,
          latest: NEWER,
          publishedAt: published,
          releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/v${NEWER}`,
        },
      ],
    ]);
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
    expect(log.info).toHaveBeenCalledWith('Administrators told about a newer release', {
      latest: NEWER,
      delivered: 2,
    });

    // A second run for the same release sends nothing.
    mail.send.mockClear();
    await notifyAdministrators((await storedState())!);
    expect(mail.send).not.toHaveBeenCalled();
  });

  it('emails again for a release newer than the last one notified, but never for an older one', async () => {
    await notifyAdministrators(await stored({ latestVersion: NEWEST, notifiedVersion: NEWER }));
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect((await storedState())?.notifiedVersion).toBe(NEWEST);

    await UpdateCheckState.deleteMany({});
    mail.send.mockClear();
    await notifyAdministrators(await stored({ latestVersion: NEWER, notifiedVersion: NEWEST }));
    expect(mail.send).not.toHaveBeenCalled();
    expect((await storedState())?.notifiedVersion).toBe(NEWEST);
  });

  it.each([
    ['the latest release is this one', { latestVersion: APP_VERSION }],
    ['the latest release is older', { latestVersion: OLDER }],
    ['no release is known', {}],
  ])('sends nothing when %s', async (_label, overrides) => {
    await notifyAdministrators(await stored(overrides));
    expect(mail.send).not.toHaveBeenCalled();
    expect((await storedState())?.notifiedVersion).toBeUndefined();
  });

  it('sends nothing, and claims nothing, without an administrator list or without email', async () => {
    mutableConfig.UPDATE_NOTIFY_EMAILS = [];
    await notifyAdministrators(await stored({ latestVersion: NEWER }));
    mutableConfig.UPDATE_NOTIFY_EMAILS = ['admin@example.com'];
    mail.configured.value = false;
    await notifyAdministrators((await storedState())!);
    expect(mail.send).not.toHaveBeenCalled();
    expect((await storedState())?.notifiedVersion).toBeUndefined();
  });

  it('hands the claim back when every address fails, so the next check retries', async () => {
    mail.send.mockResolvedValue({ success: false, message: 'smtp_send_failed: refused' });
    await notifyAdministrators(await stored({ latestVersion: NEWEST, notifiedVersion: NEWER }));
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
    expect(log.warn).toHaveBeenCalledWith(
      'No administrator could be emailed about a newer release; the next check retries',
      { latest: NEWEST },
    );
  });

  it('removes the claim again when there was no earlier notification to restore', async () => {
    mail.send.mockResolvedValue({ success: false, message: 'smtp_send_failed: refused' });
    await notifyAdministrators(await stored({ latestVersion: NEWER }));
    expect((await storedState())?.notifiedVersion).toBeUndefined();
  });

  it('sends no publication date when the release has none', async () => {
    await UpdateCheckState.create(state({ latestVersion: NEWER }));
    await notifyAdministrators((await storedState())!);
    expect(mail.send).toHaveBeenCalledWith('admin@example.com', {
      current: APP_VERSION,
      latest: NEWER,
      publishedAt: null,
      releaseUrl: `https://github.com/${REPOSITORY}/releases/tag/v${NEWER}`,
    });
  });

  it('counts a send that throws as a failed one, and hands the claim back', async () => {
    mail.send.mockRejectedValue(new Error('template failed'));
    await expect(
      notifyAdministrators(await stored({ latestVersion: NEWEST, notifiedVersion: NEWER })),
    ).resolves.toBeUndefined();
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
    expect(log.warn).toHaveBeenCalledWith(
      'No administrator could be emailed about a newer release; the next check retries',
      { latest: NEWEST },
    );
    expect(log.info).not.toHaveBeenCalled();
  });

  it('still emails the next address after one send throws', async () => {
    mail.send
      .mockRejectedValueOnce(new Error('template failed'))
      .mockResolvedValueOnce({ success: true, message: 'Email sent successfully.' });
    await notifyAdministrators(await stored({ latestVersion: NEWER }));
    expect(mail.send.mock.calls.map(([to]) => to)).toEqual([
      'admin@example.com',
      'second@example.com',
    ]);
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
    expect(log.info).toHaveBeenCalledWith('Administrators told about a newer release', {
      latest: NEWER,
      delivered: 1,
    });
  });

  it('claims a record whose notification field is stored as null', async () => {
    await UpdateCheckState.collection.insertOne({
      ...state({ latestVersion: NEWER, latestPublishedAt: published }),
      notifiedVersion: null,
    } as never);
    await notifyAdministrators((await storedState())!);
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
  });

  it('keeps the claim when at least one address was reached', async () => {
    mail.send
      .mockResolvedValueOnce({ success: false, message: 'smtp_send_failed: refused' })
      .mockResolvedValueOnce({ success: true, message: 'Email sent successfully.' });
    await notifyAdministrators(await stored({ latestVersion: NEWER }));
    expect((await storedState())?.notifiedVersion).toBe(NEWER);
  });

  it('sends once when two checks race for the same release', async () => {
    const snapshot = await stored({ latestVersion: NEWER });
    await Promise.all([notifyAdministrators(snapshot), notifyAdministrators(snapshot)]);
    expect(mail.send).toHaveBeenCalledTimes(2);
  });
});

// ── The scheduled path and "Check now" ──────────────────────────────

describe('performUpdateCheck', () => {
  it('checks, records and notifies under the lock, then releases it', async () => {
    expect(await performUpdateCheck(options())).toBe(true);
    expect(seen).toHaveLength(1);
    expect((await storedState())?.latestVersion).toBe(NEWER);
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect(await JobLock.countDocuments({ jobName: UPDATE_CHECK_LOCK_NAME })).toBe(0);
  });

  it('does nothing while another check holds the lock', async () => {
    await acquireJobLock(UPDATE_CHECK_LOCK_NAME, 60_000);
    expect(await performUpdateCheck(options())).toBe(false);
    expect(seen).toHaveLength(0);
    expect(await storedState()).toBeNull();
  });

  it('logs a lock that cannot be released instead of throwing', async () => {
    locks.failRelease.value = true;
    expect(await performUpdateCheck(options())).toBe(true);
    expect(log.error).toHaveBeenCalledWith('Could not release the release-check lock', {
      error: 'lock store unavailable',
    });
  });

  it('logs a failure instead of throwing, and still releases the lock', async () => {
    vi.spyOn(UpdateCheckState, 'findById').mockImplementation(() => {
      throw new Error('database unavailable');
    });
    expect(await performUpdateCheck(options())).toBe(false);
    expect(log.error).toHaveBeenCalledWith('Release check failed', {
      error: 'database unavailable',
    });
    expect(await JobLock.countDocuments({ jobName: UPDATE_CHECK_LOCK_NAME })).toBe(0);
  });
});

describe('checkForUpdateNow', () => {
  it('asks GitHub, answers with a fresh status, and notifies in the background', async () => {
    const result = await checkForUpdateNow(options());
    expect(result.fetched).toBe(true);
    expect(result.update).toMatchObject({ state: 'available', latestVersion: NEWER });
    expect(seen).toHaveLength(1);
    await Promise.all(getRunningJobs());
    expect(mail.send).toHaveBeenCalledTimes(2);
    expect(await JobLock.countDocuments({ jobName: UPDATE_CHECK_LOCK_NAME })).toBe(0);
  });

  it('answers from the stored state inside the cooldown, without a request', async () => {
    const now = new Date('2026-09-28T12:00:00Z');
    await UpdateCheckState.create(
      state({
        latestVersion: NEWER,
        lastSuccessAt: now,
        lastCheckedAt: new Date(now.getTime() - UPDATE_CHECK_MIN_INTERVAL_MS + 1),
      }),
    );
    const result = await checkForUpdateNow(options(now));
    expect(result).toMatchObject({ fetched: false, update: { state: 'available' } });
    expect(seen).toHaveLength(0);
  });

  it('asks again once the cooldown has passed', async () => {
    const now = new Date('2026-09-28T12:00:00Z');
    await UpdateCheckState.create(
      state({ lastCheckedAt: new Date(now.getTime() - UPDATE_CHECK_MIN_INTERVAL_MS) }),
    );
    expect((await checkForUpdateNow(options(now))).fetched).toBe(true);
    expect(seen).toHaveLength(1);
  });

  it('does not ask again when another check finished while this one waited for the lock', async () => {
    const now = new Date('2026-09-28T12:00:00Z');
    await UpdateCheckState.create(
      state({ lastCheckedAt: new Date(now.getTime() - UPDATE_CHECK_MIN_INTERVAL_MS) }),
    );
    // Between this request's first read and its lock, another check completes.
    locks.beforeAcquire.value = async () => {
      await UpdateCheckState.updateOne(
        { _id: UPDATE_CHECK_STATE_ID },
        { $set: { lastCheckedAt: now, lastSuccessAt: now, latestVersion: NEWEST } },
      );
    };
    const result = await checkForUpdateNow(options(now));
    expect(result).toMatchObject({
      fetched: false,
      update: { state: 'available', latestVersion: NEWEST },
    });
    expect(seen).toHaveLength(0);
    expect(await JobLock.countDocuments({ jobName: UPDATE_CHECK_LOCK_NAME })).toBe(0);
  });

  it('answers from the stored state while another check holds the lock', async () => {
    await acquireJobLock(UPDATE_CHECK_LOCK_NAME, 60_000);
    const result = await checkForUpdateNow(options());
    expect(result.fetched).toBe(false);
    expect(result.update.state).toBe('unknown');
    expect(seen).toHaveLength(0);
  });

  it('logs a background notification failure instead of letting it escape', async () => {
    vi.spyOn(UpdateCheckState, 'updateOne').mockRejectedValue(new Error('database unavailable'));
    const result = await checkForUpdateNow(options());
    expect(result.fetched).toBe(true);
    await Promise.all(getRunningJobs());
    expect(log.error).toHaveBeenCalledWith('Release notification failed', {
      error: 'database unavailable',
    });
    expect(mail.send).not.toHaveBeenCalled();
  });
});
