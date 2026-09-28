/**
 * The release API modules parse every response instead of casting it, so a
 * malformed answer is refused at the boundary rather than rendered.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { makeNotes, makeRelease, makeStatus, makeUpdate } from './fixtures';

const client = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../../src/services/api/client.js', () => ({ api: client }));

import {
  checkForUpdateNowApi,
  getReleaseStatusApi,
  markReleaseNotesSeenApi,
} from '../../src/services/api/releaseStatusApi';
import { getReleaseNotesApi } from '../../src/services/api/releaseNotesApi';

const envelope = (data: unknown) => ({ data: { success: true, data } });

beforeEach(() => {
  client.get.mockReset();
  client.post.mockReset();
});

describe('release API', () => {
  it('reads the status from GET /releases/status', async () => {
    const status = makeStatus({ update: makeUpdate() });
    client.get.mockResolvedValue(envelope(status));
    await expect(getReleaseStatusApi()).resolves.toEqual(status);
    expect(client.get).toHaveBeenCalledWith('/releases/status');
  });

  it('refuses a status that does not match the schema', async () => {
    client.get.mockResolvedValue(envelope({ ...makeStatus(), version: 'latest' }));
    await expect(getReleaseStatusApi()).rejects.toThrow();
  });

  it('acknowledges with POST /releases/seen carrying the version', async () => {
    client.post.mockResolvedValue(envelope({ seenVersion: '0.15.0', unseenCount: 0 }));
    await expect(markReleaseNotesSeenApi('0.15.0')).resolves.toEqual({
      seenVersion: '0.15.0',
      unseenCount: 0,
    });
    expect(client.post).toHaveBeenCalledWith('/releases/seen', { version: '0.15.0' });
  });

  it('checks now with POST /releases/update-check', async () => {
    const result = { update: makeUpdate(), fetched: true };
    client.post.mockResolvedValue(envelope(result));
    await expect(checkForUpdateNowApi()).resolves.toEqual(result);
    expect(client.post).toHaveBeenCalledWith('/releases/update-check');
  });

  it('reads the notes from GET /releases/notes, and refuses a malformed entry', async () => {
    const notes = makeNotes([makeRelease('0.15.0', { isNew: true })]);
    client.get.mockResolvedValue(envelope(notes));
    await expect(getReleaseNotesApi()).resolves.toEqual(notes);
    expect(client.get).toHaveBeenCalledWith('/releases/notes');

    client.get.mockResolvedValue(
      envelope(makeNotes([{ ...makeRelease('0.15.0'), highlights: [] }])),
    );
    await expect(getReleaseNotesApi()).rejects.toThrow();
  });
});
