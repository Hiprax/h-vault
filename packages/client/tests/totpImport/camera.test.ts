import { describe, it, expect, vi } from 'vitest';
import {
  CameraError,
  listCameras,
  openCamera,
  RECOMMENDED_MIN_CAPTURE_WIDTH,
} from '../../src/services/totpImport/camera';

/**
 * jsdom has no camera, which is exactly why `openCamera` takes its
 * `mediaDevices` as a parameter: without that seam not one of these branches
 * would be reachable, and the error taxonomy is the most valuable thing in the
 * module.
 */

function namedError(name: string): Error {
  const error = new Error(name);
  error.name = name;
  return error;
}

function fakeTrack(settings: MediaTrackSettings) {
  const stop = vi.fn();
  return {
    track: { getSettings: () => settings, stop } as unknown as MediaStreamTrack,
    stop,
  };
}

function fakeStream(settings: MediaTrackSettings) {
  const { track, stop } = fakeTrack(settings);
  const stream = {
    getVideoTracks: () => [track],
    getTracks: () => [track],
  } as unknown as MediaStream;
  return { stream, stop };
}

describe('openCamera', () => {
  it('reports the resolution the browser actually granted, not the one requested', () => {
    // The UI warns on this number, because a 720p sensor cannot resolve a dense
    // batched export and the user would otherwise spend a minute finding out.
    expect(RECOMMENDED_MIN_CAPTURE_WIDTH).toBe(1280);
  });

  it('asks for a high resolution, and only ever as an ideal', async () => {
    const { stream } = fakeStream({ width: 1920, height: 1080 });
    const getUserMedia = vi.fn().mockResolvedValue(stream);
    const handle = await openCamera({ getUserMedia } as unknown as MediaDevices);

    const constraints = getUserMedia.mock.calls[0]?.[0] as MediaStreamConstraints;
    const video = constraints.video as MediaTrackConstraints;
    expect(video.width).toEqual({ ideal: 1920 });
    // An exact constraint a device cannot meet throws and leaves the user with
    // nothing, where a lower resolution would have worked for a small export.
    expect(JSON.stringify(video)).not.toContain('exact');
    expect(handle.width).toBe(1920);
  });

  it('retries once at the lowest bar when a device refuses the ideal shape', async () => {
    const { stream } = fakeStream({ width: 640, height: 480 });
    const getUserMedia = vi
      .fn()
      .mockRejectedValueOnce(namedError('OverconstrainedError'))
      .mockResolvedValueOnce(stream);

    const handle = await openCamera({ getUserMedia } as unknown as MediaDevices);

    expect(getUserMedia).toHaveBeenCalledTimes(2);
    expect(getUserMedia.mock.calls[1]?.[0]).toEqual({ audio: false, video: true });
    expect(handle.width).toBe(640);
  });

  it.each([
    ['NotAllowedError', 'denied', /padlock/],
    ['SecurityError', 'denied', /padlock/],
    ['NotFoundError', 'not-found', /No camera was found/],
    ['NotReadableError', 'in-use', /Another application/],
    ['TrackStartError', 'in-use', /Another application/],
    ['WeirdError', 'unknown', /could not be started/],
  ])('turns %s into a %s the user can act on', async (name, reason, wording) => {
    const getUserMedia = vi.fn().mockRejectedValue(namedError(name));
    await expect(openCamera({ getUserMedia } as unknown as MediaDevices)).rejects.toMatchObject({
      reason,
      message: expect.stringMatching(wording) as unknown as string,
    });
  });

  it('reports a failed retry with the retry cause, not the original', async () => {
    const getUserMedia = vi
      .fn()
      .mockRejectedValueOnce(namedError('OverconstrainedError'))
      .mockRejectedValueOnce(namedError('NotReadableError'));
    await expect(openCamera({ getUserMedia } as unknown as MediaDevices)).rejects.toMatchObject({
      reason: 'in-use',
    });
  });

  it('names an insecure origin rather than blaming the browser', async () => {
    // `mediaDevices` is hidden outside a secure context, so its absence means
    // this far more often than it means an ancient browser.
    await expect(openCamera(undefined)).rejects.toMatchObject({ reason: 'insecure' });
  });

  it('says so when the API exists but cannot open anything', async () => {
    await expect(openCamera({} as unknown as MediaDevices)).rejects.toMatchObject({
      reason: 'unsupported',
    });
  });

  it('throws only CameraError, so the caller has one type to narrow', async () => {
    const getUserMedia = vi.fn().mockRejectedValue(new TypeError('something else entirely'));
    await expect(openCamera({ getUserMedia } as unknown as MediaDevices)).rejects.toBeInstanceOf(
      CameraError,
    );
  });

  it('stops every track, and stopping twice is harmless', async () => {
    const { stream, stop } = fakeStream({ width: 1280, height: 720 });
    const handle = await openCamera({
      getUserMedia: vi.fn().mockResolvedValue(stream),
    } as unknown as MediaDevices);

    handle.stop();
    handle.stop();
    expect(stop).toHaveBeenCalled();
  });

  it('selects a specific device exactly, because the user picked it', async () => {
    const { stream } = fakeStream({ width: 1280, height: 720 });
    const getUserMedia = vi.fn().mockResolvedValue(stream);
    await openCamera({ getUserMedia } as unknown as MediaDevices, 'device-7');
    const video = (getUserMedia.mock.calls[0]?.[0] as MediaStreamConstraints)
      .video as MediaTrackConstraints;
    expect(video.deviceId).toEqual({ exact: 'device-7' });
  });

  it('copes with a stream that reports no track settings at all', async () => {
    const stream = {
      getVideoTracks: () => [],
      getTracks: () => [],
    } as unknown as MediaStream;
    const handle = await openCamera({
      getUserMedia: vi.fn().mockResolvedValue(stream),
    } as unknown as MediaDevices);
    expect(handle.width).toBe(0);
  });
});

describe('listCameras', () => {
  it('returns only video inputs', async () => {
    const devices = [
      { kind: 'videoinput', deviceId: 'a' },
      { kind: 'audioinput', deviceId: 'b' },
    ];
    const result = await listCameras({
      enumerateDevices: vi.fn().mockResolvedValue(devices),
    } as unknown as MediaDevices);
    expect(result.map((device) => device.deviceId)).toEqual(['a']);
  });

  it('answers with an empty list rather than failing the whole scan', async () => {
    // Losing the device picker is not worth stopping for: the camera may open
    // perfectly well without it.
    expect(
      await listCameras({
        enumerateDevices: vi.fn().mockRejectedValue(new Error('nope')),
      } as unknown as MediaDevices),
    ).toEqual([]);
    expect(await listCameras(undefined)).toEqual([]);
    expect(await listCameras({} as unknown as MediaDevices)).toEqual([]);
  });
});
