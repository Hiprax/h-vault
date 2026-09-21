/**
 * Opening a camera, and saying something useful when it cannot be opened.
 *
 * ---------------------------------------------------------------------------
 * WHY THE ERROR TAXONOMY IS THE POINT
 * ---------------------------------------------------------------------------
 *
 * "Could not start the camera" is the single least useful thing this feature
 * could say, because the four things that actually go wrong have four different
 * remedies and the user can act on three of them immediately. Permission was
 * refused: the padlock in the address bar. There is no camera: use a photo or
 * paste the link. Another application holds it: quit the meeting app, which on a
 * laptop is overwhelmingly the common case and is invisible unless named. The
 * page is not on a secure origin: only reachable on a misconfigured self-host,
 * and it tells the operator exactly what to fix.
 *
 * ---------------------------------------------------------------------------
 * RESOLUTION IS THE WHOLE GAME, AND `ideal` IS WHY THIS DOES NOT THROW
 * ---------------------------------------------------------------------------
 *
 * A batched Google Authenticator export is a dense code, version 20 to 30, which
 * is 97 to 137 modules across. Reading one off a phone screen needs three to
 * four camera pixels per module, so a 480p webcam physically cannot do it and a
 * 720p one is marginal. Hence `ideal: 1920`.
 *
 * Every constraint here is `ideal` rather than exact, because an EXACT constraint
 * a device cannot meet throws `OverconstrainedError` and gives the user nothing
 * at all, where a lower resolution would at least have worked for a small
 * export. The one retry below covers a device that refuses the whole shape
 * anyway, and the granted settings are reported back so the UI can warn before
 * the user spends a minute failing to scan.
 *
 * `mediaDevices` is injected so the failure branches can be driven in tests;
 * jsdom has no camera at all, so without a seam none of this would be reachable.
 */

/**
 * `navigator.mediaDevices`, read through a widened view.
 *
 * The DOM types declare it non-optional, so the compiler believes the checks
 * below are redundant. They are not: the whole API is HIDDEN outside a secure
 * context, which is precisely the case this module has to report rather than
 * crash on.
 */
function defaultMediaDevices(): MediaDevices | undefined {
  return (globalThis.navigator as { mediaDevices?: MediaDevices } | undefined)?.mediaDevices;
}

export type CameraFailure =
  'denied' | 'not-found' | 'in-use' | 'insecure' | 'unsupported' | 'unknown';

export class CameraError extends Error {
  readonly reason: CameraFailure;

  constructor(reason: CameraFailure, message: string) {
    super(message);
    this.name = 'CameraError';
    this.reason = reason;
  }
}

export interface CameraHandle {
  readonly stream: MediaStream;
  /** What the browser actually granted, which is rarely what was asked for. */
  readonly width: number;
  readonly height: number;
  /** Idempotent. */
  readonly stop: () => void;
}

/** Below this the modules of a dense export code fall under three pixels each. */
export const RECOMMENDED_MIN_CAPTURE_WIDTH = 1280;

const IDEAL_CONSTRAINTS: MediaStreamConstraints = {
  audio: false,
  video: {
    facingMode: { ideal: 'environment' },
    width: { ideal: 1920 },
    height: { ideal: 1080 },
    // A lower frame rate often unlocks a higher-resolution mode on the same
    // sensor, and this feature would rather have pixels than frames.
    frameRate: { ideal: 15, max: 30 },
  },
};

function describe(error: unknown): CameraError {
  const name = error instanceof Error ? error.name : '';
  switch (name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return new CameraError(
        'denied',
        'Camera access was refused. Allow it from the padlock in your address bar, or paste your export link instead.',
      );
    case 'NotFoundError':
    case 'DevicesNotFoundError':
      return new CameraError(
        'not-found',
        'No camera was found on this device. Upload a photo of the code, or paste your export link.',
      );
    case 'NotReadableError':
    case 'TrackStartError':
      return new CameraError(
        'in-use',
        'Another application is using the camera. Close it, such as a video-call app, and try again.',
      );
    default:
      return new CameraError('unknown', 'The camera could not be started.');
  }
}

/**
 * Open a camera, falling back once on a device that refuses the ideal shape.
 *
 * Rejects with a {@link CameraError} and nothing else, so the caller has one
 * type to narrow and a sentence it can show without rewriting.
 */
export async function openCamera(
  mediaDevices: MediaDevices | undefined = defaultMediaDevices(),
  deviceId?: string,
): Promise<CameraHandle> {
  if (mediaDevices === undefined) {
    // No `mediaDevices` at all means an insecure origin far more often than an
    // ancient browser: the API is hidden outside a secure context.
    throw new CameraError(
      'insecure',
      'This page must be served over HTTPS to use the camera. Paste your export link instead.',
    );
  }
  if (typeof mediaDevices.getUserMedia !== 'function') {
    throw new CameraError('unsupported', 'This browser cannot open a camera here.');
  }

  const wanted: MediaStreamConstraints =
    deviceId === undefined
      ? IDEAL_CONSTRAINTS
      : { audio: false, video: { deviceId: { exact: deviceId }, width: { ideal: 1920 } } };

  let stream: MediaStream;
  try {
    stream = await mediaDevices.getUserMedia(wanted);
  } catch (error) {
    if (error instanceof Error && error.name === 'OverconstrainedError') {
      // Exactly one retry, at the lowest bar the API has. A device that refuses
      // this has nothing to offer.
      try {
        stream = await mediaDevices.getUserMedia({ audio: false, video: true });
      } catch (retryError) {
        throw describe(retryError);
      }
    } else {
      throw describe(error);
    }
  }

  const [track] = stream.getVideoTracks();
  const settings = track?.getSettings() ?? {};

  return {
    stream,
    width: settings.width ?? 0,
    height: settings.height ?? 0,
    stop: () => {
      for (const each of stream.getTracks()) each.stop();
    },
  };
}

/** The cameras a user could choose between, or an empty list. */
export async function listCameras(
  mediaDevices: MediaDevices | undefined = defaultMediaDevices(),
): Promise<MediaDeviceInfo[]> {
  if (mediaDevices === undefined || typeof mediaDevices.enumerateDevices !== 'function') return [];
  try {
    const devices = await mediaDevices.enumerateDevices();
    return devices.filter((device) => device.kind === 'videoinput');
  } catch {
    // Enumeration failing is not worth surfacing: the camera itself may still
    // open, and the only thing lost is the ability to pick a different one.
    return [];
  }
}
