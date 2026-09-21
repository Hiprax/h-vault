import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';

/**
 * The scan panel's three ways in.
 *
 * jsdom has no camera and no image decoder, so both are stubbed. What is being
 * pinned is not the decoding, which is covered by the cross-library round trip,
 * but the panel's behaviour around it: that the alternatives to a camera are
 * always offered, that a camera failure is reported with a remedy rather than a
 * shrug, and that the paste box is closed to every way a browser or a password
 * manager might read what is typed into it.
 */

const openCamera = vi.fn();
const listCameras = vi.fn().mockResolvedValue([]);
vi.mock('../../src/services/totpImport/camera', async () => {
  const actual = await vi.importActual<typeof import('../../src/services/totpImport/camera')>(
    '../../src/services/totpImport/camera',
  );
  return {
    ...actual,
    openCamera: (...args: unknown[]) => openCamera(...args),
    listCameras: () => listCameras(),
  };
});

const scan = vi.fn();
const close = vi.fn();
// Typed with its parameter, so the test can read back the callback the panel
// handed it rather than casting an untyped tuple.
const openQrScanner = vi.fn((_onUnavailable: (reason: string) => void) => ({ scan, close }));
vi.mock('../../src/services/totpImport/qrSandbox', () => ({
  openQrScanner: (onUnavailable: (reason: string) => void) => openQrScanner(onUnavailable),
}));

const { TotpScanPanel } = await import('../../src/components/tools/TotpScanPanel');
const { CameraError } = await import('../../src/services/totpImport/camera');

function renderPanel(overrides: Partial<Parameters<typeof TotpScanPanel>[0]> = {}) {
  const onDecoded = vi.fn();
  const onError = vi.fn();
  render(<TotpScanPanel onDecoded={onDecoded} onError={onError} status={null} {...overrides} />);
  return { onDecoded, onError };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal(
    'createImageBitmap',
    vi.fn(async () => ({ width: 10, height: 10, close: vi.fn() })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('the ways in', () => {
  it('offers the camera, a photo and a pasted link from the start', () => {
    // Not as fallbacks after a failure: a laptop camera is often missing, busy
    // or too coarse, and presenting the alternatives only after a failure makes
    // the failure feel like the end of the road.
    renderPanel();
    expect(screen.getByRole('button', { name: /use camera/i })).toBeInTheDocument();
    expect(screen.getByText(/upload a photo/i)).toBeInTheDocument();
    expect(screen.getByText(/paste an export link instead/i)).toBeInTheDocument();
  });

  it('tells the user where the codes are on their phone', () => {
    renderPanel();
    expect(screen.getByText(/Transfer accounts/)).toBeInTheDocument();
    expect(screen.getByText(/do this somewhere private/)).toBeInTheDocument();
  });

  it('hands a pasted link straight on, with no frame involved', async () => {
    const { onDecoded } = renderPanel();
    fireEvent.click(screen.getByText(/paste an export link instead/i));
    fireEvent.change(screen.getByLabelText('Export link'), {
      target: { value: '  otpauth-migration://offline?data=AA  ' },
    });
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /read link/i }));
    });
    expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    expect(openQrScanner).not.toHaveBeenCalled();
  });

  it('closes the paste box to spellcheck and to password managers', () => {
    // Chrome's enhanced spellcheck sends field contents off-device, which would
    // be the quietest way for a key to leave the machine.
    renderPanel();
    fireEvent.click(screen.getByText(/paste an export link instead/i));
    const box = screen.getByLabelText('Export link');
    expect(box).toHaveAttribute('spellcheck', 'false');
    expect(box).toHaveAttribute('autocomplete', 'off');
    expect(box).toHaveAttribute('data-1p-ignore');
    expect(box).toHaveAttribute('data-lpignore', 'true');
  });

  it('will not read an empty paste box', () => {
    renderPanel();
    fireEvent.click(screen.getByText(/paste an export link instead/i));
    expect(screen.getByRole('button', { name: /read link/i })).toBeDisabled();
  });
});

describe('the camera', () => {
  it('reports a refusal with the remedy, not just a failure', async () => {
    openCamera.mockRejectedValue(
      new CameraError('denied', 'Camera access was refused. Allow it from the padlock.'),
    );
    const { onError } = renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.stringContaining('padlock'));
    });
  });

  it('warns when the granted resolution is too low for a dense code', async () => {
    // A 640-wide sensor cannot put three pixels on a module of a batched export,
    // and saying so beats letting someone fight it for a minute.
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 640,
      height: 480,
      stop: vi.fn(),
    });
    renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });

    expect(await screen.findByText(/640 pixels wide/)).toBeInTheDocument();
  });

  it('shows the aiming guidance that actually helps, once running', async () => {
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1920,
      height: 1080,
      stop: vi.fn(),
    });
    renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });

    // Screen glare and brightness are the two counter-intuitive ones.
    expect(await screen.findByText(/brightness down to about half/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /stop camera/i })).toBeInTheDocument();
  });

  it('stops the camera and tears the frame down when switched off', async () => {
    const stop = vi.fn();
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1920,
      height: 1080,
      stop,
    });
    renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await act(async () => {
      fireEvent.click(await screen.findByRole('button', { name: /stop camera/i }));
    });

    expect(stop).toHaveBeenCalled();
    expect(close).toHaveBeenCalled();
  });
});

describe('the capture loop', () => {
  /** jsdom reports no intrinsic size for a video, so the loop needs one. */
  function giveVideoASize(width: number, height: number) {
    Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', {
      configurable: true,
      get: () => width,
    });
    Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', {
      configurable: true,
      get: () => height,
    });
  }

  it('crops the CENTRE SQUARE at native scale and hands the decoder a hit', async () => {
    // Never a downscale: a batched export is a dense code and shrinking the
    // frame destroys exactly the signal being looked for. The crop matches the
    // box drawn on screen.
    giveVideoASize(1920, 1080);
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1920,
      height: 1080,
      stop: vi.fn(),
    });
    scan.mockResolvedValue('otpauth-migration://offline?data=AA');
    const { onDecoded } = renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });

    await waitFor(() => {
      expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    });

    const crop = vi.mocked(globalThis.createImageBitmap).mock.calls[0];
    // 1080 square, centred horizontally in a 1920-wide frame.
    expect(crop?.slice(1)).toEqual([420, 0, 1080, 1080]);
  });

  it('keeps looking when a frame holds nothing, rather than stopping', async () => {
    giveVideoASize(1280, 720);
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1280,
      height: 720,
      stop: vi.fn(),
    });
    scan.mockResolvedValue(null);
    const { onDecoded, onError } = renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await waitFor(() => {
      expect(scan).toHaveBeenCalled();
    });

    // A miss while aiming is the common case, not an error worth showing.
    expect(onDecoded).not.toHaveBeenCalled();
    expect(onError).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /stop camera/i }));
    });
  });

  it('swallows a frame it could not grab, because the next one is 120 ms away', async () => {
    giveVideoASize(1280, 720);
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1280,
      height: 720,
      stop: vi.fn(),
    });
    vi.stubGlobal(
      'createImageBitmap',
      vi.fn(() => Promise.reject(new Error('gone'))),
    );
    const { onError } = renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await waitFor(() => {
      expect(globalThis.createImageBitmap).toHaveBeenCalled();
    });
    expect(onError).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /stop camera/i }));
    });
  });

  it('ends the session and says so when the frame itself dies', async () => {
    giveVideoASize(1280, 720);
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1280,
      height: 720,
      stop: vi.fn(),
    });
    const { onError } = renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await screen.findByRole('button', { name: /stop camera/i });

    // The driver reports an unavailable frame through the callback it was given.
    const onUnavailable = openQrScanner.mock.calls[0]?.[0];
    await act(async () => {
      onUnavailable?.('The scanner could not start. Paste your export link instead.');
    });

    expect(onError).toHaveBeenCalledWith(expect.stringContaining('Paste your export link'));
    expect(screen.getByRole('button', { name: /use camera/i })).toBeInTheDocument();
  });
});

describe('an uploaded photo', () => {
  it('decodes it through the frame and hands the result on', async () => {
    scan.mockResolvedValue('otpauth-migration://offline?data=AA');
    const { onDecoded } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    await waitFor(() => {
      expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    });
  });

  it('reports an image the scanner could not read at all', async () => {
    scan.mockRejectedValue(new Error('the frame died'));
    const { onError } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith('That image could not be read.');
    });
  });

  it('suggests a better photo when nothing was found, rather than blaming the file', async () => {
    scan.mockResolvedValue(null);
    const { onError } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith(expect.stringContaining('closer, sharper photo'));
    });
  });
});
