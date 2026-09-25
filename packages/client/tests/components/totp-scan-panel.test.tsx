import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { MAX_SANDBOX_QR_IMAGE_BYTES } from '@hvault/shared';
import { QrImageRefusedError } from '../../src/services/totpImport/qrSandbox';

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
/** Every scanner ever closed, however many were created. */
const close = vi.fn();
/**
 * One close spy PER SCANNER, so a test can say WHICH scanner was closed.
 *
 * The shared `close` above cannot: with one object returned for every call, "it
 * was closed once" is true whether the upload's scanner or the camera's was the
 * one taken down, and those are opposite outcomes. Each entry here is the close
 * of the correspondingly-numbered `openQrScanner` call.
 */
const closes: ReturnType<typeof vi.fn>[] = [];
// Typed with its parameter, so the test can read back the callback the panel
// handed it rather than casting an untyped tuple.
const openQrScanner = vi.fn((_onUnavailable: (reason: string) => void) => {
  const own = vi.fn();
  closes.push(own);
  return {
    scan,
    close: () => {
      own();
      close();
    },
  };
});
// Spreads the REAL module, so `QrImageRefusedError` keeps its identity: the
// panel distinguishes a refused image from every other failure with
// `instanceof`, and a factory that returned only `openQrScanner` would leave
// that operator with an undefined right-hand side.
vi.mock('../../src/services/totpImport/qrSandbox', async () => {
  const actual = await vi.importActual<typeof import('../../src/services/totpImport/qrSandbox')>(
    '../../src/services/totpImport/qrSandbox',
  );
  return {
    ...actual,
    openQrScanner: (onUnavailable: (reason: string) => void) => openQrScanner(onUnavailable),
  };
});

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
  closes.length = 0;
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
    // The scanner this call created belongs to this call: it is closed however
    // the call ended, or its hidden frame stays attached for ever. A close that
    // sits after the `await` inside the `try` never runs on the path that needs
    // it most.
    expect(close).toHaveBeenCalled();
  });

  it('closes the scanner it created even when the photo simply held no code', async () => {
    scan.mockResolvedValue(null);
    renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    await waitFor(() => {
      expect(close).toHaveBeenCalled();
    });
  });

  it('leaves a RUNNING camera scanner open after an upload, rather than closing it', async () => {
    // The mirror of the rule above: the panel closes what IT created and never
    // the session the camera loop is still pumping. Closing that one would stop
    // the camera dead the first time somebody also tried a photo.
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1920,
      height: 1080,
      stop: vi.fn(),
    });
    scan.mockResolvedValue('otpauth-migration://offline?data=AA');
    renderPanel();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await screen.findByRole('button', { name: /stop camera/i });
    expect(openQrScanner).toHaveBeenCalledTimes(1);

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    // No second scanner was created, and the live one was not closed.
    expect(openQrScanner).toHaveBeenCalledTimes(1);
    expect(close).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /stop camera/i }));
    });
    expect(close).toHaveBeenCalled();
  });

  it('closes the scanner IT created even when a camera started mid-decode', async () => {
    // The question the close is keyed on is "did I create this one", not "is
    // there a scanner now". Reading the ref back AFTER the await asks the second
    // question, and a camera that started while the photo was decoding answers
    // it wrongly: the ad-hoc frame is stranded, with nothing left holding a
    // reference that could ever close it.
    openCamera.mockResolvedValue({
      stream: { getTracks: () => [], getVideoTracks: () => [] },
      width: 1920,
      height: 1080,
      stop: vi.fn(),
    });
    let finishScan: (text: string | null) => void = () => undefined;
    scan.mockImplementationOnce(
      () =>
        new Promise<string | null>((resolve) => {
          finishScan = resolve;
        }),
    );
    const { onDecoded } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });
    expect(openQrScanner).toHaveBeenCalledTimes(1);

    // The camera starts while that decode is still in flight, which is what puts
    // a DIFFERENT scanner in the ref.
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /use camera/i }));
    });
    await screen.findByRole('button', { name: /stop camera/i });
    expect(openQrScanner).toHaveBeenCalledTimes(2);

    scan.mockResolvedValue(null);
    await act(async () => {
      finishScan('otpauth-migration://offline?data=AA');
    });

    expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    // Named precisely: the FIRST scanner is the upload's and was closed; the
    // SECOND is the camera's and is still running. A count alone cannot tell
    // those two apart, and they are opposite outcomes.
    expect(closes[0]).toHaveBeenCalled();
    expect(closes[1]).not.toHaveBeenCalled();

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /stop camera/i }));
    });
    expect(closes[1]).toHaveBeenCalled();
  });

  it('refuses a photo over the size bound WITHOUT asking the frame', async () => {
    // The frame answers an oversized image with a failure it cannot attribute to
    // one request, so the host must read it as the session dying — which would
    // stop a running camera because somebody picked a 20 MB photo. Refusing
    // first keeps a bad file to itself, and names the limit.
    const { onError, onDecoded } = renderPanel();

    const huge = new File([new Uint8Array(4)], 'huge.png', { type: 'image/png' });
    Object.defineProperty(huge, 'size', { value: MAX_SANDBOX_QR_IMAGE_BYTES + 1 });

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, { target: { files: [huge] } });
    });

    expect(onError).toHaveBeenCalledWith(expect.stringContaining('too large to read'));
    // Derived from the constant rather than spelled out, so the sentence cannot
    // drift away from the bound it is describing — including "or smaller",
    // which is the `>` boundary stated in words.
    expect(onError).toHaveBeenCalledWith(expect.stringContaining('12 MB or smaller'));
    // The negatives, and the whole reason the check sits here: no frame was
    // stood up, nothing was sent, and nothing was decoded.
    expect(openQrScanner).not.toHaveBeenCalled();
    expect(scan).not.toHaveBeenCalled();
    expect(onDecoded).not.toHaveBeenCalled();
  });

  it('reads a photo exactly ON the bound, which is the largest allowed', async () => {
    // `n`, not just `n+1`: a `>=` here would refuse a file the frame accepts.
    scan.mockResolvedValue('otpauth-migration://offline?data=AA');
    const { onDecoded } = renderPanel();

    const exact = new File([new Uint8Array(4)], 'exact.png', { type: 'image/png' });
    Object.defineProperty(exact, 'size', { value: MAX_SANDBOX_QR_IMAGE_BYTES });

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, { target: { files: [exact] } });
    });

    await waitFor(() => {
      expect(onDecoded).toHaveBeenCalledWith('otpauth-migration://offline?data=AA');
    });
  });

  it("shows the DRIVER's sentence for one refused image, not its own generic one", async () => {
    // "That image could not be read." cannot say which limit was crossed. The
    // driver's sentence for the frame's code can, and it is the one worth
    // showing. (It is the application's own wording: the frame sends a code.)
    scan.mockRejectedValue(new QrImageRefusedError('That image is too large to read.'));
    const { onError } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    await waitFor(() => {
      expect(onError).toHaveBeenCalledWith('That image is too large to read.');
    });
    // The negative that makes this a precedence test: the vaguer sentence must
    // never follow and overwrite it, because both land on one status line.
    expect(onError).not.toHaveBeenCalledWith('That image could not be read.');
  });

  it('stays silent when the SCANNER has already reported a reason with a remedy', async () => {
    // MEASURED ordering, and it cannot be fixed by reordering: a dying session
    // rejects the outstanding scan and THEN reports its reason synchronously,
    // but the rejection is delivered a microtask later — so the generic sentence
    // always lands second and erases the remedy. The catch has to know to keep
    // quiet.
    let reject: (error: Error) => void = () => undefined;
    scan.mockImplementationOnce(
      () =>
        new Promise((_resolve, rejectScan) => {
          reject = rejectScan;
        }),
    );
    const { onError } = renderPanel();

    const input = document.querySelector('input[type="file"]');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    // The driver reports, then the scan it had already rejected settles.
    const onUnavailable = openQrScanner.mock.calls[0]?.[0];
    await act(async () => {
      onUnavailable?.('The scanner could not start. Paste your export link instead.');
      reject(new Error('the frame is gone'));
    });

    expect(onError).toHaveBeenCalledWith(expect.stringContaining('Paste your export link'));
    expect(onError).not.toHaveBeenCalledWith('That image could not be read.');
    // Exactly one sentence reached the single status line this panel writes to.
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it('will not start a second upload while one is still decoding', async () => {
    // With the camera running an upload shares ITS session, so unbounded
    // overlapping uploads would put an unbounded number of requests on one
    // channel. The "Read link" button is gated the same way.
    let finish: (text: string | null) => void = () => undefined;
    scan.mockImplementationOnce(
      () =>
        new Promise<string | null>((resolve) => {
          finish = resolve;
        }),
    );
    renderPanel();

    const input = document.querySelector('#totp-photo-input');
    await act(async () => {
      fireEvent.change(input!, {
        target: { files: [new File([new Uint8Array(4)], 'code.png', { type: 'image/png' })] },
      });
    });

    expect(input).toBeDisabled();

    await act(async () => {
      finish(null);
    });
    expect(input).not.toBeDisabled();
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
