import { useCallback, useEffect, useRef, useState } from 'react';
import { Camera, CameraOff, Clipboard, ImageUp, Loader2 } from 'lucide-react';
import {
  CameraError,
  openCamera,
  RECOMMENDED_MIN_CAPTURE_WIDTH,
  type CameraHandle,
} from '../../services/totpImport/camera';
import { openQrScanner, type QrScanner } from '../../services/totpImport/qrSandbox';

/**
 * The three ways a code gets in, and the camera loop behind the first of them.
 *
 * ---------------------------------------------------------------------------
 * WHY ALL THREE ARE ALWAYS VISIBLE
 * ---------------------------------------------------------------------------
 *
 * Pasting and uploading are not fallbacks shown after the camera fails; they sit
 * beside it from the start. A laptop camera is often too low-resolution for a
 * batched export, is frequently held by a video-call application, and does not
 * exist at all on plenty of machines. Presenting the alternatives only after a
 * failure makes the failure feel like the end of the road.
 *
 * ---------------------------------------------------------------------------
 * THE CAPTURE, AND WHY IT NEITHER SCALES NOR SHRINKS
 * ---------------------------------------------------------------------------
 *
 * A batched export is a dense code: version 20 to 30, so 97 to 137 modules
 * across, needing three to four camera pixels per module to read off a screen.
 * Downscaling the frame to make the transfer cheaper destroys exactly the signal
 * being looked for. So the capture takes the CENTRE SQUARE AT NATIVE SCALE,
 * matching the box drawn on screen, which costs about half the pixels of a full
 * frame while keeping every one inside the area the user was asked to fill.
 *
 * `createImageBitmap` does the crop, which means the host never allocates a
 * pixel buffer at all: the bitmap is a handle, and it is transferred.
 *
 * ---------------------------------------------------------------------------
 * PACING
 * ---------------------------------------------------------------------------
 *
 * One decode in flight at a time, and frames are DROPPED rather than queued. A
 * queue turns a slow decode into growing latency and, at four megabytes a frame,
 * into a growing backlog. About eight attempts a second is past the point where
 * re-reading the same optical frame stops helping.
 */

const CAPTURE_INTERVAL_MS = 120;

interface TotpScanPanelProps {
  readonly onDecoded: (text: string) => void;
  readonly onError: (message: string) => void;
  readonly status: string | null;
}

export function TotpScanPanel({ onDecoded, onError, status }: TotpScanPanelProps) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const cameraRef = useRef<CameraHandle | null>(null);
  const scannerRef = useRef<QrScanner | null>(null);
  const runningRef = useRef(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [cameraOn, setCameraOn] = useState(false);
  const [starting, setStarting] = useState(false);
  const [cameraNote, setCameraNote] = useState<string | null>(null);
  const [pasted, setPasted] = useState('');
  const [busy, setBusy] = useState(false);

  /**
   * Read the running flag through a call, not directly.
   *
   * The compiler narrows `runningRef.current` to `true` from the loop guard and
   * has no way to know an `await` inside the loop can change it, so the check
   * after the decode reads as redundant while being the one that stops a result
   * arriving after the camera was switched off.
   */
  const isRunning = useCallback(() => runningRef.current, []);

  const stopCamera = useCallback(() => {
    runningRef.current = false;
    cameraRef.current?.stop();
    cameraRef.current = null;
    scannerRef.current?.close();
    scannerRef.current = null;
    setCameraOn(false);
  }, []);

  // Teardown on unmount is not optional: a camera left running is a recording
  // light the user did not ask for.
  useEffect(() => stopCamera, [stopCamera]);

  const startCamera = useCallback(async () => {
    setStarting(true);
    setCameraNote(null);
    try {
      const camera = await openCamera();
      cameraRef.current = camera;
      const scanner = openQrScanner((reason) => {
        onError(reason);
        stopCamera();
      });
      scannerRef.current = scanner;

      const video = videoRef.current;
      if (video !== null) {
        // A try/catch rather than `.catch()`, because a browser that refuses
        // playback can throw SYNCHRONOUSLY, which never reaches a promise
        // handler and would abort the whole camera start. Refusal is not fatal
        // either way: the stream is attached and the frame grab reads the
        // element rather than its playback state.
        try {
          video.srcObject = camera.stream;
          await video.play();
        } catch {
          // Nothing to do; scanning proceeds without an autoplaying preview.
        }
      }

      if (camera.width > 0 && camera.width < RECOMMENDED_MIN_CAPTURE_WIDTH) {
        setCameraNote(
          `This camera captures at ${String(camera.width)} pixels wide. That is usually enough for a small export and may not read a full batch. Uploading a photo taken with another phone often works better.`,
        );
      }

      setCameraOn(true);
      runningRef.current = true;
      void pump();
    } catch (error) {
      stopCamera();
      onError(error instanceof CameraError ? error.message : 'The camera could not be started.');
    } finally {
      setStarting(false);
    }
    // `pump` is stable for the life of the component and depends only on refs.
  }, [onError, stopCamera]);

  /** Grab, decode, repeat. One in flight; a miss simply takes the next frame. */
  const pump = useCallback(async () => {
    while (runningRef.current) {
      const video = videoRef.current;
      const scanner = scannerRef.current;
      if (video === null || scanner === null) break;

      const width = video.videoWidth;
      const height = video.videoHeight;
      if (width > 0 && height > 0) {
        const side = Math.min(width, height);
        try {
          const bitmap = await createImageBitmap(
            video,
            Math.floor((width - side) / 2),
            Math.floor((height - side) / 2),
            side,
            side,
          );
          const text = await scanner.scan(bitmap);
          if (text !== null && isRunning()) {
            onDecoded(text);
          }
        } catch {
          // A frame that could not be grabbed or decoded is not an error worth
          // showing: the next one is 120 ms away.
        }
      }
      await new Promise((resolve) => setTimeout(resolve, CAPTURE_INTERVAL_MS));
    }
  }, [onDecoded, isRunning]);

  const scanFile = useCallback(
    async (file: File) => {
      setBusy(true);
      try {
        const scanner = scannerRef.current ?? openQrScanner(onError);
        const text = await scanner.scan(file);
        if (scannerRef.current === null) scanner.close();
        if (text === null) {
          onError('No code was found in that image. A closer, sharper photo usually reads.');
          return;
        }
        onDecoded(text);
      } catch {
        onError('That image could not be read.');
      } finally {
        setBusy(false);
        if (fileInputRef.current !== null) fileInputRef.current.value = '';
      }
    },
    [onDecoded, onError],
  );

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 space-y-3">
        <p className="text-sm font-medium text-[hsl(var(--foreground))]">
          On your phone: Google Authenticator, then the menu, then Transfer accounts, then Export
          accounts.
        </p>
        <p className="text-xs text-[hsl(var(--muted-foreground))]">
          Those codes contain your actual secret keys. Anyone who photographs this screen can clone
          them, so do this somewhere private.
        </p>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => (cameraOn ? stopCamera() : void startCamera())}
          disabled={starting}
          className="inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] disabled:opacity-50"
        >
          {starting ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : cameraOn ? (
            <CameraOff className="h-4 w-4" />
          ) : (
            <Camera className="h-4 w-4" />
          )}
          {cameraOn ? 'Stop camera' : 'Use camera'}
        </button>

        <label className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]">
          <ImageUp className="h-4 w-4" />
          Upload a photo
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            className="sr-only"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) void scanFile(file);
            }}
          />
        </label>
      </div>

      {/* The video element is mounted ALWAYS and hidden with CSS, never rendered
          conditionally. `startCamera` attaches the stream and starts the capture
          loop synchronously after `getUserMedia` resolves, and a conditionally
          rendered element does not exist yet at that point: React has not
          re-rendered. The measured consequence was total, and silent. The stream
          was never attached, `videoRef.current` was null when the loop checked
          it, the loop broke on its first iteration, and the preview sat black
          while the camera light stayed on. */}
      <div className={cameraOn ? 'space-y-2' : 'hidden'}>
        <div className="relative mx-auto aspect-square w-full max-w-sm overflow-hidden rounded-lg bg-black">
          {/* Mirrored for aiming only. The CAPTURE is never mirrored: QR
                layout is chirality-dependent and a mirrored raster does not
                decode. */}
          <video
            ref={videoRef}
            playsInline
            muted
            className="h-full w-full object-cover"
            style={{ transform: 'scaleX(-1)' }}
          />
          <div className="pointer-events-none absolute inset-6 rounded-lg border-2 border-white/70" />
        </div>
        <p className="text-center text-xs text-[hsl(var(--muted-foreground))]">
          Hold the phone about 30 cm away, filling the box. Turn its brightness down to about half
          and tilt it slightly, so the screen does not reflect a light into the camera.
        </p>
      </div>

      {cameraNote !== null && (
        <p role="status" className="text-xs text-amber-600 dark:text-amber-400">
          {cameraNote}
        </p>
      )}

      <details className="rounded-lg border border-[hsl(var(--border))] p-3">
        <summary className="cursor-pointer text-sm text-[hsl(var(--foreground))]">
          <Clipboard className="mr-1.5 inline h-3.5 w-3.5" />
          Paste an export link instead
        </summary>
        <div className="mt-3 space-y-2">
          <label htmlFor="totp-paste" className="sr-only">
            Export link
          </label>
          {/* Autofill, spellcheck and password-manager hints are all off: Chrome's
              enhanced spellcheck sends field contents off-device, which would be
              the quietest way for a key to leave this machine. */}
          <textarea
            id="totp-paste"
            value={pasted}
            onChange={(event) => setPasted(event.target.value)}
            rows={3}
            spellCheck={false}
            autoComplete="off"
            autoCorrect="off"
            autoCapitalize="off"
            data-1p-ignore
            data-lpignore="true"
            placeholder="otpauth-migration://offline?data=..."
            className="w-full rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] p-2 font-mono text-xs text-[hsl(var(--foreground))]"
          />
          <button
            type="button"
            disabled={pasted.trim().length === 0 || busy}
            onClick={() => {
              onDecoded(pasted.trim());
              setPasted('');
            }}
            className="rounded-md bg-[hsl(var(--primary))] px-3 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] disabled:opacity-50"
          >
            Read link
          </button>
        </div>
      </details>

      {status !== null && (
        <p role="status" className="text-sm text-[hsl(var(--foreground))]">
          {status}
        </p>
      )}
    </div>
  );
}
