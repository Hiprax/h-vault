import { useCallback, useEffect, useRef, useState } from 'react';
import { Camera, CameraOff, Clipboard, ImageUp, Loader2 } from 'lucide-react';
import { MAX_SANDBOX_QR_IMAGE_BYTES } from '@hvault/shared';
import {
  CameraError,
  openCamera,
  RECOMMENDED_MIN_CAPTURE_WIDTH,
  type CameraHandle,
} from '../../services/totpImport/camera';
import {
  openQrScanner,
  QrImageRefusedError,
  type QrScanner,
} from '../../services/totpImport/qrSandbox';

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

  /**
   * How many times the SCANNER ITSELF has reported a reason, ever.
   *
   * The panel has a generic sentence for a scan that failed — "That image could
   * not be read." — and the driver has specific ones that name the remedy: "The
   * scanner could not start. Paste your export link instead.", or the
   * driver's sentence for the code the frame sent about an image it refused
   * (always the application's own words, never the frame's). Both arrive for
   * the SAME failure, and
   * the two consumers of this panel funnel both into one status line
   * (`onError={setStatus}`), so whichever lands last is the only one the user
   * ever sees.
   *
   * MEASURED, and it is an ordering that cannot be fixed by reordering: when a
   * frame never starts, `die()` rejects the outstanding scan and THEN calls back
   * with its reason, synchronously — but a promise rejection is delivered a
   * microtask later, so the generic sentence always lands second and erases the
   * remedy. Comparing this counter across the await is what lets the catch below
   * stay silent when something better has already been said.
   */
  const driverReports = useRef(0);

  const reportFromDriver = useCallback(
    (reason: string) => {
      driverReports.current += 1;
      onError(reason);
    },
    [onError],
  );

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
        reportFromDriver(reason);
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
  }, [onError, reportFromDriver, stopCamera]);

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

  /**
   * Decode an uploaded photo, through the camera's frame when one is running and
   * through a frame of its own when one is not.
   *
   * ## Why the close sits in a `finally`, keyed on what this call CREATED
   *
   * Two mistakes lived in three lines here, and both are only visible on the
   * failure path.
   *
   * The close used to sit AFTER the `await`, inside the `try`, so a scan that
   * REJECTED jumped straight past it. Every failed upload therefore left one
   * more hidden `/sandbox.html` iframe attached to the document — an
   * opaque-origin document with a live port, for the rest of the page's life —
   * and the failure was not rare: posting a `Blob` in a transfer list threw on
   * every single attempt, so the leak was the only outcome this path ever had.
   *
   * The condition used to re-read `scannerRef.current` AFTER the await, which
   * asks the wrong question. The question is not "is there a scanner now" but
   * "did I create this one": a camera started while the decode was in flight
   * makes the ref non-null and would strand the ad-hoc frame again, and a camera
   * STOPPED while it was in flight would have this call close a scanner that was
   * already closed. Recording what this call CREATED answers the real question,
   * and `close()` is idempotent either way.
   */
  const scanFile = useCallback(
    async (file: File) => {
      // REFUSED HERE AS WELL AS IN THE FRAME, and the two bounds are not
      // redundant. The frame's is the CONTROL: it is the only thing standing
      // between a decompression bomb and the tab, it is applied to bytes this
      // side cannot vouch for, and it cannot be moved here.
      //
      // This one is about COST and IMMEDIACY, and it is deliberately the weaker
      // claim of the two. It stops a structured clone of a dozen or more
      // mebibytes crossing what is, in Chromium, a process boundary, only to be
      // refused on the far side, and it answers instantly with a sentence naming
      // the limit. It closes NOTHING on its own: a 48 MP photograph is 8000 x
      // 6000 and routinely under this bound, and a format the engine cannot
      // decode has no size at all — both reach the frame and are refused there,
      // per request, by `SandboxQrFailedMessage`. That reply is what makes one
      // bad file cost one image instead of the whole session.
      if (file.size > MAX_SANDBOX_QR_IMAGE_BYTES) {
        if (fileInputRef.current !== null) fileInputRef.current.value = '';
        onError(
          // "or smaller", because the bound is `>`: a file of exactly this many
          // bytes is accepted. The number is derived from the constant so the
          // sentence cannot drift away from the rule it describes.
          `That photo is too large to read. It has to be ${String(Math.floor(MAX_SANDBOX_QR_IMAGE_BYTES / 1024 / 1024))} MB or smaller, and most phones can save or send a smaller copy.`,
        );
        return;
      }
      setBusy(true);
      // Read once, before anything can await: this is the record of whether the
      // scanner below belongs to this call or to the camera loop.
      const running = scannerRef.current;
      // Assigned only once `openQrScanner` has RETURNED, so a constructor that
      // throws leaves nothing to take down and still reaches the catch below.
      let created: QrScanner | null = null;
      // Read BEFORE the await: anything the driver reports from here on is more
      // specific than this function's own fallback, and must not be erased by it.
      const reportsBefore = driverReports.current;
      try {
        const scanner = running ?? openQrScanner(reportFromDriver);
        if (running === null) created = scanner;
        const text = await scanner.scan(file);
        if (text === null) {
          onError('No code was found in that image. A closer, sharper photo usually reads.');
          return;
        }
        onDecoded(text);
      } catch (error) {
        if (driverReports.current !== reportsBefore) {
          // The driver has ALREADY put a better sentence on screen — the remedy
          // for a frame that never started, or a failure it reported for itself.
          // Both consumers of this panel funnel every message into one status
          // line, so saying anything now would overwrite it with something
          // vaguer. Staying silent is the report.
        } else if (error instanceof QrImageRefusedError) {
          // The frame looked at this image and said, by code, which limit it
          // crossed; the driver has already turned that into its own sentence.
          onError(error.message);
        } else {
          onError('That image could not be read.');
        }
      } finally {
        // Never the camera's: closing that one would stop a running scan dead.
        created?.close();
        setBusy(false);
        if (fileInputRef.current !== null) fileInputRef.current.value = '';
      }
    },
    [onDecoded, onError, reportFromDriver],
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

        <label
          className={`inline-flex items-center gap-2 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] ${busy ? 'cursor-not-allowed opacity-50' : 'cursor-pointer hover:bg-[hsl(var(--accent))]'}`}
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ImageUp className="h-4 w-4" />}
          Upload a photo
          {/* An id, like every other upload control in the application, so a
              test can name THIS input rather than "the file input on the page"
              and keep naming it if a second one is ever added. */}
          <input
            ref={fileInputRef}
            id="totp-photo-input"
            type="file"
            accept="image/*"
            // One upload at a time, like the "Read link" button below. Not
            // cosmetic: with the camera running, an upload shares ITS session,
            // so without this a user picking three photographs in a row puts
            // four requests on one channel and the scanner's own reasoning
            // about how many can be outstanding stops being true.
            disabled={busy}
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
