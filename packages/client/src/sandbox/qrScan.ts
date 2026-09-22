import decodeQR from 'qr/decode.js';
import {
  MAX_SANDBOX_QR_IMAGE_BYTES,
  MAX_SANDBOX_QR_IMAGE_SIDE,
  MAX_SANDBOX_QR_TEXT_LENGTH,
  type SandboxQrReply,
} from '@hvault/shared';

/**
 * The QR decoder, inside the isolated document.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS AS A SEPARATE MODULE
 * ---------------------------------------------------------------------------
 *
 * Two reasons, and the second one is not obvious.
 *
 * FIRST, containment. `qr` is a third-party decoder fed pixels that ultimately
 * come from whatever the camera was pointed at. Running it here means a
 * compromised release of it has no vault key beside it, no token, no storage and
 * no way to reach the network except a credential-less same-origin GET, rather
 * than sitting in the application's origin where `location =` is available. It
 * is the same rule that keeps Prettier and the JSON repairer out of the app.
 *
 * SECOND, the chunk name. `sandbox.ts` imports THIS module dynamically and this
 * module imports `qr/decode.js` statically. Importing `qr/decode.js` directly
 * from `sandbox.ts` would emit a chunk named after the package's own entry file,
 * `decode`, which is already the name of the chunk `src/sandbox/decode.ts`
 * produces. Rollup would resolve the collision as `decode2`, and `chunkBaseName`
 * in the bundle gate maps that to no budget at all, so the new chunk would be
 * silently unbudgeted. The wrapper is what gives it a name of its own.
 *
 * ---------------------------------------------------------------------------
 * WHAT GOES BACK
 * ---------------------------------------------------------------------------
 *
 * One bounded string, and only if it looks like an OTP URI. The frame does not
 * parse it, does not interpret it and never sends a pixel back. Refusing
 * anything that is not an `otpauth:` or `otpauth-migration:` URI here means a QR
 * code on a poster cannot hand the application an arbitrary string to reason
 * about, and it costs one regular expression.
 */

const OTP_URI = /^otpauth(-migration)?:/i;

/** Pixels, however the request carried them. */
async function toImageData(image: unknown): Promise<ImageData> {
  let bitmap: ImageBitmap;

  if (typeof ImageBitmap !== 'undefined' && image instanceof ImageBitmap) {
    bitmap = image;
  } else if (image instanceof Blob) {
    // The only control against a decompression bomb on this path, and it has to
    // come BEFORE the decode: the decoded size is what kills the tab, and by the
    // time a bitmap exists the memory is already gone.
    if (image.size > MAX_SANDBOX_QR_IMAGE_BYTES) {
      throw new Error('That image is too large to read.');
    }
    bitmap = await createImageBitmap(image);
  } else {
    throw new Error('The scan request was not understood.');
  }

  try {
    // Checked after the decode as well, because a small file can declare an
    // enormous canvas.
    if (bitmap.width > MAX_SANDBOX_QR_IMAGE_SIDE || bitmap.height > MAX_SANDBOX_QR_IMAGE_SIDE) {
      throw new Error('That image is too large to read.');
    }
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext('2d');
    if (context === null) throw new Error('This browser cannot read images here.');
    context.drawImage(bitmap, 0, 0);
    return context.getImageData(0, 0, bitmap.width, bitmap.height);
  } finally {
    // Release the decoded pixels as soon as they have been copied, rather than
    // waiting for collection: at a camera's frame rate that is the difference
    // between steady memory and a sawtooth.
    bitmap.close();
  }
}

/**
 * Decode one image.
 *
 * `effort` and `timeLimit` are the caller's, because a live camera frame and a
 * still photograph want opposite settings: a frame that does not read quickly
 * should be dropped for the next one, while a photograph deserves everything the
 * decoder has.
 */
export async function scanImage(
  requestId: number,
  image: unknown,
  effort: number,
  timeLimitMs: number,
): Promise<SandboxQrReply> {
  let pixels: ImageData;
  try {
    pixels = await toImageData(image);
  } catch (error) {
    // `qrFailed`, NOT `failed`, and the difference is the whole point of the
    // two kinds. Everything `toImageData` refuses is a property of THIS image —
    // too many bytes, too many pixels, a format this engine cannot decode — and
    // the next image may well be fine. Answering with the unattributable
    // `failed` told the host the session had died, which stopped a running
    // camera because somebody picked one oversized photograph.
    return {
      kind: 'qrFailed',
      requestId,
      reason: error instanceof Error ? error.message : 'Unreadable image.',
    };
  }

  let text: string;
  try {
    text = decodeQR(
      { width: pixels.width, height: pixels.height, data: pixels.data },
      { effort, timeLimit: timeLimitMs },
    );
  } catch {
    // The decoder throws when it finds nothing, which while aiming a camera is
    // the ordinary case rather than an error.
    return { kind: 'qrMiss', requestId };
  }

  if (text.length > MAX_SANDBOX_QR_TEXT_LENGTH || !OTP_URI.test(text)) {
    // A real code, but not one this feature can use. Reported as a miss so the
    // camera keeps looking rather than stopping on a poster.
    return { kind: 'qrMiss', requestId };
  }

  return { kind: 'qrFound', requestId, text };
}
