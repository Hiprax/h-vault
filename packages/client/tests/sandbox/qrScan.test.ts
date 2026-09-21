import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { MAX_SANDBOX_QR_IMAGE_BYTES, MAX_SANDBOX_QR_IMAGE_SIDE } from '@hvault/shared';

/**
 * The frame's side of the scan, with the browser pieces stubbed.
 *
 * jsdom has neither `OffscreenCanvas` nor `createImageBitmap`, and neither is
 * what this file is about: the real decoding is covered by the cross-library
 * round trip beside it. What belongs here is the frame's own policy — what it
 * agrees to decode at all, and what it refuses to hand back.
 */

const decodeQR = vi.fn();
vi.mock('qr/decode.js', () => ({ default: (...args: unknown[]) => decodeQR(...args) }));

const { scanImage } = await import('../../src/sandbox/qrScan');

class FakeImageBitmap {
  constructor(
    readonly width: number,
    readonly height: number,
  ) {}
  close = vi.fn();
}

const pixels = { data: new Uint8ClampedArray(4), width: 1, height: 1 };

beforeEach(() => {
  decodeQR.mockReset();
  vi.stubGlobal('ImageBitmap', FakeImageBitmap);
  vi.stubGlobal(
    'OffscreenCanvas',
    class {
      getContext() {
        return { drawImage: vi.fn(), getImageData: () => pixels };
      }
    },
  );
  vi.stubGlobal(
    'createImageBitmap',
    vi.fn(async () => new FakeImageBitmap(100, 100)),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function bitmap(width = 100, height = 100) {
  return new FakeImageBitmap(width, height) as unknown as ImageBitmap;
}

describe('what the frame agrees to hand back', () => {
  it('returns a decoded export link with the id it was asked under', async () => {
    decodeQR.mockReturnValue('otpauth-migration://offline?data=AAAA');
    await expect(scanImage(7, bitmap(), 2, 120)).resolves.toEqual({
      kind: 'qrFound',
      requestId: 7,
      text: 'otpauth-migration://offline?data=AAAA',
    });
  });

  it('returns a single account link too', async () => {
    decodeQR.mockReturnValue('otpauth://totp/a?secret=JBSWY3DPEHPK3PXP');
    const reply = await scanImage(1, bitmap(), 2, 120);
    expect(reply.kind).toBe('qrFound');
  });

  it('reports a code it cannot use as a MISS, so the camera keeps looking', async () => {
    // A poster in the background is a real QR code and is not an error; stopping
    // the scan on one would strand the user.
    decodeQR.mockReturnValue('https://example.com/not-an-otp');
    expect((await scanImage(1, bitmap(), 2, 120)).kind).toBe('qrMiss');
  });

  it('reports no code found as a miss, which while aiming is the common case', async () => {
    decodeQR.mockImplementation(() => {
      throw new Error('not found');
    });
    expect((await scanImage(1, bitmap(), 2, 120)).kind).toBe('qrMiss');
  });

  it('refuses an oversized decoded string rather than passing it on', async () => {
    decodeQR.mockReturnValue(`otpauth://${'x'.repeat(20_000)}`);
    expect((await scanImage(1, bitmap(), 2, 120)).kind).toBe('qrMiss');
  });

  it('passes the effort settings it was given through to the decoder', async () => {
    decodeQR.mockReturnValue('otpauth://totp/a?secret=AA');
    await scanImage(1, bitmap(), 9, 250);
    expect(decodeQR.mock.calls[0]?.[1]).toEqual({ effort: 9, timeLimit: 250 });
  });

  it('releases the decoded pixels rather than waiting for collection', async () => {
    // At a camera's frame rate this is the difference between steady memory and
    // a sawtooth.
    decodeQR.mockReturnValue('otpauth://totp/a?secret=AA');
    const image = new FakeImageBitmap(100, 100);
    await scanImage(1, image as unknown as ImageBitmap, 2, 120);
    expect(image.close).toHaveBeenCalled();
  });
});

describe('what the frame refuses to decode at all', () => {
  it('refuses an image larger than it will read, BEFORE decoding it', async () => {
    // The only control against a decompression bomb: a 64000 x 64000 PNG is a
    // few hundred kilobytes on the wire and about 16 GB decoded, and by the time
    // a bitmap exists the memory is already gone.
    const huge = new Blob([new Uint8Array(10)]);
    Object.defineProperty(huge, 'size', { value: MAX_SANDBOX_QR_IMAGE_BYTES + 1 });
    const reply = await scanImage(1, huge, 2, 120);
    expect(reply.kind).toBe('failed');
    expect(globalThis.createImageBitmap).not.toHaveBeenCalled();
  });

  it('refuses an image whose decoded dimensions are enormous', async () => {
    // A small file can still declare a huge canvas, which is why the check
    // happens on both sides of the decode.
    const reply = await scanImage(1, bitmap(MAX_SANDBOX_QR_IMAGE_SIDE + 1, 10), 2, 120);
    expect(reply.kind).toBe('failed');
  });

  it('refuses something that is not an image at all', async () => {
    expect((await scanImage(1, { nope: true }, 2, 120)).kind).toBe('failed');
  });

  it('decodes an uploaded file by way of the browser, in the frame', async () => {
    decodeQR.mockReturnValue('otpauth://totp/a?secret=AA');
    const reply = await scanImage(3, new Blob([new Uint8Array(4)]), 2, 120);
    expect(globalThis.createImageBitmap).toHaveBeenCalled();
    expect(reply.kind).toBe('qrFound');
  });
});
