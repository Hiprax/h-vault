import { describe, it, expect } from 'vitest';
import QRCode from 'qrcode';
import decodeQR from 'qr/decode.js';
import { parseMigrationUri } from '../../src/services/totpImport/migrationUri';
import { encodeMigrationUri, sampleSecret } from '../support/migrationEncoder';

/**
 * The QR leg, decoded for real, in Node, with no browser and no canvas.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT CIRCULAR
 * ---------------------------------------------------------------------------
 *
 * `qrcode` (soldair) encodes and `qr` (paulmillr) decodes, and they share no
 * code. A round trip between them exercises the encoder's version selection,
 * mask choice and Reed-Solomon generation against the decoder's finder-pattern
 * location, perspective correction, sampling and error correction. A bug in
 * either shows up as a failure rather than as two copies of the same mistake
 * agreeing with each other.
 *
 * It needs no canvas because `QRCode.create` returns the module matrix directly,
 * so the raster can be built by hand. That is what makes this a plain unit test
 * rather than something only the browser suite could run.
 *
 * The protobuf leg is a first-party round trip and is covered elsewhere; what is
 * cross-implementation here is the QR itself.
 */

interface Raster {
  width: number;
  height: number;
  data: Uint8ClampedArray;
  version: number;
}

/** Render a QR to RGBA at `scale` pixels per module, with a quiet zone. */
function rasterise(text: string, scale = 4, quiet = 4): Raster {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'L' });
  const size = qr.modules.size;
  const src = qr.modules.data;
  const dim = (size + quiet * 2) * scale;
  const data = new Uint8ClampedArray(dim * dim * 4).fill(255);

  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      if (!src[y * size + x]) continue;
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const px = ((y + quiet) * scale + dy) * dim + (x + quiet) * scale + dx;
          data[px * 4] = 0;
          data[px * 4 + 1] = 0;
          data[px * 4 + 2] = 0;
        }
      }
    }
  }
  return { width: dim, height: dim, data, version: qr.version };
}

function decode(raster: Raster): string {
  return decodeQR(
    { width: raster.width, height: raster.height, data: raster.data },
    { effort: Number.POSITIVE_INFINITY, timeLimit: Number.POSITIVE_INFINITY },
  );
}

function tryDecode(raster: Raster): string | null {
  try {
    return decode(raster);
  } catch {
    return null;
  }
}

/** Rotate a square raster by an exact quarter turn: a permutation, no resampling. */
function rotate(raster: Raster, quarters: number): Raster {
  let current = raster;
  for (let turn = 0; turn < quarters; turn += 1) {
    const { width, height, data } = current;
    const out = new Uint8ClampedArray(data.length);
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const from = (y * width + x) * 4;
        const to = (x * height + (height - 1 - y)) * 4;
        for (let channel = 0; channel < 4; channel += 1) {
          out[to + channel] = data[from + channel] ?? 0;
        }
      }
    }
    current = { width: height, height: width, data: out, version: current.version };
  }
  return current;
}

function mirror(raster: Raster): Raster {
  const { width, height, data } = raster;
  const out = new Uint8ClampedArray(data.length);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const from = (y * width + x) * 4;
      const to = (y * width + (width - 1 - x)) * 4;
      for (let channel = 0; channel < 4; channel += 1) {
        out[to + channel] = data[from + channel] ?? 0;
      }
    }
  }
  return { ...raster, data: out };
}

const ONE_ACCOUNT = encodeMigrationUri({
  entries: [{ secret: sampleSecret(), name: 'Acme:alice@example.com', issuer: 'Acme' }],
  version: 1,
  batchSize: 1,
  batchIndex: 0,
  batchId: 77,
});

describe('a real QR round trip, across two independent implementations', () => {
  it('decodes an export link back to the accounts it carried', () => {
    const decoded = decode(rasterise(ONE_ACCOUNT, 6));
    expect(decoded).toBe(ONE_ACCOUNT);

    const payload = parseMigrationUri(decoded);
    expect(payload.entries).toHaveLength(1);
    expect(payload.entries[0]?.issuer).toBe('Acme');
  });

  it('survives every quarter turn, because a phone is never held straight', () => {
    for (const quarters of [1, 2, 3]) {
      expect(tryDecode(rotate(rasterise(ONE_ACCOUNT, 6), quarters))).toBe(ONE_ACCOUNT);
    }
  });

  it('FAILS on a mirrored image, which is why the capture is never mirrored', () => {
    // The preview is mirrored so aiming feels right, and the capture must not
    // be: QR layout is chirality-dependent. This turns that comment into a fact
    // somebody would have to delete a passing test to ignore.
    expect(tryDecode(mirror(rasterise(ONE_ACCOUNT, 6)))).toBeNull();
  });
});

describe('scale, and what this test can and cannot say about it', () => {
  it('reads a clean raster at every scale, down to one pixel per module', () => {
    // MEASURED, and worth recording because it contradicts the obvious guess.
    // On a synthetic, noise-free raster at maximum effort the decoder manages
    // even one pixel per module.
    //
    // So this test does NOT pin the three-to-four pixels the scanner's guidance
    // asks for. That figure is a property of PHOTOGRAPHING A SCREEN — sensor
    // noise, defocus, perspective, and the moire between two pixel grids — none
    // of which a generated bitmap has. Asserting a failure here would be pinning
    // an artefact of this fixture rather than anything about a camera, and it
    // would break the day the decoder improved.
    for (const scale of [1, 2, 3, 4, 8]) {
      expect(tryDecode(rasterise(ONE_ACCOUNT, scale))).toBe(ONE_ACCOUNT);
    }
  });

  it('a ten-account export really is a dense code', () => {
    // Version 20 and up is 97 modules across, which at three pixels each needs
    // about 300 pixels of the frame before any margin. That is the number behind
    // the low-resolution warning the scanner shows.
    const many = encodeMigrationUri({
      entries: Array.from({ length: 10 }, (_, i) => ({
        secret: sampleSecret(i + 1),
        name: `Service${String(i)}:user${String(i)}@example.com`,
        issuer: `Service${String(i)}`,
      })),
      version: 1,
      batchSize: 1,
      batchIndex: 0,
      batchId: 5,
    });
    const raster = rasterise(many, 5);
    expect(raster.version).toBeGreaterThanOrEqual(20);
    expect(tryDecode(raster)).toBe(many);
  });
});
