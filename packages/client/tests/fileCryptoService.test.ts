import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { CryptoManager, CryptoError } from '@hiprax/crypto';
import {
  encryptFile,
  decryptFile,
  describeFileCryptoError,
  isValidPassword,
  FileTooLargeError,
  MAX_CONTAINER_OVERHEAD_BYTES,
} from '../src/services/crypto/fileCryptoService';

// Fast Argon2id so the property matrix stays quick. The wire format still
// embeds these params (memoryCost 8192 clears the RFC 9106 §3.1 floor of
// 8 * parallelism), so round-trips remain byte-valid. Production omits this and
// uses the fixed 32 MiB browser default.
const FAST_OPTS = { managerOptions: { memoryCost: 8192, timeCost: 1 } } as const;

// Valid per the package rule (>= 20 chars). A distinct, also-valid wrong password.
const PASSWORD = 'Correct-Horse-Battery-Staple-9!';
const WRONG_PASSWORD = 'Totally-Different-Password-7?';

function fileOf(bytes: Uint8Array, name: string, type = ''): File {
  return new File([bytes], name, type ? { type } : undefined);
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  // Web Crypto caps getRandomValues at 65536 bytes per call — fill in chunks.
  for (let off = 0; off < n; off += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  }
  return out;
}

async function roundTrip(bytes: Uint8Array, name = 'file.bin', type = ''): Promise<Uint8Array> {
  const { blob, filename } = await encryptFile(fileOf(bytes, name, type), PASSWORD, FAST_OPTS);
  const encFile = fileOf(await bytesOf(blob), filename, 'application/octet-stream');
  const { blob: out } = await decryptFile(encFile, PASSWORD, FAST_OPTS);
  return bytesOf(out);
}

// ---------------------------------------------------------------------------
// Smoke test — prove the BROWSER build resolved (32 MiB default, Node-only stub)
// ---------------------------------------------------------------------------

describe('fileCryptoService — browser build resolution', () => {
  it('uses the 32 MiB browser Argon2id default (memoryCost === 2 ** 15)', () => {
    const manager = new CryptoManager();
    expect(manager.getParameters().argon2Options.memoryCost).toBe(2 ** 15);
    // The Node build would report 2 ** 17 (128 MiB) here.
    expect(manager.getParameters().argon2Options.memoryCost).not.toBe(2 ** 17);
  });

  it('exposes the Node-only file method as a throwing browser stub', () => {
    const manager = new CryptoManager() as unknown as {
      encryptFileSync: (a: string, b: string, c: string) => void;
    };
    let caught: unknown;
    try {
      manager.encryptFileSync('in', 'out', PASSWORD);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(CryptoError);
    expect((caught as CryptoError).code).toBe('UNSUPPORTED_IN_BROWSER');
  });

  it('completes one real container round-trip in jsdom', async () => {
    // Build the bytes in the test realm (jsdom's TextEncoder yields a
    // foreign-realm Uint8Array that trips toEqual's constructor check).
    const original = Uint8Array.from('hello secure vault', (ch) => ch.charCodeAt(0));
    const recovered = await roundTrip(original, 'greeting.txt', 'text/plain');
    expect(recovered).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Round-trip byte-identity — the overriding requirement
// ---------------------------------------------------------------------------

describe('fileCryptoService — round-trip byte identity', () => {
  const sizes = [0, 1, 15, 16, 17, 1024, 1024 * 1024];

  // Each round-trip runs a real Argon2id KDF (WASM) twice plus AES-GCM +
  // SHA-256 over the payload; the 1 MiB case is by far the heaviest single
  // operation in the whole client suite. It comfortably finishes in isolation,
  // but the coverage gate runs ~8 worker threads in parallel that all contend
  // for CPU on WASM/crypto at once, and under that contention this one test can
  // exceed the tight 15 s global `testTimeout` on a loaded machine. A larger
  // per-test bound only widens the hang-guard for this legitimately-slow work —
  // the byte-identity assertions below are unchanged.
  const ROUND_TRIP_TIMEOUT_MS = 60_000;

  for (const size of sizes) {
    it(
      `recovers ${size} random bytes exactly`,
      async () => {
        const original = randomBytes(size);
        const recovered = await roundTrip(original);
        expect(recovered.length).toBe(size);
        expect(recovered).toEqual(original);
      },
      ROUND_TRIP_TIMEOUT_MS,
    );
  }

  it('recovers an all-zero payload exactly', async () => {
    const original = new Uint8Array(4096); // all zeros
    const recovered = await roundTrip(original);
    expect(recovered).toEqual(original);
  });

  it('recovers arbitrary binary (0..255 pattern) exactly', async () => {
    const original = new Uint8Array(256);
    for (let i = 0; i < 256; i++) original[i] = i;
    const recovered = await roundTrip(original);
    expect(recovered).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Metadata fidelity — filename / mime / size sealed and restored
// ---------------------------------------------------------------------------

describe('fileCryptoService — metadata fidelity', () => {
  it('appends .enc to the encrypted download name', async () => {
    const { filename } = await encryptFile(
      fileOf(randomBytes(32), 'report.pdf', 'application/pdf'),
      PASSWORD,
      FAST_OPTS,
    );
    expect(filename).toBe('report.pdf.enc');
  });

  it('restores the original filename and mime from inside the container', async () => {
    const bytes = randomBytes(64);
    const { blob, filename } = await encryptFile(
      fileOf(bytes, 'report.pdf', 'application/pdf'),
      PASSWORD,
      FAST_OPTS,
    );
    const {
      blob: out,
      filename: restored,
      mime,
    } = await decryptFile(
      fileOf(await bytesOf(blob), filename, 'application/octet-stream'),
      PASSWORD,
      FAST_OPTS,
    );
    expect(restored).toBe('report.pdf');
    expect(mime).toBe('application/pdf');
    expect(out.type).toBe('application/pdf');
    expect(await bytesOf(out)).toEqual(bytes);
  });

  it('preserves unicode / emoji filenames', async () => {
    const name = 'reçu-café-🔐-账单.txt';
    const { blob, filename } = await encryptFile(
      fileOf(randomBytes(16), name, 'text/plain'),
      PASSWORD,
      FAST_OPTS,
    );
    const { filename: restored } = await decryptFile(
      fileOf(await bytesOf(blob), filename),
      PASSWORD,
      FAST_OPTS,
    );
    expect(restored).toBe(name);
  });

  it('preserves a name with no extension', async () => {
    const { blob, filename } = await encryptFile(
      fileOf(randomBytes(16), 'LICENSE', ''),
      PASSWORD,
      FAST_OPTS,
    );
    expect(filename).toBe('LICENSE.enc');
    const { filename: restored, mime } = await decryptFile(
      fileOf(await bytesOf(blob), filename),
      PASSWORD,
      FAST_OPTS,
    );
    expect(restored).toBe('LICENSE');
    // Empty File type defaults to application/octet-stream on encrypt.
    expect(mime).toBe('application/octet-stream');
  });

  it('falls back to octet-stream when the container seals an empty mime', async () => {
    // The package encodes `mime: ''` as present-but-empty (only `undefined` is
    // "absent"), and a foreign .enc may carry one — the fallback must still fire.
    const manager = new CryptoManager(FAST_OPTS.managerOptions);
    const bytes = randomBytes(48);
    const container = await manager.encryptContainer(bytes, PASSWORD, {
      filename: 'z.bin',
      mime: '',
    });
    const { mime, blob } = await decryptFile(
      fileOf(container, 'z.bin.enc', 'application/octet-stream'),
      PASSWORD,
      FAST_OPTS,
    );
    expect(mime).toBe('application/octet-stream');
    expect(blob.type).toBe('application/octet-stream');
    expect(await bytesOf(blob)).toEqual(bytes);
  });

  it('falls back to stripping .enc when the container carries no filename', async () => {
    // Encrypt directly with no filename metadata, then decrypt via the service.
    const manager = new CryptoManager(FAST_OPTS.managerOptions);
    const bytes = randomBytes(32);
    const container = await manager.encryptContainer(bytes, PASSWORD);
    const { filename, blob } = await decryptFile(
      fileOf(container, 'MyDocument.ENC', 'application/octet-stream'),
      PASSWORD,
      FAST_OPTS,
    );
    expect(filename).toBe('MyDocument'); // .ENC stripped case-insensitively
    expect(await bytesOf(blob)).toEqual(bytes);
  });
});

// ---------------------------------------------------------------------------
// Nondeterminism — fresh salt/DEK/IVs every time, both decrypt
// ---------------------------------------------------------------------------

describe('fileCryptoService — nondeterminism', () => {
  it('produces different ciphertext each time yet both decrypt to the same bytes', async () => {
    const original = randomBytes(512);
    const file = () => fileOf(original, 'x.bin');
    const a = await encryptFile(file(), PASSWORD, FAST_OPTS);
    const b = await encryptFile(file(), PASSWORD, FAST_OPTS);

    const aBytes = await bytesOf(a.blob);
    const bBytes = await bytesOf(b.blob);
    expect(aBytes).not.toEqual(bBytes);

    const outA = await decryptFile(fileOf(aBytes, a.filename), PASSWORD, FAST_OPTS);
    const outB = await decryptFile(fileOf(bBytes, b.filename), PASSWORD, FAST_OPTS);
    expect(await bytesOf(outA.blob)).toEqual(original);
    expect(await bytesOf(outB.blob)).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// Account-agnostic — no account key material, no store, fresh manager decrypts
// ---------------------------------------------------------------------------

describe('fileCryptoService — account-agnostic', () => {
  it('imports no authStore or account crypto service', () => {
    // Vitest runs each workspace with cwd = the package dir (packages/client).
    const source = readFileSync(
      path.resolve(process.cwd(), 'src/services/crypto/fileCryptoService.ts'),
      'utf8',
    );
    // Look only at real module specifiers, not the doc comment prose.
    const specifiers = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]);
    const dynamic = [...source.matchAll(/import\(\s*['"]([^'"]+)['"]\s*\)/g)].map((m) => m[1]);
    const all = [...specifiers, ...dynamic];
    expect(all.some((s) => /authStore/i.test(s ?? ''))).toBe(false);
    expect(all.some((s) => /crypto\/cryptoService/i.test(s ?? ''))).toBe(false);
    // Confirms only the package + shared constants are imported.
    expect(all).toContain('@hiprax/crypto');
    expect(all).toContain('@hvault/shared');
  });

  it('decrypts with a fresh, independently-constructed manager (only the password matters)', async () => {
    const bytes = randomBytes(128);
    // Encrypt with a fresh manager instance A...
    const a = new CryptoManager(FAST_OPTS.managerOptions);
    const container = await a.encryptContainer(bytes, PASSWORD, { filename: 'z.bin', mime: '' });
    // ...decrypt through the service (which uses its own manager) — no shared state.
    const { blob, filename } = await decryptFile(
      fileOf(container, 'z.bin.enc', 'application/octet-stream'),
      PASSWORD,
      FAST_OPTS,
    );
    expect(filename).toBe('z.bin');
    expect(await bytesOf(blob)).toEqual(bytes);
  });
});

// ---------------------------------------------------------------------------
// Negative paths — honest, oracle-free failure classification
// ---------------------------------------------------------------------------

describe('fileCryptoService — negative paths', () => {
  async function containerFor(bytes: Uint8Array, name = 'secret.txt'): Promise<Uint8Array> {
    const { blob } = await encryptFile(fileOf(bytes, name, 'text/plain'), PASSWORD, FAST_OPTS);
    return bytesOf(blob);
  }

  it('wrong password → wrong-password-or-corrupt', async () => {
    const container = await containerFor(randomBytes(64));
    const err = await decryptFile(
      fileOf(container, 'secret.txt.enc'),
      WRONG_PASSWORD,
      FAST_OPTS,
    ).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(CryptoError);
    expect(describeFileCryptoError(err).kind).toBe('wrong-password-or-corrupt');
  });

  it('a flipped ciphertext byte → wrong-password-or-corrupt', async () => {
    const container = await containerFor(randomBytes(1024));
    // Flip the final byte (payload GCM tag region) — auth fails.
    container[container.length - 1] ^= 0xff;
    const kind = await decryptFile(fileOf(container, 'secret.txt.enc'), PASSWORD, FAST_OPTS).then(
      () => 'no-throw',
      (err) => describeFileCryptoError(err).kind,
    );
    expect(kind).toBe('wrong-password-or-corrupt');
  });

  it('a truncated blob (< 174-byte overhead) → not-a-file', async () => {
    const tiny = new Uint8Array(10).fill(7);
    const kind = await decryptFile(fileOf(tiny, 'x.enc'), PASSWORD, FAST_OPTS).then(
      () => 'no-throw',
      (err) => describeFileCryptoError(err).kind,
    );
    expect(kind).toBe('not-a-file');
  });

  it('a random non-container blob (>= 174 bytes) → not-a-file', async () => {
    const junk = new Uint8Array(200).fill(1); // first 4 bytes != "HPCR"
    const kind = await decryptFile(fileOf(junk, 'x.enc'), PASSWORD, FAST_OPTS).then(
      () => 'no-throw',
      (err) => describeFileCryptoError(err).kind,
    );
    expect(kind).toBe('not-a-file');
  });

  it('a weak/short password is rejected by isValidPassword and by encryptFile', async () => {
    expect(isValidPassword('short')).toBe(false);
    // 18 chars, no uppercase/symbol → fails both the length and composition rules.
    expect(isValidPassword('onlylowercaseanddi')).toBe(false);
    expect(isValidPassword(PASSWORD)).toBe(true);

    const kind = await encryptFile(fileOf(randomBytes(16), 'a.txt'), 'weak', FAST_OPTS).then(
      () => 'no-throw',
      (err) => describeFileCryptoError(err).kind,
    );
    expect(kind).toBe('weak-password');
  });

  it('oversize on encrypt → FileTooLargeError / too-large (before any crypto)', async () => {
    const big = fileOf(randomBytes(2048), 'big.bin');
    await expect(
      encryptFile(big, PASSWORD, { ...FAST_OPTS, maxSizeBytes: 1024 }),
    ).rejects.toBeInstanceOf(FileTooLargeError);

    const kind = await encryptFile(big, PASSWORD, { ...FAST_OPTS, maxSizeBytes: 1024 }).then(
      () => 'no-throw',
      (err) => describeFileCryptoError(err).kind,
    );
    expect(kind).toBe('too-large');
  });

  it('oversize on decrypt → FileTooLargeError / too-large (plaintext cap + container overhead)', async () => {
    // The decrypt guard admits the plaintext cap PLUS MAX_CONTAINER_OVERHEAD_BYTES.
    // A blob larger than that ceiling is rejected before any read (the guard runs
    // first, so the bytes need not be a real container). With maxSizeBytes = 1 the
    // effective ceiling is 1 + overhead, so a blob two bytes over the overhead trips it.
    const oversized = fileOf(new Uint8Array(MAX_CONTAINER_OVERHEAD_BYTES + 2), 'big.enc');
    await expect(
      decryptFile(oversized, PASSWORD, { ...FAST_OPTS, maxSizeBytes: 1 }),
    ).rejects.toBeInstanceOf(FileTooLargeError);
    expect(
      describeFileCryptoError(new FileTooLargeError(MAX_CONTAINER_OVERHEAD_BYTES, 1)).kind,
    ).toBe('too-large');
  });

  it('decrypts a container produced at exactly the plaintext cap (N1 regression — container-overhead allowance)', async () => {
    // A file encrypted at exactly the plaintext cap yields a container that is
    // necessarily LARGER than the cap. Guarding the container against the bare cap
    // would make it un-decryptable by the same tool; the guard must admit the
    // container overhead so a correct-password file ALWAYS decrypts.
    const cap = 4096;
    const plaintext = randomBytes(cap); // exactly at the plaintext cap
    const { blob, filename } = await encryptFile(fileOf(plaintext, 'atcap.bin'), PASSWORD, {
      ...FAST_OPTS,
      maxSizeBytes: cap,
    });
    const container = await bytesOf(blob);
    // The container overhead makes it strictly larger than the plaintext cap...
    expect(container.length).toBeGreaterThan(cap);
    // ...yet decrypting with the SAME plaintext cap must succeed (regression guard).
    const { blob: out } = await decryptFile(fileOf(container, filename), PASSWORD, {
      ...FAST_OPTS,
      maxSizeBytes: cap,
    });
    expect(await bytesOf(out)).toEqual(plaintext);
  });

  it('describeFileCryptoError maps engine-unavailable and unknown codes', () => {
    expect(
      describeFileCryptoError(new CryptoError('x', undefined, 'ARGON2_NOT_AVAILABLE')).kind,
    ).toBe('engine-unavailable');
    expect(
      describeFileCryptoError(new CryptoError('x', undefined, 'KEY_DERIVATION_FAILED')).kind,
    ).toBe('engine-unavailable');
    expect(
      describeFileCryptoError(new CryptoError('x', undefined, 'CONTAINER_INTEGRITY_FAILED')).kind,
    ).toBe('integrity');
    expect(describeFileCryptoError(new Error('plain')).kind).toBe('unknown');
    expect(describeFileCryptoError(new CryptoError('x', undefined, 'SOME_NEW_CODE')).kind).toBe(
      'unknown',
    );
  });
});
