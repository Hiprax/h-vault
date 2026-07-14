/**
 * fileCryptoService — standalone, account-agnostic file encryption.
 *
 * A thin wrapper over `@hiprax/crypto`'s isomorphic v2 **container** mode
 * (`encryptContainer` / `decryptContainer`). It powers the client-only "File
 * Encryption" tool: the user picks any file and a password, and the browser
 * produces / consumes a self-contained `.enc` container. Nothing is uploaded
 * and no account key material is ever touched.
 *
 * Zero-knowledge / account-agnostic invariant (enforced by design):
 *   - This module MUST NOT import `authStore` or any account crypto service
 *     (`services/crypto/cryptoService`, the vault/MEK key hierarchy, etc.). The
 *     only secret it handles is the file password the caller passes in, and it
 *     never reaches the network. A file encrypted here decrypts with the same
 *     password on any machine, signed in as anyone or no one, because only the
 *     password matters.
 *
 * Crypto delegation: the container format (envelope KEK/DEK keying, confidential
 * filename/mime/size metadata, embedded plaintext SHA-256 re-verified on
 * decrypt, and an AAD-bound header) lives entirely inside `@hiprax/crypto`. We
 * add no format layer of our own, so there is exactly one wire format and a
 * correct-password file always decrypts to byte-identical output.
 *
 * Argon2id profile: the module-level default manager is constructed with NO
 * `memoryCost` override, so it uses the package's browser default (32 MiB /
 * t=3 / p=1). Because each container embeds the exact KDF params it was made
 * with, keeping the fixed default guarantees any browser that can encrypt can
 * also decrypt. Tests may pass a lighter `managerOptions` override to speed
 * Argon2id up without changing the wire format.
 */

import {
  CryptoManager,
  CryptoError,
  isValidPassword,
  type CryptoManagerOptions,
} from '@hiprax/crypto';
import { FILE_ENCRYPTION_FILE_EXTENSION } from '@hvault/shared';

/** Re-exported so the encrypt panel can gate on the package's own rule. */
export { isValidPassword };

const OCTET_STREAM = 'application/octet-stream';

/**
 * Strip the `.enc` filename hint (case-insensitive) when the container carries
 * no filename. Kept a literal that must stay in sync with
 * {@link FILE_ENCRYPTION_FILE_EXTENSION} (`.enc`).
 */
const EXTENSION_STRIP_RE = /\.enc$/i;

/**
 * Upper bound on how many bytes larger a `.enc` container is than the plaintext
 * it wraps. `@hiprax/crypto` v2 containers add a fixed 174-byte envelope plus an
 * encrypted metadata block (filename + mime, each up to 65535 UTF-8 bytes, a
 * 32-byte plaintext SHA-256, the original size, and the GCM IV/tag framing) — a
 * theoretical worst case of roughly 128 KiB. 256 KiB is a safe ceiling with
 * generous headroom.
 *
 * {@link decryptFile} admits `maxSizeBytes + MAX_CONTAINER_OVERHEAD_BYTES` rather
 * than the bare plaintext cap, because a file encrypted at exactly the cap yields
 * a container that is necessarily LARGER than the cap. Guarding the container
 * against the bare plaintext cap would make such a file un-decryptable by the
 * very tool that produced it, breaking the "a correct password always decrypts to
 * byte-identical output" invariant for plaintexts in the top band just under the
 * cap. This allowance is negligible next to any realistic cap, so it does not
 * meaningfully weaken the decrypt-side OOM guard.
 */
export const MAX_CONTAINER_OVERHEAD_BYTES = 256 * 1024;

/** Options accepted by both {@link encryptFile} and {@link decryptFile}. */
export interface FileCryptoOptions {
  /**
   * Client-side ceiling on the **plaintext** size in bytes. When set, the size
   * guard runs BEFORE any bytes are read into memory:
   *   - {@link encryptFile} rejects a plaintext whose `size` exceeds it.
   *   - {@link decryptFile} rejects a `.enc` whose `size` exceeds
   *     `maxSizeBytes + MAX_CONTAINER_OVERHEAD_BYTES` — the container is always
   *     larger than its plaintext, so admitting the overhead keeps a file
   *     encrypted at the cap decryptable while still bounding memory.
   * Rejection throws {@link FileTooLargeError} so a huge `.enc` can't OOM the
   * tab on decrypt any more than a huge plaintext can on encrypt.
   */
  maxSizeBytes?: number;
  /**
   * Test-only Argon2id override (e.g. `{ memoryCost: 8192, timeCost: 1 }`) to
   * speed property tests. Production callers omit this so the fixed 32 MiB
   * browser default is used. The wire format still embeds the params, so
   * round-trips stay valid regardless.
   */
  managerOptions?: CryptoManagerOptions;
}

/**
 * Thrown when a file exceeds the client-enforced size ceiling before any crypto
 * runs. Distinct from {@link CryptoError} so the UI can surface a "too large"
 * message without confusing it with a crypto failure.
 */
export class FileTooLargeError extends Error {
  readonly actualBytes: number;
  readonly maxBytes: number;

  constructor(actualBytes: number, maxBytes: number) {
    super(`File is ${actualBytes} bytes, which exceeds the ${maxBytes}-byte limit.`);
    this.name = 'FileTooLargeError';
    this.actualBytes = actualBytes;
    this.maxBytes = maxBytes;
  }
}

/**
 * Module-level default browser manager (lazily constructed). Built with NO
 * `memoryCost` override so it carries the package's 32 MiB browser default.
 */
let defaultManager: CryptoManager | undefined;

function getManager(managerOptions?: CryptoManagerOptions): CryptoManager {
  if (managerOptions) {
    // A caller-supplied (test) override always yields a fresh instance so the
    // shared default's profile is never mutated.
    return new CryptoManager(managerOptions);
  }
  defaultManager ??= new CryptoManager();
  return defaultManager;
}

function enforceSizeGuard(file: File, maxSizeBytes: number | undefined): void {
  if (maxSizeBytes !== undefined && file.size > maxSizeBytes) {
    throw new FileTooLargeError(file.size, maxSizeBytes);
  }
}

/**
 * Wrap crypto output bytes in a `Blob` without copying. The DOM `BlobPart`
 * type narrows array-buffer views to `ArrayBuffer`-backed ones, whereas the
 * package returns `Uint8Array<ArrayBufferLike>`. The bytes are always backed by
 * a plain (non-shared) `ArrayBuffer` at runtime — Web Crypto and hash-wasm never
 * produce a `SharedArrayBuffer` — so this assertion is sound and avoids copying
 * up to the size limit's worth of data.
 */
function bytesToBlob(bytes: Uint8Array, type: string): Blob {
  return new Blob([bytes as BlobPart], { type });
}

/**
 * Encrypt an arbitrary file into a `.enc` container, sealing its original
 * filename and mime confidentially inside.
 *
 * @returns a `Blob` of the container bytes and the suggested download filename
 *   (`<originalName>.enc`).
 * @throws {@link FileTooLargeError} when `opts.maxSizeBytes` is exceeded, or a
 *   {@link CryptoError} on a weak/missing password or engine failure.
 */
export async function encryptFile(
  file: File,
  password: string,
  opts?: FileCryptoOptions,
): Promise<{ blob: Blob; filename: string }> {
  enforceSizeGuard(file, opts?.maxSizeBytes);

  const manager = getManager(opts?.managerOptions);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const container = await manager.encryptContainer(bytes, password, {
    filename: file.name,
    mime: file.type || OCTET_STREAM,
  });

  return {
    blob: bytesToBlob(container, OCTET_STREAM),
    filename: file.name + FILE_ENCRYPTION_FILE_EXTENSION,
  };
}

/**
 * Decrypt a `.enc` container, restoring the original bytes plus the sealed-in
 * filename and mime.
 *
 * @returns a `Blob` (typed with the restored mime) and the restored filename;
 *   when the container carries no filename, the `.enc` suffix is stripped from
 *   the uploaded name as a fallback.
 * @throws {@link FileTooLargeError} when the `.enc` size exceeds
 *   `opts.maxSizeBytes + MAX_CONTAINER_OVERHEAD_BYTES`, or a {@link CryptoError}
 *   on a non-container blob, a wrong password / tamper, or a failed integrity
 *   check. Map it with {@link describeFileCryptoError}.
 */
export async function decryptFile(
  file: File,
  password: string,
  opts?: FileCryptoOptions,
): Promise<{ blob: Blob; filename: string; mime: string }> {
  // A container is always larger than its plaintext, so admit the plaintext cap
  // PLUS the maximum container overhead — otherwise a file encrypted at exactly
  // the cap (whose container necessarily exceeds it) could not be decrypted here.
  enforceSizeGuard(
    file,
    opts?.maxSizeBytes === undefined ? undefined : opts.maxSizeBytes + MAX_CONTAINER_OVERHEAD_BYTES,
  );

  const manager = getManager(opts?.managerOptions);
  const bytes = new Uint8Array(await file.arrayBuffer());
  const { data, meta } = await manager.decryptContainer(bytes, password);

  // Fall back to octet-stream when the sealed mime is absent OR an empty string.
  // The package encodes an explicit `mime: ''` as a present-but-empty field (only
  // `undefined` is treated as absent), and a foreign `.enc` may carry one, so a
  // plain `??` would wrongly yield a Blob typed `''`. The explicit test gives the
  // `||`-style falsy fallback the plan's decrypt spec calls for.
  const mime = meta.mime === undefined || meta.mime === '' ? OCTET_STREAM : meta.mime;
  return {
    blob: bytesToBlob(data, mime),
    filename: meta.filename ?? file.name.replace(EXTENSION_STRIP_RE, ''),
    mime,
  };
}

/** Discriminated classification of a file-crypto failure for UI messaging. */
export type FileCryptoErrorKind =
  | 'not-a-file'
  | 'wrong-password-or-corrupt'
  | 'integrity'
  | 'engine-unavailable'
  | 'too-large'
  | 'weak-password'
  | 'unknown';

export interface FileCryptoErrorDescription {
  kind: FileCryptoErrorKind;
  message: string;
}

/**
 * Not-a-container `CryptoError.code`s (pre-authentication structural rejects).
 * A blob shorter than the fixed 174-byte overhead yields `TRUNCATED_CONTAINER`
 * rather than `CONTAINER_INVALID_MAGIC`; both mean "not a valid file".
 */
const NOT_A_FILE_CODES = new Set<string>([
  'INVALID_CONTAINER_INPUT',
  'INVALID_ENCRYPTED_DATA',
  'TRUNCATED_CONTAINER',
  'CONTAINER_INVALID_MAGIC',
  'CONTAINER_UNSUPPORTED_VERSION',
  'CONTAINER_UNSUPPORTED_KDF',
  'CONTAINER_INVALID_HEADER_PARAM',
  'CONTAINER_KDF_PARAMS_OUT_OF_BOUNDS',
]);

const MESSAGES: Record<FileCryptoErrorKind, string> = {
  'not-a-file': "This isn't a valid H-Vault encrypted file.",
  'wrong-password-or-corrupt': 'Incorrect password, or the file is corrupted.',
  integrity: "The file's integrity check failed. The file may be damaged.",
  'engine-unavailable':
    'The encryption engine could not start in this browser. Try a newer browser over HTTPS.',
  'too-large': 'This file is too large to process in your browser.',
  'weak-password':
    'This password is too weak. Use at least 20 characters, or 8+ with an uppercase letter, a lowercase letter, a digit, and a symbol.',
  unknown: 'Something went wrong. Please try again.',
};

/**
 * Map a thrown error to a user-facing `{ kind, message }`.
 *
 * IMPORTANT: keys on `CryptoError.code`, NEVER `.type`. A WASM `CompileError`
 * under a restrictive CSP surfaces as `.code === 'KEY_DERIVATION_FAILED'` on
 * BOTH encrypt and decrypt (only `.type` differs — `remapKdfErrorForDecryption`
 * re-types decrypt failures to `DECRYPTION_FAILED` while PRESERVING `.code`), so
 * a `.type`-based mapper would misclassify it as a wrong password. `.code` keeps
 * engine-unavailable distinct from wrong-password-or-corrupt.
 */
export function describeFileCryptoError(err: unknown): FileCryptoErrorDescription {
  if (err instanceof FileTooLargeError) {
    return { kind: 'too-large', message: MESSAGES['too-large'] };
  }

  if (err instanceof CryptoError) {
    const kind = classifyCryptoErrorCode(err.code);
    return { kind, message: MESSAGES[kind] };
  }

  return { kind: 'unknown', message: MESSAGES.unknown };
}

function classifyCryptoErrorCode(code: string): FileCryptoErrorKind {
  if (code === 'KEY_DERIVATION_FAILED' || code === 'ARGON2_NOT_AVAILABLE') {
    return 'engine-unavailable';
  }
  if (code === 'DECRYPTION_FAILED' || code === 'CONTAINER_DECRYPTION_FAILED') {
    return 'wrong-password-or-corrupt';
  }
  if (code === 'CONTAINER_INTEGRITY_FAILED' || code === 'CONTAINER_METADATA_MALFORMED') {
    return 'integrity';
  }
  if (code === 'WEAK_PASSWORD' || code === 'INVALID_PASSWORD') {
    return 'weak-password';
  }
  if (NOT_A_FILE_CODES.has(code)) {
    return 'not-a-file';
  }
  return 'unknown';
}
