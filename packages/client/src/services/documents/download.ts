/**
 * Reading a stored document back: the ONE verified read path, and the two ways
 * of saving what it produces.
 *
 * Nothing in this module renders a document byte, and nothing may be added here
 * that does. A stored document is arbitrary attacker-supplied input — it is
 * whatever anyone was able to persuade this account's owner to save — and the
 * origin it would be parsed in is the one holding the unlocked vault key. So the
 * app decrypts, verifies, and hands the bytes to the operating system through a
 * save dialog. Rendering one happens later, inside an isolated document with an
 * opaque origin that holds no key, no token, no cookie and no storage; until
 * that document exists, the honest answer is a download.
 *
 * ## Four checks, in the order a reader must make them
 *
 * Each of them exists because a hostile or broken SERVER is the thing this
 * design assumes, and each catches something the next one cannot:
 *
 * 1. **The row is the row that was asked for.** `_id` is HKDF `info` material
 *    for all three of this document's keys, so a response describing a different
 *    document would derive three different keys and fail in a way that reads as
 *    corruption. Comparing the id costs one string comparison and names the real
 *    problem.
 * 2. **The row's framing agrees with the authenticated copy inside the sealed
 *    metadata.** This is Core Design Rule 5 and it is MANDATORY rather than
 *    advisory: the server holds `chunkPlaintextBytes`, `chunkCount` and
 *    `plaintextBytes` in plaintext columns and computes every segment's byte
 *    range from them, while the same three values are sealed inside the metadata
 *    blob under a key the server does not have. A copy that is merely
 *    "detectable" is decoration; the comparison is what makes the plaintext
 *    columns unforgeable.
 * 3. **Every segment authenticates.** The position is inside the nonce
 *    (`noncePrefix || u32be(index) || lastFlag`), so a reordered, replayed,
 *    truncated or substituted segment does not decrypt at all — there is no
 *    partial plaintext and no "verify afterwards" step.
 * 4. **The whole file hashes to what the metadata says.** A running SHA-256
 *    across the plaintext, compared at the end. It is the only check that spans
 *    segments rather than living inside one, and it is the one that catches a
 *    fault in THIS client rather than in the data.
 *
 * A failure of 4 arrives after bytes have already been handed to a sink, which
 * is why {@link DocumentPlaintextSink} has a `discard` at all: a partially
 * written file that the user could mistake for their document is a worse outcome
 * than no file.
 *
 * ## One read path, two sinks
 *
 * {@link streamDocumentPlaintext} is the implementation and
 * {@link readDocumentPlaintext} is its accumulating specialisation. Every
 * consumer — the save-dialog path, the in-memory path, and later the preview —
 * goes through one of those two, and the second is written in terms of the
 * first. That is deliberate: a second reader that skipped one of the four checks
 * above would be a document rendered from bytes this module would have refused,
 * and the difference would be invisible until it mattered.
 */

import { documentResponseSchema, type DocumentMeta, type DocumentResponse } from '@hvault/shared';
import { getDocumentApi, getDocumentSegmentApi } from '../api/documentsApi.js';
import { cryptoService } from '../crypto/cryptoService.js';
import {
  decryptMeta,
  decryptSegment,
  deriveMetaKey,
  deriveStreamKey,
  deriveWrapKey,
  unwrapDek,
  zeroDek,
  type DocumentBytes,
} from '../crypto/documentCryptoService.js';
import { getSha256Factory } from '../../lib/lazySha256.js';
import { downloadBlob } from '../../lib/download.js';
import { useAuthStore } from '../../stores/authStore.js';

// ---------------------------------------------------------------------------
// Filenames
// ---------------------------------------------------------------------------

/** What a name that sanitises away to nothing is saved as. */
export const FALLBACK_DOWNLOAD_FILENAME = 'document';

/**
 * Characters a filename may not carry out of this application, as one class.
 *
 * Written as escapes, never as the characters themselves: half of them are
 * invisible and one of them reverses the reading order of everything after it,
 * so a source file holding them literally would be misleading whoever reads it
 * next, which is the same trick this constant exists to defeat.
 *
 *   * U+0000 to U+001F and U+007F to U+009F, the C0 and C1 control characters.
 *     A newline or a NUL inside a name reaches a shell, a log or a file manager
 *     as something other than one name.
 *   * The two path separators. A document name comes out of a blob this account
 *     sealed, but it is still a name chosen by whoever handed the user the file,
 *     and a leading `..` followed by a separator is a traversal attempt wherever
 *     a save path is built by concatenation.
 *   * U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069 — every
 *     member of Unicode's Bidi_Control set: the Arabic letter mark, the two
 *     directional marks, the embeddings, the overrides and the isolates. A name
 *     carrying U+202E just before the letters `gnp.exe` DISPLAYS as `report`
 *     followed by `exe.png`, in every file manager and in this application's own
 *     list. That is the whole trick: the user opens what they read as an image.
 *     The set is taken whole rather than by picking the characters that seemed
 *     dangerous, because U+061C reorders neutrals exactly as U+200F does and was
 *     missed on the first pass for no better reason than being less famous.
 *
 * They are REPLACED with an underscore rather than deleted, because a name that
 * was tampered with should look tampered with. Deleting the override above
 * would produce `reportgnp.exe`, which is odd but plausible; replacing it
 * produces `report_gnp.exe`, which is visibly not the file it claimed to be.
 */
const UNSAFE_FILENAME_CHARACTERS =
  /[\u0000-\u001f\u007f-\u009f\/\\\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;

/**
 * A stored document's name, made safe to hand to a save dialog or to an
 * `<a download>`.
 *
 * The trailing trim covers Windows, where a name ending in a dot or a space is
 * silently rewritten by the filesystem, so `evil.exe.` becomes `evil.exe` after
 * the user has read the harmless-looking name. LEADING dots are deliberately
 * kept: `.bashrc` and `.env` are ordinary files, and a leading dot cannot
 * traverse anything once the separators are gone.
 */
export function sanitizeDownloadFilename(name: string): string {
  const replaced = name.replace(UNSAFE_FILENAME_CHARACTERS, '_');
  // `.replace` before `.trim` on the trailing side, because a name of `. . .`
  // must not survive as `. .`.
  const trimmed = replaced.trim().replace(/[. ]+$/, '');
  return trimmed === '' ? FALLBACK_DOWNLOAD_FILENAME : trimmed;
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

/** Which of this module's own checks refused a document. */
export type DocumentIntegrityFailure = 'identity' | 'framing' | 'digest';

/**
 * Raised when a document did not survive one of the four checks above.
 *
 * A distinct type rather than a message, because the caller acts on it: an
 * integrity failure is the one outcome where a file may already have been
 * written and then emptied, so the user has to be told the download was
 * DISCARDED rather than that it failed. A network error is a different sentence.
 */
export class DocumentIntegrityError extends Error {
  constructor(
    readonly failure: DocumentIntegrityFailure,
    message: string,
  ) {
    super(message);
    this.name = 'DocumentIntegrityError';
  }
}

/**
 * Raised when a read stopped because the user dismissed the save dialog, or
 * because the page navigated away, or because the vault locked.
 *
 * Never reported as a failure, exactly as `UploadCancelledError` is not: a user
 * who closed the save dialog does not need to be told their download broke.
 */
export class DocumentDownloadCancelledError extends Error {
  constructor(message = 'Download cancelled') {
    super(message);
    this.name = 'DocumentDownloadCancelledError';
  }
}

// ---------------------------------------------------------------------------
// The read
// ---------------------------------------------------------------------------

/**
 * Where verified plaintext goes, one segment at a time.
 *
 * `discard` is called when the whole-file checks fail AFTER segments have been
 * written, and it must leave nothing a user could mistake for the document.
 */
export interface DocumentPlaintextSink {
  write: (segment: DocumentBytes) => Promise<void>;
  discard: () => Promise<void>;
}

/** What {@link readDocumentPlaintext} returns: the opened metadata and the file. */
export interface DocumentPlaintext {
  meta: DocumentMeta;
  bytes: DocumentBytes;
}

/** The one option every read shares. */
export interface ReadDocumentOptions {
  /**
   * Stops the read between segments and cancels the segment request in flight.
   *
   * A download is PAGE-scoped, unlike an upload: the store is module-level so a
   * transfer survives navigation, but a download exists to put a file in front
   * of the person looking at it, so navigating away or locking the vault ends
   * it. The detail view aborts on unmount, which is what makes a lock stop the
   * decryption rather than let it run to completion and save a file after the
   * vault has closed.
   */
  signal?: AbortSignal;
}

/**
 * A signal that is never aborted, for a caller that passed none.
 *
 * One module-level controller rather than a `signal === undefined` branch at
 * every check: the checks below are re-read after every await precisely because
 * the answer changes underneath them, and an optional chain at each one would be
 * three more branches that only exist because a parameter is optional.
 */
const NEVER_ABORTED = new AbortController().signal;

/**
 * Whether the read has been cancelled, read through a CALL.
 *
 * A bare `signal.aborted` would be narrowed by the type checker after the first
 * check in a function, and every later re-check would look redundant to
 * `no-unnecessary-condition` — but the value changes underneath the reader,
 * which is the entire point. `documentsStore` keeps the same predicate for the
 * same reason; they are two words of arithmetic rather than a shared rule, and a
 * store is not something a service should import for a boolean.
 */
function isAborted(signal: AbortSignal): boolean {
  return signal.aborted;
}

/**
 * The unlocked vault key, or a throw. Read at CALL time, never at module scope.
 *
 * A local three-line wrapper rather than an import of `documentsStore`'s
 * identical `getVaultKey`, and the same goes for {@link base64ToBytes} below.
 * Neither is a RULE with two copies: the rule is `authStore`'s single vault-key
 * slot and `cryptoService`'s single base64 decoder, and both of those still have
 * exactly one definition that both modules call. What is written twice is the
 * two-line adapter to them, and the alternative — a service reaching into a
 * store for a helper, or a third module existing to hold two lines — costs more
 * than it saves.
 */
function requireVaultKey(): CryptoKey {
  const { vaultKey } = useAuthStore.getState();
  if (!vaultKey) {
    throw new Error('Vault is locked. Unlock it before opening a document.');
  }
  return vaultKey;
}

/** Decode one of the row's base64 framing fields, through the client's single decoder. */
function base64ToBytes(value: string): DocumentBytes {
  return new Uint8Array(cryptoService.base64ToArrayBuffer(value));
}

/**
 * The three framing values that exist on the row AND inside the sealed metadata.
 *
 * Declared as data rather than as three comparisons so the refusal can name
 * EVERY field that disagrees instead of only the first, and so adding a fourth
 * framing column is one line in one place rather than a check somebody forgets
 * to write.
 */
const AUTHENTICATED_FRAMING_FIELDS = [
  'chunkPlaintextBytes',
  'chunkCount',
  'plaintextBytes',
] as const satisfies readonly (keyof DocumentMeta & keyof DocumentResponse)[];

/**
 * Read one document, verifying it, and hand each segment to `sink` as it is
 * verified.
 *
 * THE read path. {@link readDocumentPlaintext} is written in terms of it and
 * nothing else may be: a second reader is a second place for one of the four
 * checks in this module's header to be missing.
 *
 * Returns the opened metadata, so a caller that streamed the bytes still learns
 * the name, the type and the size it needs to describe what it saved.
 */
export async function streamDocumentPlaintext(
  id: string,
  sink: DocumentPlaintextSink,
  options: ReadDocumentOptions = {},
): Promise<DocumentMeta> {
  // Lower-cased rather than parsed: the schema below pins `_id` to lowercase
  // hex, so a malformed argument cannot equal a well-formed row and the identity
  // check refuses it with a message about the document rather than about a regex.
  const documentId = id.toLowerCase();
  const vaultKey = requireVaultKey();
  const signal = options.signal ?? NEVER_ABORTED;

  const body = (await getDocumentApi(documentId)).data;
  if (!body.success) throw new Error('Failed to read the document');
  const row = documentResponseSchema.parse(body.data);
  if (row._id !== documentId) {
    throw new DocumentIntegrityError(
      'identity',
      'The server answered with a different document; nothing was downloaded.',
    );
  }
  if (isAborted(signal)) throw new DocumentDownloadCancelledError();

  const dek = await unwrapDek(row, await deriveWrapKey(vaultKey, documentId));
  try {
    const streamSalt = base64ToBytes(row.streamSalt);
    const meta = await decryptMeta(await deriveMetaKey(dek, streamSalt, documentId), row);

    const disagreements = AUTHENTICATED_FRAMING_FIELDS.filter(
      (field) => row[field] !== meta[field],
    );
    if (disagreements.length > 0) {
      throw new DocumentIntegrityError(
        'framing',
        `This document's stored details disagree with its sealed contents (${disagreements.join(', ')}), so it was not downloaded.`,
      );
    }

    const streamKey = await deriveStreamKey(dek, streamSalt, documentId);
    const noncePrefix = base64ToBytes(row.noncePrefix);
    const createSHA256 = await getSha256Factory();
    const hasher = await createSHA256();
    hasher.init();

    for (let index = 0; index < meta.chunkCount; index += 1) {
      if (isAborted(signal)) throw new DocumentDownloadCancelledError();
      // One request per segment, in order and one at a time. The byte window is
      // computed server-side from the row, so there is no range to send and no
      // way to ask for one that straddles two segments.
      let sealed: DocumentBytes;
      try {
        sealed = new Uint8Array((await getDocumentSegmentApi(documentId, index, signal)).data);
      } catch (error) {
        // An abort landing WHILE a request is in flight rejects it with the
        // transport's own cancellation, which carries no response and would
        // otherwise be reported to the user as a failed download — after they
        // locked their vault or navigated away, which is not a failure at all.
        // The signal is the honest source of truth, so it is consulted before
        // the rejection is even looked at, exactly as the upload loop does.
        if (isAborted(signal)) throw new DocumentDownloadCancelledError();
        throw error;
      }
      const segment = await decryptSegment(
        streamKey,
        { noncePrefix, index, isLast: index === meta.chunkCount - 1 },
        sealed,
      );
      hasher.update(segment);
      await sink.write(segment);
    }

    // There is deliberately NO "did the right number of bytes arrive" check
    // beside this one, and the omission is the interesting part. Once the
    // framing comparison above has passed, `plaintextBytes`, `chunkCount` and
    // `chunkPlaintextBytes` are all authenticated, and the row's own schema
    // pins `ciphertextBytes = plaintextBytes + 16 * chunkCount`. AES-GCM
    // plaintext is exactly as long as its ciphertext, so a segment that
    // authenticates is exactly as long as the segment that was sealed: every
    // non-final one holds `chunkPlaintextBytes` and the last holds the
    // remainder, and the sum telescopes to `plaintextBytes` identically. A
    // length check could therefore only ever fail if `decryptSegment` itself
    // lied about the length of its own output — which nothing but a mock of the
    // unit under test can arrange. It would be a branch no honest test could
    // reach, so it is written here as arithmetic rather than as code.
    if (hasher.digest('hex') !== meta.sha256) {
      await sink.discard();
      throw new DocumentIntegrityError(
        'digest',
        'This document did not match the checksum sealed with it, so the download was discarded.',
      );
    }

    return meta;
  } finally {
    // On every path, including the refusals: a key that decrypts this user's
    // file must not outlive the read that needed it.
    zeroDek(dek);
  }
}

/**
 * Read one document into memory, verified.
 *
 * The shape a caller wants when it needs the WHOLE file — the in-memory save
 * path, and later the preview, which has to hand a complete buffer across a
 * message channel. A caller that can consume the file as it arrives should use
 * {@link streamDocumentPlaintext} instead and keep its memory flat.
 */
export async function readDocumentPlaintext(
  id: string,
  options: ReadDocumentOptions = {},
): Promise<DocumentPlaintext> {
  const segments: DocumentBytes[] = [];
  let total = 0;
  const meta = await streamDocumentPlaintext(
    id,
    {
      write: (segment) => {
        segments.push(segment);
        total += segment.length;
        return Promise.resolve();
      },
      // Nothing was written anywhere a user can see, and the caller receives a
      // rejection rather than a buffer, so there is nothing to undo.
      discard: () => Promise.resolve(),
    },
    options,
  );

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const segment of segments) {
    bytes.set(segment, offset);
    offset += segment.length;
  }
  return { meta, bytes };
}

// ---------------------------------------------------------------------------
// The two save paths
// ---------------------------------------------------------------------------

/**
 * The slice of the File System Access API this module uses.
 *
 * Declared locally because `showSaveFilePicker` is not in TypeScript's DOM
 * library (`FileSystemFileHandle` and `FileSystemWritableFileStream`, which it
 * returns and which do the work, both are). A local structural type keeps the
 * feature detection honest without a global augmentation that would claim the
 * method exists everywhere.
 */
type SaveFilePicker = (options: { suggestedName: string }) => Promise<FileSystemFileHandle>;

/**
 * The save-dialog API, or `null` where it does not exist (Firefox, Safari,
 * jsdom, any non-secure context).
 *
 * Probed with `'x' in window` rather than `typeof window.x`, which is the idiom
 * `getLockManager` in `services/api/client.ts` uses for the same reason: the
 * property is absent from the DOM types, so an optional chain would not compile
 * and a `typeof` on an undeclared property would not narrow.
 */
function getSaveFilePicker(): SaveFilePicker | null {
  if ('showSaveFilePicker' in window && typeof window.showSaveFilePicker === 'function') {
    return window.showSaveFilePicker as SaveFilePicker;
  }
  return null;
}

/** Whether a rejection is the user closing the save dialog rather than a fault. */
function isPickerDismissal(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/**
 * What a save needs: the id to read, and the name the user is already looking
 * at.
 *
 * The name is here for ONE reason — the save dialog has to be opened before the
 * first request (see {@link saveDocument}) and so cannot wait for the freshly
 * decrypted copy. It is a suggestion in a dialog the user then confirms, never
 * an assertion about what is being saved.
 */
export interface SaveableDocument {
  id: string;
  meta: DocumentMeta;
}

/** What {@link saveDocument} accepts beyond the options every read shares. */
export interface SaveDocumentOptions extends ReadDocumentOptions {
  /**
   * Whether the save dialog may be used where the browser has one. Defaults to
   * `true`; only a caller saving SEVERAL documents in one gesture passes
   * `false`.
   *
   * It is a caller's choice rather than a detail of this module because the
   * constraint that decides it belongs to the caller: `showSaveFilePicker`
   * requires TRANSIENT ACTIVATION, and transient activation does not survive an
   * await on the network. A single download opens its dialog on the click's own
   * activation, before the first request, and is fine. The second document of a
   * sequential run reaches the dialog after a full read of the first, by which
   * time the activation is long gone, and the browser refuses with a
   * `SecurityError` — not the `AbortError` that means "the user closed it", so
   * it would be reported to that user as a failed download of a document
   * nothing was wrong with.
   *
   * Turning the dialog off costs the streaming write ({@link saveThroughPicker}
   * keeps memory flat; {@link saveThroughBlob} holds one document at a time) and
   * buys the two things a bulk run needs: no per-file gesture, and no partial
   * file anywhere — the blob path writes nothing at all until the digest has
   * been checked, so a document that fails verification produces no file to
   * mistake for it rather than an emptied one.
   */
  useSaveDialog?: boolean;
}

/**
 * Save one document to disk, through the save dialog where the browser has one
 * and through a Blob download where it does not.
 *
 * The dialog is opened BEFORE the first request, which is not a stylistic
 * ordering: `showSaveFilePicker` requires transient activation, and a click's
 * activation does not survive a round trip to the server. That is why the
 * suggested name is taken from the metadata this client decrypted when it listed
 * the document; the read that follows re-derives and re-verifies everything
 * independently, and the path with no dialog uses the freshly authenticated name
 * instead.
 *
 * Rejects with {@link DocumentDownloadCancelledError} when the user dismisses
 * the dialog or the read is aborted, and with {@link DocumentIntegrityError}
 * when the document did not verify. Every other rejection is the network or the
 * server.
 *
 * Resolves with the name the file was actually saved as.
 */
export async function saveDocument(
  doc: SaveableDocument,
  options: SaveDocumentOptions = {},
): Promise<string> {
  // `=== false` rather than a falsy test, so an omitted option keeps the dialog:
  // the single download is the common case and it must not have to opt in.
  const picker = options.useSaveDialog === false ? null : getSaveFilePicker();
  if (picker === null) return saveThroughBlob(doc.id, options);

  let handle: FileSystemFileHandle;
  try {
    handle = await picker({ suggestedName: sanitizeDownloadFilename(doc.meta.name) });
  } catch (error) {
    if (isPickerDismissal(error)) throw new DocumentDownloadCancelledError();
    throw error;
  }
  return saveThroughPicker(doc.id, handle, options);
}

/**
 * The streaming path: constant memory, because each verified segment is written
 * to the file and then dropped.
 *
 * ## What happens to the chosen file when this goes wrong
 *
 * `createWritable()` does not touch the chosen file. It writes to a swap file
 * and only replaces the target when `close()` resolves, and `abort()` discards
 * the swap and leaves the target exactly as it was. That gives two different
 * right answers, and collapsing them into one would be a real loss either way:
 *
 *   * **The document failed verification.** The file is TRUNCATED TO ZERO and
 *     committed. The bytes were decrypted and are not the document, so a
 *     zero-byte file at the chosen path is an unambiguous record that something
 *     was attempted and discarded — better than a path that silently looks
 *     untouched to anyone who missed the message.
 *   * **Anything else** — a dropped connection, a lock, a navigation away, the
 *     user cancelling. Nothing was decided about the document, so the swap is
 *     ABORTED and the chosen path keeps whatever was there. Emptying a file the
 *     user already had because their network blinked is destroying data to
 *     report an error.
 */
async function saveThroughPicker(
  id: string,
  handle: FileSystemFileHandle,
  options: ReadDocumentOptions,
): Promise<string> {
  const writable = await handle.createWritable();
  // A mutable field rather than a `let`, because the only writer is the sink's
  // closure: the type checker cannot see a closure it merely passed somewhere
  // run, so it narrows a captured `let` to its initial value and reports the
  // branch below as dead. A property read is re-widened by the intervening call,
  // which is the truth here.
  const outcome = { discarded: false };
  try {
    await streamDocumentPlaintext(
      id,
      {
        write: async (segment) => {
          await writable.write(segment);
        },
        discard: async () => {
          // Flagged AFTER the truncation resolves, never before: the flag's only
          // reader decides between committing an emptied file and abandoning the
          // swap, and a flag set ahead of the write it describes would claim a
          // truncation that had not happened.
          await writable.truncate(0);
          outcome.discarded = true;
        },
      },
      options,
    );
  } catch (error) {
    try {
      if (outcome.discarded) await writable.close();
      else await writable.abort();
    } catch {
      // The stream is already broken. The read's own failure is the one worth
      // reporting, and a second one raised while tidying up would hide it.
    }
    throw error;
  }
  await writable.close();
  return handle.name;
}

/**
 * The in-memory path, for a browser with no save dialog: read the whole file,
 * verified, then hand it to the anchor-and-object-URL helper every other
 * download in this application already uses.
 *
 * Nothing reaches the user until the digest has been checked, so this path has
 * no discard to perform: a document that fails verification is a rejection and
 * never a file.
 */
async function saveThroughBlob(id: string, options: ReadDocumentOptions): Promise<string> {
  const { meta, bytes } = await readDocumentPlaintext(id, options);
  // The freshly decrypted name rather than the list's copy, because this path
  // never had to name the file before reading it and so has no reason to use the
  // older of the two.
  const filename = sanitizeDownloadFilename(meta.name);
  // `meta.mime` is the type the file was uploaded with, and it is legitimately
  // empty for a type the operating system did not recognise. An empty `type` is
  // what a Blob defaults to anyway, so it is passed through rather than guessed
  // at — this application does not sniff a document's contents.
  downloadBlob(new Blob([bytes], { type: meta.mime }), filename);
  return filename;
}
