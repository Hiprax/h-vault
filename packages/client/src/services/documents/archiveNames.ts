/**
 * The paths documents are given inside an archive: safe to extract anywhere,
 * unique, and mirroring the vault's folders.
 *
 * A document's name, and every folder name above it, is text the account's owner
 * chose, or that whoever handed them the file chose. Inside an archive it becomes
 * a PATH that an extractor on some other machine will write to, so every segment
 * is made safe on its own before it is joined with `/`. A segment can therefore
 * never introduce a directory boundary, climb out of the extraction folder, or
 * name a file Windows refuses to create.
 *
 * ## One segment, in this order
 *
 *   1. Unicode NFC, so a name typed on macOS (which decomposes) and the same
 *      name typed elsewhere are one name, and a lone UTF-16 surrogate becomes
 *      U+FFFD, since it has no UTF-8 encoding at all.
 *   2. The download rules every saved file already follows
 *      (`stripUnsafeFilenameCharacters`): control and bidirectional characters
 *      and both path separators replaced, the ends trimmed, trailing dots gone.
 *   3. The characters Windows reserves (`< > : " | ? *`) and the separator
 *      look-alikes (U+2044, U+2215, U+29F8, U+FF0F, U+FF3C), which some
 *      conversions map back onto `/` and `\\`, replaced with `_`.
 *   4. A Windows device name (CON, PRN, AUX, NUL, COM0-9, LPT0-9 and their
 *      superscript-digit forms), with or without an extension, prefixed `_`.
 *   5. A segment of nothing but dot-like characters becomes the fallback.
 *   6. At most 255 UTF-8 bytes, cut on a code-point boundary, keeping the
 *      extension (and any ` (2)` added to keep it unique), then trimmed again.
 *
 * ## Unique, and stable for the whole run
 *
 * Two documents may share a name, and so may two folders, so names are made
 * unique per directory, ignoring case (Windows and macOS do), by inserting
 * ` (2)`, ` (3)`… before the extension. One allocator serves a whole run,
 * including every archive a Continue adds, so extracting all of them into one
 * folder never collides. A file's name is RESERVED only once its document has
 * been written, and only for good once its archive has been saved: an archive
 * that is thrown away gives its names back.
 */

import {
  MAX_DOCUMENT_EXT_LENGTH,
  MAX_FOLDER_NESTING_DEPTH,
  splitDocumentName,
} from '@hvault/shared';
import type { DecryptedFolder } from '../../stores/vaultStore.js';
import { folderAncestry } from '../export/folderPath.js';
import { stripUnsafeFilenameCharacters } from './download.js';

/** The longest segment, in UTF-8 bytes, that every common filesystem accepts. */
const MAX_SEGMENT_BYTES = 255;

/** What a document whose name has nothing safe left in it is called. */
export const FALLBACK_DOCUMENT_SEGMENT = 'document';

/** What a folder whose name has nothing safe left in it is called. */
export const FALLBACK_FOLDER_SEGMENT = 'folder';

/** A UTF-16 surrogate standing alone (in `u` mode, a paired one is one code point). */
const LONE_SURROGATE = /[\uD800-\uDFFF]/gu;

/** Windows-reserved characters and separator look-alikes. */
const NON_PORTABLE_CHARACTERS = /[<>:"|?*\u2044\u2215\u29f8\uff0f\uff3c]/g;

/** A Windows device name, alone or before an extension (`CON`, `con.txt`, `COM1 .log`). */
const RESERVED_DEVICE_NAME =
  /^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]) *(?:\.|$)/i;

/** Nothing but dots and the characters that render as one. */
const DOT_LIKE_ONLY = /^[.\u2024\uff0e]+$/;

/** Trailing dots and spaces, which Windows silently removes from a name. */
const TRAILING_DOTS_AND_SPACES = /[. ]+$/;

function utf8Length(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** The longest prefix of `text` that fits in `budget` UTF-8 bytes, whole code points only. */
function cutToBytes(text: string, budget: number): string {
  let used = 0;
  let kept = '';
  for (const character of text) {
    used += utf8Length(character);
    if (used > budget) break;
    kept += character;
  }
  return kept;
}

/**
 * `stem` followed by `tail` in at most 255 UTF-8 bytes, cutting only the stem.
 *
 * Only a stem that WAS cut is trimmed: its new end may be a dot or a space the
 * name never ended with. An uncut stem is left exactly as written, dots and all
 * (`.._.._etc_passwd` keeps both of its `..`). A stem cut to nothing becomes the
 * fallback, so the tail never stands alone as a hidden dotfile.
 */
function fitSegment(stem: string, tail: string, fallback: string): string {
  const cut = cutToBytes(stem, MAX_SEGMENT_BYTES - utf8Length(tail));
  if (cut === stem) return `${stem}${tail}`;
  const trimmed = cut.replace(TRAILING_DOTS_AND_SPACES, '');
  return `${trimmed === '' ? fallback : trimmed}${tail}`;
}

/** A name split so that a cut or a counter never touches its extension. */
function splitForArchive(segment: string): { stem: string; suffix: string } {
  const { stem, suffix } = splitDocumentName(segment);
  // An "extension" longer than any real one is part of the name, so a long name
  // with a stray dot is cut at its end rather than at that dot.
  return suffix.length - 1 > MAX_DOCUMENT_EXT_LENGTH
    ? { stem: segment, suffix: '' }
    : { stem, suffix };
}

/**
 * The two rules that judge a segment as a WHOLE, applied to its final form,
 * after every cut and trim: a cut can turn a long name into a bare device name
 * (`CON` followed by spaces and one wide character) or into nothing but dots.
 * The `_` prefix can never make either again, and the re-fit keeps it within
 * the byte limit.
 */
function settle(segment: string, fallback: string): string {
  if (DOT_LIKE_ONLY.test(segment)) return fallback;
  if (!RESERVED_DEVICE_NAME.test(segment)) return segment;
  const { stem, suffix } = splitForArchive(`_${segment}`);
  return fitSegment(stem, suffix, fallback);
}

/** One name, made safe as a single path segment (see this module's header). */
export function archiveSegment(name: string, fallback: string): string {
  const segment = stripUnsafeFilenameCharacters(
    name.normalize('NFC').replace(LONE_SURROGATE, '\uFFFD'),
  ).replace(NON_PORTABLE_CHARACTERS, '_');
  if (segment === '') return fallback;
  const { stem, suffix } = splitForArchive(segment);
  return settle(fitSegment(stem, suffix, fallback), fallback);
}

/** `segment` with ` (n)` before its extension, still within the byte limit. */
function numbered(segment: string, counter: number, fallback: string): string {
  const { stem, suffix } = splitForArchive(segment);
  return settle(fitSegment(stem, ` (${String(counter)})${suffix}`, fallback), fallback);
}

/**
 * The key two names in one directory collide on: composed, and compared in
 * UPPER case, which folds what lower case keeps apart (a final sigma and a
 * medial one), so a merge is never missed; an extra ` (2)` is the only cost.
 */
function collisionKey(segment: string): string {
  return segment.normalize('NFC').toUpperCase();
}

/** Where one document will go: its path, and what reserving it means. */
export interface ArchivePlacement {
  /** The full `/`-separated path inside the archive. */
  path: string;
  /** Its length in UTF-8 bytes, which is what the archive's size depends on. */
  pathBytes: number;
  /** The directory it lands in, `''` for the archive's root. */
  directory: string;
  /** Its collision key in that directory. */
  key: string;
}

/** Assigns every document of one run its path inside the archive. */
export class ArchivePathAllocator {
  /** Each folder's chain from its root, by folder id. */
  readonly #chains: Map<string, readonly DecryptedFolder[]>;
  /** The directory each chain of folder ids was given, so it never changes. */
  readonly #directories = new Map<string, string>();
  /** The names taken in each directory, by collision key. */
  readonly #taken = new Map<string, Set<string>>();
  /** File names reserved for the archive being written, not yet saved. */
  #pending: { directory: string; key: string }[] = [];

  constructor(folders: readonly DecryptedFolder[]) {
    this.#chains = folderAncestry(folders);
  }

  #names(directory: string): Set<string> {
    let names = this.#taken.get(directory);
    if (names === undefined) {
      names = new Set();
      this.#taken.set(directory, names);
    }
    return names;
  }

  /** `segment`, or the first numbered form of it, that `directory` does not hold. */
  #unique(directory: string, segment: string, fallback: string): string {
    const names = this.#names(directory);
    let candidate = segment;
    for (let counter = 2; names.has(collisionKey(candidate)); counter += 1) {
      candidate = numbered(segment, counter, fallback);
    }
    return candidate;
  }

  /**
   * The directory a document in `folderId` goes to: its folders' names, each made
   * safe and unique within its parent, joined with `/`. A folder this run cannot
   * resolve (a name that did not decrypt, a folder deleted meanwhile) is the root.
   *
   * Directories are given for good the first time they are needed, whatever
   * happens to the archive that needed them, so one folder is one directory for
   * the whole run.
   */
  #directoryFor(folderId: string | undefined): string {
    // `''` is no folder's id, so a document filed nowhere misses like one filed
    // in a folder this run cannot resolve.
    const chain = this.#chains.get(folderId ?? '');
    // Deeper than the folder editor lets a tree go, the chain came from a
    // restored (possibly hand-edited) backup or a server inventing folders, and
    // could otherwise grow one path past what a ZIP entry name can record. Such
    // documents go to the root.
    if (chain === undefined || chain.length > MAX_FOLDER_NESTING_DEPTH) return '';
    let directory = '';
    let idPath = '';
    for (const folder of chain) {
      idPath = `${idPath}/${folder.id}`;
      const known = this.#directories.get(idPath);
      if (known !== undefined) {
        directory = known;
        continue;
      }
      const segment = this.#unique(
        directory,
        archiveSegment(folder.name, FALLBACK_FOLDER_SEGMENT),
        FALLBACK_FOLDER_SEGMENT,
      );
      this.#names(directory).add(collisionKey(segment));
      directory = directory === '' ? segment : `${directory}/${segment}`;
      this.#directories.set(idPath, directory);
    }
    return directory;
  }

  /** Where a document named `name`, in `folderId`, would go. Reserves nothing. */
  place(name: string, folderId: string | undefined): ArchivePlacement {
    const directory = this.#directoryFor(folderId);
    const segment = this.#unique(
      directory,
      archiveSegment(name, FALLBACK_DOCUMENT_SEGMENT),
      FALLBACK_DOCUMENT_SEGMENT,
    );
    const path = directory === '' ? segment : `${directory}/${segment}`;
    return { path, pathBytes: utf8Length(path), directory, key: collisionKey(segment) };
  }

  /** Reserve a placement for the archive being written, once its document is in it. */
  reserve(placement: ArchivePlacement): void {
    this.#names(placement.directory).add(placement.key);
    this.#pending.push({ directory: placement.directory, key: placement.key });
  }

  /** The archive was saved: its names are taken for the rest of the run. */
  keepArchive(): void {
    this.#pending = [];
  }

  /** The archive was thrown away: give its names back. */
  dropArchive(): void {
    for (const { directory, key } of this.#pending) this.#names(directory).delete(key);
    this.#pending = [];
  }
}
