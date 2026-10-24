/**
 * Where an archive is written: straight into a file the person chose, or into
 * memory and then handed to the browser's downloads.
 *
 * ## The file the person chose (Chromium's save dialog)
 *
 * Where the browser has `showSaveFilePicker`, the dialog opens on the click that
 * started the export, so it has to be called SYNCHRONOUSLY from that click: the
 * click's transient activation does not survive an await. The archive is then
 * written into `createWritable()`'s swap file, entry by entry, so memory holds no
 * more than the document being read, and an archive of any size up to the Zip32
 * maximum fits. `close()` puts the finished file in place; `abort()` drops the
 * swap and leaves whatever was at the chosen path (the browser may already have
 * created an empty file there when the dialog closed, so the honest report of a
 * dropped archive is "nothing was saved", never "nothing was created").
 *
 * ## Memory, then the browser's downloads (every other browser)
 *
 * The archive's parts are kept as `Blob`s, outside the script heap, and handed to
 * the browser as ONE download when the archive is finished: the same
 * anchor-and-object-URL download, after an await, that a single document's
 * in-memory save already relies on. Such an archive is held whole until it is
 * saved, so it is bounded: {@link IN_MEMORY_ARCHIVE_LIMIT_BYTES}, past which the
 * export continues in a further archive.
 */

import { downloadBlob } from '../../lib/download.js';
import { getSaveFilePicker, isPickerDismissal } from './download.js';
import { ZIP32_MAX_ARCHIVE_BYTES } from './zipArchive.js';

/**
 * The most an in-memory archive holds before the export continues in another,
 * in bytes. A phone browser holding this much plaintext as Blobs is near what it
 * will keep without discarding the page; a desktop one has room to spare. A
 * single document larger than this still goes into an archive of its own.
 */
export const IN_MEMORY_ARCHIVE_LIMIT_BYTES = 512 * 1024 * 1024;

/** The archive's MIME type. */
const ZIP_MIME_TYPE = 'application/zip';

/**
 * What kind of file a target writes: how the save dialog describes it, the type the
 * in-memory download carries, and the size limit of each of the two targets.
 *
 * The ZIP export and the full backup are the two kinds. They share the targets
 * because the two hard parts are the same for both: the dialog has to be opened on
 * the click's own activation, and a file abandoned part-way must leave nothing a
 * person could mistake for the finished one.
 */
export interface SaveTargetSpec {
  /** The file type's name in the save dialog. */
  readonly description: string;
  readonly mime: string;
  /** The extension the dialog offers, dot included. */
  readonly extension: string;
  /** The SOFT size limit of a file written into the file the person chose. */
  readonly fileLimitBytes: number;
  /** The SOFT size limit of a file built in memory, then handed to the downloads. */
  readonly memoryLimitBytes: number;
}

/** The ZIP archive the documents export writes. */
const ZIP_ARCHIVE: SaveTargetSpec = {
  description: 'ZIP archive',
  mime: ZIP_MIME_TYPE,
  extension: '.zip',
  fileLimitBytes: ZIP32_MAX_ARCHIVE_BYTES,
  memoryLimitBytes: IN_MEMORY_ARCHIVE_LIMIT_BYTES,
};

/** One archive being written. */
export interface ArchiveTarget {
  /** `file` when written into the file the person chose; `download` when handed to the browser. */
  readonly kind: 'file' | 'download';
  /** The archive's file name: the one chosen in the dialog, or the one the download carries. */
  readonly name: string;
  /** The SOFT size limit for this archive, in bytes (see `zipArchive.ts`). */
  readonly limitBytes: number;
  /** Append the next part of the archive. */
  write: (chunk: Blob) => Promise<void>;
  /** The archive is complete: save it. */
  commit: () => Promise<void>;
  /** The archive is abandoned: drop everything written. Never rejects. */
  discard: () => Promise<void>;
}

/**
 * The name an archive is offered under: `hvault-documents-YYYY-MM-DD.zip`, and
 * `…-part-N.zip` for the Nth archive of one export. The date is the UTC one,
 * like every other file this application saves.
 */
export function archiveFileName(now: Date, part: number): string {
  const day = now.toISOString().slice(0, 10);
  return part > 1
    ? `hvault-documents-${day}-part-${String(part)}.zip`
    : `hvault-documents-${day}.zip`;
}

function fileTarget(
  handle: FileSystemFileHandle,
  writable: FileSystemWritableFileStream,
  spec: SaveTargetSpec,
): ArchiveTarget {
  return {
    kind: 'file',
    name: handle.name,
    limitBytes: spec.fileLimitBytes,
    write: (chunk) => writable.write(chunk),
    commit: () => writable.close(),
    discard: async () => {
      try {
        await writable.abort();
      } catch {
        // The stream is already broken, which is why it is being dropped; the
        // failure that broke it is the one the person is told about.
      }
    },
  };
}

function downloadTarget(name: string, spec: SaveTargetSpec): ArchiveTarget {
  let parts: Blob[] = [];
  return {
    kind: 'download',
    name,
    limitBytes: spec.memoryLimitBytes,
    write: (chunk) => {
      parts.push(chunk);
      return Promise.resolve();
    },
    commit: () => {
      downloadBlob(new Blob(parts, { type: spec.mime }), name);
      parts = [];
      return Promise.resolve();
    },
    discard: () => {
      parts = [];
      return Promise.resolve();
    },
  };
}

/**
 * Open a target for a file of kind `spec`, offered as `suggestedName`.
 *
 * MUST be called synchronously from the click that asked for the file: where the
 * save dialog exists it is opened before this function's first await. Resolves
 * `null` when the person dismisses the dialog; any other refusal (the browser
 * declining the dialog or the file) rejects.
 */
export async function openSaveTarget(
  suggestedName: string,
  spec: SaveTargetSpec,
): Promise<ArchiveTarget | null> {
  const picker = getSaveFilePicker();
  if (picker === null) return downloadTarget(suggestedName, spec);
  let handle: FileSystemFileHandle;
  try {
    handle = await picker({
      suggestedName,
      startIn: 'downloads',
      types: [{ description: spec.description, accept: { [spec.mime]: [spec.extension] } }],
    });
  } catch (error) {
    if (isPickerDismissal(error)) return null;
    throw error;
  }
  return fileTarget(handle, await handle.createWritable(), spec);
}

/**
 * Open a target for an archive offered as `suggestedName`: {@link openSaveTarget}
 * for the documents export's ZIP archive.
 *
 * MUST be called synchronously from the click that asked for the archive.
 */
export function openArchiveTarget(suggestedName: string): Promise<ArchiveTarget | null> {
  return openSaveTarget(suggestedName, ZIP_ARCHIVE);
}
