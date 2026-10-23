/**
 * A ZIP archive writer: STORED entries only, in the most widely readable layout,
 * and nothing it does depends on what the stored bytes say.
 *
 * ## Why this is not a dependency
 *
 * A document's bytes are untrusted input, and the page that runs this holds the
 * unlocked vault key. That rules out anything that INTERPRETS them here (the
 * document store's governing rule: nothing is parsed in the app origin), and it
 * makes every line of code that touches them worth reading. A stored-only writer
 * is small enough to read in full: it copies each file's bytes verbatim and
 * frames them with headers built from numbers it was handed, the one computation
 * over the bytes being CRC-32, which is as content-agnostic as the AES-GCM and
 * SHA-256 that already run over the same bytes in the same page. There is no
 * compressor, no parser and no branch on a byte value. The libraries that exist
 * either always write data descriptors (client-zip) or cannot describe archives
 * past 4 GiB and stream with descriptors too (fflate); this writer needs neither.
 *
 * ## The layout, and why it is the compatible one
 *
 * Every entry is written AFTER its file has been read and verified in full, so
 * its CRC-32 and size are known before its local header is: the header carries
 * the real values, general-purpose bit 3 is clear and there is no data
 * descriptor. That is the layout every extractor reads, including the streaming
 * ones that cannot handle a stored entry followed by a descriptor. Names are
 * UTF-8 with bit 11 set; method 0; "version needed" 1.0; "made by" MS-DOS 2.0
 * (0x0014), so the zero attribute fields never extract as a Unix mode of 000;
 * no extra fields, no comments, no directory entries (every mainstream extractor
 * creates the directories a path names).
 *
 * There is no Zip64. The 32-bit size and offset fields reserve 0xFFFFFFFF, and
 * the 16-bit entry count 0xFFFF, as markers meaning "look in the Zip64 record",
 * so an archive here stays strictly below both: {@link ZIP32_MAX_ARCHIVE_BYTES}
 * and {@link ZIP32_MAX_ENTRIES}. A larger export is split into several archives
 * by the caller, never written past them.
 *
 * ## Timestamps
 *
 * The MS-DOS date and time fields have no time zone: every extractor reads them
 * as the LOCAL time of the machine doing the extracting. So they are written
 * from the local calendar fields of the machine doing the archiving, which is
 * what makes a document captured at 09:00 show 09:00 to the person who archived
 * it. The fields hold years 1980 to 2107 at two-second resolution; a time outside
 * that range is clamped to its nearest end.
 */

/** Bytes of a local file header, before the name. */
const LOCAL_HEADER_BYTES = 30;

/** Bytes of a central directory record, before the name. */
const CENTRAL_RECORD_BYTES = 46;

/** Bytes of the end-of-central-directory record (no comment). */
const END_RECORD_BYTES = 22;

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_RECORD_SIGNATURE = 0x02014b50;
const END_RECORD_SIGNATURE = 0x06054b50;

/** "Made by" MS-DOS (host 0), specification 2.0. */
const VERSION_MADE_BY = 0x0014;

/** "Version needed": 1.0, a stored file. */
const VERSION_NEEDED = 10;

/** General-purpose bit 11: the name is UTF-8. Bit 3 (data descriptor) stays clear. */
const FLAG_UTF8_NAME = 0x0800;

/** Compression method 0: stored. */
const METHOD_STORED = 0;

/**
 * The largest archive this writer produces, in bytes. One below 0xFFFFFFFF,
 * which a reader takes as "the real value is in a Zip64 record".
 */
export const ZIP32_MAX_ARCHIVE_BYTES = 0xffff_fffe;

/** The most entries one archive holds. One below 0xFFFF, the Zip64 marker. */
export const ZIP32_MAX_ENTRIES = 0xfffe;

/**
 * The longest entry name, in UTF-8 bytes: the 16-bit field that records it. A
 * longer name would be stored modulo 65,536, leaving a header that points into
 * the entry's own data, where a reader walking local headers would take the
 * document's bytes for the next header. So it is refused, never truncated.
 */
const ZIP_MAX_NAME_BYTES = 0xffff;

/** The earliest and latest years the MS-DOS date field can hold. */
const DOS_FIRST_YEAR = 1980;
const DOS_LAST_YEAR = 2107;

/**
 * The CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320) lookup table, built
 * on first use rather than when the module loads, so a page that never builds
 * an archive never pays for it.
 *
 * Read through a `DataView` rather than indexed: `getUint32` returns a number,
 * where indexing a typed array is `number | undefined` under this project's
 * compiler settings, and the `?? 0` that would answer it is a branch no input
 * can reach.
 */
let crcTable: DataView | null = null;

function buildCrcTable(): DataView {
  const table = new DataView(new ArrayBuffer(256 * 4));
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table.setUint32(index * 4, value >>> 0);
  }
  return table;
}

/**
 * CRC-32 of `bytes`, continuing from the CRC of everything before them.
 *
 * `crc32(b, crc32(a))` is the CRC of `a` followed by `b`, so a file read in
 * segments is checksummed one segment at a time, as each arrives.
 */
export function crc32(bytes: Uint8Array, previous = 0): number {
  crcTable ??= buildCrcTable();
  const table = crcTable;
  let crc = ~previous >>> 0;
  for (const byte of bytes) {
    crc = table.getUint32(((crc ^ byte) & 0xff) * 4) ^ (crc >>> 8);
  }
  return ~crc >>> 0;
}

/**
 * The MS-DOS time and date fields for `moment`, from its LOCAL calendar fields
 * (see this module's header), clamped to the years the fields can hold. An
 * invalid date is clamped to the earliest one, since no year compares as valid.
 */
export function dosDateTime(moment: Date): { time: number; date: number } {
  const year = moment.getFullYear();
  if (!(year >= DOS_FIRST_YEAR)) return { time: 0, date: (1 << 5) | 1 };
  if (year > DOS_LAST_YEAR) {
    return {
      time: (23 << 11) | (59 << 5) | 29,
      date: ((DOS_LAST_YEAR - DOS_FIRST_YEAR) << 9) | (12 << 5) | 31,
    };
  }
  return {
    time: (moment.getHours() << 11) | (moment.getMinutes() << 5) | (moment.getSeconds() >> 1),
    date: ((year - DOS_FIRST_YEAR) << 9) | ((moment.getMonth() + 1) << 5) | moment.getDate(),
  };
}

/** Where the archive's bytes go, in order. */
export interface ZipSink {
  write: (chunk: Blob) => Promise<void>;
}

/** One file to add. Its bytes have been read and verified in full already. */
export interface ZipFileEntry {
  /** A safe, `/`-separated relative path (see `archiveNames.ts`). */
  path: string;
  /** What the extractor shows as the file's modification time. */
  modified: Date;
  /** The file's bytes, in order. */
  chunks: readonly Blob[];
  /** CRC-32 of exactly those bytes, computed as they were read. */
  crc: number;
}

/** What the central directory needs to remember about one written entry. */
interface CentralRecord {
  name: Uint8Array;
  time: number;
  date: number;
  crc: number;
  size: number;
  offset: number;
}

/**
 * Writes one archive to a sink: files with {@link addFile}, then the central
 * directory with {@link finish}.
 *
 * `limitBytes` is the caller's SOFT limit for this archive, answered by
 * {@link fits}; the Zip32 maxima are the HARD limits, enforced by {@link addFile}
 * whatever the soft one says.
 */
export class StoredZipWriter {
  readonly #sink: ZipSink;
  readonly #limitBytes: number;
  readonly #records: CentralRecord[] = [];
  /** Bytes written so far: where the next local header starts. */
  #offset = 0;
  /** Bytes the central directory will take, for the records so far. */
  #centralBytes = 0;

  constructor(sink: ZipSink, limitBytes: number) {
    this.#sink = sink;
    this.#limitBytes = limitBytes;
  }

  /** How many files have been added. */
  get entryCount(): number {
    return this.#records.length;
  }

  /** The finished archive's size if one more file of `size` bytes, named in `pathBytes` bytes, were added. */
  #projectedBytes(pathBytes: number, size: number): number {
    return (
      this.#offset +
      LOCAL_HEADER_BYTES +
      pathBytes +
      size +
      this.#centralBytes +
      CENTRAL_RECORD_BYTES +
      pathBytes +
      END_RECORD_BYTES
    );
  }

  /**
   * Whether a file of `size` bytes, named in `pathBytes` UTF-8 bytes, keeps the
   * finished archive within the soft limit.
   *
   * An EMPTY archive admits any file: a document larger than the limit on its
   * own still has to be exportable, and an archive holding just it is the
   * smallest one that can. A FULL one admits nothing more, so a list longer than
   * one archive can count continues in the next instead of failing.
   */
  fits(pathBytes: number, size: number): boolean {
    if (this.entryCount === 0) return true;
    return (
      this.entryCount < ZIP32_MAX_ENTRIES &&
      this.#projectedBytes(pathBytes, size) <= this.#limitBytes
    );
  }

  /**
   * Write one file: its local header, then its bytes.
   *
   * Refused, before anything is written, when its name is longer than the name
   * field can record, or when it would take the archive past either Zip32
   * maximum.
   */
  async addFile(entry: ZipFileEntry): Promise<void> {
    const name = new TextEncoder().encode(entry.path);
    const size = entry.chunks.reduce((total, chunk) => total + chunk.size, 0);
    if (name.length > ZIP_MAX_NAME_BYTES) {
      throw new Error('This file name is too long for a ZIP archive.');
    }
    if (
      this.entryCount >= ZIP32_MAX_ENTRIES ||
      this.#projectedBytes(name.length, size) > ZIP32_MAX_ARCHIVE_BYTES
    ) {
      throw new Error('This archive cannot hold another file without the Zip64 format.');
    }
    const { time, date } = dosDateTime(entry.modified);

    const header = new Uint8Array(LOCAL_HEADER_BYTES + name.length);
    const view = new DataView(header.buffer);
    view.setUint32(0, LOCAL_HEADER_SIGNATURE, true);
    view.setUint16(4, VERSION_NEEDED, true);
    view.setUint16(6, FLAG_UTF8_NAME, true);
    view.setUint16(8, METHOD_STORED, true);
    view.setUint16(10, time, true);
    view.setUint16(12, date, true);
    view.setUint32(14, entry.crc, true);
    view.setUint32(18, size, true);
    view.setUint32(22, size, true);
    view.setUint16(26, name.length, true);
    // Offset 28, the extra-field length, stays zero: the buffer starts zeroed.
    header.set(name, LOCAL_HEADER_BYTES);

    const offset = this.#offset;
    await this.#sink.write(new Blob([header]));
    for (const chunk of entry.chunks) await this.#sink.write(chunk);

    this.#offset += header.length + size;
    this.#records.push({ name, time, date, crc: entry.crc, size, offset });
    this.#centralBytes += CENTRAL_RECORD_BYTES + name.length;
  }

  /** Write the central directory and the end record. Nothing may be added after. */
  async finish(): Promise<void> {
    const tail = new Uint8Array(this.#centralBytes + END_RECORD_BYTES);
    const view = new DataView(tail.buffer);
    let at = 0;
    for (const record of this.#records) {
      view.setUint32(at, CENTRAL_RECORD_SIGNATURE, true);
      view.setUint16(at + 4, VERSION_MADE_BY, true);
      view.setUint16(at + 6, VERSION_NEEDED, true);
      view.setUint16(at + 8, FLAG_UTF8_NAME, true);
      view.setUint16(at + 10, METHOD_STORED, true);
      view.setUint16(at + 12, record.time, true);
      view.setUint16(at + 14, record.date, true);
      view.setUint32(at + 16, record.crc, true);
      view.setUint32(at + 20, record.size, true);
      view.setUint32(at + 24, record.size, true);
      view.setUint16(at + 28, record.name.length, true);
      // Offsets 30 to 41 stay zero, as the buffer starts: the extra-field and
      // comment lengths, the starting disk, and the internal and external
      // attributes. Not written, so no line here could disagree with that.
      view.setUint32(at + 42, record.offset, true);
      tail.set(record.name, at + CENTRAL_RECORD_BYTES);
      at += CENTRAL_RECORD_BYTES + record.name.length;
    }
    view.setUint32(at, END_RECORD_SIGNATURE, true);
    // Offsets 4 and 6 (this disk, the directory's disk) and 20 (the comment
    // length) stay zero: one disk, no comment.
    view.setUint16(at + 8, this.#records.length, true);
    view.setUint16(at + 10, this.#records.length, true);
    view.setUint32(at + 12, this.#centralBytes, true);
    view.setUint32(at + 16, this.#offset, true);
    await this.#sink.write(new Blob([tail]));
  }
}
