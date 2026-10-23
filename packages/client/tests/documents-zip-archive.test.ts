// @vitest-environment node
/**
 * The stored-only ZIP writer, checked against an INDEPENDENT reader.
 *
 * Every archive here is read back with `yauzl` in strict mode, through
 * `support/zipOracle.ts`, which also compares each local header with its central
 * record and each CRC-32 with `node:zlib`'s. Where the SOFT limit's boundary is
 * pinned, it is the measured length of an archive the writer really produced;
 * the hard-limit cases state the header sizes (30, 46 and 22 bytes) as APPNOTE
 * defines them, which is the specification, not the writer's arithmetic.
 */
import { describe, expect, it } from 'vitest';
import { crc32 as zlibCrc32 } from 'node:zlib';
import {
  StoredZipWriter,
  ZIP32_MAX_ARCHIVE_BYTES,
  ZIP32_MAX_ENTRIES,
  crc32,
  dosDateTime,
  type ZipFileEntry,
} from '../src/services/documents/zipArchive';
import { concatBlobs, readArchive } from './support/zipOracle';

/** A sink that keeps everything it is handed. */
function collectingSink(): { parts: Blob[]; write: (chunk: Blob) => Promise<void> } {
  const parts: Blob[] = [];
  return {
    parts,
    write: (chunk) => {
      parts.push(chunk);
      return Promise.resolve();
    },
  };
}

/** `length` deterministic bytes. */
function ramp(length: number, seed = 0): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Array.from({ length }, (_, index) => (index * 7 + 11 + seed) % 251));
}

/** An entry for `bytes`, split into segments of `segment` bytes as a read would deliver them. */
function entryFor(path: string, bytes: Uint8Array<ArrayBuffer>, segment = 8): ZipFileEntry {
  const chunks: Blob[] = [];
  let crc = 0;
  for (let at = 0; at < bytes.length; at += segment) {
    const slice = bytes.slice(at, at + segment);
    crc = crc32(slice, crc);
    chunks.push(new Blob([slice]));
  }
  return { path, modified: new Date(2026, 9, 23, 14, 37, 58), chunks, crc };
}

async function archiveOf(entries: readonly ZipFileEntry[], limit = ZIP32_MAX_ARCHIVE_BYTES) {
  const sink = collectingSink();
  const writer = new StoredZipWriter(sink, limit);
  for (const entry of entries) await writer.addFile(entry);
  await writer.finish();
  return concatBlobs(sink.parts);
}

describe('crc32', () => {
  it('matches the standard check value and node:zlib, whole or in segments', () => {
    const digits = new TextEncoder().encode('123456789');
    expect(crc32(digits)).toBe(0xcbf43926);

    const data = ramp(1000, 3);
    expect(crc32(data)).toBe(zlibCrc32(data));
    // Continued across segments exactly as over the whole file.
    expect(crc32(data.slice(333), crc32(data.slice(0, 333)))).toBe(zlibCrc32(data));
    // Nothing at all checksums to zero, and leaves a running value unchanged.
    expect(crc32(new Uint8Array(0))).toBe(0);
    expect(crc32(new Uint8Array(0), 0x12345678)).toBe(0x12345678);
  });
});

describe('dosDateTime', () => {
  /** The fields as APPNOTE defines them, decoded. */
  function decode({ time, date }: { time: number; date: number }) {
    return {
      year: (date >> 9) + 1980,
      month: (date >> 5) & 0x0f,
      day: date & 0x1f,
      hours: time >> 11,
      minutes: (time >> 5) & 0x3f,
      seconds: (time & 0x1f) * 2,
    };
  }

  it('encodes the local calendar fields, seconds to the even second below', () => {
    expect(decode(dosDateTime(new Date(2026, 9, 23, 14, 37, 59)))).toEqual({
      year: 2026,
      month: 10,
      day: 23,
      hours: 14,
      minutes: 37,
      seconds: 58,
    });
  });

  it('holds the first instant the fields can describe and clamps anything earlier to it', () => {
    const first = { year: 1980, month: 1, day: 1, hours: 0, minutes: 0, seconds: 0 };
    expect(decode(dosDateTime(new Date(1980, 0, 1, 0, 0, 0)))).toEqual(first);
    expect(decode(dosDateTime(new Date(1979, 11, 31, 23, 59, 59)))).toEqual(first);
    // An invalid date compares as no year at all, and takes the same floor.
    expect(decode(dosDateTime(new Date(Number.NaN)))).toEqual(first);
  });

  it('holds the last instant the fields can describe and clamps anything later to it', () => {
    const last = { year: 2107, month: 12, day: 31, hours: 23, minutes: 59, seconds: 58 };
    expect(decode(dosDateTime(new Date(2107, 11, 31, 23, 59, 59)))).toEqual(last);
    expect(decode(dosDateTime(new Date(2108, 0, 1, 0, 0, 0)))).toEqual(last);
  });
});

describe('StoredZipWriter', () => {
  it('writes stored entries an independent reader opens byte for byte, in order', async () => {
    const alpha = ramp(20);
    const unicode = ramp(13, 5);
    const archive = await archiveOf([
      entryFor('alpha.txt', alpha),
      entryFor('Folder/Übersicht 文書.md', unicode, 4),
      entryFor('empty.bin', new Uint8Array(0)),
    ]);

    const entries = await readArchive(archive);

    expect(entries.map((entry) => entry.name)).toEqual([
      'alpha.txt',
      'Folder/Übersicht 文書.md',
      'empty.bin',
    ]);
    expect([...entries[0]!.bytes]).toEqual([...alpha]);
    expect([...entries[1]!.bytes]).toEqual([...unicode]);
    expect(entries[2]!.bytes).toHaveLength(0);
    for (const { entry } of entries) {
      // The layout promised in the module's header, read from the central record
      // (the oracle has already checked each local header agrees with it).
      expect(entry.versionMadeBy).toBe(0x0014);
      expect(entry.versionNeededToExtract).toBe(10);
      expect(entry.generalPurposeBitFlag).toBe(0x0800);
      expect(entry.externalFileAttributes).toBe(0);
      expect(entry.internalFileAttributes).toBe(0);
      expect(entry.fileCommentLength).toBe(0);
      // Decoded by the reader, as the local time an extractor shows.
      expect(entry.getLastModDate({ timezone: 'local', forceDosFormat: true }).getTime()).toBe(
        new Date(2026, 9, 23, 14, 37, 58).getTime(),
      );
    }
  });

  it('writes a well-formed empty archive when finished with nothing in it', async () => {
    const archive = await archiveOf([]);

    expect(archive).toHaveLength(22);
    await expect(readArchive(archive)).resolves.toEqual([]);
  });

  it('counts its entries', async () => {
    const writer = new StoredZipWriter(collectingSink(), ZIP32_MAX_ARCHIVE_BYTES);
    expect(writer.entryCount).toBe(0);
    await writer.addFile(entryFor('a', ramp(3)));
    await writer.addFile(entryFor('b', ramp(3)));
    expect(writer.entryCount).toBe(2);
  });

  it('admits a second file exactly up to the soft limit, measured on a real archive', async () => {
    const first = entryFor('first.txt', ramp(40));
    const second = entryFor('second.txt', ramp(25));
    const secondPathBytes = new TextEncoder().encode('second.txt').length;
    // The finished size of the two-file archive, as written and measured.
    const exact = (await archiveOf([first, second])).length;

    const atLimit = new StoredZipWriter(collectingSink(), exact);
    await atLimit.addFile(first);
    expect(atLimit.fits(secondPathBytes, 25)).toBe(true);

    const belowLimit = new StoredZipWriter(collectingSink(), exact - 1);
    await belowLimit.addFile(first);
    expect(belowLimit.fits(secondPathBytes, 25)).toBe(false);
    // A longer name moves the boundary too, twice over (local header and record).
    expect(atLimit.fits(secondPathBytes + 1, 25)).toBe(false);
  });

  it('admits ANY first file to an empty archive, however small the limit', async () => {
    const sink = collectingSink();
    const writer = new StoredZipWriter(sink, 1);
    expect(writer.fits(9, 100)).toBe(true);

    // The soft limit is the caller's to ask about; writing past it is allowed.
    await writer.addFile(entryFor('oversized.bin', ramp(100)));
    await writer.finish();
    const entries = await readArchive(await concatBlobs(sink.parts));
    expect(entries.map((entry) => entry.bytes.length)).toEqual([100]);
  });

  it('refuses a file that would take the archive past the Zip32 byte maximum, before writing anything', async () => {
    const path = 'big.bin';
    const pathBytes = new TextEncoder().encode(path).length;
    // A stand-in for a Blob of exactly the size that lands the finished archive
    // ON the maximum: the writer reads only `size` before deciding, and writes
    // the stand-in through untouched when it is admitted.
    const atMaximum = ZIP32_MAX_ARCHIVE_BYTES - (30 + pathBytes + 46 + pathBytes + 22);
    const stand = (size: number) => ({ size }) as unknown as Blob;

    const admitted = collectingSink();
    await new StoredZipWriter(admitted, ZIP32_MAX_ARCHIVE_BYTES).addFile({
      path,
      modified: new Date(2026, 0, 1),
      chunks: [stand(atMaximum)],
      crc: 0,
    });
    expect(admitted.parts).toHaveLength(2);

    const refused = collectingSink();
    await expect(
      new StoredZipWriter(refused, ZIP32_MAX_ARCHIVE_BYTES).addFile({
        path,
        modified: new Date(2026, 0, 1),
        chunks: [stand(atMaximum + 1)],
        crc: 0,
      }),
    ).rejects.toThrow('This archive cannot hold another file without the Zip64 format.');
    expect(refused.parts).toHaveLength(0);
  });

  it('refuses a file past the Zip32 entry maximum, before writing anything', async () => {
    const sink = collectingSink();
    const writer = new StoredZipWriter(sink, ZIP32_MAX_ARCHIVE_BYTES);
    const empty: ZipFileEntry = { path: 'e', modified: new Date(2026, 0, 1), chunks: [], crc: 0 };
    for (let count = 0; count < ZIP32_MAX_ENTRIES - 1; count += 1) await writer.addFile(empty);
    // One below the cap, one more still fits...
    expect(writer.fits(1, 0)).toBe(true);
    await writer.addFile(empty);
    const written = sink.parts.length;
    // A full archive admits nothing more, so a run continues in another one.
    expect(writer.fits(1, 0)).toBe(false);

    await expect(writer.addFile(empty)).rejects.toThrow(
      'This archive cannot hold another file without the Zip64 format.',
    );
    expect(writer.entryCount).toBe(ZIP32_MAX_ENTRIES);
    expect(sink.parts).toHaveLength(written);
  });

  it('refuses a name longer than its 16-bit field can record, before writing anything', async () => {
    const atLimit = collectingSink();
    const accepting = new StoredZipWriter(atLimit, ZIP32_MAX_ARCHIVE_BYTES);
    await accepting.addFile(entryFor('a'.repeat(0xffff), ramp(3)));
    await accepting.finish();
    const [entry] = await readArchive(await concatBlobs(atLimit.parts));
    expect(entry!.name).toHaveLength(0xffff);
    expect(entry!.entry.fileNameLength).toBe(0xffff);

    const refused = collectingSink();
    await expect(
      new StoredZipWriter(refused, ZIP32_MAX_ARCHIVE_BYTES).addFile(
        entryFor('a'.repeat(0x10000), ramp(3)),
      ),
    ).rejects.toThrow('This file name is too long for a ZIP archive.');
    // A multi-byte name is measured in BYTES, not characters.
    await expect(
      new StoredZipWriter(refused, ZIP32_MAX_ARCHIVE_BYTES).addFile(
        entryFor('\u00e9'.repeat(0x8000), ramp(3)),
      ),
    ).rejects.toThrow('This file name is too long for a ZIP archive.');
    expect(refused.parts).toHaveLength(0);
  });
});
