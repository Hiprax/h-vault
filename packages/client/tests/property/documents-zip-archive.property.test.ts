// @vitest-environment node
/**
 * The ZIP writer, as properties: for EVERY set of files a run could archive, an
 * independent reader opens exactly those files, byte for byte, under exactly
 * those names, at exactly the local time each was given.
 *
 * Run twice by the property gate: once in UTC like every other suite, and once
 * in America/New_York. The MS-DOS time fields are LOCAL time (see
 * `zipArchive.ts`), and in UTC local and universal time are the same, so a writer
 * that read `getUTCHours()` where it should read `getHours()` passes every UTC
 * run; only the second zone can tell them apart. The fields are compared with
 * the local calendar fields directly, never as instants: in the hour a
 * fall-back repeats, two instants share one DOS time, and a reader rebuilding a
 * `Date` can only return one of them.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  StoredZipWriter,
  ZIP32_MAX_ARCHIVE_BYTES,
  crc32,
  type ZipFileEntry,
} from '../../src/services/documents/zipArchive';
import { concatBlobs, readArchive } from '../support/zipOracle';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property.js';

/** What APPNOTE says the two fields hold, decoded. */
function decode(time: number, date: number) {
  return {
    year: (date >> 9) + 1980,
    month: (date >> 5) & 0x0f,
    day: date & 0x1f,
    hours: time >> 11,
    minutes: (time >> 5) & 0x3f,
    seconds: (time & 0x1f) * 2,
  };
}

/** The local calendar fields of `moment`, seconds to the even second below. */
function localFields(moment: Date) {
  return {
    year: moment.getFullYear(),
    month: moment.getMonth() + 1,
    day: moment.getDate(),
    hours: moment.getHours(),
    minutes: moment.getMinutes(),
    seconds: moment.getSeconds() - (moment.getSeconds() % 2),
  };
}

async function roundTrip(
  files: readonly { path: string; bytes: Uint8Array<ArrayBuffer>; modified: Date }[],
) {
  const parts: Blob[] = [];
  const writer = new StoredZipWriter(
    {
      write: (chunk) => {
        parts.push(chunk);
        return Promise.resolve();
      },
    },
    ZIP32_MAX_ARCHIVE_BYTES,
  );
  for (const file of files) {
    const entry: ZipFileEntry = {
      path: file.path,
      modified: file.modified,
      chunks: [new Blob([file.bytes])],
      crc: crc32(file.bytes),
    };
    await writer.addFile(entry);
  }
  await writer.finish();
  return readArchive(await concatBlobs(parts));
}

const PATH_ALPHABET = [...'abcXYZ019 -_()', 'é', '文', '😀'];

const file = fc.record({
  path: fc
    .array(
      fc.array(fc.constantFrom(...PATH_ALPHABET), { minLength: 1, maxLength: 12 }).map(
        (units) =>
          // A segment never starts or ends with a space, as safe names never do.
          `x${units.join('')}x`,
      ),
      { minLength: 1, maxLength: 3 },
    )
    .map((segments) => segments.join('/')),
  bytes: fc.uint8Array({ maxLength: 96 }).map((bytes) => new Uint8Array(bytes)),
  modified: fc.date({
    min: new Date(1980, 0, 1, 0, 0, 0),
    max: new Date(2107, 11, 31, 23, 59, 59),
    noInvalidDate: true,
  }),
});

describe('StoredZipWriter, for every set of files', () => {
  it('writes an archive an independent reader opens to exactly those files and local times', async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(file, { maxLength: 8 }), async (files) => {
        const entries = await roundTrip(files);
        const where = propertyBanner();
        expect(
          entries.map((entry) => entry.name),
          where,
        ).toEqual(files.map((f) => f.path));
        files.forEach((f, index) => {
          const entry = entries[index]!;
          expect([...entry.bytes], where).toEqual([...f.bytes]);
          expect(decode(entry.entry.lastModFileTime, entry.entry.lastModFileDate), where).toEqual(
            localFields(f.modified),
          );
        });
      }),
      propertyRun(),
    );
  });

  it('writes the local time of an hour a fall-back repeats, as the clock read it', async () => {
    // 01:30 on the day daylight saving ends in New York in 2026: in that zone
    // the hour from 01:00 happens twice. Constructed from local fields, so in
    // every zone the clock read 01:30 and the archive must say 01:30.
    const moment = new Date(2026, 10, 1, 1, 30, 0);
    const [entry] = await roundTrip([
      { path: 'repeated-hour.txt', bytes: new Uint8Array([1, 2, 3]), modified: moment },
    ]);

    expect(decode(entry!.entry.lastModFileTime, entry!.entry.lastModFileDate)).toEqual({
      year: 2026,
      month: 11,
      day: 1,
      hours: 1,
      minutes: 30,
      seconds: 0,
    });
  });
});
