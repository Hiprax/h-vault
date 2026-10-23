/**
 * An INDEPENDENT reading of a ZIP archive, for the tests of the archive writer.
 *
 * The writer is first-party code, so a test that checked its output with
 * arithmetic of its own would be the writer checking itself. This reads an
 * archive with `yauzl`, a separate, widely used reader opened in its strictest
 * mode, and adds the checks yauzl does not make on its own:
 *
 *   * every local file header agrees with its central directory record, field
 *     by field (yauzl reads the central directory and skips past the local
 *     header's fields);
 *   * every entry's CRC-32 matches its bytes, computed by `node:zlib` (yauzl
 *     does not verify CRCs);
 *   * the layout this application promises: stored (method 0), UTF-8 names (bit
 *     11 set), no data descriptor (bit 3 clear), no extra fields.
 *
 * Any disagreement throws, naming the entry and the field.
 */
import { crc32 } from 'node:zlib';
import type { Readable } from 'node:stream';
import { fromBufferPromise, type Entry } from 'yauzl';

/** One entry, as an independent reader saw it. */
export interface OracleEntry {
  /** The decoded name. */
  name: string;
  /** The stored bytes. */
  bytes: Uint8Array;
  /** The central directory record, as parsed. */
  entry: Entry;
}

async function readAll(stream: Readable): Promise<Uint8Array> {
  const parts: Buffer[] = [];
  for await (const part of stream) parts.push(part as Buffer);
  return new Uint8Array(Buffer.concat(parts));
}

/** Read every entry of `archive`, refusing anything this application must never write. */
export async function readArchive(archive: Uint8Array): Promise<OracleEntry[]> {
  const zip = await fromBufferPromise(Buffer.from(archive), {
    lazyEntries: true,
    strictFileNames: true,
    validateEntrySizes: true,
    decodeStrings: true,
  });
  const entries: OracleEntry[] = [];
  for await (const entry of zip.eachEntry()) {
    const local = await zip.readLocalFileHeaderPromise(entry);
    const bytes = await readAll(await zip.openReadStreamPromise(entry));
    const disagreements = [
      local.versionNeededToExtract === entry.versionNeededToExtract ? '' : 'version needed',
      local.generalPurposeBitFlag === entry.generalPurposeBitFlag ? '' : 'flags',
      local.compressionMethod === 0 && entry.compressionMethod === 0 ? '' : 'method',
      local.lastModFileTime === entry.lastModFileTime ? '' : 'time',
      local.lastModFileDate === entry.lastModFileDate ? '' : 'date',
      local.crc32 === entry.crc32 && entry.crc32 === crc32(bytes) ? '' : 'crc',
      local.compressedSize === bytes.length && local.uncompressedSize === bytes.length
        ? ''
        : 'local sizes',
      entry.compressedSize === bytes.length && entry.uncompressedSize === bytes.length
        ? ''
        : 'central sizes',
      local.fileName.equals(entry.fileNameRaw) ? '' : 'name bytes',
      (entry.generalPurposeBitFlag & 0x0800) !== 0 ? '' : 'utf-8 flag',
      (entry.generalPurposeBitFlag & 0x0008) === 0 ? '' : 'data descriptor flag',
      local.extraFieldLength === 0 && entry.extraFieldLength === 0 ? '' : 'extra field',
    ].filter((problem) => problem !== '');
    if (disagreements.length > 0) {
      throw new Error(`${entry.fileName}: ${disagreements.join(', ')}`);
    }
    entries.push({ name: entry.fileName, bytes, entry });
  }
  return entries;
}

/** Everything a sink was handed, as one byte array. */
export async function concatBlobs(parts: readonly Blob[]): Promise<Uint8Array> {
  return new Uint8Array(await new Blob([...parts]).arrayBuffer());
}
