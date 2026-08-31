/**
 * The storage-port contract, run against the in-memory double.
 *
 * The cases live in `helpers/storageContract.ts` because the conformance gate runs
 * the SAME function against a real engine in a container: that is what makes the
 * double a stand-in rather than a second opinion. This file is the push-tier half of
 * that pair, plus the handful of assertions that are about the DOUBLE itself and
 * therefore cannot be shared (the inspection helpers a controller test will use, and
 * the one edge the real engine answers with a status code of its own).
 */
import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { buildObjectKey } from '../src/utils/documentObjects.js';
import { createInMemoryStorage } from './helpers/inMemoryStorage.js';
import { runStorageContract } from './helpers/storageContract.js';

/** A realistic key, so the double is exercised with the shape production uses. */
function uniqueKey(): string {
  return buildObjectKey(randomBytes(12).toString('hex'), randomBytes(12).toString('hex'));
}

runStorageContract('in-memory double', () => ({
  provider: createInMemoryStorage(),
  uniqueKey,
}));

describe('in-memory storage double — the parts a real engine cannot share', () => {
  it('reports stored keys and bytes so a test can assert nothing was written', async () => {
    const storage = createInMemoryStorage();
    const key = uniqueKey();

    expect(storage.storedKeys()).toEqual([]);
    expect(storage.readObject(key)).toBeUndefined();

    await storage.putObject(key, Buffer.from('sealed-bytes'));

    expect(storage.storedKeys()).toEqual([key]);
    expect(storage.readObject(key)).toEqual(Buffer.from('sealed-bytes'));
  });

  it('keeps its own copy of the bytes, so a caller mutating its buffer cannot change the object', async () => {
    const storage = createInMemoryStorage();
    const key = uniqueKey();
    const body = Buffer.from('original');

    await storage.putObject(key, body);
    body.fill(0);

    // A double that stored the caller's buffer by reference would make an upload
    // test pass while production, which sends the bytes over a socket, would not.
    expect(storage.readObject(key)).toEqual(Buffer.from('original'));
  });

  it('refuses a range that starts past the end of the object instead of returning nothing', async () => {
    const storage = createInMemoryStorage();
    const key = uniqueKey();
    await storage.putObject(key, Buffer.from('12345678'));

    // The real provider maps the engine's "range not satisfiable" to a 500, and the
    // server never asks for such a range: `segmentRange` refuses to compute one. The
    // point of the assertion is that neither implementation quietly answers with an
    // empty stream, which would reach the browser as a decryption failure.
    await expect(storage.getObjectRange(key, 8, 9)).rejects.toMatchObject({ statusCode: 500 });
    await expect(storage.getObjectRange(key, 4, 3)).rejects.toMatchObject({ statusCode: 500 });
    await expect(storage.getObjectRange(key, -1, 4)).rejects.toMatchObject({ statusCode: 500 });
    // The clamp S3 performs: an end past the object returns the rest of it.
    expect((await storage.getObjectRange(key, 6, 99)).bytes).toBe(2);
  });

  it('refuses a completion that names a part it does not hold', async () => {
    const storage = createInMemoryStorage();
    const key = uniqueKey();
    const uploadId = await storage.createMultipartUpload(key);
    const part = await storage.uploadPart(key, uploadId, 1, Buffer.from('abcd'));

    await expect(
      storage.completeMultipartUpload(key, uploadId, [
        { partNumber: 1, etag: part.etag },
        { partNumber: 2, etag: '"never-uploaded"' },
      ]),
    ).rejects.toMatchObject({ statusCode: 500 });
    // The negative: a refused completion must not leave a partial object behind,
    // because quota is counted from stored bytes.
    expect(storage.storedKeys()).toEqual([]);

    await expect(
      storage.completeMultipartUpload(key, uploadId, [{ partNumber: 1, etag: '"wrong-etag"' }]),
    ).rejects.toMatchObject({ statusCode: 500 });
  });

  it('pairs an upload id with its key, so a mismatched pair is a 404', async () => {
    const storage = createInMemoryStorage();
    const mine = uniqueKey();
    const other = uniqueKey();
    const uploadId = await storage.createMultipartUpload(mine);

    // An upload id names exactly one key. The controller derives both from the same
    // staging row, so a mismatch is a bug — and a double that ignored the key would
    // let a cross-document mix-up pass its tests.
    await expect(storage.uploadPart(other, uploadId, 1, Buffer.from('x'))).rejects.toMatchObject({
      statusCode: 404,
    });
    await expect(storage.listParts(other, uploadId)).rejects.toMatchObject({ statusCode: 404 });
    await expect(storage.listParts(mine, uploadId)).resolves.toEqual([]);
  });

  it('issues deterministic upload ids and content-addressed etags', async () => {
    const first = createInMemoryStorage();
    const second = createInMemoryStorage();
    const key = uniqueKey();

    const firstId = await first.createMultipartUpload(key);
    const secondId = await second.createMultipartUpload(key);
    const firstPart = await first.uploadPart(key, firstId, 1, Buffer.from('same-bytes'));
    const secondPart = await second.uploadPart(key, secondId, 1, Buffer.from('same-bytes'));

    // Determinism is a harness requirement, not a nicety: an id or an etag drawn
    // from entropy would make a failing assertion irreproducible from the seed.
    expect(firstId).toBe(secondId);
    expect(firstPart.etag).toBe(secondPart.etag);
    // Quoted, as S3 returns it, because the provider passes an ETag through
    // verbatim and a test that compared unquoted values would pass here and fail
    // against the engine.
    expect(firstPart.etag.startsWith('"')).toBe(true);
    expect(firstPart.etag.endsWith('"')).toBe(true);
  });

  it('lists every open upload when no prefix is given', async () => {
    const storage = createInMemoryStorage();
    const first = uniqueKey();
    const second = uniqueKey();
    await storage.createMultipartUpload(first);
    await storage.createMultipartUpload(second);

    const listed = await storage.listMultipartUploads();

    expect([...listed].map((upload) => upload.key).sort()).toEqual([first, second].sort());
  });
});
