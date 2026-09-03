import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { StorageProvider, StorageRangeRead } from '../../src/services/storage/types.js';

/**
 * The storage-port CONTRACT: the behaviour every `StorageProvider` must have,
 * written once and run against every implementation.
 *
 * This module holds the cases rather than a `.test.ts` file so that two suites can
 * run them: `storage-contract.test.ts` runs them against the in-memory double in
 * the ordinary push tier, and the conformance gate runs the same function against a
 * real engine in a container. A test file cannot be imported by another test file
 * without being collected twice, which is why the cases live here and each suite is
 * a two-line caller.
 *
 * Two rules kept every case honest:
 *
 *   * **Nothing here may assert an engine-specific refusal.** A part below a
 *     service's minimum size, `InvalidPart`, a checksum requirement: those differ
 *     between S3 services, so they belong to the engine-specific half of the
 *     conformance suite. What is asserted here is what this design DEPENDS on, and
 *     what a second implementation could get wrong while still looking finished.
 *
 *     The same rule caught a case in this very file once the conformance gate
 *     existed to check it: the LISTING ORDER of open multipart uploads was
 *     asserted here as "key order", which is documented behaviour for one AWS
 *     bucket class, is documented as NOT holding for another, and does not hold for
 *     the engine this stack ships. It has been replaced by the completeness claim
 *     the collector actually rests on. An ordering belief is exactly the shape this
 *     rule exists to keep out.
 *   * **The part sizes are deliberately tiny.** The port is size-agnostic — its job
 *     is concatenation, ordering and ranges — so exercising it with 8 MiB parts
 *     would buy nothing but minutes. The real 8 MiB framing is proved by the
 *     conformance gate against the real engine and by the upload suites. This does
 *     rest on one engine PERMISSION rather than on the design alone: real AWS S3 and
 *     Cloudflare R2 reject a non-final part below 5 MiB with `EntityTooSmall`, and
 *     the engine this stack ships accepts one (measured). Running these cases
 *     against a stricter service means raising the sizes here, not weakening a case.
 */

/** What a caller must supply in order to run the contract against something. */
export interface StorageContractHarness {
  provider: StorageProvider;
  /**
   * A key nothing else in this run uses. The conformance gate shares one bucket
   * across a file, so uniqueness cannot be assumed from an empty bucket.
   */
  uniqueKey: () => string;
}

/** Reads a ranged read to the end, so a case can compare exact bytes. */
async function collect(read: StorageRangeRead): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of read.body) {
    chunks.push(Buffer.from(chunk as Buffer));
  }
  return Buffer.concat(chunks);
}

/** Bytes with a recognisable pattern, so a wrong slice is obvious in a diff. */
function pattern(label: string, length: number): Buffer {
  const body = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) {
    body[index] = (label.charCodeAt(0) + index) % 256;
  }
  return body;
}

export function runStorageContract(
  label: string,
  setup: () => StorageContractHarness | Promise<StorageContractHarness>,
): void {
  describe(`StorageProvider contract (${label})`, () => {
    let provider: StorageProvider;
    let uniqueKey: () => string;
    let issuedKeys: string[];

    /** A fresh key, remembered so teardown can reclaim whatever the case left. */
    function newKey(): string {
      const key = uniqueKey();
      issuedKeys.push(key);
      return key;
    }

    /** A key derived from another, for the cases that need several at one prefix. */
    function derivedKey(base: string, suffix: string): string {
      const key = `${base}-${suffix}`;
      issuedKeys.push(key);
      return key;
    }

    beforeEach(async () => {
      const harness = await setup();
      provider = harness.provider;
      uniqueKey = harness.uniqueKey;
      issuedKeys = [];
    });

    afterEach(async () => {
      // Teardown swallows failures on purpose: a case that already failed must not
      // be reported a second time as a cleanup error, and against a real engine an
      // object the case never created is an expected 404 here.
      for (const key of issuedKeys) {
        const uploads = await provider.listMultipartUploads(key).catch(() => []);
        for (const upload of uploads) {
          await provider.abortMultipartUpload(upload.key, upload.uploadId).catch(() => undefined);
        }
        await provider.deleteObject(key).catch(() => undefined);
      }
    });

    it('confirms the bucket is reachable without writing anything to it', async () => {
      const key = newKey();

      await expect(provider.headBucket()).resolves.toBeUndefined();

      const listing = await provider.listObjects(key);
      expect(listing.objects).toEqual([]);
      expect(listing.nextContinuationToken).toBeUndefined();
    });

    it('stores a whole object and reads back its exact bytes at every boundary', async () => {
      const key = newKey();
      const body = pattern('A', 16);
      await provider.putObject(key, body);

      const stat = await provider.headObject(key);
      expect(stat.bytes).toBe(16);

      // Whole object, first byte, last byte, and an interior slice: an off-by-one
      // in either end of an inclusive range shows up in at least one of these.
      expect(await collect(await provider.getObjectRange(key, 0, 15))).toEqual(body);
      expect(await collect(await provider.getObjectRange(key, 0, 0))).toEqual(body.subarray(0, 1));
      expect(await collect(await provider.getObjectRange(key, 15, 15))).toEqual(body.subarray(15));
      expect(await collect(await provider.getObjectRange(key, 4, 11))).toEqual(
        body.subarray(4, 12),
      );

      // The reported length is the length of the RANGE, not of the object, which is
      // what the read path sets Content-Length from.
      expect((await provider.getObjectRange(key, 4, 11)).bytes).toBe(8);
    });

    it('reports a missing object as 404 on both read paths', async () => {
      const key = newKey();

      await expect(provider.headObject(key)).rejects.toMatchObject({ statusCode: 404 });
      await expect(provider.getObjectRange(key, 0, 15)).rejects.toMatchObject({ statusCode: 404 });
    });

    it('deletes one key, leaves its neighbour, and treats a repeat delete as done', async () => {
      const base = newKey();
      const doomed = derivedKey(base, 'doomed');
      const survivor = derivedKey(base, 'survivor');
      await provider.putObject(doomed, pattern('B', 8));
      await provider.putObject(survivor, pattern('C', 8));

      await provider.deleteObject(doomed);

      await expect(provider.headObject(doomed)).rejects.toMatchObject({ statusCode: 404 });
      // The negative that matters for the garbage collector: a per-key delete must
      // never take a second object with it.
      await expect(provider.headObject(survivor)).resolves.toMatchObject({ bytes: 8 });
      // Idempotent, which is what lets the purge path run twice after a crash.
      await expect(provider.deleteObject(doomed)).resolves.toBeUndefined();
    });

    it('assembles a multipart upload as the pure concatenation of its parts', async () => {
      const key = newKey();
      const first = pattern('D', 32);
      const second = pattern('E', 32);
      const third = pattern('F', 5);
      const uploadId = await provider.createMultipartUpload(key);

      const uploaded = [
        await provider.uploadPart(key, uploadId, 1, first),
        await provider.uploadPart(key, uploadId, 2, second),
        await provider.uploadPart(key, uploadId, 3, third),
      ];
      expect(uploaded.map((part) => part.bytes)).toEqual([32, 32, 5]);

      // The ledger the completion step verifies: ascending, one entry per part, with
      // the exact sizes. A short FINAL part is legitimate; the server is what
      // refuses a short middle one.
      const ledger = await provider.listParts(key, uploadId);
      expect(ledger.map((part) => part.partNumber)).toEqual([1, 2, 3]);
      expect(ledger.map((part) => part.bytes)).toEqual([32, 32, 5]);
      expect(ledger.map((part) => part.etag)).toEqual(uploaded.map((part) => part.etag));

      await provider.completeMultipartUpload(
        key,
        uploadId,
        uploaded.map((part) => ({ partNumber: part.partNumber, etag: part.etag })),
      );

      const stat = await provider.headObject(key);
      expect(stat.bytes).toBe(69);
      expect(await collect(await provider.getObjectRange(key, 0, 68))).toEqual(
        Buffer.concat([first, second, third]),
      );
      // Every part is readable at exactly the offset the framing predicts, which is
      // the property "one segment is one part is one range" rests on.
      expect(await collect(await provider.getObjectRange(key, 0, 31))).toEqual(first);
      expect(await collect(await provider.getObjectRange(key, 32, 63))).toEqual(second);
      expect(await collect(await provider.getObjectRange(key, 64, 68))).toEqual(third);

      // And the upload is gone, so the garbage collector will not try to abort it.
      await expect(provider.listMultipartUploads(key)).resolves.toEqual([]);
    });

    it('orders the stored object by PART NUMBER, not by the order the parts arrived', async () => {
      const key = newKey();
      const first = pattern('N', 12);
      const second = pattern('O', 12);
      const uploadId = await provider.createMultipartUpload(key);

      // Deliberately backwards on both counts: part 2 is uploaded first, and the
      // completion names it first. A client retrying one part out of a queue does
      // exactly this, and an implementation that concatenated in ARRIVAL order
      // would produce a file that decrypts to nothing with no error anywhere.
      const secondEntry = await provider.uploadPart(key, uploadId, 2, second);
      const firstEntry = await provider.uploadPart(key, uploadId, 1, first);
      await provider.completeMultipartUpload(key, uploadId, [
        { partNumber: 2, etag: secondEntry.etag },
        { partNumber: 1, etag: firstEntry.etag },
      ]);

      const body = await collect(await provider.getObjectRange(key, 0, 23));
      expect(body).toEqual(Buffer.concat([first, second]));
      expect(body.subarray(0, 12)).not.toEqual(second);
    });

    it('replaces a re-uploaded part number instead of appending a second entry', async () => {
      const key = newKey();
      const first = pattern('G', 16);
      const stale = pattern('H', 16);
      const fresh = pattern('I', 9);
      const uploadId = await provider.createMultipartUpload(key);

      const firstEntry = await provider.uploadPart(key, uploadId, 1, first);
      const staleEntry = await provider.uploadPart(key, uploadId, 2, stale);
      const freshEntry = await provider.uploadPart(key, uploadId, 2, fresh);

      const ledger = await provider.listParts(key, uploadId);
      // The negative: a retried part must not leave the upload holding two entries
      // for part 2, because the completion step counts them.
      expect(ledger).toHaveLength(2);
      expect(ledger[1]).toMatchObject({ partNumber: 2, bytes: 9, etag: freshEntry.etag });
      expect(freshEntry.etag).not.toBe(staleEntry.etag);

      await provider.completeMultipartUpload(key, uploadId, [
        { partNumber: 1, etag: firstEntry.etag },
        { partNumber: 2, etag: freshEntry.etag },
      ]);

      const body = await collect(await provider.getObjectRange(key, 0, 24));
      expect(body).toEqual(Buffer.concat([first, fresh]));
      expect(body.byteLength).toBe(25);
    });

    it('abandons an aborted upload and materialises no object for it', async () => {
      const key = newKey();
      const uploadId = await provider.createMultipartUpload(key);
      await provider.uploadPart(key, uploadId, 1, pattern('J', 16));

      await provider.abortMultipartUpload(key, uploadId);

      await expect(provider.listMultipartUploads(key)).resolves.toEqual([]);
      // The negative: an abort must not leave a half-written object behind, because
      // quota is counted from stored bytes.
      await expect(provider.headObject(key)).rejects.toMatchObject({ statusCode: 404 });
      await expect(provider.uploadPart(key, uploadId, 2, pattern('K', 16))).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it('reports an unknown upload id as 404 rather than as an empty ledger', async () => {
      const key = newKey();

      await expect(provider.listParts(key, 'no-such-upload-id')).rejects.toMatchObject({
        statusCode: 404,
      });
      await expect(provider.abortMultipartUpload(key, 'no-such-upload-id')).rejects.toMatchObject({
        statusCode: 404,
      });
    });

    it('lists an open upload with its key, its id and when it was initiated', async () => {
      const mine = newKey();
      const other = newKey();
      const myUploadId = await provider.createMultipartUpload(mine);
      await provider.createMultipartUpload(other);

      const listed = await provider.listMultipartUploads(mine);

      expect(listed).toHaveLength(1);
      expect(listed[0]).toMatchObject({ key: mine, uploadId: myUploadId });
      // The garbage collector aborts an upload only when it can prove it is old, so
      // a real initiation date is a requirement rather than a nicety.
      expect(listed[0]?.initiated).toBeInstanceOf(Date);
      // The negative: the prefix filter is what keeps one account's sweep away from
      // another's uploads.
      expect(listed.map((upload) => upload.key)).not.toContain(other);
    });

    it('reports every open upload under the prefix, in an order no caller may assume', async () => {
      // COMPLETENESS is what the collector depends on; SEQUENCE is not, and this
      // case used to assert the sequence. It said "S3 sorts by object key first and
      // only then by initiation time", which is a property of ONE AWS bucket class
      // rather than of S3: the ListMultipartUploads reference documents exactly
      // that sorting for a general purpose bucket and, in the same block, documents
      // a directory bucket as one where "the multipart uploads aren't sorted
      // lexicographically based on the object keys".
      //
      // The engine this stack ships does not sort by key either. MEASURED
      // 2026-09-02 against the pinned image: five uploads opened for keys
      // zz, aa, mm, bb, yy came back as yy, bb, mm, zz, aa — neither key order nor
      // the order they were opened in — and the sequence is exactly the set sorted
      // by UPLOAD ID, stable across repeated calls. Two uploads on ONE key came
      // back reversed. Against a bucket shared with the rest of a suite the old
      // assertion therefore failed about three runs in four.
      //
      // So the port promises a complete page and says nothing about its sequence,
      // which is what `types.ts` documents and what `documentCleanup`'s first sweep
      // is written for: it FILTERS on `initiated` and never breaks early, which is
      // correct under all three of those orders and under any other. The engine's
      // own ordering is recorded in the conformance suite, where a real engine can
      // keep the record honest; the double's is pinned in `storage-contract.test.ts`,
      // where it belongs, because it is a determinism choice for a fake.
      const base = newKey();
      const openedFirst = derivedKey(base, 'a');
      const openedSecond = derivedKey(base, 'b');
      const firstId = await provider.createMultipartUpload(openedFirst);
      const secondId = await provider.createMultipartUpload(openedSecond);

      const listed = await provider.listMultipartUploads(`${base}-`);

      // THE NEGATIVE this case exists for, asserted before anything else so that a
      // short answer cannot slip past a vacuous loop: the listing must not be
      // TRUNCATED to the head of whatever order the engine picked. A provider that
      // returned the engine's first entry only, or that stopped at one page and
      // dropped the rest, passes any "is it sorted" assertion and fails here — and
      // in production it would strand every upload behind the head, unreclaimed,
      // for ever.
      expect(listed).toHaveLength(2);
      expect(listed.map((upload) => `${upload.key}#${upload.uploadId}`).sort()).toEqual(
        [`${openedFirst}#${firstId}`, `${openedSecond}#${secondId}`].sort(),
      );
      // Every entry is individually datable, which is what makes FILTERING possible
      // where ordering is not: an entry whose age the caller cannot read is one the
      // collector must leave alone, so the field has to be present per entry rather
      // than inferable from a position in the list.
      for (const upload of listed) {
        expect(upload.initiated).toBeInstanceOf(Date);
      }
    });

    it('pages a prefix listing through its continuation token, each key exactly once', async () => {
      const base = newKey();
      const outsider = newKey();
      const keys = ['1', '2', '3', '4', '5'].map((suffix) => derivedKey(base, suffix));
      for (const key of keys) {
        await provider.putObject(key, pattern('L', 4));
      }
      await provider.putObject(outsider, pattern('M', 4));

      const seen: string[] = [];
      let continuationToken: string | undefined;
      let pages = 0;
      do {
        const page = await provider.listObjects(`${base}-`, {
          maxKeys: 2,
          ...(continuationToken === undefined ? {} : { continuationToken }),
        });
        pages += 1;
        expect(page.objects.length).toBeLessThanOrEqual(2);
        for (const object of page.objects) {
          seen.push(object.key);
          expect(object.bytes).toBe(4);
        }
        continuationToken = page.nextContinuationToken;
      } while (continuationToken !== undefined && pages < 10);

      expect([...seen].sort()).toEqual([...keys].sort());
      expect(new Set(seen).size).toBe(keys.length);
      expect(pages).toBe(3);
      // The negative: a prefix listing must never reach a key outside the prefix,
      // which is the guarantee an account-wide erasure rests on.
      expect(seen).not.toContain(outsider);
    });

    it('resumes a prefix listing strictly after a key it is given, and ignores it once past', async () => {
      const base = newKey();
      const keys = ['1', '2', '3', '4'].map((suffix) => derivedKey(base, suffix));
      for (const key of keys) {
        await provider.putObject(key, pattern('S', 4));
      }

      // `startAfter` takes an ordinary key rather than an engine-minted token,
      // which is the whole reason the garbage collector's orphan sweep can stop
      // after a bounded slice of the bucket and continue an hour later. A
      // continuation token could not carry that: it is opaque, so no caller may
      // assume it still means anything on the next run.
      const resumed = await provider.listObjects(`${base}-`, { startAfter: keys[1] as string });

      expect(resumed.objects.map((object) => object.key)).toEqual([keys[2], keys[3]]);

      // Past the last key there is nothing left, and that is an empty page rather
      // than an error or a wrap back to the beginning — which is what lets the
      // sweep recognise the end of the bucket and start over on its next run.
      const exhausted = await provider.listObjects(`${base}-`, { startAfter: keys[3] as string });
      expect(exhausted.objects).toEqual([]);
      expect(exhausted.nextContinuationToken).toBeUndefined();
    });
  });
}
