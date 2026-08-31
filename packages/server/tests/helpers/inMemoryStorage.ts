import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { httpErrors } from '@hiprax/errors';
import type {
  CompletedPart,
  ListObjectsOptions,
  StorageObjectPage,
  StoragePart,
  StorageProvider,
  StorageRangeRead,
  StorageUploadSummary,
  StoredObjectStat,
  StoredObjectSummary,
} from '../../src/services/storage/types.js';

/**
 * An in-memory `StorageProvider` over two Maps.
 *
 * WHY IT EXISTS. Object storage is an EXTERNAL service, in the same class as SMTP
 * and the breach API, so the unit and integration tiers replace it here rather than
 * starting a container per test file. The datastore under test in those tiers is
 * Mongo, and Mongo stays real. What this double must never become is a second
 * implementation with its own opinions: the same contract suite
 * (`helpers/storageContract.ts`) runs against this and against a real engine in the
 * conformance gate, so a divergence is a test failure rather than a surprise in
 * production.
 *
 * It therefore models the S3 semantics the design depends on, deliberately:
 *
 *   * a completed multipart object is the pure CONCATENATION of its parts in
 *     ascending part-number order, which is what makes one crypto segment one part
 *     one range;
 *   * re-uploading a part number REPLACES that entry rather than appending a second
 *     one;
 *   * a `Range` read is INCLUSIVE at both ends, and an `end` past the object is
 *     clamped, exactly as S3 clamps it;
 *   * a missing object or an unknown upload id is the same 404 the real provider
 *     maps `NoSuchKey` and `NoSuchUpload` to, so a caller cannot tell the two
 *     implementations apart by their failures either;
 *   * `deleteObject` on an absent key SUCCEEDS, because S3's delete is idempotent
 *     and the garbage collector relies on that.
 *
 * What it does NOT model is any engine-specific refusal (a part below a service's
 * minimum size, `InvalidPart`, `EntityTooSmall`): those are exactly what the
 * conformance gate exists to measure against the real thing, and inventing them
 * here would mean asserting a behaviour nobody verified.
 *
 * Nothing in it uses entropy or the wall clock beyond `new Date()` for a stored
 * timestamp: upload ids come from a per-instance counter, and ETags are the SHA-256
 * of the bytes, so two runs of a test produce the same values.
 *
 * TWO LIMITS, recorded here because each will be discovered at exactly the wrong
 * moment otherwise:
 *
 *   1. It ALWAYS populates `lastModified` and `initiated`, so the one case those
 *      fields are optional FOR — the garbage collector's "an object whose age I
 *      cannot establish is one I must not delete" rule — cannot be reached through
 *      this double as written. The job that needs that case has to give the double a
 *      way to omit them (a constructor option, added by the phase that has a test
 *      calling it; adding one now with no caller fails the dead-code gate).
 *   2. Its multipart implementation accepts non-final parts of ANY size, which the
 *      shared contract relies on. Real AWS S3 and Cloudflare R2 refuse a non-final
 *      part below 5 MiB with `EntityTooSmall`; the engine this stack ships tolerates
 *      it (measured), which is why the contract suite may use tiny parts. That is a
 *      property of the engine under test, not of every S3 service.
 */

interface StoredObject {
  body: Buffer;
  lastModified: Date;
}

interface PendingUpload {
  key: string;
  initiated: Date;
  /** Keyed by part number, so a re-upload replaces rather than appends. */
  parts: Map<number, { etag: string; body: Buffer }>;
}

/**
 * The double plus the two inspection helpers a test needs in order to assert what
 * did NOT happen, which is the half of an assertion a mock usually cannot make.
 */
export interface InMemoryStorageProvider extends StorageProvider {
  /** Every key currently stored, sorted, for "nothing was written" assertions. */
  storedKeys(): string[];
  /** The stored bytes of one object, or `undefined` when it is absent. */
  readObject(key: string): Buffer | undefined;
}

/** S3's own default page size for a listing, so pagination behaves the same way. */
const DEFAULT_MAX_KEYS = 1_000;

/** Quoted, as S3 returns it, because the provider passes an ETag through verbatim. */
function etagFor(body: Buffer): string {
  return `"${createHash('sha256').update(body).digest('hex')}"`;
}

export function createInMemoryStorage(): InMemoryStorageProvider {
  const objects = new Map<string, StoredObject>();
  const uploads = new Map<string, PendingUpload>();
  let uploadCounter = 0;

  function requireObject(key: string): StoredObject {
    const object = objects.get(key);
    if (!object) {
      throw httpErrors.notFound('Stored object not found');
    }
    return object;
  }

  function requireUpload(uploadId: string, key: string): PendingUpload {
    const upload = uploads.get(uploadId);
    // The key is checked as well as the id: an upload id names one key, and a call
    // that pairs them wrongly is a bug the real engine also refuses.
    if (!upload || upload.key !== key) {
      throw httpErrors.notFound('Multipart upload not found');
    }
    return upload;
  }

  return {
    storedKeys: (): string[] => [...objects.keys()].sort(),

    readObject: (key: string): Buffer | undefined => objects.get(key)?.body,

    // EVERY method below is `async`, without exception, and that is not a style
    // choice. These bodies throw for a missing object or an unknown upload id, and
    // a non-async function throws SYNCHRONOUSLY: a caller writing
    // `await provider.headObject(key)` inside a try/catch would still be served,
    // but `expect(...).rejects` would not, and neither would a caller that stores
    // the promise before awaiting it. The real provider is async all the way down,
    // so anything else here is a difference between the double and production.
    headBucket: async (): Promise<void> => {
      // Nothing to check: the double IS the bucket.
    },

    putObject: async (key: string, body: Uint8Array): Promise<void> => {
      // `Buffer.from` COPIES. Storing the caller's buffer by reference would let a
      // test mutate an object it had already "uploaded", which a socket cannot do.
      objects.set(key, { body: Buffer.from(body), lastModified: new Date() });
    },

    headObject: async (key: string): Promise<StoredObjectStat> => {
      const object = requireObject(key);
      return { bytes: object.body.byteLength, lastModified: object.lastModified };
    },

    getObjectRange: async (key: string, start: number, end: number): Promise<StorageRangeRead> => {
      const object = requireObject(key);
      if (start >= object.body.byteLength || start > end || start < 0) {
        // The real provider maps the engine's 416 to a 500. The server never asks
        // for a range outside the object (`segmentRange` refuses to compute one),
        // so this exists to make a future bug loud instead of returning an empty
        // stream that would surface as a decryption failure in the browser.
        throw httpErrors.internalServerError('Requested range is not satisfiable');
      }
      // S3 clamps an end past the object rather than failing, and so does this.
      const slice = object.body.subarray(start, Math.min(end + 1, object.body.byteLength));
      return { body: Readable.from([slice]), bytes: slice.byteLength };
    },

    deleteObject: async (key: string): Promise<void> => {
      // No existence check: S3's delete is idempotent, and the purge path repeats
      // after a crash precisely because it is.
      objects.delete(key);
    },

    listObjects: async (
      prefix: string,
      options?: ListObjectsOptions,
    ): Promise<StorageObjectPage> => {
      const maxKeys = options?.maxKeys ?? DEFAULT_MAX_KEYS;
      const after = options?.continuationToken;
      const matching = [...objects.entries()]
        .filter(([key]) => key.startsWith(prefix))
        .filter(([key]) => after === undefined || key > after)
        .sort(([left], [right]) => (left < right ? -1 : 1));

      const page = matching.slice(0, maxKeys);
      const objectsPage: StoredObjectSummary[] = page.map(([key, object]) => ({
        key,
        bytes: object.body.byteLength,
        lastModified: object.lastModified,
      }));
      const lastKey = page.at(-1)?.[0];
      const truncated = matching.length > page.length;

      return {
        objects: objectsPage,
        // The token is the last key returned, which is what makes the next page
        // resume strictly after it. `undefined` means the listing is complete.
        ...(truncated && lastKey !== undefined ? { nextContinuationToken: lastKey } : {}),
      };
    },

    createMultipartUpload: async (key: string): Promise<string> => {
      uploadCounter += 1;
      const uploadId = `mem-upload-${String(uploadCounter)}`;
      uploads.set(uploadId, { key, initiated: new Date(), parts: new Map() });
      return uploadId;
    },

    uploadPart: async (
      key: string,
      uploadId: string,
      partNumber: number,
      body: Uint8Array,
    ): Promise<StoragePart> => {
      const upload = requireUpload(uploadId, key);
      const stored = Buffer.from(body);
      const etag = etagFor(stored);
      // Keyed by part number, so a retry REPLACES the entry. An append would leave
      // the completion step counting two parts where the client sent one.
      upload.parts.set(partNumber, { etag, body: stored });
      return { partNumber, etag, bytes: stored.byteLength };
    },

    completeMultipartUpload: async (
      key: string,
      uploadId: string,
      parts: CompletedPart[],
    ): Promise<void> => {
      const upload = requireUpload(uploadId, key);
      const ordered = [...parts].sort((left, right) => left.partNumber - right.partNumber);
      const bodies: Buffer[] = [];
      for (const part of ordered) {
        const held = upload.parts.get(part.partNumber);
        if (!held || held.etag !== part.etag) {
          throw httpErrors.internalServerError(
            `Multipart completion referenced part ${String(part.partNumber)}, which the upload does not hold`,
          );
        }
        bodies.push(held.body);
      }
      objects.set(key, { body: Buffer.concat(bodies), lastModified: new Date() });
      uploads.delete(uploadId);
    },

    abortMultipartUpload: async (key: string, uploadId: string): Promise<void> => {
      requireUpload(uploadId, key);
      uploads.delete(uploadId);
    },

    listParts: async (key: string, uploadId: string): Promise<StoragePart[]> => {
      const upload = requireUpload(uploadId, key);
      const parts = [...upload.parts.entries()]
        .map(([partNumber, part]) => ({
          partNumber,
          etag: part.etag,
          bytes: part.body.byteLength,
        }))
        // Ascending, as the engine reports them, so a caller checking contiguity
        // sees the same order from both implementations.
        .sort((left, right) => left.partNumber - right.partNumber);
      return parts;
    },

    listMultipartUploads: async (prefix?: string): Promise<StorageUploadSummary[]> => {
      const summaries: StorageUploadSummary[] = [];
      for (const [uploadId, upload] of uploads) {
        if (prefix !== undefined && !upload.key.startsWith(prefix)) continue;
        summaries.push({ key: upload.key, uploadId, initiated: upload.initiated });
      }
      return summaries;
    },
  };
}
