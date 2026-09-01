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
 * Nothing in it uses entropy: upload ids come from a per-instance counter, ETags are
 * the SHA-256 of the bytes, and every stored timestamp comes from the injectable
 * clock in {@link InMemoryStorageOptions} (defaulting to `new Date()`), so two runs
 * of a test produce the same values.
 *
 * ONE LIMIT REMAINS, recorded here because it will be discovered at exactly the
 * wrong moment otherwise: its multipart implementation accepts non-final parts of
 * ANY size, which the shared contract relies on. Real AWS S3 and Cloudflare R2
 * refuse a non-final part below 5 MiB with `EntityTooSmall`; the engine this stack
 * ships tolerates it (measured), which is why the contract suite may use tiny
 * parts. That is a property of the engine under test, not of every S3 service.
 *
 * The limit that USED to sit beside it — that the double always populated
 * `lastModified` and `initiated`, so the "an object whose age I cannot establish is
 * one I must not delete" rule could not be reached — is gone: {@link
 * InMemoryStorageOptions} now carries `omitTimestamps` for exactly that case, and
 * `clock` for the ages the garbage collector's thresholds are expressed in. Both
 * arrived with the tests that call them, which is why they are not dead options.
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

/**
 * S3's own default page size for a listing, so pagination behaves the same way.
 *
 * Exported because a test that must cross the page boundary has to seed
 * `DEFAULT_MAX_KEYS + 1` objects, and a test restating `1_000` for itself stops
 * testing pagination the day this number changes — it would then seed a single
 * page and pass while asserting nothing.
 */
export const DEFAULT_MAX_KEYS = 1_000;

/** Quoted, as S3 returns it, because the provider passes an ETag through verbatim. */
function etagFor(body: Buffer): string {
  return `"${createHash('sha256').update(body).digest('hex')}"`;
}

/**
 * The two knobs the garbage collector's tests need, and nothing else.
 *
 * Both exist because the collector reasons about TIME, which is the one thing a
 * double cannot be allowed to take from the wall clock: its thresholds are "older
 * than `DOCUMENT_UPLOAD_TTL_HOURS + 1h`" and "older than 24 h", and a test that
 * seeded an object and then waited a day to assert on it is not a test.
 */
export interface InMemoryStorageOptions {
  /**
   * The clock every stored timestamp is read from. Injectable rather than frozen,
   * so one test can seed an object "yesterday" and another "just now" against the
   * same instance by moving the clock between writes.
   */
  clock?: () => Date;
  /**
   * When true, every listing reports objects and uploads WITHOUT a timestamp,
   * exactly as an engine that declines to report one does.
   *
   * This is not an oddity worth skipping: `StoredObjectSummary.lastModified` and
   * `StorageUploadSummary.initiated` are optional in the port precisely so that
   * "I cannot establish this object's age" is representable, and the collector's
   * rule is that such an object must be LEFT ALONE. Without this option the rule
   * is unreachable, so the branch that enforces it could be deleted and every test
   * would still pass.
   */
  omitTimestamps?: boolean;
}

export function createInMemoryStorage(
  options: InMemoryStorageOptions = {},
): InMemoryStorageProvider {
  const now = options.clock ?? ((): Date => new Date());
  const omitTimestamps = options.omitTimestamps ?? false;
  const objects = new Map<string, StoredObject>();
  const uploads = new Map<string, PendingUpload>();
  let uploadCounter = 0;

  /**
   * Spreads a timestamp into a summary, or nothing at all under `omitTimestamps`.
   * One helper for all three call sites, so the double cannot end up reporting an
   * age on one listing and withholding it on another.
   */
  function withLastModified(value: Date): { lastModified?: Date } {
    return omitTimestamps ? {} : { lastModified: value };
  }

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
      objects.set(key, { body: Buffer.from(body), lastModified: now() });
    },

    headObject: async (key: string): Promise<StoredObjectStat> => {
      const object = requireObject(key);
      return { bytes: object.body.byteLength, ...withLastModified(object.lastModified) };
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
      // S3 ignores `StartAfter` when a `ContinuationToken` is present, so the
      // token wins here too: the double must not answer a call one way that the
      // engine answers another.
      const after = options?.continuationToken ?? options?.startAfter;
      const matching = [...objects.entries()]
        .filter(([key]) => key.startsWith(prefix))
        .filter(([key]) => after === undefined || key > after)
        .sort(([left], [right]) => (left < right ? -1 : 1));

      const page = matching.slice(0, maxKeys);
      const objectsPage: StoredObjectSummary[] = page.map(([key, object]) => ({
        key,
        bytes: object.body.byteLength,
        ...withLastModified(object.lastModified),
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
      uploads.set(uploadId, { key, initiated: now(), parts: new Map() });
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
      objects.set(key, { body: Buffer.concat(bodies), lastModified: now() });
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
        summaries.push({
          key: upload.key,
          uploadId,
          ...(omitTimestamps ? {} : { initiated: upload.initiated }),
        });
      }
      // Sorted by KEY, then by initiation time among uploads sharing one, because
      // that is the order S3 reports and the port warns callers about explicitly:
      // it is NOT age order, so a sweep that stopped at the first entry younger
      // than its threshold would leave older uploads unreclaimed for ever.
      // Returning insertion order here would make that trap unreachable through the
      // double — a test could seed the young upload first, pass, and prove nothing.
      summaries.sort((left, right) => {
        if (left.key !== right.key) return left.key < right.key ? -1 : 1;
        return (left.initiated?.getTime() ?? 0) - (right.initiated?.getTime() ?? 0);
      });
      return summaries;
    },
  };
}
