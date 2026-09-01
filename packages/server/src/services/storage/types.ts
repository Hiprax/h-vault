import type { Readable } from 'node:stream';

/**
 * The storage port: everything the document store needs from object storage, and
 * nothing else.
 *
 * It exists so that exactly one module in this codebase knows what S3 is. The
 * controller, the garbage-collection job and the account-cascade helper speak this
 * interface; `s3Provider.ts` is the only implementation that ships, and the test
 * suite's in-memory double implements the same twelve methods so the unit tier
 * needs no container while the conformance gate runs the identical cases against a
 * real engine.
 *
 * Three shaping rules, each one a decision rather than an accident:
 *
 *   * **The bucket is not a parameter.** It belongs to the configured provider, so
 *     no caller can address another bucket and no test can pass one by mistake.
 *   * **Keys are opaque strings here.** They are built by `utils/documentObjects.ts`
 *     and are always server-assigned; this layer neither parses nor validates them.
 *   * **Deletion is per key.** There is deliberately no bulk-delete method: S3's
 *     Multi-Object Delete MANDATES a request checksum, which the pinned
 *     `WHEN_REQUIRED` checksum settings do not remove, and depending on it would
 *     quietly break the "any S3-compatible service works" promise on the services
 *     that reject the SDK's checksum header. Per-key deletes cost one request each
 *     on paths (garbage collection, account erasure) that are already asynchronous.
 *
 * Failures arrive as HTTP errors from `@hiprax/errors`, mapped once inside the
 * implementation: a missing object is 404, an unreachable engine is 503, and
 * anything else is 500 with the underlying error preserved on `cause` and logged.
 * A caller therefore never inspects an SDK error shape, and the in-memory double
 * raises the same errors for the same conditions.
 */
export interface StorageProvider {
  /**
   * Proves the configured bucket exists and the credentials can see it. Used as a
   * readiness probe, and by the conformance gate to wait for a freshly started
   * engine without a fixed sleep.
   */
  headBucket(): Promise<void>;

  /**
   * Writes a whole object in one request. Used ONLY for a single-segment upload,
   * where a multipart upload would be three round trips to store one 8 MiB part.
   */
  putObject(key: string, body: Uint8Array): Promise<void>;

  /** Size and last-modified time of one stored object. 404 when it is absent. */
  headObject(key: string): Promise<StoredObjectStat>;

  /**
   * Reads one INCLUSIVE byte range, as a stream.
   *
   * A stream rather than a buffer because the read path pipes it straight to the
   * HTTP response: buffering here would make the server's memory a multiple of the
   * segment size times the number of concurrent downloads. `start` and `end` come
   * from `segmentRange`, never from a client-supplied header.
   */
  getObjectRange(key: string, start: number, end: number): Promise<StorageRangeRead>;

  /** Deletes one object. Absent is not an error: S3 delete is idempotent. */
  deleteObject(key: string): Promise<void>;

  /**
   * Lists one page of objects under a prefix.
   *
   * Pagination is the CALLER's, deliberately: the orphan sweep bounds itself to a
   * fixed number of keys per run, so it must be able to stop, and a helper that
   * looped internally would hand it the whole bucket.
   *
   * The other side of that decision is a trap, so it is written down here rather
   * than learned later: a caller that must be EXHAUSTIVE has to follow
   * `nextContinuationToken` itself. One user may own up to `MAX_DOCUMENTS_PER_USER`
   * objects against an engine page of a thousand, so an account erasure that read
   * one page would silently leave the rest of that account's ciphertext in the
   * bucket, recoverable only by the orphan sweep's own hourly bound.
   */
  listObjects(prefix: string, options?: ListObjectsOptions): Promise<StorageObjectPage>;

  /** Opens a multipart upload and returns the engine's upload id. */
  createMultipartUpload(key: string): Promise<string>;

  /** Uploads one part and returns the ledger entry the completion step verifies. */
  uploadPart(
    key: string,
    uploadId: string,
    partNumber: number,
    body: Uint8Array,
  ): Promise<StoragePart>;

  /**
   * Completes a multipart upload from the given parts, which the implementation
   * sends in ascending part-number order because S3 requires it.
   */
  completeMultipartUpload(key: string, uploadId: string, parts: CompletedPart[]): Promise<void>;

  /**
   * Abandons a multipart upload and lets the engine reclaim its parts. Used when a
   * completion is refused and by the garbage collector for uploads no staging row
   * claims.
   */
  abortMultipartUpload(key: string, uploadId: string): Promise<void>;

  /**
   * The COMPLETE part ledger the engine holds for an upload, paginated
   * internally.
   *
   * Internally, unlike `listObjects`, because a partial answer here is a WRONG
   * answer: the completion step counts these parts and compares their sizes, so a
   * truncated page would refuse a legitimate upload or accept a mis-framed one.
   */
  listParts(key: string, uploadId: string): Promise<StoragePart[]>;

  /**
   * One page of multipart uploads the engine still holds, in the ENGINE's own order,
   * each with the time it recorded when the upload was initiated.
   *
   * NOT in age order, and a caller must not assume it is: S3 sorts these by object
   * key first and only then by initiation time among uploads sharing a key. A sweep
   * that stopped at the first entry younger than its threshold would therefore leave
   * older uploads unreclaimed for ever. Filter on `initiated`; never break early.
   *
   * One page (up to the engine's own maximum) rather than every upload: this feeds
   * a best-effort reclamation that runs hourly, so a backlog drains over successive
   * runs, and an unbounded listing on a shared code path is how one wedged account
   * starves the job.
   */
  listMultipartUploads(prefix?: string): Promise<StorageUploadSummary[]>;
}

/** Options for one page of a prefix listing. */
export interface ListObjectsOptions {
  /**
   * Opaque token from a previous page's {@link StorageObjectPage}.
   *
   * OPAQUE is the operative word, and it bounds the lifetime of this value: S3
   * documents the token as obfuscated and says nothing about how long one stays
   * valid or whether it survives being handed back later. It is therefore the
   * right way to walk one listing to its end INSIDE a single operation, and the
   * wrong way to resume a walk an hour later — for which {@link startAfter}
   * exists.
   */
  continuationToken?: string;
  /**
   * Resume the listing strictly AFTER this key, which is an ordinary key rather
   * than an engine-minted token.
   *
   * It exists for the garbage collector's orphan sweep, the one caller that
   * examines a bounded slice of the bucket per run and continues from where the
   * previous run stopped. A `continuationToken` cannot express that: it is opaque,
   * so nothing may assume it is still meaningful on the next hourly tick, and the
   * in-memory double could only ever pretend otherwise. `StartAfter` is a plain
   * string this codebase produced itself, so the double and the real engine agree
   * on it by construction and the conformance suite can pin that agreement.
   *
   * S3 ignores `StartAfter` when `ContinuationToken` is also present. Callers pass
   * one or the other, never both.
   */
  startAfter?: string;
  /** Upper bound on the keys in this page. The engine may return fewer. */
  maxKeys?: number;
}

/** One page of a prefix listing. */
export interface StorageObjectPage {
  objects: StoredObjectSummary[];
  /**
   * Present only while more pages exist, so `nextContinuationToken === undefined`
   * is the end of the listing and needs no separate `isTruncated` flag to
   * contradict.
   */
  nextContinuationToken?: string;
}

/** One object as a listing reports it. */
export interface StoredObjectSummary {
  key: string;
  bytes: number;
  /**
   * Optional because an engine is not obliged to report it, and the orphan sweep
   * requires it: a key whose age is unknown is a key that sweep must leave alone,
   * so absence has to be representable rather than defaulted to the epoch.
   */
  lastModified?: Date;
}

/** One object as `headObject` reports it. */
export interface StoredObjectStat {
  bytes: number;
  lastModified?: Date;
}

/** A ranged read: the stream and the number of bytes the engine says it holds. */
export interface StorageRangeRead {
  body: Readable;
  /**
   * The length the engine reported for the range. Compared against the length the
   * framing predicts, so a short or over-long range is caught here rather than
   * surfacing as a decryption failure in the browser.
   */
  bytes: number;
}

/** One entry of an upload's part ledger. */
export interface StoragePart {
  /** One-based, as S3 numbers parts. */
  partNumber: number;
  etag: string;
  bytes: number;
}

/** The identifying half of a part, which is all a completion needs. */
export interface CompletedPart {
  partNumber: number;
  etag: string;
}

/** One multipart upload the engine still holds. */
export interface StorageUploadSummary {
  key: string;
  uploadId: string;
  /**
   * Optional for the same reason as `lastModified` above: the garbage collector
   * only aborts an upload it can prove is old, so an unknown initiation time means
   * "leave it".
   */
  initiated?: Date;
}
