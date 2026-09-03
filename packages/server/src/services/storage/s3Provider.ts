import { Readable } from 'node:stream';
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CreateMultipartUploadCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListMultipartUploadsCommand,
  ListObjectsV2Command,
  ListPartsCommand,
  PutObjectCommand,
  S3Client,
  UploadPartCommand,
} from '@aws-sdk/client-s3';
import { httpErrors } from '@hiprax/errors';
import { createModuleLogger } from '../../utils/logger.js';
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
} from './types.js';

const logger = createModuleLogger('storage/s3');

/**
 * The S3-compatible implementation of the storage port — the ONLY module in this
 * codebase that imports the AWS SDK.
 *
 * Everything the SDK will not do for us is done here, once:
 *
 *   * the client options are PINNED and explained, because two of them decide
 *     whether this works against anything other than the engine it was developed
 *     against;
 *   * every response is checked for the fields the caller depends on, because the
 *     SDK types every one of them as optional and a missing ETag turns into a
 *     completion that fails hours later;
 *   * every failure is mapped to an HTTP error exactly once, so no controller ever
 *     inspects an SDK error shape.
 */

/** Everything the provider needs in order to reach a bucket. */
export interface S3StorageOptions {
  endpoint: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  forcePathStyle: boolean;
}

/**
 * Bound the CONNECT phase, so an endpoint that resolves but never answers surfaces
 * as a 503 in a few seconds instead of hanging a request until the client gives up.
 */
const S3_CONNECTION_TIMEOUT_MS = 5_000;

/**
 * Bound socket IDLENESS, not total duration.
 *
 * The distinction is the whole reason `requestTimeout` is deliberately absent
 * below. `requestTimeout` caps how long the request AND response may take in
 * total, and on the segment read path the response is a stream this server pipes
 * to the browser: a slow phone applies backpressure, the body takes as long as the
 * download takes, and a total cap would abort a perfectly healthy transfer. An
 * idle timeout kills a socket that has stopped making progress, which is the
 * failure actually worth reacting to.
 */
const S3_SOCKET_IDLE_TIMEOUT_MS = 60_000;

/**
 * One initial attempt plus two retries. Pinned rather than inherited so that a
 * future SDK default cannot silently multiply the request budget of a path that
 * already holds a semaphore slot and 8 MiB of buffered part.
 */
const S3_MAX_ATTEMPTS = 3;

/**
 * SDK/engine error names that mean "the thing you named is not there".
 *
 * `NoSuchBucket` is deliberately NOT in this set. S3 reports a missing bucket as a
 * 404 too, but the two mean opposite things to a user: a missing OBJECT is an
 * ordinary answer the UI renders as "this file is gone", while a missing BUCKET is
 * a misconfigured deployment in which EVERY document reads as gone. Telling
 * somebody their files are permanently lost because an operator renamed a bucket is
 * the wrong answer in a password manager, and the 404 branch is deliberately
 * unlogged, so the mistake would not even leave a trace. It is classified as
 * unavailable instead: 503, logged, and recoverable.
 */
const NOT_FOUND_TOKENS = new Set(['NoSuchKey', 'NotFound', 'NoSuchUpload']);

/**
 * Error names and system error codes that mean "the engine could not be reached",
 * as opposed to "the engine answered and said no".
 *
 * The distinction matters to the caller: an unreachable engine is a 503 the client
 * may retry, while a refusal is a defect one of the two sides has to fix.
 */
const UNAVAILABLE_TOKENS = new Set([
  // The configured target is not there at all — an operator problem, not a user's
  // missing file. See NOT_FOUND_TOKENS above for why it lives here despite S3
  // answering 404 for it.
  'NoSuchBucket',
  'TimeoutError',
  'RequestAbortedError',
  'NetworkingError',
  'ECONNREFUSED',
  'ECONNRESET',
  'ENOTFOUND',
  'EAI_AGAIN',
  'EPIPE',
  'ETIMEDOUT',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPROTO',
  'ERR_SOCKET_CONNECTION_TIMEOUT',
]);

/** How far down a `cause` chain the classifier looks before giving up. */
const MAX_CAUSE_DEPTH = 4;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Flattens an unknown thrown value into the two things the classifier needs: every
 * `name`/`code` string on it or its causes, and the HTTP status the SDK recorded.
 *
 * The `cause` walk is not decoration. The SDK wraps a socket-level failure in its
 * own error, so `ECONNREFUSED` is routinely one or two levels down, and a
 * classifier that only read the top-level `name` would report a wedged endpoint as
 * a 500.
 */
function describeError(error: unknown): { tokens: Set<string>; status: number | undefined } {
  const tokens = new Set<string>();
  let status: number | undefined;
  let current: unknown = error;

  for (let depth = 0; depth <= MAX_CAUSE_DEPTH && isRecord(current); depth += 1) {
    const name = current.name;
    const code = current.code;
    if (typeof name === 'string') tokens.add(name);
    if (typeof code === 'string') tokens.add(code);

    const metadata = current.$metadata;
    if (status === undefined && isRecord(metadata)) {
      const httpStatusCode = metadata.httpStatusCode;
      if (typeof httpStatusCode === 'number') status = httpStatusCode;
    }

    current = current.cause;
  }

  return { tokens, status };
}

function hasAnyToken(tokens: Set<string>, candidates: Set<string>): boolean {
  for (const token of tokens) {
    if (candidates.has(token)) return true;
  }
  return false;
}

/**
 * The single mapping from a storage failure to an HTTP error, and therefore the
 * single place this feature decides what a storage failure MEANS.
 *
 *   * a missing object, upload or bucket -> 404, unlogged, because it is an
 *     ordinary answer: the read path renders it as "this file is gone" and the
 *     garbage collector treats it as work already done;
 *   * an unreachable or overloaded engine -> 503, logged, because the operator is
 *     the only person who can act on it;
 *   * anything else -> 500 with the original error on `cause` and logged, because
 *     the error middleware redacts a 5xx body in production and the cause is then
 *     the only surviving description.
 *
 * Returns the error rather than throwing it, so every call site reads
 * `throw mapStorageError(...)` and the compiler still sees the function it is in
 * as terminating.
 */
function mapStorageError(error: unknown, operation: string): Error {
  const { tokens, status } = describeError(error);

  // Resolved BEFORE the 404 branch, because a missing bucket arrives as a 404 and
  // the name is the only thing separating "this object is gone" from "everything is
  // gone". A status-first order would classify it as an ordinary missing file.
  const unavailableByName = hasAnyToken(tokens, UNAVAILABLE_TOKENS);

  if (!unavailableByName && (status === 404 || hasAnyToken(tokens, NOT_FOUND_TOKENS))) {
    return httpErrors.notFound('Stored object not found', { cause: error });
  }

  // A 503 or 504 FROM the engine is the engine telling us it cannot serve the
  // request right now, which is the same thing a refused connection tells us, so
  // it earns the same status rather than a generic 500.
  if (unavailableByName || status === 503 || status === 504) {
    logger.error('Object storage is unreachable', {
      operation,
      tokens: [...tokens],
      status,
    });
    return httpErrors.serviceUnavailable('Object storage is unavailable', { cause: error });
  }

  logger.error('Object storage request failed', { operation, tokens: [...tokens], status });
  return httpErrors.internalServerError('Object storage request failed', { cause: error });
}

/**
 * A response field the caller cannot work without. Raised as a 500 with the
 * operation named, because an engine that omits an ETag or a content length is
 * broken in a way no retry fixes and no client can be told about.
 */
function missingField(operation: string, field: string): Error {
  logger.error('Object storage response was incomplete', { operation, field });
  return httpErrors.internalServerError(`Object storage response omitted ${field}`);
}

/** Builds one part-ledger entry, refusing a response that cannot describe a part. */
function toStoragePart(
  operation: string,
  part: { PartNumber?: number | undefined; ETag?: string | undefined; Size?: number | undefined },
): StoragePart {
  const { PartNumber, ETag, Size } = part;
  if (PartNumber === undefined || ETag === undefined || Size === undefined) {
    throw missingField(operation, 'a complete part ledger entry');
  }
  // The ETag is passed through VERBATIM, quotes included. S3 returns it quoted and
  // expects the same string back at completion; normalising it here would make the
  // value this server stores differ from the value the engine compares.
  return { partNumber: PartNumber, etag: ETag, bytes: Size };
}

/**
 * Builds an S3 provider over the given connection settings.
 *
 * The client is created once per provider and lives for the process: its keep-alive
 * sockets are what keep a thirteen-part upload from re-handshaking thirteen times.
 * `getStorage()` in this directory's `index.ts` is what makes that "once".
 */
export function createS3Provider(options: S3StorageOptions): StorageProvider {
  const { bucket } = options;
  const client = new S3Client({
    endpoint: options.endpoint,
    region: options.region,
    credentials: {
      accessKeyId: options.accessKeyId,
      secretAccessKey: options.secretAccessKey,
    },
    // Virtual-host addressing puts the bucket in the hostname, which needs DNS
    // that an in-stack service name does not have. Operator-configurable, because
    // a hosted service may require the other style.
    forcePathStyle: options.forcePathStyle,
    // PORTABILITY AND STREAMING, not a fix for any one engine. The SDK's default
    // is 'WHEN_SUPPORTED', which adds a CRC32 header to every request and
    // validates one on every response. Two reasons that is wrong here, and
    // neither is the engine this stack ships with (that one ACCEPTS the defaults,
    // measured):
    //   * Cloudflare R2 and Backblaze B2 reject the SDK's default checksum
    //     header, so the "any S3-compatible service works" promise would be false
    //     the first time somebody pointed this at their own storage;
    //   * a RANGED get of a multipart object has no whole-object checksum to
    //     validate, so response validation cannot help the read path at all.
    // Every segment is AES-GCM sealed, so integrity does not depend on this: a
    // flipped bit fails the tag check in the browser, which is the only place a
    // checksum could be trusted in a zero-knowledge design anyway.
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    maxAttempts: S3_MAX_ATTEMPTS,
    requestHandler: {
      connectionTimeout: S3_CONNECTION_TIMEOUT_MS,
      socketTimeout: S3_SOCKET_IDLE_TIMEOUT_MS,
    },
  });

  /** Runs one SDK call, mapping any failure exactly once. */
  async function send<T>(operation: string, call: () => Promise<T>): Promise<T> {
    try {
      return await call();
    } catch (error) {
      throw mapStorageError(error, operation);
    }
  }

  return {
    headBucket: async (): Promise<void> => {
      await send('HeadBucket', () => client.send(new HeadBucketCommand({ Bucket: bucket })));
    },

    putObject: async (key: string, body: Uint8Array): Promise<void> => {
      await send('PutObject', () =>
        client.send(
          new PutObjectCommand({
            Bucket: bucket,
            Key: key,
            Body: body,
            // Stated explicitly so the request carries a plain Content-Length
            // rather than a chunked-encoding body, which some S3 services refuse.
            ContentLength: body.byteLength,
          }),
        ),
      );
    },

    headObject: async (key: string): Promise<StoredObjectStat> => {
      const response = await send('HeadObject', () =>
        client.send(new HeadObjectCommand({ Bucket: bucket, Key: key })),
      );
      if (typeof response.ContentLength !== 'number') {
        throw missingField('HeadObject', 'ContentLength');
      }
      return {
        bytes: response.ContentLength,
        ...(response.LastModified === undefined ? {} : { lastModified: response.LastModified }),
      };
    },

    getObjectRange: async (key: string, start: number, end: number): Promise<StorageRangeRead> => {
      const response = await send('GetObject', () =>
        client.send(
          new GetObjectCommand({
            Bucket: bucket,
            Key: key,
            // INCLUSIVE on both ends, which is what `segmentRange` produces.
            Range: `bytes=${String(start)}-${String(end)}`,
          }),
        ),
      );
      // In Node the SDK hands back an `IncomingMessage`, which IS a Readable. The
      // check is a narrowing rather than a suspicion, and it costs nothing.
      if (!(response.Body instanceof Readable)) {
        throw missingField('GetObject', 'a readable body');
      }
      if (typeof response.ContentLength !== 'number') {
        throw missingField('GetObject', 'ContentLength');
      }
      return { body: response.Body, bytes: response.ContentLength };
    },

    deleteObject: async (key: string): Promise<void> => {
      // Per key, never Multi-Object Delete: that operation mandates a request
      // checksum, which the pinned checksum settings above do not remove.
      await send('DeleteObject', () =>
        client.send(new DeleteObjectCommand({ Bucket: bucket, Key: key })),
      );
    },

    listObjects: async (
      prefix: string,
      listOptions?: ListObjectsOptions,
    ): Promise<StorageObjectPage> => {
      const response = await send('ListObjectsV2', () =>
        client.send(
          new ListObjectsV2Command({
            Bucket: bucket,
            Prefix: prefix,
            ...(listOptions?.continuationToken === undefined
              ? {}
              : { ContinuationToken: listOptions.continuationToken }),
            ...(listOptions?.startAfter === undefined
              ? {}
              : { StartAfter: listOptions.startAfter }),
            ...(listOptions?.maxKeys === undefined ? {} : { MaxKeys: listOptions.maxKeys }),
          }),
        ),
      );
      const objects: StoredObjectSummary[] = [];
      for (const object of response.Contents ?? []) {
        // A row with no key or no size describes nothing actionable. Skipped
        // rather than thrown, because the ONE caller is a sweep that deletes
        // objects: it must be able to keep going, and it must never act on a row
        // it cannot fully read.
        if (object.Key === undefined || object.Size === undefined) continue;
        objects.push({
          key: object.Key,
          bytes: object.Size,
          ...(object.LastModified === undefined ? {} : { lastModified: object.LastModified }),
        });
      }
      const nextContinuationToken =
        response.IsTruncated === true ? response.NextContinuationToken : undefined;
      return {
        objects,
        ...(nextContinuationToken === undefined ? {} : { nextContinuationToken }),
      };
    },

    createMultipartUpload: async (key: string): Promise<string> => {
      const response = await send('CreateMultipartUpload', () =>
        client.send(new CreateMultipartUploadCommand({ Bucket: bucket, Key: key })),
      );
      if (response.UploadId === undefined) {
        throw missingField('CreateMultipartUpload', 'UploadId');
      }
      return response.UploadId;
    },

    uploadPart: async (
      key: string,
      uploadId: string,
      partNumber: number,
      body: Uint8Array,
    ): Promise<StoragePart> => {
      const response = await send('UploadPart', () =>
        client.send(
          new UploadPartCommand({
            Bucket: bucket,
            Key: key,
            UploadId: uploadId,
            PartNumber: partNumber,
            Body: body,
            ContentLength: body.byteLength,
          }),
        ),
      );
      if (response.ETag === undefined) {
        throw missingField('UploadPart', 'ETag');
      }
      // The size is echoed from what was SENT rather than read back from the
      // response: the engine does not report it here, and the caller needs it to
      // keep its own ledger.
      return { partNumber, etag: response.ETag, bytes: body.byteLength };
    },

    completeMultipartUpload: async (
      key: string,
      uploadId: string,
      parts: CompletedPart[],
    ): Promise<void> => {
      // Ascending part order is an S3 requirement, and the caller's ledger is
      // already verified against `ListParts` before it gets here. Sorting a copy
      // means a caller cannot get this wrong, and costs one pass over at most a
      // few hundred entries.
      const ordered = [...parts].sort((left, right) => left.partNumber - right.partNumber);
      await send('CompleteMultipartUpload', () =>
        client.send(
          new CompleteMultipartUploadCommand({
            Bucket: bucket,
            Key: key,
            UploadId: uploadId,
            MultipartUpload: {
              Parts: ordered.map((part) => ({ PartNumber: part.partNumber, ETag: part.etag })),
            },
          }),
        ),
      );
    },

    abortMultipartUpload: async (key: string, uploadId: string): Promise<void> => {
      await send('AbortMultipartUpload', () =>
        client.send(
          new AbortMultipartUploadCommand({ Bucket: bucket, Key: key, UploadId: uploadId }),
        ),
      );
    },

    listParts: async (key: string, uploadId: string): Promise<StoragePart[]> => {
      const parts: StoragePart[] = [];
      let partNumberMarker: string | undefined;

      // Paginated to exhaustion, unlike every other listing here: the completion
      // step COUNTS these parts and compares their sizes, so stopping at the
      // engine's first page (1,000 parts) would silently answer a different
      // question than the one asked.
      do {
        const response = await send('ListParts', () =>
          client.send(
            new ListPartsCommand({
              Bucket: bucket,
              Key: key,
              UploadId: uploadId,
              ...(partNumberMarker === undefined ? {} : { PartNumberMarker: partNumberMarker }),
            }),
          ),
        );
        for (const part of response.Parts ?? []) {
          parts.push(toStoragePart('ListParts', part));
        }
        partNumberMarker =
          response.IsTruncated === true ? response.NextPartNumberMarker : undefined;
      } while (partNumberMarker !== undefined);

      return parts;
    },

    listMultipartUploads: async (prefix?: string): Promise<StorageUploadSummary[]> => {
      const response = await send('ListMultipartUploads', () =>
        client.send(
          new ListMultipartUploadsCommand({
            Bucket: bucket,
            ...(prefix === undefined ? {} : { Prefix: prefix }),
          }),
        ),
      );
      const uploads: StorageUploadSummary[] = [];
      for (const upload of response.Uploads ?? []) {
        // Same rule as the object listing: an entry missing its key or its upload
        // id cannot be aborted, so it is skipped rather than allowed to abort the
        // whole sweep.
        if (upload.Key === undefined || upload.UploadId === undefined) continue;
        uploads.push({
          key: upload.Key,
          uploadId: upload.UploadId,
          ...(upload.Initiated === undefined ? {} : { initiated: upload.Initiated }),
        });
      }
      return uploads;
    },
  };
}
