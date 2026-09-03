/**
 * `services/storage/s3Provider.ts` and `services/storage/index.ts`, with the AWS
 * SDK mocked at its own boundary.
 *
 * WHY THIS SUITE EXISTS AT ALL, because the reason shapes every case in it. The
 * push tier reaches the documents controller through a mock of
 * `services/storage/index.js`, and the conformance gate runs the contract suite
 * against the interface, so without this file `s3Provider.ts` would be production
 * code that NOTHING in the push tier ever executes — roughly 120 lines of it,
 * against a package coverage aggregate that is ratcheted upward and can only be
 * satisfied by covering the code rather than by excluding it.
 *
 * The seam is `S3Client`: its constructor is captured so the PINNED client options
 * are asserted as the values the provider really passes, and its `send` is a spy so
 * every command, every input and every failure mapping is asserted without a socket.
 * Every command class is the REAL one (`importOriginal`), so a command's name and
 * its `input` are the SDK's own, not a fake's.
 *
 * Three classes of assertion, and the last two are the ones a hand-written mock
 * usually misses:
 *
 *   1. the client options, including the deliberate ABSENCE of `requestTimeout`;
 *   2. the response fields the SDK types as optional and the caller cannot work
 *      without — a missing ETag, a missing content length, a body that is not a
 *      stream, a part ledger entry with a hole in it;
 *   3. the failure mapping, which is the only place in this feature that decides
 *      what a storage failure MEANS to an HTTP client.
 */
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
// Named rather than restated: `packages/shared/tests/constants.test.ts` fails any
// file outside the definition that spells either chunk size as a decimal literal,
// and it is right to — a second copy of 8 MiB is a second source of truth.
import { DOCUMENT_CIPHERTEXT_CHUNK_BYTES } from '@hvault/shared';

/**
 * The SDK boundary. `importOriginal` keeps every command class real; only the
 * client is replaced, and it records what it was constructed with.
 */
const sdk = vi.hoisted(() => ({
  constructed: [] as Record<string, unknown>[],
  send: vi.fn(),
}));

vi.mock('@aws-sdk/client-s3', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@aws-sdk/client-s3')>();
  class CapturingS3Client {
    send = sdk.send;
    constructor(clientConfig: Record<string, unknown>) {
      sdk.constructed.push(clientConfig);
    }
  }
  return { ...actual, S3Client: CapturingS3Client };
});

/**
 * The module logger, mocked so the "with the cause logged" half of the mapping
 * contract is assertable, and so a 404 can be proved NOT to log.
 */
const logs = vi.hoisted(() => ({
  error: vi.fn(),
  warn: vi.fn(),
  info: vi.fn(),
  debug: vi.fn(),
  verbose: vi.fn(),
  http: vi.fn(),
  silly: vi.fn(),
}));

vi.mock('../src/utils/logger.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/utils/logger.js')>();
  return { ...actual, createModuleLogger: () => logs };
});

const { createS3Provider } = await import('../src/services/storage/s3Provider.js');
const { config } = await import('../src/config/index.js');
// `getStorage` is deliberately NOT imported here: its two behaviours (the 503 and
// the memoisation) are asserted against FRESH module instances, because the memo is
// process-lifetime and the suite runs in shuffled order.
const { resolveStorageOptions } = await import('../src/services/storage/index.js');

type S3StorageOptions = Parameters<typeof createS3Provider>[0];

const OPTIONS: S3StorageOptions = {
  endpoint: 'http://hvault-storage:3900',
  region: 'garage-region',
  bucket: 'hvault-documents',
  accessKeyId: 'access-key-id',
  secretAccessKey: 'secret-access-key-value',
  forcePathStyle: true,
};

const KEY = 'u/66c0f1a2b3c4d5e6f7a8b9c0/d/507f1f77bcf86cd799439011';

/** Every command the provider sent, as its class name and its exact input. */
function sentCommands(): { name: string; input: unknown }[] {
  return sdk.send.mock.calls.map((call) => {
    const command = call[0] as { constructor: { name: string }; input: unknown };
    return { name: command.constructor.name, input: command.input };
  });
}

/** An error shaped the way the SDK shapes one. */
function sdkError(name: string, extra: Record<string, unknown> = {}): Error {
  return Object.assign(new Error(`simulated ${name}`), { name }, extra);
}

beforeEach(() => {
  sdk.constructed.length = 0;
  sdk.send.mockReset();
  for (const level of Object.values(logs)) level.mockClear();
});

describe('createS3Provider — the pinned client options', () => {
  it('passes exactly the documented option set to the SDK client', () => {
    createS3Provider(OPTIONS);

    expect(sdk.constructed).toHaveLength(1);
    expect(sdk.constructed[0]).toEqual({
      endpoint: 'http://hvault-storage:3900',
      region: 'garage-region',
      credentials: {
        accessKeyId: 'access-key-id',
        secretAccessKey: 'secret-access-key-value',
      },
      forcePathStyle: true,
      // Portability and streaming, not a fix for the engine this stack ships:
      // Cloudflare R2 and Backblaze B2 reject the SDK's default checksum header,
      // and a ranged GET of a multipart object has no whole-object checksum to
      // validate in the first place.
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
      maxAttempts: 3,
      requestHandler: {
        connectionTimeout: 5_000,
        socketTimeout: 60_000,
      },
    });
  });

  it('sets no total request timeout, because the read path streams to the client', () => {
    createS3Provider(OPTIONS);

    const clientConfig = sdk.constructed[0];
    const requestHandler = clientConfig?.['requestHandler'] as Record<string, unknown> | undefined;

    // THE NEGATIVE THAT MATTERS. `requestTimeout` caps request AND response
    // duration in total, and a segment response is a stream this server pipes to a
    // browser: a slow phone applies backpressure, so a total cap would abort a
    // healthy download. Only socket IDLENESS is bounded.
    expect(requestHandler).not.toHaveProperty('requestTimeout');
    expect(requestHandler).not.toHaveProperty('throwOnRequestTimeout');
    expect(clientConfig).not.toHaveProperty('retryMode');
  });

  it('builds one client per provider, not one per call', async () => {
    const provider = createS3Provider(OPTIONS);
    sdk.send.mockResolvedValue({});

    await provider.headBucket();
    await provider.deleteObject(KEY);

    // Keep-alive is the point: a thirteen-part upload must reuse one connection
    // pool rather than handshake thirteen times.
    expect(sdk.constructed).toHaveLength(1);
  });

  it('hands the real SDK options it actually resolves, not keys it ignores', async () => {
    // The mock above proves what the provider PASSES. This proves the real client
    // accepts and resolves the same values, which a captured object cannot: a
    // renamed or dropped SDK option would sail through every other assertion here.
    createS3Provider(OPTIONS);
    const captured = sdk.constructed[0];
    expect(captured).toBeDefined();

    // The CAPTURED object, not a copy of it retyped here: an assertion built from
    // literals would keep passing if production dropped `maxAttempts` or renamed an
    // option, which is the one failure this case exists to catch.
    const actual = await vi.importActual<typeof import('@aws-sdk/client-s3')>('@aws-sdk/client-s3');
    const client = new actual.S3Client(
      captured as NonNullable<ConstructorParameters<typeof actual.S3Client>[0]>,
    );

    expect(await client.config.region()).toBe('garage-region');
    expect(await client.config.maxAttempts()).toBe(3);
    expect(client.config.forcePathStyle).toBe(true);
    client.destroy();
  });
});

describe('createS3Provider — the command each method issues', () => {
  it('probes the bucket by name', async () => {
    sdk.send.mockResolvedValue({});

    await createS3Provider(OPTIONS).headBucket();

    expect(sentCommands()).toEqual([
      { name: 'HeadBucketCommand', input: { Bucket: 'hvault-documents' } },
    ]);
  });

  it('writes a whole object with an explicit content length', async () => {
    sdk.send.mockResolvedValue({});
    const body = Buffer.from('sealed-segment');

    await createS3Provider(OPTIONS).putObject(KEY, body);

    expect(sentCommands()).toEqual([
      {
        name: 'PutObjectCommand',
        input: {
          Bucket: 'hvault-documents',
          Key: KEY,
          Body: body,
          // Explicit, so the request carries a plain Content-Length instead of a
          // chunked-encoding body that some S3 services refuse.
          ContentLength: 14,
        },
      },
    ]);
  });

  it('reads a range with an INCLUSIVE end and reports the range length', async () => {
    sdk.send.mockResolvedValue({
      Body: Readable.from([Buffer.from('range-bytes')]),
      ContentLength: 11,
    });

    const read = await createS3Provider(OPTIONS).getObjectRange(KEY, 1_024, 2_047);

    expect(sentCommands()).toEqual([
      {
        name: 'GetObjectCommand',
        input: {
          Bucket: 'hvault-documents',
          Key: KEY,
          // Both ends inclusive, exactly what `segmentRange` produces. An
          // exclusive end here would read one byte of the next segment.
          Range: 'bytes=1024-2047',
        },
      },
    ]);
    expect(read.bytes).toBe(11);
    expect(read.body).toBeInstanceOf(Readable);
  });

  it('stats an object and carries its last-modified time through', async () => {
    const lastModified = new Date('2026-08-31T00:00:00.000Z');
    sdk.send.mockResolvedValue({ ContentLength: 8_388_624, LastModified: lastModified });

    const stat = await createS3Provider(OPTIONS).headObject(KEY);

    expect(sentCommands()).toEqual([
      { name: 'HeadObjectCommand', input: { Bucket: 'hvault-documents', Key: KEY } },
    ]);
    expect(stat).toEqual({ bytes: 8_388_624, lastModified });
  });

  it('omits last-modified rather than inventing one when the engine does not report it', async () => {
    sdk.send.mockResolvedValue({ ContentLength: 16 });

    const stat = await createS3Provider(OPTIONS).headObject(KEY);

    // Absence has to survive: the orphan sweep deletes an object only when it can
    // prove the object is old, so a defaulted epoch would make everything old.
    expect(stat).toStrictEqual({ bytes: 16 });
    expect(stat.lastModified).toBeUndefined();
  });

  it('deletes per key, and never through Multi-Object Delete', async () => {
    sdk.send.mockResolvedValue({});
    const provider = createS3Provider(OPTIONS);

    await provider.deleteObject(KEY);
    await provider.deleteObject(`${KEY}-second`);

    // The rule, asserted as a negative because it is invisible otherwise:
    // Multi-Object Delete MANDATES a request checksum, which the pinned
    // `WHEN_REQUIRED` settings do not remove, so depending on it would break the
    // services that reject the SDK's checksum header.
    expect(sentCommands().map((command) => command.name)).toEqual([
      'DeleteObjectCommand',
      'DeleteObjectCommand',
    ]);
    expect(sentCommands().some((command) => command.name.includes('DeleteObjects'))).toBe(false);
  });

  it('opens a multipart upload and returns the engine s upload id', async () => {
    sdk.send.mockResolvedValue({ UploadId: 'engine-upload-id' });

    const uploadId = await createS3Provider(OPTIONS).createMultipartUpload(KEY);

    expect(uploadId).toBe('engine-upload-id');
    expect(sentCommands()).toEqual([
      {
        name: 'CreateMultipartUploadCommand',
        input: { Bucket: 'hvault-documents', Key: KEY },
      },
    ]);
  });

  it('uploads a part with its number and length, and echoes the sent size back', async () => {
    sdk.send.mockResolvedValue({ ETag: '"part-etag"' });
    const body = Buffer.alloc(4_096, 7);

    const part = await createS3Provider(OPTIONS).uploadPart(KEY, 'engine-upload-id', 3, body);

    expect(sentCommands()).toEqual([
      {
        name: 'UploadPartCommand',
        input: {
          Bucket: 'hvault-documents',
          Key: KEY,
          UploadId: 'engine-upload-id',
          PartNumber: 3,
          Body: body,
          ContentLength: 4_096,
        },
      },
    ]);
    // The ETag is passed through VERBATIM, quotes included, because the engine
    // compares the same string back at completion.
    expect(part).toEqual({ partNumber: 3, etag: '"part-etag"', bytes: 4_096 });
  });

  it('completes an upload with its parts sorted ascending, whatever order it was given', async () => {
    sdk.send.mockResolvedValue({});

    await createS3Provider(OPTIONS).completeMultipartUpload(KEY, 'engine-upload-id', [
      { partNumber: 3, etag: '"three"' },
      { partNumber: 1, etag: '"one"' },
      { partNumber: 2, etag: '"two"' },
    ]);

    expect(sentCommands()).toEqual([
      {
        name: 'CompleteMultipartUploadCommand',
        input: {
          Bucket: 'hvault-documents',
          Key: KEY,
          UploadId: 'engine-upload-id',
          MultipartUpload: {
            // S3 requires ascending order, and an out-of-order list is refused by
            // the engine rather than reordered, so a caller cannot get this wrong.
            Parts: [
              { PartNumber: 1, ETag: '"one"' },
              { PartNumber: 2, ETag: '"two"' },
              { PartNumber: 3, ETag: '"three"' },
            ],
          },
        },
      },
    ]);
  });

  it('does not mutate the caller s part list while sorting it', async () => {
    sdk.send.mockResolvedValue({});
    const parts = [
      { partNumber: 2, etag: '"two"' },
      { partNumber: 1, etag: '"one"' },
    ];

    await createS3Provider(OPTIONS).completeMultipartUpload(KEY, 'engine-upload-id', parts);

    // The caller's ledger is its own record of what it uploaded; reordering it
    // underneath would corrupt an audit trail for a sort this function only needs
    // locally.
    expect(parts.map((part) => part.partNumber)).toEqual([2, 1]);
  });

  it('aborts an upload by key and id', async () => {
    sdk.send.mockResolvedValue({});

    await createS3Provider(OPTIONS).abortMultipartUpload(KEY, 'engine-upload-id');

    expect(sentCommands()).toEqual([
      {
        name: 'AbortMultipartUploadCommand',
        input: { Bucket: 'hvault-documents', Key: KEY, UploadId: 'engine-upload-id' },
      },
    ]);
  });

  it('lists objects under a prefix, adding no paging keys when none were asked for', async () => {
    sdk.send.mockResolvedValue({ Contents: [] });

    const page = await createS3Provider(OPTIONS).listObjects('u/66c0f1a2b3c4d5e6f7a8b9c0/');

    // `toStrictEqual`, not `toEqual`: the latter cannot see a key whose value is
    // `undefined`, so it would pass unchanged if the conditional spread became
    // `ContinuationToken: listOptions?.continuationToken` — which is exactly the
    // regression this test's name claims to catch.
    expect(sentCommands()).toStrictEqual([
      {
        name: 'ListObjectsV2Command',
        input: { Bucket: 'hvault-documents', Prefix: 'u/66c0f1a2b3c4d5e6f7a8b9c0/' },
      },
    ]);
    expect(page).toStrictEqual({ objects: [] });
  });

  it('forwards a continuation token and a key ceiling when the caller supplies them', async () => {
    sdk.send.mockResolvedValue({});

    const page = await createS3Provider(OPTIONS).listObjects('u/x/', {
      continuationToken: 'page-2',
      maxKeys: 1_000,
    });

    expect(sentCommands()).toEqual([
      {
        name: 'ListObjectsV2Command',
        input: {
          Bucket: 'hvault-documents',
          Prefix: 'u/x/',
          ContinuationToken: 'page-2',
          MaxKeys: 1_000,
        },
      },
    ]);
    // A response with no `Contents` at all is an empty page, not a crash — and
    // strictly `{objects: []}`, with no `nextContinuationToken` key at all.
    expect(page).toStrictEqual({ objects: [] });
  });

  it('lists one page of multipart uploads, optionally filtered by prefix', async () => {
    const initiated = new Date('2026-08-30T12:00:00.000Z');
    sdk.send.mockResolvedValue({
      Uploads: [{ Key: KEY, UploadId: 'engine-upload-id', Initiated: initiated }],
    });

    const uploads = await createS3Provider(OPTIONS).listMultipartUploads('u/x/');

    expect(sentCommands()).toEqual([
      {
        name: 'ListMultipartUploadsCommand',
        input: { Bucket: 'hvault-documents', Prefix: 'u/x/' },
      },
    ]);
    expect(uploads).toEqual([{ key: KEY, uploadId: 'engine-upload-id', initiated }]);
  });

  it('sends no prefix at all when the caller wants every upload', async () => {
    sdk.send.mockResolvedValue({});

    const uploads = await createS3Provider(OPTIONS).listMultipartUploads();

    expect(sentCommands()).toStrictEqual([
      { name: 'ListMultipartUploadsCommand', input: { Bucket: 'hvault-documents' } },
    ]);
    expect(uploads).toStrictEqual([]);
  });
});

describe('createS3Provider — responses the engine may not fill in', () => {
  it('refuses a ranged read whose body is not a stream', async () => {
    sdk.send.mockResolvedValue({ Body: 'not-a-stream', ContentLength: 12 });

    await expect(createS3Provider(OPTIONS).getObjectRange(KEY, 0, 11)).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted a readable body',
    });
    expect(logs.error).toHaveBeenCalledWith('Object storage response was incomplete', {
      operation: 'GetObject',
      field: 'a readable body',
    });
  });

  it('refuses a ranged read with no content length rather than guessing one', async () => {
    sdk.send.mockResolvedValue({ Body: Readable.from([Buffer.from('x')]) });

    await expect(createS3Provider(OPTIONS).getObjectRange(KEY, 0, 0)).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted ContentLength',
    });
  });

  it('refuses a stat with no content length, because quota is counted from it', async () => {
    sdk.send.mockResolvedValue({ LastModified: new Date() });

    await expect(createS3Provider(OPTIONS).headObject(KEY)).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted ContentLength',
    });
  });

  it('refuses an upload id the engine did not return', async () => {
    sdk.send.mockResolvedValue({ Bucket: 'hvault-documents' });

    await expect(createS3Provider(OPTIONS).createMultipartUpload(KEY)).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted UploadId',
    });
  });

  it('refuses a part with no ETag, because completion needs it hours later', async () => {
    sdk.send.mockResolvedValue({});

    await expect(
      createS3Provider(OPTIONS).uploadPart(KEY, 'engine-upload-id', 1, Buffer.alloc(8)),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted ETag',
    });
  });

  it.each([
    ['no part number', { ETag: '"e"', Size: 8 }],
    ['no ETag', { PartNumber: 1, Size: 8 }],
    ['no size', { PartNumber: 1, ETag: '"e"' }],
  ])('refuses a part ledger entry with %s', async (_label, part) => {
    sdk.send.mockResolvedValue({ Parts: [part] });

    await expect(
      createS3Provider(OPTIONS).listParts(KEY, 'engine-upload-id'),
    ).rejects.toMatchObject({
      statusCode: 500,
      message: 'Object storage response omitted a complete part ledger entry',
    });
  });

  it('skips a listed object it cannot fully read instead of acting on half of it', async () => {
    sdk.send.mockResolvedValue({
      Contents: [
        { Key: `${KEY}-a`, Size: 16, LastModified: new Date('2026-01-01T00:00:00.000Z') },
        { Size: 16 },
        { Key: `${KEY}-c` },
        { Key: `${KEY}-d`, Size: 32 },
      ],
    });

    const page = await createS3Provider(OPTIONS).listObjects('u/');

    // The one caller is a sweep that DELETES objects. A row with no key or no size
    // describes nothing it can act on, so it is dropped rather than allowed to
    // abort the sweep or, worse, to be acted on with a defaulted value.
    expect(page.objects).toStrictEqual([
      { key: `${KEY}-a`, bytes: 16, lastModified: new Date('2026-01-01T00:00:00.000Z') },
      // Strictly two keys: no `lastModified: undefined` on the row the engine gave
      // no timestamp for, because absence is what the orphan sweep reads.
      { key: `${KEY}-d`, bytes: 32 },
    ]);
  });

  it('skips a listed upload it cannot abort instead of failing the whole sweep', async () => {
    sdk.send.mockResolvedValue({
      Uploads: [{ Key: KEY, UploadId: 'good' }, { UploadId: 'no-key' }, { Key: `${KEY}-b` }],
    });

    const uploads = await createS3Provider(OPTIONS).listMultipartUploads();

    expect(uploads).toStrictEqual([{ key: KEY, uploadId: 'good' }]);
  });
});

describe('createS3Provider — pagination', () => {
  it('walks every page of a part ledger, because a partial ledger is a wrong answer', async () => {
    sdk.send
      .mockResolvedValueOnce({
        Parts: [{ PartNumber: 1, ETag: '"one"', Size: DOCUMENT_CIPHERTEXT_CHUNK_BYTES }],
        IsTruncated: true,
        NextPartNumberMarker: '1',
      })
      .mockResolvedValueOnce({
        Parts: [{ PartNumber: 2, ETag: '"two"', Size: 1_234 }],
        IsTruncated: false,
      });

    const parts = await createS3Provider(OPTIONS).listParts(KEY, 'engine-upload-id');

    expect(parts).toEqual([
      { partNumber: 1, etag: '"one"', bytes: DOCUMENT_CIPHERTEXT_CHUNK_BYTES },
      { partNumber: 2, etag: '"two"', bytes: 1_234 },
    ]);
    const commands = sentCommands();
    expect(commands).toHaveLength(2);
    // The marker is what makes the second request the NEXT page rather than the
    // same one again, and a loop that dropped it would never terminate.
    expect(commands[0]?.input).toEqual({
      Bucket: 'hvault-documents',
      Key: KEY,
      UploadId: 'engine-upload-id',
    });
    expect(commands[1]?.input).toEqual({
      Bucket: 'hvault-documents',
      Key: KEY,
      UploadId: 'engine-upload-id',
      PartNumberMarker: '1',
    });
  });

  it('reads an upload with no parts yet as an empty ledger', async () => {
    // A staging row can exist before its first part lands, and the completion
    // check must see "no parts" rather than crash on a response field the engine
    // omits when there is nothing to report.
    sdk.send.mockResolvedValue({ IsTruncated: false });

    await expect(createS3Provider(OPTIONS).listParts(KEY, 'engine-upload-id')).resolves.toEqual([]);
    expect(sentCommands()).toHaveLength(1);
  });

  it('stops walking a part ledger when the engine truncates without a marker', async () => {
    // Truncated but with no next marker: continuing would re-request page one for
    // ever. One page is the honest answer, and the completion check then refuses
    // the upload on the part COUNT rather than hanging.
    sdk.send.mockResolvedValue({
      Parts: [{ PartNumber: 1, ETag: '"one"', Size: 8 }],
      IsTruncated: true,
    });

    const parts = await createS3Provider(OPTIONS).listParts(KEY, 'engine-upload-id');

    expect(parts).toHaveLength(1);
    expect(sentCommands()).toHaveLength(1);
  });

  it('hands a prefix listing s continuation token to the caller rather than looping', async () => {
    sdk.send.mockResolvedValue({
      Contents: [{ Key: KEY, Size: 16 }],
      IsTruncated: true,
      NextContinuationToken: 'page-2',
    });

    const page = await createS3Provider(OPTIONS).listObjects('u/');

    // The orphan sweep bounds itself to a fixed number of keys per run, so it must
    // be able to STOP. A provider that paginated internally would hand it the
    // whole bucket.
    expect(page.nextContinuationToken).toBe('page-2');
    expect(sentCommands()).toHaveLength(1);
  });

  it('reports no continuation token when the listing is complete', async () => {
    sdk.send.mockResolvedValue({
      Contents: [{ Key: KEY, Size: 16 }],
      IsTruncated: false,
      // A token present on a non-truncated response is meaningless, and following
      // it would list the bucket twice.
      NextContinuationToken: 'stale-token',
    });

    const page = await createS3Provider(OPTIONS).listObjects('u/');

    expect(page.nextContinuationToken).toBeUndefined();
  });

  it('reads exactly one page of multipart uploads, even when the engine has more', async () => {
    sdk.send.mockResolvedValue({
      Uploads: [{ Key: KEY, UploadId: 'first' }],
      IsTruncated: true,
      NextKeyMarker: KEY,
      NextUploadIdMarker: 'first',
    });

    const uploads = await createS3Provider(OPTIONS).listMultipartUploads();

    // Deliberate: this feeds a best-effort reclamation that runs hourly, so a
    // backlog drains over successive runs instead of one wedged account starving
    // the job.
    expect(uploads).toHaveLength(1);
    expect(sentCommands()).toHaveLength(1);
  });
});

describe('createS3Provider — the one place a storage failure is given a meaning', () => {
  it.each([
    ['NoSuchKey by name', sdkError('NoSuchKey')],
    ['NoSuchUpload by name', sdkError('NoSuchUpload')],
    [
      'a 404 with an unfamiliar name',
      sdkError('SomeNewError', { $metadata: { httpStatusCode: 404 } }),
    ],
  ])('maps %s to 404 and does not log it', async (_label, error) => {
    sdk.send.mockRejectedValue(error);

    await expect(createS3Provider(OPTIONS).headObject(KEY)).rejects.toMatchObject({
      statusCode: 404,
      message: 'Stored object not found',
    });
    // A missing object is an ORDINARY answer: the read path renders it and the
    // garbage collector treats it as work already done. Logging it would fill the
    // log with the successful half of a purge.
    expect(logs.error).not.toHaveBeenCalled();
  });

  it.each([
    ['a request timeout', sdkError('TimeoutError')],
    ['an aborted request', sdkError('RequestAbortedError')],
    ['a refused connection', sdkError('Error', { code: 'ECONNREFUSED' })],
    ['a DNS failure', sdkError('Error', { code: 'EAI_AGAIN' })],
    [
      'an engine that says it is unavailable',
      sdkError('ServiceUnavailable', { $metadata: { httpStatusCode: 503 } }),
    ],
    ['a gateway timeout', sdkError('GatewayTimeout', { $metadata: { httpStatusCode: 504 } })],
    // A MISSING BUCKET, which S3 also reports as a 404 and which this deliberately
    // does not treat as one. A missing object is an ordinary answer the UI renders
    // as "this file is gone"; a missing bucket is a misconfigured deployment in
    // which every document reads that way, and the 404 branch is silent, so the
    // operator would get no log either. Classified as unavailable, and the name is
    // what distinguishes the two because the status cannot.
    [
      'a bucket that is not there',
      sdkError('NoSuchBucket', { $metadata: { httpStatusCode: 404 } }),
    ],
  ])('maps %s to 503 and logs it for the operator', async (_label, error) => {
    sdk.send.mockRejectedValue(error);

    await expect(createS3Provider(OPTIONS).headBucket()).rejects.toMatchObject({
      statusCode: 503,
      message: 'Object storage is unavailable',
    });
    expect(logs.error).toHaveBeenCalledWith(
      'Object storage is unreachable',
      expect.objectContaining({ operation: 'HeadBucket' }),
    );
  });

  it('classifies a bare system-error object that carries a code but no name', async () => {
    // Not every failure the SDK surfaces is an Error subclass with a name: a raw
    // system error object reaches the mapper as `{ code, errno, syscall }`, and a
    // classifier that only read `name` would call an unreachable endpoint a 500.
    sdk.send.mockRejectedValue({ code: 'ECONNRESET', syscall: 'read' });

    await expect(createS3Provider(OPTIONS).headBucket()).rejects.toMatchObject({
      statusCode: 503,
    });
  });

  it('ignores an SDK metadata block that carries no numeric status', async () => {
    // `$metadata` is always present on an SDK error and its `httpStatusCode` is
    // typed optional, so an error raised before a response arrived has the block
    // and not the number. It must not be read as a status of zero.
    sdk.send.mockRejectedValue(sdkError('SomethingOdd', { $metadata: {} }));

    await expect(createS3Provider(OPTIONS).headBucket()).rejects.toMatchObject({
      statusCode: 500,
    });
    expect(logs.error).toHaveBeenCalledWith('Object storage request failed', {
      operation: 'HeadBucket',
      tokens: ['SomethingOdd'],
      status: undefined,
    });
  });

  it('finds a socket failure the SDK wrapped inside its own error', async () => {
    const wrapped = Object.assign(sdkError('AggregateError'), {
      cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
    });
    sdk.send.mockRejectedValue(wrapped);

    // Without the cause walk this would be reported as a 500, and an operator
    // whose endpoint is simply wrong would be hunting a defect in this code.
    await expect(createS3Provider(OPTIONS).deleteObject(KEY)).rejects.toMatchObject({
      statusCode: 503,
    });
  });

  it('gives up walking a cause chain rather than following it for ever', async () => {
    // Six levels deep, past the bound. The classifier answers 500 instead of
    // spending unbounded time on a cyclic or adversarial chain, and 500 is the
    // honest answer for an error it could not classify.
    let error: Error = Object.assign(new Error('root'), { code: 'ECONNREFUSED' });
    for (let depth = 0; depth < 6; depth += 1) {
      error = Object.assign(new Error(`wrapper-${String(depth)}`), { cause: error });
    }
    sdk.send.mockRejectedValue(error);

    await expect(createS3Provider(OPTIONS).deleteObject(KEY)).rejects.toMatchObject({
      statusCode: 500,
    });
  });

  it('maps anything else to 500, preserving the cause the production body redacts', async () => {
    const original = sdkError('AccessDenied', { $metadata: { httpStatusCode: 403 } });
    sdk.send.mockRejectedValue(original);

    const failure = await createS3Provider(OPTIONS)
      .putObject(KEY, Buffer.alloc(4))
      .catch((error: unknown) => error);

    expect(failure).toMatchObject({
      statusCode: 500,
      message: 'Object storage request failed',
      // The error middleware redacts a 5xx body in production, so the cause is the
      // only surviving description of what actually happened.
      cause: original,
    });
    expect(logs.error).toHaveBeenCalledWith('Object storage request failed', {
      operation: 'PutObject',
      tokens: ['AccessDenied'],
      status: 403,
    });
  });

  it('maps a thrown value that is not an error object at all', async () => {
    sdk.send.mockRejectedValue('a bare string');

    await expect(createS3Provider(OPTIONS).headBucket()).rejects.toMatchObject({
      statusCode: 500,
      cause: 'a bare string',
    });
    expect(logs.error).toHaveBeenCalledWith('Object storage request failed', {
      operation: 'HeadBucket',
      tokens: [],
      status: undefined,
    });
  });
});

describe('services/storage/index — resolving the configuration', () => {
  const KEYS = ['S3_ENDPOINT', 'S3_BUCKET', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY'] as const;
  const CONFIGURED = {
    S3_ENDPOINT: 'http://hvault-storage:3900',
    S3_BUCKET: 'hvault-documents',
    S3_ACCESS_KEY_ID: 'access-key-id',
    S3_SECRET_ACCESS_KEY: 'secret-access-key-value',
  } as const;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    // The four values are written onto the loaded config object rather than mocked
    // through the config module: mocking it would replace config for the whole
    // module graph, including the harness's own setup file. Restored in afterEach,
    // which is what keeps this safe under the suite's shuffled order.
    saved = Object.fromEntries(KEYS.map((key) => [key, config[key]]));
  });

  afterEach(() => {
    for (const key of KEYS) config[key] = saved[key];
    vi.unstubAllEnvs();
  });

  it('returns every connection value, plus the region and the addressing style', () => {
    Object.assign(config, CONFIGURED);

    expect(resolveStorageOptions()).toEqual({
      endpoint: 'http://hvault-storage:3900',
      bucket: 'hvault-documents',
      accessKeyId: 'access-key-id',
      secretAccessKey: 'secret-access-key-value',
      region: config.S3_REGION,
      forcePathStyle: config.S3_FORCE_PATH_STYLE,
    });
  });

  it.each(KEYS)('reports storage as unconfigured when %s alone is missing', (missing) => {
    Object.assign(config, CONFIGURED);
    config[missing] = undefined;

    // All-or-none, and each variable on its own: a half-configured storage must
    // never half-enable a feature whose availability the client learns from
    // GET /config.
    expect(resolveStorageOptions()).toBeUndefined();
  });

  it('answers 503 rather than constructing a client when storage is unconfigured', async () => {
    // A fresh module instance, because the memo below is process-lifetime. The
    // suite's own environment pins the four variables EMPTY, so the freshly
    // evaluated config reads them as unset.
    //
    // `vi.resetModules()` is safe HERE specifically: this module graph reaches
    // `config/index.ts` and `utils/logger.ts` and no Mongoose model, so it cannot
    // re-register a schema and throw `OverwriteModelError`. A later phase that gives
    // `services/storage/index.ts` a model import invalidates that, not this comment.
    vi.resetModules();
    const storage = await import('../src/services/storage/index.js');
    const freshConfig = await import('../src/config/index.js');

    // The resolver and `storageConfigured` must be the same decision, not two
    // spellings of it that could drift apart when a fifth variable is added.
    expect(freshConfig.storageConfigured).toBe(false);
    expect(() => storage.getStorage()).toThrow(
      expect.objectContaining({
        statusCode: 503,
        message: 'Object storage is not configured',
      }),
    );
    // The negative: no client is built for a deployment that has no storage.
    expect(sdk.constructed).toHaveLength(0);
  });

  it('builds the client once and returns the same provider afterwards', async () => {
    // Stubbed on the ENVIRONMENT rather than on the loaded object, because a fresh
    // module instance re-reads `process.env` through the real config schema — so
    // this exercises the operator-facing path, bounds included.
    for (const key of KEYS) vi.stubEnv(key, CONFIGURED[key]);
    vi.resetModules();
    const storage = await import('../src/services/storage/index.js');
    const freshConfig = await import('../src/config/index.js');

    expect(freshConfig.storageConfigured).toBe(true);
    const first = storage.getStorage();
    const second = storage.getStorage();

    expect(second).toBe(first);
    // One client for the process: thirteen parts of an upload share one keep-alive
    // pool, and a per-call client would also mean a per-call credential resolve.
    expect(sdk.constructed).toHaveLength(1);
    expect(sdk.constructed[0]).toMatchObject({
      endpoint: 'http://hvault-storage:3900',
      forcePathStyle: true,
    });
  });
});
