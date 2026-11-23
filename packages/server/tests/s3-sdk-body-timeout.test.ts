/**
 * What the S3 SDK's `socketTimeout` does to a response BODY that stops arriving.
 *
 * `createS3Provider` bounds socket IDLENESS rather than total duration
 * (`S3_SOCKET_IDLE_TIMEOUT_MS`, see the docblock in s3Provider.ts), and the
 * segment read path pipes the GetObject body straight to the browser. Whether a
 * stalled body is cut by that idle timeout is a property of the SDK's HTTP
 * handler, not of this repository, so it is pinned here against the REAL client,
 * built with the provider's own option shape, and a loopback server that sends the
 * headers and the first bytes of a body and then goes silent.
 */
import http from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';

/** Short enough for a unit test; the provider's real value is 60 s. */
const SOCKET_TIMEOUT_MS = 300;
const DECLARED_LENGTH = 4096;
const SENT_BEFORE_STALL = 16;

let server: http.Server | undefined;
const sockets = new Set<Socket>();

afterEach(async () => {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
});

/** A GetObject answer whose body stops after SENT_BEFORE_STALL of DECLARED_LENGTH bytes. */
async function stallingEngine(): Promise<string> {
  server = http.createServer((_req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(DECLARED_LENGTH),
      ETag: '"stall"',
    });
    res.write(Buffer.alloc(SENT_BEFORE_STALL, 7));
    // ...and nothing more: the socket stays open and idle.
  });
  server.on('connection', (socket) => sockets.add(socket));
  await new Promise<void>((resolve) => server?.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function clientFor(endpoint: string): S3Client {
  // The provider's option shape (s3Provider.ts), with a test-sized idle timeout.
  return new S3Client({
    endpoint,
    region: 'us-east-1',
    forcePathStyle: true,
    credentials: { accessKeyId: 'test-key', secretAccessKey: 'test-secret' },
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    maxAttempts: 1,
    requestHandler: { connectionTimeout: 2_000, socketTimeout: SOCKET_TIMEOUT_MS },
  });
}

describe('the S3 SDK socket timeout and a stalled response body', () => {
  // Measured on both sides of the 3.1138 -> 3.1169 upgrade: the stall is cut at the
  // same moment either way (about one timeout after the last byte), but
  // @smithy/node-http-handler 4.12 surfaced it as `Error: aborted` (ECONNRESET) and
  // 4.14 as a typed TimeoutError naming the inactivity. Both are classified as
  // transient by s3Provider.ts, and the segment read path treats any body error
  // alike (it logs the message and resets the client's socket).
  it('cuts a body that stalls after its headers with a TimeoutError naming the idle socket', async () => {
    const client = clientFor(await stallingEngine());
    const object = await client.send(new GetObjectCommand({ Bucket: 'b', Key: 'k' }));
    const body = object.Body as Readable;

    let received = 0;
    const outcome = await new Promise<string>((resolve) => {
      body.on('data', (chunk: Buffer) => (received += chunk.length));
      body.on('end', () => resolve('ended'));
      body.on('error', (error: Error & { code?: string }) =>
        resolve(`error:${error.name}:${error.code ?? ''}:${error.message}`),
      );
      setTimeout(() => resolve('pending'), SOCKET_TIMEOUT_MS * 5);
    });
    body.destroy();
    client.destroy();

    expect(received).toBe(SENT_BEFORE_STALL);
    expect(outcome).toBe(
      `error:TimeoutError::@smithy/node-http-handler - the request socket timed out after ${SOCKET_TIMEOUT_MS} ms of inactivity (configured by client requestHandler).`,
    );
  });
});
