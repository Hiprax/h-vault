import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { Response } from 'express';
import { createModuleLogger, errorMessage } from './logger.js';

const logger = createModuleLogger('json-stream');

/**
 * Sending a large JSON document a piece at a time, with backpressure, instead of
 * building it as rows in an array, then a string, then a buffer.
 *
 * The whole-document shape of the heavy responses (a backup download, a vault
 * export) and of the vault list pages is produced by an async generator of string
 * chunks; each row is `JSON.stringify`d on its own as the cursor hands it over, so
 * what is resident at once is a row, not the vault. `pipeline` is what makes the
 * database wait for a slow client: an unawaited `res.write` would merely move the
 * whole body into the socket's buffer.
 *
 * The status and headers are the CALLER's, set before this runs: once the first
 * chunk is written the response is committed, so anything that must refuse (a size
 * limit, a missing configuration) is decided before it. A failure after that point
 * cannot be reported as an error response, so it DESTROYS the connection instead:
 * the client sees a truncated transfer rather than a document with an error
 * envelope glued to its end, and nothing here ever rethrows into the error
 * middleware.
 */

/** How a streamed response ended. */
export interface StreamOutcome {
  /** True when every chunk was handed to the socket and the response finished. */
  completed: boolean;
  /** The bytes the document produced (all of them when `completed`). */
  bytes: number;
}

/** A source of rows that may hold a server-side cursor. */
type Rows<T> = AsyncIterable<T> & { close?: () => unknown };

/**
 * Rows a database cursor that feeds a streamed response (or a job building one)
 * asks the server for per round trip: about 8 MB of the largest vault rows. Left
 * to the driver, the first batch is 101 rows and each later one up to 16 MiB, so a
 * cursor over half-megabyte rows would hold ~50 MB before the first row is used,
 * and an estimate pass that is about to refuse at 25 MB would read 90 MB first.
 */
export const ROW_CURSOR_BATCH_SIZE = 16;

/**
 * The projection every vault row leaves the server under when it is written
 * into a FILE the owner keeps: the encrypted export and both backup paths.
 *
 * Those cursors are lean, so the models' `toJSON` strip never runs on them and
 * this is the only thing between a row's database bookkeeping and the file.
 * `userId` (the account's own id) and `__v` (the document version counter) are
 * read by nothing that consumes such a file: import and restore take the owner
 * from the session and pin writes on the STORED row's version. `sourceRefId`
 * is a foreign provenance id and `searchHash` is gone (F-12). The row `_id` and
 * the timestamps stay: every format-v2 field is sealed to its row's `_id`, a
 * restore matches on it, and the plaintext export's row schemas require both
 * timestamps.
 */
export const EXPORTED_ROW_PROJECTION = '-userId -__v -sourceRefId -searchHash';

/**
 * Closes `rows` if it is a database cursor, and never throws.
 *
 * Load-bearing: a Mongoose `QueryCursor` is its own async iterator and has no
 * `return()`, so leaving a `for await` early (a client that went away, the send
 * deadline, a size refusal) does NOT close it. The server would keep the cursor,
 * and for a sorted list page the rest of the page, until its idle timeout.
 */
async function closeRows<T>(rows: Rows<T>): Promise<void> {
  if (typeof rows.close !== 'function') return;
  try {
    await rows.close();
  } catch (err: unknown) {
    logger.warn('A database cursor could not be closed', { error: errorMessage(err) });
  }
}

/**
 * Walks `rows` one at a time and closes the cursor on EVERY exit, including a
 * throw from `onRow` (a size refusal).
 */
export async function forEachRow<T>(rows: Rows<T>, onRow: (row: T) => void): Promise<void> {
  try {
    for await (const row of rows) onRow(row);
  } finally {
    await closeRows(rows);
  }
}

/**
 * The rows of a cursor as the elements of a JSON array: `[`, each row serialized
 * alone and separated by commas, `]`. `onRow` sees each row as it goes, which is how
 * a caller counts them without holding them. The cursor is closed however the
 * array ends, including when the stream reading it is destroyed part-way.
 */
export async function* jsonArrayOf<T>(
  rows: Rows<T>,
  onRow?: (row: T) => void,
): AsyncGenerator<string> {
  try {
    yield '[';
    let first = true;
    for await (const row of rows) {
      onRow?.(row);
      yield first ? JSON.stringify(row) : `,${JSON.stringify(row)}`;
      first = false;
    }
    yield ']';
  } finally {
    await closeRows(rows);
  }
}

/**
 * The members of `tail` as a continuation of an object already open: `,"a":1,...}`.
 * Serialized by `JSON.stringify`, so `undefined` members are dropped exactly as a
 * whole-document `JSON.stringify` would drop them.
 */
export function closingMembers(tail: Record<string, unknown>): string {
  const encoded = JSON.stringify(tail);
  return encoded === '{}' ? '}' : `,${encoded.slice(1)}`;
}

/**
 * Writes `chunks` to `res` with backpressure and resolves once the response has
 * finished or failed. Never rejects: a failure (a cursor error, a client that went
 * away, the deadline) destroys the connection and is logged.
 *
 * `deadlineMs`, when given, is an ABSOLUTE bound on the whole transfer, armed now:
 * a client that has not taken the body by then is cut off, which is what stops a
 * paused or trickling reader from holding the caller's admission slot for hours.
 */
export async function sendJsonStream(
  res: Response,
  chunks: AsyncIterable<string>,
  options: { deadlineMs?: number; label: string },
): Promise<StreamOutcome> {
  let bytes = 0;
  async function* counted(): AsyncGenerator<Buffer> {
    for await (const chunk of chunks) {
      const buffer = Buffer.from(chunk, 'utf8');
      bytes += buffer.length;
      yield buffer;
    }
  }

  const deadline =
    options.deadlineMs === undefined
      ? undefined
      : setTimeout(() => {
          logger.warn(`${options.label}: the client did not take the response in time`, {
            deadlineMs: options.deadlineMs,
            bytes,
          });
          res.destroy(new Error('send deadline passed'));
        }, options.deadlineMs);
  deadline?.unref();

  try {
    await pipeline(Readable.from(counted()), res);
    return { completed: true, bytes };
  } catch (err: unknown) {
    // `pipeline` has already destroyed both ends. Nothing is written after this.
    logger.warn(`${options.label}: the response stream ended early`, {
      error: errorMessage(err),
      bytes,
    });
    return { completed: false, bytes };
  } finally {
    // No deadline is left behind a finished stream (`clearTimeout(undefined)` is a no-op).
    clearTimeout(deadline);
  }
}
