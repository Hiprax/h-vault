/**
 * A database cursor that cannot be closed never breaks the stream that read it.
 *
 * `forEachRow` and `jsonArrayOf` close their cursor on every exit, because a
 * Mongoose `QueryCursor` left by an early exit stays open on the server until its
 * idle timeout. Closing can fail (the connection that would carry the kill is the
 * one that just dropped); that failure is logged, and must neither replace the
 * error that ended the walk nor turn a complete walk into a failed one.
 */
import { describe, it, expect, vi } from 'vitest';
import { Writable } from 'node:stream';
import type { Response } from 'express';
import { forEachRow, jsonArrayOf, sendJsonStream } from '../src/utils/jsonStream.js';

/** Rows `values`, from a cursor whose `close()` rejects; `closes` counts the calls. */
function unclosableCursor(values: number[]) {
  const counter = { closes: 0 };
  const rows = {
    async *[Symbol.asyncIterator]() {
      for (const value of values) yield value;
    },
    close: () => {
      counter.closes += 1;
      return Promise.reject(new Error('the connection that would close it is gone'));
    },
  };
  return { rows, counter };
}

describe('a cursor whose close fails', () => {
  it('forEachRow still visits every row and resolves', async () => {
    const { rows, counter } = unclosableCursor([1, 2, 3]);
    const seen: number[] = [];

    await expect(forEachRow(rows, (row) => seen.push(row))).resolves.toBeUndefined();

    expect(seen).toEqual([1, 2, 3]);
    expect(counter.closes).toBe(1);
  });

  it("forEachRow reports the walk's own error, not the close failure", async () => {
    const { rows, counter } = unclosableCursor([1, 2, 3]);

    await expect(
      forEachRow(rows, (row) => {
        if (row === 2) throw new RangeError('too large');
      }),
    ).rejects.toThrow(RangeError);
    expect(counter.closes).toBe(1);
  });

  it('jsonArrayOf still produces the whole array', async () => {
    const { rows, counter } = unclosableCursor([1, 2]);
    let text = '';

    for await (const chunk of jsonArrayOf(rows)) text += chunk;

    expect(text).toBe('[1,2]');
    expect(counter.closes).toBe(1);
  });
});

describe('a stream that finished', () => {
  it('leaves no send deadline behind to cut off a response already delivered', async () => {
    const written: string[] = [];
    const res = new Writable({
      write(chunk: Buffer, _encoding, done) {
        written.push(chunk.toString('utf8'));
        done();
      },
    });
    const destroyedWith: unknown[] = [];
    const destroy = res.destroy.bind(res);
    res.destroy = (error?: Error) => {
      destroyedWith.push(error);
      return destroy(error);
    };

    // Only the deadline's own timer functions are faked: the stream itself runs
    // on the real event loop (next ticks and immediates).
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let outcome: Awaited<ReturnType<typeof sendJsonStream>>;
    try {
      outcome = await sendJsonStream(
        res as unknown as Response,
        (async function* () {
          yield '{"a":';
          yield '1}';
        })(),
        { deadlineMs: 30, label: 'test stream' },
      );
      // Nothing is left armed, and moving the clock well past the deadline fires nothing.
      expect(vi.getTimerCount()).toBe(0);
      vi.advanceTimersByTime(1_000);
    } finally {
      vi.useRealTimers();
    }

    expect(outcome).toEqual({ completed: true, bytes: 7 });
    expect(written.join('')).toBe('{"a":1}');
    expect(destroyedWith.filter((error) => error instanceof Error)).toEqual([]);
  });
});
