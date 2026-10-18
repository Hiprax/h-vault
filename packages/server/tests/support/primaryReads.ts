/**
 * Records every Mongoose query a request runs, with its model, operation,
 * projection and read preference, so a suite can hold EACH vault-key read to the
 * primary by the fields it selects.
 *
 * A deployment whose `MONGODB_URI` sets `readPreference=secondaryPreferred` sends
 * every read that does not say otherwise to a secondary, which may not yet have seen
 * a rotation's commit. The reads that decide a vault-key write, or hand a session the
 * wrapper it derives its key from, pin the primary with `.read('primary')`; a check
 * keyed only on "some read was pinned" would stay green with all but one pin
 * removed, which is why reads are told apart by their projection.
 */
import { expect, vi } from 'vitest';
import mongoose from 'mongoose';

export interface RecordedRead {
  /** The model the query runs against (`User`, `Document`, …). */
  model: string;
  /** The query operation (`findOne`, `find`, …). */
  op: string;
  /** The projection's field names, sorted and space-separated. */
  fields: string;
  /** The read preference the query carries, or `undefined` when it names none. */
  readPreference: string | undefined;
}

/** Starts recording; the returned array fills as queries execute. */
export function recordReads(): RecordedRead[] {
  const reads: RecordedRead[] = [];
  const realExec = mongoose.Query.prototype.exec;
  vi.spyOn(mongoose.Query.prototype, 'exec').mockImplementation(function (
    this: mongoose.Query<unknown, unknown>,
    ...args: Parameters<typeof realExec>
  ) {
    const internals = this as unknown as {
      _fields?: Record<string, unknown>;
      op?: string;
    };
    const preference = this.getOptions().readPreference as { mode?: string } | string | undefined;
    reads.push({
      model: this.model.modelName,
      op: internals.op ?? '',
      fields: Object.keys(internals._fields ?? {})
        .sort()
        .join(' '),
      readPreference: typeof preference === 'string' ? preference : preference?.mode,
    });
    return realExec.apply(this, args);
  } as never);
  return reads;
}

/**
 * Asserts that `model` was read with exactly the projection `fields` (any order,
 * space-separated) at least once, and that EVERY such read named the primary.
 */
export function expectReadFromPrimary(
  reads: readonly RecordedRead[],
  model: string,
  fields: string,
): void {
  const wanted = fields.split(' ').sort().join(' ');
  const matching = reads.filter((read) => read.model === model && read.fields === wanted);
  expect(matching.length, `no ${model} read selecting [${wanted}] ran`).toBeGreaterThan(0);
  for (const read of matching) {
    expect(read.readPreference, `${model} read selecting [${wanted}]`).toBe('primary');
  }
}
