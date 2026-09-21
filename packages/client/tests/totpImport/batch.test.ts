import { describe, it, expect } from 'vitest';
import {
  acceptPart,
  capturedParts,
  collectedEntries,
  emptyBatch,
  isComplete,
  type BatchState,
} from '../../src/services/totpImport/batch';
import { readMigrationPayload } from '../../src/services/totpImport/migrationReader';
import { encodePayload, sampleSecret } from '../support/migrationEncoder';

function part(options: {
  index: number;
  size: number;
  id: number;
  names?: string[];
  seed?: number;
}) {
  const names = options.names ?? [`account-${String(options.index)}`];
  return readMigrationPayload(
    encodePayload({
      entries: names.map((name, i) => ({
        secret: sampleSecret((options.seed ?? 1) + i),
        name,
      })),
      batchSize: options.size,
      batchIndex: options.index,
      batchId: options.id,
    }),
  );
}

function add(state: BatchState, payload: ReturnType<typeof part>): BatchState {
  const outcome = acceptPart(state, payload);
  if (outcome.kind !== 'added') throw new Error(`expected added, got ${outcome.kind}`);
  return outcome.state;
}

describe('batch collection', () => {
  it('completes a single-code export on one scan', () => {
    const state = add(emptyBatch(), part({ index: 0, size: 1, id: 5 }));
    expect(isComplete(state)).toBe(true);
    expect(capturedParts(state)).toBe(1);
  });

  it('waits for every part of a multi-code export', () => {
    let state = add(emptyBatch(), part({ index: 0, size: 3, id: 9 }));
    expect(isComplete(state)).toBe(false);
    state = add(state, part({ index: 1, size: 3, id: 9 }));
    expect(isComplete(state)).toBe(false);
    expect(capturedParts(state)).toBe(2);
    state = add(state, part({ index: 2, size: 3, id: 9 }));
    expect(isComplete(state)).toBe(true);
  });

  it('accepts the parts in any order, because a person holding a phone will not be orderly', () => {
    let state = add(emptyBatch(), part({ index: 2, size: 3, id: 9 }));
    state = add(state, part({ index: 0, size: 3, id: 9 }));
    state = add(state, part({ index: 1, size: 3, id: 9 }));
    expect(isComplete(state)).toBe(true);
    // Still returned in the order the export defined, not the order scanned.
    expect(collectedEntries(state).map((entry) => entry.name)).toEqual([
      'account-0',
      'account-1',
      'account-2',
    ]);
  });

  it('completes without ever asking whether the index starts at zero or one', () => {
    // Nothing published says which it is. Counting DISTINCT parts is correct
    // under either convention, and this pins that the code does not assume one.
    let state = add(emptyBatch(), part({ index: 1, size: 2, id: 4 }));
    state = add(state, part({ index: 0, size: 2, id: 4 }));
    expect(isComplete(state)).toBe(true);
  });

  it('treats re-scanning the same code as a no-op, not as progress', () => {
    const first = part({ index: 0, size: 2, id: 9 });
    const state = add(emptyBatch(), first);
    const outcome = acceptPart(state, first);
    expect(outcome.kind).toBe('duplicate');
    if (outcome.kind === 'duplicate') {
      expect(capturedParts(outcome.state)).toBe(1);
      expect(isComplete(outcome.state)).toBe(false);
    }
  });

  it('refuses a part from a different export rather than mixing two sets', () => {
    const state = add(emptyBatch(), part({ index: 0, size: 2, id: 9 }));
    expect(acceptPart(state, part({ index: 1, size: 2, id: 10 })).kind).toBe('wrong-export');
  });

  it('refuses the same part index carrying different accounts', () => {
    // Two exports made moments apart can share an id; the contents are what
    // actually says they are different.
    const state = add(emptyBatch(), part({ index: 0, size: 2, id: 9, names: ['a'] }));
    const clash = part({ index: 0, size: 2, id: 9, names: ['b'] });
    expect(acceptPart(state, clash).kind).toBe('conflicting-part');
  });

  it('refuses a part whose accounts match by name but not by key', () => {
    const state = add(emptyBatch(), part({ index: 0, size: 2, id: 9, names: ['a'], seed: 1 }));
    const clash = part({ index: 0, size: 2, id: 9, names: ['a'], seed: 2 });
    expect(acceptPart(state, clash).kind).toBe('conflicting-part');
  });

  it('reports an empty set as incomplete and holding nothing', () => {
    const state = emptyBatch();
    expect(isComplete(state)).toBe(false);
    expect(capturedParts(state)).toBe(0);
    expect(collectedEntries(state)).toEqual([]);
  });

  it('flattens every account across parts', () => {
    let state = add(emptyBatch(), part({ index: 0, size: 2, id: 3, names: ['a', 'b'] }));
    state = add(state, part({ index: 1, size: 2, id: 3, names: ['c'] }));
    expect(collectedEntries(state).map((entry) => entry.name)).toEqual(['a', 'b', 'c']);
  });
});
