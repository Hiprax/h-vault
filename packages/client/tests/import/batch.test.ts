import { describe, it, expect } from 'vitest';
import { chunkBySize } from '../../src/services/import';

describe('chunkBySize', () => {
  it('splits items into batches under the byte cap, preserving order and count', () => {
    const items = Array.from({ length: 10 }, (_, i) => ({ id: i, blob: 'x'.repeat(100) }));
    const batches = chunkBySize(items, 300);
    expect(batches.length).toBeGreaterThan(1);
    expect(batches.flat().map((x) => x.id)).toEqual(items.map((x) => x.id));
    for (const b of batches) {
      if (b.length > 1) expect(JSON.stringify(b).length).toBeLessThanOrEqual(350);
    }
  });

  it('respects the max-count cap', () => {
    const items = [0, 1, 2, 3, 4];
    expect(chunkBySize(items, 1_000_000, 2).map((b) => b.length)).toEqual([2, 2, 1]);
  });

  it('places a single oversized item in its own batch rather than dropping it', () => {
    const items = [{ big: 'x'.repeat(500) }, { small: 'y' }];
    const batches = chunkBySize(items, 100);
    expect(batches).toHaveLength(2);
    expect(batches[0]).toHaveLength(1);
    expect(batches[1]).toHaveLength(1);
  });

  it('returns an empty array for no items', () => {
    expect(chunkBySize([], 1000)).toEqual([]);
  });
});
