/**
 * Unit coverage for the client breach-check service (`runBreachCheck`):
 * deduplication, prefix grouping, suffix match/miss, honest reporting of
 * unchecked passwords (server `errors[]`, request failure), 429 + Retry-After
 * backoff (retry then success, and retry-exhaustion), batch chunking, progress,
 * abort, and the k-anonymity guarantee (only 5-char prefixes are ever sent).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockCheckBreachBatchApi } = vi.hoisted(() => ({ mockCheckBreachBatchApi: vi.fn() }));

vi.mock('../src/services/api/userApi', () => ({
  checkBreachBatchApi: (...args: unknown[]) => mockCheckBreachBatchApi(...args),
}));

import { runBreachCheck } from '../src/services/health/breachCheck';
import type { DecryptedVaultItem } from '../src/stores/vaultStore';

function loginItem(id: string, password: string | undefined): DecryptedVaultItem {
  return {
    id,
    itemType: 'login',
    name: id,
    tags: [],
    favorite: false,
    data: password === undefined ? {} : { password },
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    _raw: {},
  } as unknown as DecryptedVaultItem;
}

async function sha1HexUpper(password: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

function body(ranges: Record<string, string>, errors: string[] = []) {
  return { data: { success: true, data: ranges, errors } };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('runBreachCheck', () => {
  it('returns zeros and never calls the API when no item has a password', async () => {
    const result = await runBreachCheck([loginItem('a', undefined), loginItem('b', '')]);
    expect(result).toEqual({ breached: [], totalCount: 0, checkedCount: 0, failedCount: 0 });
    expect(mockCheckBreachBatchApi).not.toHaveBeenCalled();
  });

  it('checks a shared password once and fans the finding out to every item', async () => {
    const hash = await sha1HexUpper('shared');
    mockCheckBreachBatchApi.mockResolvedValue(body({ [hash.slice(0, 5)]: `${hash.slice(5)}:42` }));

    const result = await runBreachCheck([loginItem('a', 'shared'), loginItem('b', 'shared')]);

    expect(mockCheckBreachBatchApi).toHaveBeenCalledTimes(1);
    expect(mockCheckBreachBatchApi.mock.calls[0]?.[0]).toEqual([hash.slice(0, 5)]);
    expect(result.totalCount).toBe(1);
    expect(result.checkedCount).toBe(1);
    expect(result.failedCount).toBe(0);
    expect(result.breached).toHaveLength(2);
    expect(result.breached.every((f) => f.count === 42)).toBe(true);
  });

  it('only sends 5-char prefixes (k-anonymity)', async () => {
    const hash = await sha1HexUpper('secret');
    mockCheckBreachBatchApi.mockResolvedValue(body({ [hash.slice(0, 5)]: `${hash.slice(5)}:1` }));

    await runBreachCheck([loginItem('a', 'secret')]);

    const sent = mockCheckBreachBatchApi.mock.calls.flatMap((c) => c[0] as string[]);
    expect(sent.every((p) => p.length === 5)).toBe(true);
    expect(sent).not.toContain(hash); // never the full hash
  });

  it('reports a non-matching suffix as checked-but-not-breached', async () => {
    const hash = await sha1HexUpper('clean');
    mockCheckBreachBatchApi.mockResolvedValue(body({ [hash.slice(0, 5)]: 'DEADBEEF:9' }));

    const result = await runBreachCheck([loginItem('a', 'clean')]);

    expect(result.breached).toHaveLength(0);
    expect(result.checkedCount).toBe(1);
    expect(result.failedCount).toBe(0);
  });

  it('counts a server-reported error prefix as failed, never as safe', async () => {
    const okHash = await sha1HexUpper('pwned');
    const failHash = await sha1HexUpper('unknown');
    mockCheckBreachBatchApi.mockResolvedValue(
      body({ [okHash.slice(0, 5)]: `${okHash.slice(5)}:3` }, [failHash.slice(0, 5)]),
    );

    const result = await runBreachCheck([loginItem('a', 'pwned'), loginItem('b', 'unknown')]);

    expect(result.checkedCount).toBe(1);
    expect(result.failedCount).toBe(1);
    expect(result.breached).toHaveLength(1);
  });

  it('marks the whole batch failed when the request rejects (non-429)', async () => {
    mockCheckBreachBatchApi.mockRejectedValue(new Error('network down'));

    const result = await runBreachCheck([loginItem('a', 'p1'), loginItem('b', 'p2')]);

    expect(result.totalCount).toBe(2);
    expect(result.checkedCount).toBe(0);
    expect(result.failedCount).toBe(2);
    expect(result.breached).toHaveLength(0);
  });

  it('retries a 429 honoring Retry-After, then succeeds', async () => {
    const hash = await sha1HexUpper('p1');
    mockCheckBreachBatchApi
      .mockRejectedValueOnce({ response: { status: 429, headers: { 'retry-after': '0' } } })
      .mockResolvedValue(body({ [hash.slice(0, 5)]: `${hash.slice(5)}:2` }));

    const result = await runBreachCheck([loginItem('a', 'p1')]);

    expect(mockCheckBreachBatchApi).toHaveBeenCalledTimes(2);
    expect(result.checkedCount).toBe(1);
    expect(result.breached).toHaveLength(1);
  });

  it('gives up after exhausting 429 retries and reports the batch as failed', async () => {
    mockCheckBreachBatchApi.mockRejectedValue({
      response: { status: 429, headers: { 'retry-after': '0' } },
    });

    const result = await runBreachCheck([loginItem('a', 'p1')]);

    // 1 initial attempt + 3 retries.
    expect(mockCheckBreachBatchApi).toHaveBeenCalledTimes(4);
    expect(result.failedCount).toBe(1);
    expect(result.checkedCount).toBe(0);
  });

  it('splits into multiple batches beyond the prefix cap', async () => {
    mockCheckBreachBatchApi.mockImplementation((prefixes: string[]) =>
      Promise.resolve(body(Object.fromEntries(prefixes.map((p) => [p, ''])))),
    );
    const items = Array.from({ length: 150 }, (_, i) => loginItem(`i${i}`, `distinct-pw-${i}`));

    const result = await runBreachCheck(items);

    expect(result.totalCount).toBe(150);
    expect(result.checkedCount).toBe(150);
    expect(result.failedCount).toBe(0);
    // 150 unique prefixes over a 100/batch cap -> at least 2 requests.
    expect(mockCheckBreachBatchApi.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it('reports monotonic progress ending at total/total', async () => {
    const hash = await sha1HexUpper('p1');
    mockCheckBreachBatchApi.mockResolvedValue(body({ [hash.slice(0, 5)]: `${hash.slice(5)}:1` }));
    const onProgress = vi.fn();

    await runBreachCheck([loginItem('a', 'p1')], { onProgress });

    expect(onProgress).toHaveBeenCalledWith(0, 1);
    expect(onProgress).toHaveBeenLastCalledWith(1, 1);
  });

  it('does not call the API when aborted before it starts', async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await runBreachCheck([loginItem('a', 'p1')], { signal: controller.signal });
    expect(mockCheckBreachBatchApi).not.toHaveBeenCalled();
    expect(result.checkedCount).toBe(0);
  });
});
