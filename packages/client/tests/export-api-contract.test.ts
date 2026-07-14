/**
 * Contract test for `exportVaultApi` (T28).
 *
 * Asserts the declared response type matches the real server wire shape:
 * `{ success: true, data: { items, folders, metadata } }`. The typed access
 * `res.data.data.items` only compiles against `ApiResponse<ExportResponse>` —
 * it would fail to type-check against the previous `ApiResponse<{ data: string }>`
 * declaration, so the type-check gate enforces the corrected contract.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ExportResponse, ItemType } from '@hvault/shared';

// ---------------------------------------------------------------------------
// Mock the Axios client so no real network/CSRF setup runs.
// ---------------------------------------------------------------------------

const mockPost = vi.fn();

vi.mock('../src/services/api/client', () => ({
  api: {
    post: (...args: unknown[]) => mockPost(...args),
  },
  clearCsrfToken: vi.fn(),
}));

// Imported after the mock so the mocked client is wired in.
import { exportVaultApi } from '../src/services/api/userApi';

describe('exportVaultApi response contract', () => {
  beforeEach(() => {
    mockPost.mockReset();
  });

  it('returns and types the { items, folders, metadata } envelope', async () => {
    const wire = {
      data: {
        success: true as const,
        data: {
          items: [
            {
              _id: 'item-1',
              itemType: 'login' as ItemType,
              tags: [] as string[],
              favorite: false,
              encryptedData: 'enc-data',
              dataIv: 'data-iv',
              dataTag: 'data-tag',
              encryptedName: 'enc-name',
              nameIv: 'name-iv',
              nameTag: 'name-tag',
              createdAt: '2026-01-01T00:00:00.000Z',
              updatedAt: '2026-01-01T00:00:00.000Z',
            },
          ],
          folders: [],
          metadata: {
            exportDate: '2026-01-01T00:00:00.000Z',
            version: '1.2.3',
            itemCount: 1,
          },
        },
      },
    };
    mockPost.mockResolvedValue(wire);

    const res = await exportVaultApi({ format: 'json', authHash: 'auth-hash' });

    expect(mockPost).toHaveBeenCalledWith('/tools/export', {
      format: 'json',
      authHash: 'auth-hash',
    });

    if (!res.data.success) {
      throw new Error('expected a successful export envelope');
    }

    // Typed access — proves the corrected `ApiResponse<ExportResponse>` shape.
    const payload: ExportResponse = res.data.data;
    expect(payload.items).toHaveLength(1);
    expect(payload.items[0]?.itemType).toBe('login');
    expect(payload.items[0]?.encryptedData).toBe('enc-data');
    expect(payload.folders).toEqual([]);
    expect(payload.metadata.itemCount).toBe(1);
    expect(payload.metadata.version).toBe('1.2.3');
    expect(payload.metadata.exportDate).toBe('2026-01-01T00:00:00.000Z');
  });

  it('posts to /tools/export with an undefined body when called with no argument', async () => {
    // The runtime contract that can actually break: `exportVaultApi` must be a
    // thin pass-through of `api.post(url, body)` — it forwards the URL and the
    // (possibly undefined) body verbatim. A refactor that hard-coded a body or
    // changed the URL would fail here (unlike the echoed-value asserts above).
    // That it returns the AxiosResponse (not `res.data`) unchanged is exercised
    // by the first test, which reads `res.data.data`.
    mockPost.mockResolvedValue({
      data: { success: true, data: { items: [], folders: [], metadata: {} } },
    });

    await exportVaultApi();

    expect(mockPost).toHaveBeenCalledWith('/tools/export', undefined);
  });
});
