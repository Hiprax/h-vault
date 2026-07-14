/**
 * Additional client test coverage for H-Vault.
 *
 * This file previously contained large `readFileSync(...).toContain(...)` blocks
 * that asserted the SOURCE TEXT of hooks, the API client, ProtectedRoute,
 * AppLayout, VaultList, VaultItemDetail, cryptoService, the page files, etc.
 * Those greps executed no production code, so they gave zero regression signal:
 * inverting a guard, breaking the 401 refresh interceptor, or throwing on a page
 * mount left every substring present and every test green, while a harmless
 * rename/reformat turned them red. They have been removed — the behavior is now
 * exercised for real elsewhere:
 *   - ProtectedRoute        -> phase4-robustness.test.tsx, coverage-auth-layout.test.tsx
 *   - useAutoLock/AppLayout -> coverage-auth-layout.test.tsx
 *   - API client            -> services-functional.test.ts, refresh-multitab.test.ts
 *   - offlineCache          -> offlineCache.test.ts
 *   - VaultList             -> coverage-vault-components.test.tsx
 *   - VaultItemDetail       -> coverage-vault-item-detail.test.tsx
 *   - VaultHealthPage       -> coverage-vault-health.test.tsx
 *   - page smoke render     -> pages-coverage.test.tsx
 *
 * What remains is the genuinely behavioral vaultSearch coverage.
 */

import { describe, it, expect, beforeAll } from 'vitest';

// ===========================================================================
// vaultSearch: itemMatchesSearch array and object field search
// ===========================================================================

describe('vaultSearch itemMatchesSearch', () => {
  let itemMatchesSearch: typeof import('../src/lib/vaultSearch').itemMatchesSearch;

  beforeAll(async () => {
    const mod = await import('../src/lib/vaultSearch');
    itemMatchesSearch = mod.itemMatchesSearch;
  });

  it('should match string entries in array data fields', () => {
    const item = {
      name: 'Test Item',
      tags: [],
      itemType: 'login' as const,
      data: { uris: ['https://example.com', 'https://test.org'] },
    };
    expect(itemMatchesSearch(item, 'example')).toBe(true);
    expect(itemMatchesSearch(item, 'test.org')).toBe(true);
    expect(itemMatchesSearch(item, 'notfound')).toBe(false);
  });

  it('should match string values inside object entries in array data fields', () => {
    const item = {
      name: 'Custom Fields Item',
      tags: [],
      itemType: 'login' as const,
      data: {
        customFields: [
          { name: 'API Key', value: 'secret-abc-123', type: 'hidden' },
          { name: 'Server', value: 'production-west', type: 'text' },
        ],
      },
    };
    expect(itemMatchesSearch(item, 'secret-abc')).toBe(true);
    expect(itemMatchesSearch(item, 'production-west')).toBe(true);
    expect(itemMatchesSearch(item, 'nothere')).toBe(false);
  });

  it('should not match non-string or null array entries', () => {
    const item = {
      name: 'Mixed Item',
      tags: [],
      itemType: 'note' as const,
      data: { mixed: [42, null, true, 'findme'] },
    };
    expect(itemMatchesSearch(item, 'findme')).toBe(true);
    expect(itemMatchesSearch(item, '42')).toBe(false);
  });
});
