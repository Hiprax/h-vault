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

  // -------------------------------------------------------------------------
  // Nested plain objects
  //
  // The function handled exactly two shapes, a string and an array, and had no
  // branch for a plain nested object. An address is a nested plain object
  // (`data.address` on an identity, `data.billingAddress` on a card), so NO
  // address field had EVER been searchable on either type.
  // -------------------------------------------------------------------------

  const IDENTITY_ADDRESS = {
    street: '42 Rabbit Hole Lane',
    street2: 'Flat 2',
    city: 'Springfield',
    state: 'Wonderland',
    zip: 'W1 0AA',
    country: 'Fantasia',
    deliveryNotes: 'Ring twice, gate code 4821',
  };

  function identity() {
    return {
      name: 'Ada Lovelace',
      tags: [],
      itemType: 'identity' as const,
      data: { firstName: 'Ada', lastName: 'Lovelace', address: { ...IDENTITY_ADDRESS } },
    };
  }

  it.each(Object.entries(IDENTITY_ADDRESS))("matches an identity address's %s", (_field, value) => {
    expect(itemMatchesSearch(identity(), value.toLowerCase())).toBe(true);
  });

  it("matches a card's nested billing address", () => {
    const item = {
      name: 'Visa',
      tags: [],
      itemType: 'card' as const,
      data: {
        cardholderName: 'Ada',
        billingAddress: { street: '1 Main St', city: 'London', zip: 'E1 6AN', country: 'UK' },
      },
    };
    expect(itemMatchesSearch(item, 'main st')).toBe(true);
    expect(itemMatchesSearch(item, 'e1 6an')).toBe(true);
    expect(itemMatchesSearch(item, 'nowhere')).toBe(false);
  });

  it('still reports no match for a query absent from every nested field', () => {
    expect(itemMatchesSearch(identity(), 'gringotts')).toBe(false);
  });

  it('terminates on a self-referential object rather than overflowing the stack', () => {
    // A bound, not tidiness: a hand-crafted or corrupted blob could nest into
    // itself, and search runs on every keystroke over every item.
    const cyclic: Record<string, unknown> = { label: 'outer' };
    cyclic.self = cyclic;
    const item = { name: 'Cyclic', tags: [], itemType: 'note' as const, data: { cyclic } };

    expect(itemMatchesSearch(item, 'outer')).toBe(true);
    expect(itemMatchesSearch(item, 'missing')).toBe(false);
  });

  it('searches three hops and stops', () => {
    // Three hops is what the decrypted schemas can actually produce: a top-level
    // string, one nesting (an address field), and two (a `uris` / `customFields`
    // entry's own fields). A FOURTH is out of contract and deliberately not
    // searched — that is the bound keeping the recursion terminating.
    //
    // This assertion is load-bearing: the string check precedes the depth check,
    // so an off-by-one in the constant silently widens the walk by a whole level
    // with nothing else noticing.
    const item = {
      name: 'Deep',
      tags: [],
      itemType: 'note' as const,
      data: { l1: { l2: { hop3: 'reachable' } }, d1: { d2: { d3: { hop4: 'unreachable' } } } },
    };
    expect(itemMatchesSearch(item, 'reachable')).toBe(true);
    expect(itemMatchesSearch(item, 'unreachable')).toBe(false);
  });

  it('treats an undecodable placeholder as a non-match rather than throwing', () => {
    const item = {
      name: 'Broken',
      tags: [],
      itemType: 'login' as const,
      data: { _raw: null, _validationError: true },
    };
    expect(itemMatchesSearch(item, 'anything')).toBe(false);
    // The item is still findable by NAME, which is what keeps it remediable.
    expect(itemMatchesSearch(item, 'broken')).toBe(true);
  });
});
