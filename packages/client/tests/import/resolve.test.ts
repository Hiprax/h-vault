import { describe, it, expect, vi } from 'vitest';
import type { ItemType } from '@hvault/shared';
import { computeContentKey } from '../../src/services/import/identity';
import {
  resolveImport,
  type ConflictStrategy,
  type ImportResolution,
} from '../../src/services/import/resolve';

/**
 * The resolver decides, holistically and once, what an import does to the vault.
 * Everything the plan promises rests on it: ten accounts on one site staying ten
 * items, a re-import changing nothing, `overwrite` updating exactly the right row
 * (and never a placeholder), and — critically — the outcome being INDEPENDENT of
 * how the payload is batched, which is the 0.2.0 regression this guards.
 *
 * These tests drive the REAL Web Crypto digest installed by `tests/setup.ts`.
 */

// Purity guard: the resolver (and identity) must never pull in the auth store.
vi.mock('../../src/stores/authStore', () => {
  throw new Error('resolve.ts must not import authStore, directly or transitively');
});

type Data = Record<string, unknown>;

interface Inc {
  itemType: ItemType;
  name: string;
  data: Data;
  tags: string[];
  favorite: boolean;
}

interface VaultItem {
  id: string;
  itemType: ItemType;
  name: string;
  data: Data;
  deletedAt?: string | undefined;
}

const login = (username: string, host: string, password = 'pw'): Data => ({
  username,
  password,
  uris: [{ uri: `https://${host}`, match: 'domain' }],
});

const inc = (itemType: ItemType, name: string, data: Data, tags: string[] = []): Inc => ({
  itemType,
  name,
  data,
  tags,
  favorite: false,
});

const ex = (
  id: string,
  itemType: ItemType,
  name: string,
  data: Data,
  deletedAt?: string,
): VaultItem => ({
  id,
  itemType,
  name,
  data,
  ...(deletedAt !== undefined ? { deletedAt } : {}),
});

const countAll = (r: ImportResolution<unknown, unknown>): number =>
  r.inserts.length +
  r.updates.length +
  r.duplicateSkipped.length +
  r.duplicateInFile.length +
  r.unchanged.length;

const STRATEGIES: ConflictStrategy[] = ['skip', 'overwrite', 'keep_both'];

describe('resolveImport — inserts and matching basics', () => {
  it('keeps ten same-host logins with distinct usernames as ten inserts, under every strategy', async () => {
    const incoming = Array.from({ length: 10 }, (_, i) =>
      inc('login', 'Google', login(`user${i}@gmail.com`, 'accounts.google.com')),
    );

    for (const strategy of STRATEGIES) {
      const r = await resolveImport({ existing: [], incoming, strategy });
      expect(r.inserts).toHaveLength(10);
      expect(r.updates).toHaveLength(0);
      expect(r.duplicateInFile).toHaveLength(0);
      expect(countAll(r)).toBe(incoming.length);
    }
  });

  it('never matches across item types (a note named like a login stays an insert)', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com'))];
    const incoming = [inc('note', 'GitHub', { content: 'a note that happens to share the name' })];

    const r = await resolveImport({ existing, incoming, strategy: 'skip' });
    expect(r.inserts).toHaveLength(1);
    expect(r.duplicateSkipped).toHaveLength(0);
  });
});

describe('resolveImport — skip', () => {
  it('re-importing the identical set changes nothing (all duplicateSkipped)', async () => {
    const existing = [
      ex('e1', 'login', 'GitHub', login('octocat', 'github.com')),
      ex('e2', 'note', 'Recovery', { content: 'codes' }),
    ];
    const incoming = [
      inc('login', 'GitHub', login('octocat', 'github.com')),
      inc('note', 'Recovery', { content: 'codes' }),
    ];

    const r = await resolveImport({ existing, incoming, strategy: 'skip' });
    expect(r.inserts).toHaveLength(0);
    expect(r.updates).toHaveLength(0);
    expect(r.duplicateSkipped).toHaveLength(2);
    expect(countAll(r)).toBe(2);
  });
});

describe('resolveImport — overwrite', () => {
  it('updates exactly the matched id when a login password changes', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com', 'old-pw'))];
    const incoming = [inc('login', 'GitHub', login('octocat', 'github.com', 'new-pw'))];

    const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(r.updates).toHaveLength(1);
    expect(r.updates[0]!.existing.id).toBe('e1');
    expect(r.inserts).toHaveLength(0);
    expect(r.unchanged).toHaveLength(0);
  });

  it('reports an identical-content match as unchanged, never an update (overwrite idempotency)', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com', 'pw'))];
    const incoming = [inc('login', 'GitHub', login('octocat', 'github.com', 'pw'))];

    const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(r.updates).toHaveLength(0);
    expect(r.unchanged).toHaveLength(1);
    expect(r.inserts).toHaveLength(0);
  });

  it('inserts when nothing matches', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com'))];
    const incoming = [inc('login', 'GitLab', login('alice', 'gitlab.com'))];

    const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(r.inserts).toHaveLength(1);
    expect(r.updates).toHaveLength(0);
  });

  it('deterministically targets the FIRST existing item when the vault holds duplicates of one key', async () => {
    // An anomalous vault state: two pre-existing items share one identity key.
    // The match slot must go to the first in array order, regardless of the order
    // in which the internal hashing promises happen to settle.
    const existing = [
      ex('first', 'login', 'GitHub', login('octocat', 'github.com', 'old')),
      ex('second', 'login', 'GitHub (dup)', login('octocat', 'github.com', 'old')),
    ];
    const incoming = [inc('login', 'GitHub', login('octocat', 'github.com', 'new'))];

    // Repeat to shake out any completion-order nondeterminism.
    for (let i = 0; i < 5; i++) {
      const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
      expect(r.updates).toHaveLength(1);
      expect(r.updates[0]!.existing.id).toBe('first');
    }
  });

  it('keeps content-distinct rows that share a logical key: last wins the update, the rest insert', async () => {
    const existing = [ex('e1', 'login', 'Prod', login('admin', 'example.com', 'prod-pw'))];
    // Two incoming rows for example.com/admin with DIFFERENT passwords: genuinely
    // distinct credentials, so they are not collapsed. The LAST wins the single
    // update against the existing item; the earlier one is inserted.
    const incoming = [
      inc('login', 'Prod', login('admin', 'example.com', 'first-pw')),
      inc('login', 'Staging', login('admin', 'example.com', 'second-pw')),
    ];

    const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(r.updates).toHaveLength(1);
    expect(r.updates[0]!.existing.id).toBe('e1');
    expect(r.updates[0]!.incoming.name).toBe('Staging'); // the LAST row
    expect(r.inserts).toHaveLength(1);
    expect(r.inserts[0]!.name).toBe('Prod'); // the earlier row
    expect(countAll(r)).toBe(2);
  });
});

describe('resolveImport — keep_both', () => {
  it('never matches: every row inserts even when an identical item exists', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com'))];
    const incoming = [
      inc('login', 'GitHub', login('octocat', 'github.com')),
      inc('login', 'GitHub', login('octocat', 'github.com')),
    ];

    const r = await resolveImport({ existing, incoming, strategy: 'keep_both' });
    expect(r.inserts).toHaveLength(2);
    expect(r.duplicateInFile).toHaveLength(0);
    expect(r.duplicateSkipped).toHaveLength(0);
  });
});

describe('resolveImport — intra-file exact duplicates', () => {
  // Two rows identical in name+data but differing only in a non-identity field
  // (tags) are exact-content duplicates and collapse. Which survivor is kept is
  // observable through the tag.
  const dupPair: [Inc, Inc] = [
    inc('note', 'N', { content: 'c' }, ['first']),
    inc('note', 'N', { content: 'c' }, ['last']),
  ];

  it('skip keeps the FIRST occurrence, reports the rest as duplicateInFile', async () => {
    const r = await resolveImport({ existing: [], incoming: dupPair, strategy: 'skip' });
    expect(r.inserts).toHaveLength(1);
    expect(r.inserts[0]!.tags).toEqual(['first']);
    expect(r.duplicateInFile).toHaveLength(1);
    expect(r.duplicateInFile[0]!.tags).toEqual(['last']);
  });

  it('overwrite keeps the LAST occurrence, reports the rest as duplicateInFile', async () => {
    const r = await resolveImport({ existing: [], incoming: dupPair, strategy: 'overwrite' });
    expect(r.inserts).toHaveLength(1);
    expect(r.inserts[0]!.tags).toEqual(['last']);
    expect(r.duplicateInFile).toHaveLength(1);
    expect(r.duplicateInFile[0]!.tags).toEqual(['first']);
  });

  it('keep_both inserts every occurrence', async () => {
    const r = await resolveImport({ existing: [], incoming: dupPair, strategy: 'keep_both' });
    expect(r.inserts).toHaveLength(2);
    expect(r.duplicateInFile).toHaveLength(0);
  });
});

describe('resolveImport — matching scope exclusions', () => {
  it('never matches a trashed existing item', async () => {
    const existing = [
      ex('e1', 'login', 'GitHub', login('octocat', 'github.com'), '2024-01-01T00:00:00.000Z'),
    ];
    const incoming = [inc('login', 'GitHub', login('octocat', 'github.com'))];

    const skip = await resolveImport({ existing, incoming, strategy: 'skip' });
    expect(skip.inserts).toHaveLength(1);
    expect(skip.duplicateSkipped).toHaveLength(0);

    const overwrite = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(overwrite.updates).toHaveLength(0);
    expect(overwrite.inserts).toHaveLength(1);
  });

  it('never matches an undecodable existing placeholder, and never makes it an update target', async () => {
    // A placeholder kept after a decrypt/validation failure. It superficially
    // carries login-shaped fields, but `_validationError` marks it undecodable,
    // so it must be excluded from the index entirely.
    const placeholder: VaultItem = {
      id: 'bad',
      itemType: 'login',
      name: 'broken',
      data: {
        _validationError: true,
        username: 'octocat',
        uris: [{ uri: 'https://github.com', match: 'domain' }],
      },
    };
    const good = ex('good', 'login', 'GitLab', login('alice', 'gitlab.com', 'old'));
    const incoming = [
      inc('login', 'GitHub', login('octocat', 'github.com')),
      inc('login', 'GitLab', login('alice', 'gitlab.com', 'new')),
    ];

    const skip = await resolveImport({
      existing: [placeholder, good],
      incoming,
      strategy: 'skip',
    });
    // The github row does NOT match the excluded placeholder → it inserts.
    expect(skip.inserts.map((i) => i.name)).toContain('GitHub');
    expect(skip.duplicateSkipped.map((i) => i.name)).not.toContain('GitHub');

    const overwrite = await resolveImport({
      existing: [placeholder, good],
      incoming,
      strategy: 'overwrite',
    });
    // Only the decodable `good` item is ever an update target — never `bad`.
    expect(overwrite.updates.map((u) => u.existing.id)).not.toContain('bad');
    expect(overwrite.updates.map((u) => u.existing.id)).toContain('good');
  });

  it('also excludes the `{ _raw }` placeholder shape from matching', async () => {
    const placeholder: VaultItem = {
      id: 'bad',
      itemType: 'note',
      name: 'broken',
      data: { _raw: 'undecryptable' },
    };
    const incoming = [inc('note', 'broken', { _raw: 'undecryptable' })];

    const r = await resolveImport({ existing: [placeholder], incoming, strategy: 'skip' });
    expect(r.inserts).toHaveLength(1);
    expect(r.duplicateSkipped).toHaveLength(0);
  });
});

describe('resolveImport — accounting is exhaustive', () => {
  it('every incoming row lands in exactly one bucket', async () => {
    const existing = [ex('e1', 'login', 'GitHub', login('octocat', 'github.com', 'old'))];
    const incoming = [
      inc('login', 'GitHub', login('octocat', 'github.com', 'new')), // update
      inc('login', 'GitLab', login('alice', 'gitlab.com')), // insert
      inc('note', 'N', { content: 'x' }), // insert
      inc('note', 'N', { content: 'x' }), // duplicateInFile
    ];

    const r = await resolveImport({ existing, incoming, strategy: 'overwrite' });
    expect(countAll(r)).toBe(incoming.length);
  });
});

// ---------------------------------------------------------------------------
// Batch-independence property test — the 0.2.0 regression guard.
// ---------------------------------------------------------------------------

let insertCounter = 0;

/** Apply a resolution to a simulated vault, mirroring what the server executor does. */
function applyResolution(
  existing: VaultItem[],
  resolution: ImportResolution<Inc, VaultItem>,
): VaultItem[] {
  const next = existing.map((e) => ({ ...e }));
  for (const u of resolution.updates) {
    const target = next.find((e) => e.id === u.existing.id);
    if (target) {
      target.name = u.incoming.name;
      target.data = u.incoming.data;
    }
  }
  for (const ins of resolution.inserts) {
    next.push({
      id: `new-${insertCounter++}`,
      itemType: ins.itemType,
      name: ins.name,
      data: ins.data,
    });
  }
  return next;
}

function chunk<T>(arr: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** A stable, id-independent fingerprint of a vault: the sorted content keys. */
async function contentFingerprint(vault: VaultItem[]): Promise<string[]> {
  const keys = await Promise.all(vault.map((v) => computeContentKey(v)));
  return keys.sort();
}

async function resolveWhole(
  existing: VaultItem[],
  incoming: Inc[],
  strategy: ConflictStrategy,
): Promise<VaultItem[]> {
  const r = (await resolveImport({ existing, incoming, strategy })) as ImportResolution<
    Inc,
    VaultItem
  >;
  return applyResolution(existing, r);
}

async function resolveChunked(
  existing: VaultItem[],
  incoming: Inc[],
  strategy: ConflictStrategy,
  size: number,
): Promise<VaultItem[]> {
  // Realistic batched import: each batch commits before the next resolves, so
  // later batches see the vault the earlier ones produced (idempotent re-run
  // semantics). The final vault must equal resolving the whole set at once.
  let vault = existing.map((e) => ({ ...e }));
  for (const batch of chunk(incoming, size)) {
    const r = (await resolveImport({
      existing: vault,
      incoming: batch,
      strategy,
    })) as ImportResolution<Inc, VaultItem>;
    vault = applyResolution(vault, r);
  }
  return vault;
}

describe('resolveImport — batch independence (0.2.0 regression guard)', () => {
  // A representative import with: a changed-password match, distinct-username
  // accounts on one host, exact intra-file duplicates split across batches, and
  // a note duplicate. Deliberately free of content-distinct rows that share a
  // logical key, which are the ONE documented case where batch boundaries can
  // legitimately change the result (a false split, never lost data).
  const existing = (): VaultItem[] => [
    ex('e1', 'login', 'GitHub', login('octocat', 'github.com', 'old')),
  ];
  const incoming: Inc[] = [
    inc('login', 'GitHub', login('octocat', 'github.com', 'new')),
    inc('login', 'Google', login('alice@gmail.com', 'accounts.google.com')),
    inc('login', 'Google', login('alice@gmail.com', 'accounts.google.com')), // exact dup
    inc('login', 'Google', login('bob@gmail.com', 'accounts.google.com')),
    inc('note', 'Recovery', { content: 'codes' }),
    inc('note', 'Recovery', { content: 'codes' }), // exact dup
    inc('login', 'Google', login('carol@gmail.com', 'accounts.google.com')),
  ];

  for (const strategy of STRATEGIES) {
    it(`whole-set and every chunking agree on the final vault (${strategy})`, async () => {
      const whole = await contentFingerprint(await resolveWhole(existing(), incoming, strategy));

      for (const size of [1, 2, 3, 5, 7, 100]) {
        const chunked = await contentFingerprint(
          await resolveChunked(existing(), incoming, strategy, size),
        );
        expect(chunked).toEqual(whole);
      }
    });
  }

  it('the whole-set accounting always sums to the number of incoming rows', async () => {
    for (const strategy of STRATEGIES) {
      const r = await resolveImport({ existing: existing(), incoming, strategy });
      expect(countAll(r)).toBe(incoming.length);
    }
  });
});
