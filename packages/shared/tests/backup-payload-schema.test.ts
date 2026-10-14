/**
 * `backupPayloadSchema` (F-14): the skeleton a restore's backup file is checked
 * against before the server takes any lock.
 *
 * Two properties carry the weight. It is LOOSE: every key it does not name, at the
 * top and in every row, passes through, because the restore's own allowlists judge
 * the rows and a strict skeleton would hand them empty objects. And its row arrays
 * are bounded by LENGTH BEFORE their elements are looked at, so an oversized array
 * of junk costs one issue, not one per element.
 *
 * Bounds are pinned by PARSING at the bound and one past it, never by comparing
 * constants.
 */
import { describe, expect, it } from 'vitest';
import { backupPayloadSchema } from '../src/schemas/user.js';
import { MAX_FOLDERS_PER_USER, MAX_ITEMS_PER_USER } from '../src/constants/index.js';

function rows(count: number, row: unknown = {}): unknown[] {
  return Array.from({ length: count }, () => row);
}

function issuesOf(input: unknown) {
  const result = backupPayloadSchema.safeParse(input);
  expect(result.success).toBe(false);
  return result.success ? [] : result.error.issues;
}

describe('backupPayloadSchema keeps everything it does not name', () => {
  it('passes every top-level block and every row field through untouched', () => {
    const payload = {
      version: '0.15.0',
      exportDate: '2026-10-14T00:00:00.000Z',
      items: [{ _id: 'a', itemType: 'login', encryptedData: 'x', tags: ['t'], nested: { k: 1 } }],
      folders: [{ _id: 'f', encryptedName: 'n', parentId: null }],
      encryptedVaultKey: 'evk',
      backupEncryption: { encryptedBWK: 'b', bwkSalt: 's' },
      metadata: { itemCount: 1, folderCount: 1 },
      documentSummary: { count: 2 },
      integrity: 'f'.repeat(64),
    };

    const result = backupPayloadSchema.safeParse(payload);

    expect(result.success).toBe(true);
    expect(result.data).toStrictEqual(payload);
  });

  it('accepts a numeric version and a payload naming none of its keys', () => {
    expect(backupPayloadSchema.safeParse({ version: 1 }).success).toBe(true);
    expect(backupPayloadSchema.safeParse({}).success).toBe(true);
  });
});

describe('backupPayloadSchema refuses a payload of the wrong shape, naming where', () => {
  it.each([
    ['an array', [], []],
    ['a string', 'x', []],
    ['null', null, []],
    ['a number', 5, []],
    ['`items` as a number', { items: 5 }, ['items']],
    ['`items` as an object', { items: {} }, ['items']],
    ['`items` holding null', { items: [null] }, ['items', 0]],
    ['`items` holding an array', { items: [{}, []] }, ['items', 1]],
    ['`items` holding a string', { items: ['row'] }, ['items', 0]],
    ['`folders` as a string', { folders: 'x' }, ['folders']],
    ['`folders` holding a number', { folders: [1] }, ['folders', 0]],
    ['`version` as an object', { version: {} }, ['version']],
    ['`version` as a boolean', { version: true }, ['version']],
    ['`exportDate` as a number', { exportDate: 1 }, ['exportDate']],
  ])('%s', (_label, input, path) => {
    const issues = issuesOf(input);

    expect(issues).toHaveLength(1);
    expect(issues[0]!.path).toEqual(path);
  });
});

describe('backupPayloadSchema bounds the row arrays', () => {
  it(`accepts exactly ${String(MAX_ITEMS_PER_USER)} items and refuses one more`, () => {
    expect(backupPayloadSchema.safeParse({ items: rows(MAX_ITEMS_PER_USER) }).success).toBe(true);

    const issues = issuesOf({ items: rows(MAX_ITEMS_PER_USER + 1) });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ code: 'too_big', path: ['items'] });
  });

  it(`accepts exactly ${String(MAX_FOLDERS_PER_USER)} folders and refuses one more`, () => {
    expect(backupPayloadSchema.safeParse({ folders: rows(MAX_FOLDERS_PER_USER) }).success).toBe(
      true,
    );

    const issues = issuesOf({ folders: rows(MAX_FOLDERS_PER_USER + 1) });
    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ code: 'too_big', path: ['folders'] });
  });

  it('judges the LENGTH before the elements: an oversized array of junk is one issue', () => {
    // A plain `z.array(row).max(n)` parses every element first and checks the
    // length afterwards: n + 2 issues, one per null plus the length, and the cost
    // of a 25 MiB array of them is millions of issue objects.
    const issues = issuesOf({ items: rows(MAX_ITEMS_PER_USER + 1, null) });

    expect(issues).toHaveLength(1);
    expect(issues[0]).toMatchObject({ code: 'too_big', path: ['items'] });
  });

  it('within the bound, a bad element is still reported with its index', () => {
    const items = rows(MAX_ITEMS_PER_USER);
    items[MAX_ITEMS_PER_USER - 1] = null;

    const issues = issuesOf({ items });

    expect(issues).toHaveLength(1);
    expect(issues[0]!.path).toEqual(['items', MAX_ITEMS_PER_USER - 1]);
  });
});
