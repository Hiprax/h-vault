/**
 * The two vault-write budgets are sized from the per-user caps, not from a
 * number somebody liked.
 *
 * ## The failure these budgets exist to prevent
 *
 * The client's bulk actions are not one request. A bulk tag sends one
 * `PUT /vault/items/:id` per selected item, a trash purge one
 * `DELETE /vault/items/:id/permanent` per row, and a folder drag one
 * `PUT /folders/:id/sort` per sibling whose position moved, all through
 * `Promise.all` with no retry on a 429. A budget below the largest of those does
 * not stop an abusive caller; it stops a legitimate bulk action PARTWAY THROUGH
 * and leaves the selection half-changed. That is the hazard
 * `breach-batch-budget.test.ts` and `document-limiter-budget.test.ts` were written
 * for, and the shape is the same: the NEED is computed here from the shared
 * constants, and the shipped budget must cover it.
 *
 * The other direction matters too, because these routes write an audit row that
 * is kept for 365 days: a budget grown past a few whole-collection passes is an
 * open-ended audit-log writer again, so each budget is also held under a ceiling.
 */
import { describe, it, expect } from 'vitest';
import { MAX_FOLDERS_PER_USER, MAX_ITEMS_PER_USER } from '@hvault/shared';
import {
  FOLDER_WRITE_RATE_LIMIT_MAX,
  TWO_FACTOR_VERIFY_RATE_LIMIT_MAX,
  VAULT_ITEM_WRITE_RATE_LIMIT_MAX,
  VAULT_WRITE_RATE_LIMIT_WINDOW_MS,
} from '../src/middleware/rateLimiter.js';

/** The most whole-collection passes a budget may allow before it bounds nothing. */
const MAX_PASSES_BEFORE_UNBOUNDED = 3;

describe('vaultItemWriteLimiter budget', () => {
  it('covers two bulk actions over every row the account can hold, back to back', () => {
    // `MAX_ITEMS_PER_USER` counts active and trashed rows together, so a "select
    // all, tag" or a whole-trash purge is at most that many requests; tag
    // everything, then purge a full trash, is two such passes.
    expect(VAULT_ITEM_WRITE_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(MAX_ITEMS_PER_USER * 2);
  });

  it('stays a bound: no more than a few whole-vault passes per window', () => {
    expect(VAULT_ITEM_WRITE_RATE_LIMIT_MAX).toBeLessThanOrEqual(
      MAX_ITEMS_PER_USER * MAX_PASSES_BEFORE_UNBOUNDED,
    );
  });
});

describe('folderWriteLimiter budget', () => {
  it('covers two worst-case drags in a row', () => {
    // A drag re-sorts at most every OTHER sibling, one request each.
    const worstDrag = MAX_FOLDERS_PER_USER - 1;
    expect(FOLDER_WRITE_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(worstDrag * 2);
  });

  it('stays a bound, and far below the item budget it does not share', () => {
    expect(FOLDER_WRITE_RATE_LIMIT_MAX).toBeLessThanOrEqual(
      MAX_FOLDERS_PER_USER * MAX_PASSES_BEFORE_UNBOUNDED,
    );
    expect(FOLDER_WRITE_RATE_LIMIT_MAX).toBeLessThan(VAULT_ITEM_WRITE_RATE_LIMIT_MAX);
  });
});

describe('the windows the budgets are spent over', () => {
  it('spends the vault-write budgets over fifteen minutes, like every other derived budget', () => {
    // A whole-vault bulk action through a browser's six connections takes minutes,
    // not seconds; a one-minute window would refuse the same action the budget
    // was sized to allow.
    expect(VAULT_WRITE_RATE_LIMIT_WINDOW_MS).toBe(15 * 60 * 1000);
  });

  it('keeps the 2FA-setup budget at the attempt count the address-keyed limiter allowed', () => {
    // Re-keying the route from the address to the account was the change; the
    // number of guesses a pending setup tolerates was not.
    expect(TWO_FACTOR_VERIFY_RATE_LIMIT_MAX).toBe(20);
  });
});
