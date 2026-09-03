/**
 * The rotation payload budget.
 *
 * `POST /vault/items/bulk-reencrypt` carries an account's whole re-encrypted
 * surface in one request, behind a route-specific 30 MB body parser. Adding a
 * third leg to that request is exactly the change that can quietly make a
 * rotation that used to fit stop fitting — and a rotation that will not fit is a
 * vault key that can never be changed again, which is worse than any single
 * document being large.
 *
 * The property that makes the documents leg safe is ENVELOPE ENCRYPTION: a
 * rotation rewraps the 32-byte document key, never the file. So a document's
 * contribution to this payload is a constant a few hundred bytes wide, whatever
 * the file weighs — an account holding one 100 MB document and an account holding
 * one 16-byte document send byte-identical rotation legs. Every assertion below
 * derives its numbers from the real shared constants and the real wire schema, so
 * a bound that moved, or a size field that crept into the leg, fails here rather
 * than at some operator's rotation years from now.
 */
import { describe, it, expect } from 'vitest';
import {
  MAX_DOCUMENTS_PER_ROTATION,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
  MAX_FOLDERS_PER_USER,
  MAX_ITEMS_PER_USER,
  PASSWORD_HISTORY_MAX,
  documentKeyRewrapSchema,
} from '@hvault/shared';
import { BULK_REENCRYPT_BODY_LIMIT_BYTES } from '../src/routes/vault.js';

/** A 24-character lowercase hex id, the only shape `objectIdSchema` accepts. */
const SAMPLE_ID = 'a'.repeat(24);

/** A base64 IV and tag at their wire maxima, which every leg shares. */
const MAX_IV_LENGTH = 24;
const MAX_TAG_LENGTH = 32;

/** The wrapped-DEK bound, the same one `User.encryptedVaultKey` carries. */
const MAX_WRAPPED_KEY_LENGTH = 200;

/** The size of a value once it is a JSON string, i.e. what the parser counts. */
function encodedBytes(value: unknown): number {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

/** One documents-leg entry with every field at its maximum accepted length. */
function maximalDocumentEntry(): Record<string, string> {
  return {
    id: SAMPLE_ID,
    encryptedDek: 'd'.repeat(MAX_WRAPPED_KEY_LENGTH),
    dekIv: 'i'.repeat(MAX_IV_LENGTH),
    dekTag: 't'.repeat(MAX_TAG_LENGTH),
  };
}

/**
 * The worst-case items leg, per row.
 *
 * `passwordHistory` is what dominates it: `PASSWORD_HISTORY_MAX` entries, each
 * holding a ciphertext bounded by the same `MAX_ENCRYPTED_DATA_LENGTH` as the
 * item's own payload.
 */
function maximalItemEntry(): Record<string, unknown> {
  return {
    id: SAMPLE_ID,
    encryptedName: 'n'.repeat(MAX_ENCRYPTED_NAME_LENGTH),
    nameIv: 'i'.repeat(MAX_IV_LENGTH),
    nameTag: 't'.repeat(MAX_TAG_LENGTH),
    encryptedData: 'd'.repeat(MAX_ENCRYPTED_DATA_LENGTH),
    dataIv: 'i'.repeat(MAX_IV_LENGTH),
    dataTag: 't'.repeat(MAX_TAG_LENGTH),
    searchHash: 'a'.repeat(64),
    passwordHistory: Array.from({ length: PASSWORD_HISTORY_MAX }, () => ({
      encryptedPassword: 'p'.repeat(MAX_ENCRYPTED_DATA_LENGTH),
      iv: 'i'.repeat(MAX_IV_LENGTH),
      tag: 't'.repeat(MAX_TAG_LENGTH),
      changedAt: '2026-09-01T00:00:00.000Z',
    })),
  };
}

function maximalFolderEntry(): Record<string, string> {
  return {
    id: SAMPLE_ID,
    encryptedName: 'n'.repeat(MAX_ENCRYPTED_NAME_LENGTH),
    nameIv: 'i'.repeat(MAX_IV_LENGTH),
    nameTag: 't'.repeat(MAX_TAG_LENGTH),
  };
}

const documentEntryBytes = encodedBytes(maximalDocumentEntry());
// `MAX_DOCUMENTS_PER_ROTATION`, not the advertised per-user limit: the wire cap is
// what a worst-case body may actually carry, and it is deliberately a few rows
// above the limit an init refuses at, because an account can finish past that
// limit and a rotation must name every row it holds.
const documentsLegBytes = documentEntryBytes * MAX_DOCUMENTS_PER_ROTATION;
const foldersLegBytes = encodedBytes(maximalFolderEntry()) * MAX_FOLDERS_PER_USER;
const itemsLegBytes = encodedBytes(maximalItemEntry()) * MAX_ITEMS_PER_USER;

/**
 * The per-row ceiling this leg is designed around.
 *
 * A rotation entry is an id, a wrapped 256-bit key, an IV and a tag. Four hundred
 * bytes is the round number that fits those maxima with a little slack for JSON
 * punctuation, and nothing else may be added to the leg without moving it —
 * deliberately, because the next thing anyone would reach for is a size or a
 * framing field, and neither belongs in a rewrap.
 */
const DOCUMENT_ENTRY_BUDGET_BYTES = 400;

/**
 * The share of the parser the documents leg may claim.
 *
 * A tenth, so that enabling the document store cannot be what pushes an account
 * that could rotate yesterday over the limit today. It is a headroom rule, not a
 * measurement: the measured value is an order of magnitude below it.
 */
const DOCUMENTS_LEG_BUDGET_FRACTION = 0.1;

describe('rotation payload budget — the documents leg', () => {
  it('accepts an entry at every field maximum and rejects one character more, so the budget is pinned by parsing', () => {
    const maximal = maximalDocumentEntry();
    expect(documentKeyRewrapSchema.safeParse(maximal).success).toBe(true);

    // Each bound checked in the direction that matters: one character past it
    // must be refused, or the "maximum" the budget is derived from is fiction.
    for (const [field, overLength] of [
      ['encryptedDek', MAX_WRAPPED_KEY_LENGTH + 1],
      ['dekIv', MAX_IV_LENGTH + 1],
      ['dekTag', MAX_TAG_LENGTH + 1],
    ] as const) {
      const over = { ...maximal, [field]: 'x'.repeat(overLength) };
      expect(
        documentKeyRewrapSchema.safeParse(over).success,
        `${field} accepted over its max`,
      ).toBe(false);
    }
  });

  it('carries only the id and the wrapped key, so a document costs the same to rotate whatever it weighs', () => {
    // The load-bearing assertion of this file. A rotation entry that gained
    // `plaintextBytes`, `chunkCount`, `streamSalt` or — catastrophically — the
    // ciphertext itself would make the payload scale with stored bytes, and this
    // is what says no. Sorted, because the schema's key order is not a contract.
    expect(Object.keys(documentKeyRewrapSchema.shape).sort()).toEqual([
      'dekIv',
      'dekTag',
      'encryptedDek',
      'id',
    ]);

    expect(documentEntryBytes).toBeLessThanOrEqual(DOCUMENT_ENTRY_BUDGET_BYTES);
  });

  it('fits a full account of documents inside a tenth of the route body limit', () => {
    expect(documentsLegBytes).toBeLessThan(
      BULK_REENCRYPT_BODY_LIMIT_BYTES * DOCUMENTS_LEG_BUDGET_FRACTION,
    );
  });

  it('costs two orders of magnitude less per row than an item, which is what makes a large store rotatable', () => {
    expect(documentEntryBytes * 100).toBeLessThan(encodedBytes(maximalItemEntry()));
  });

  it('leaves the parser sized by the items leg exactly as it was before the feature existed', () => {
    // Folders and documents are the two FIXED-COST legs: both are bounded by a
    // per-row constant that no user action can grow. Together they stay two
    // orders of magnitude below the items leg, which is what the 30 MB parser was
    // sized against — so enabling the document store does not change which leg
    // that number has to be re-derived from.
    expect((foldersLegBytes + documentsLegBytes) * 100).toBeLessThan(itemsLegBytes);
  });
});
