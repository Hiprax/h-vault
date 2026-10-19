/**
 * The custom-field limit on import, as properties.
 *
 * Three claims hold for EVERY row and every limit, not just the examples in
 * `customFieldsLimit.test.ts`: the row never keeps more fields than the limit,
 * limiting it again changes nothing, and no hidden value past the limit appears
 * anywhere in the row or the report (nor any hidden value at all in the free text
 * or the report).
 *
 * Every hidden value is a SENTINEL: a private-use marker, its index and a closing
 * marker. Names, text values and the free text are drawn from an alphabet that
 * contains neither marker, so finding a sentinel can only mean a leak, and no
 * sentinel is a substring of another (`H1` is closed before `H10` could begin).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { MAX_NOTE_CONTENT_LENGTH, MAX_SECRET_DESCRIPTION_LENGTH } from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { limitImportItem } from '../../src/services/import/customFieldsLimit';
import type { ResolvableImportItem } from '../../src/services/import';
import {
  propertyBanner,
  propertyRun,
  stringFromAlphabet,
} from '../../../../tests/harness/property.js';

const OPEN = '\uE000';
const CLOSE = '\uE001';
const sentinel = (index: number): string => `${OPEN}H${String(index)}${CLOSE}`;

const SAFE_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 :.-\n';

const NOTES_KEY: Record<ItemType, string> = {
  login: 'notes',
  card: 'notes',
  identity: 'notes',
  note: 'content',
  secret: 'description',
};
const NOTES_MAX: Record<ItemType, number> = {
  login: MAX_NOTE_CONTENT_LENGTH,
  card: MAX_NOTE_CONTENT_LENGTH,
  identity: MAX_NOTE_CONTENT_LENGTH,
  note: MAX_NOTE_CONTENT_LENGTH,
  secret: MAX_SECRET_DESCRIPTION_LENGTH,
};

interface Draft {
  itemType: ItemType;
  cap: number;
  notes: string | undefined;
  fields: { name: string; type: 'text' | 'hidden' | 'boolean'; value: string }[];
}

const draftArbitrary: fc.Arbitrary<Draft> = fc.record({
  itemType: fc.constantFrom<ItemType>('login', 'secret', 'note', 'card', 'identity'),
  cap: fc.integer({ min: 1, max: 8 }),
  notes: fc.option(stringFromAlphabet(SAFE_ALPHABET, { maxLength: 20 }), { nil: undefined }),
  fields: fc.array(
    fc.record({
      name: stringFromAlphabet(SAFE_ALPHABET, { minLength: 1, maxLength: 8 }),
      type: fc.constantFrom('text' as const, 'hidden' as const, 'boolean' as const),
      value: stringFromAlphabet(SAFE_ALPHABET, { maxLength: 12 }),
    }),
    { maxLength: 14 },
  ),
});

/** Build the row, giving every hidden field its own sentinel value. */
function toRow(draft: Draft): ResolvableImportItem {
  const customFields = draft.fields.map((field, index) =>
    field.type === 'hidden' ? { ...field, value: sentinel(index) } : field,
  );
  const data: Record<string, unknown> = { customFields };
  if (draft.notes !== undefined) data[NOTES_KEY[draft.itemType]] = draft.notes;
  return { itemType: draft.itemType, name: 'Row', data, tags: [], favorite: false };
}

describe('limitImportItem — properties', () => {
  it('never keeps more than the limit, and keeps exactly the first fields', () => {
    fc.assert(
      fc.property(draftArbitrary, (draft) => {
        const row = toRow(draft);
        const { item } = limitImportItem(row, draft.cap);
        const kept = item.data.customFields as unknown[];
        expect(kept.length, propertyBanner()).toBeLessThanOrEqual(draft.cap);
        expect(kept).toEqual((row.data.customFields as unknown[]).slice(0, draft.cap));
        const text = item.data[NOTES_KEY[draft.itemType]];
        if (typeof text === 'string') {
          expect(text.length).toBeLessThanOrEqual(NOTES_MAX[draft.itemType]);
        }
      }),
      propertyRun(),
    );
  });

  it('is idempotent: limiting the result again returns it unchanged, with no report', () => {
    fc.assert(
      fc.property(draftArbitrary, (draft) => {
        const once = limitImportItem(toRow(draft), draft.cap);
        const twice = limitImportItem(once.item, draft.cap);
        expect(twice.item, propertyBanner()).toBe(once.item);
        expect(twice.report).toBeNull();
      }),
      propertyRun(),
    );
  });

  it('writes no hidden value past the limit anywhere, and none at all in the text or report', () => {
    fc.assert(
      fc.property(draftArbitrary, (draft) => {
        const { item, report } = limitImportItem(toRow(draft), draft.cap);
        const rowJson = JSON.stringify(item);
        draft.fields.forEach((field, index) => {
          if (field.type === 'hidden' && index >= draft.cap) {
            expect(rowJson, propertyBanner()).not.toContain(sentinel(index));
          }
        });
        const text = item.data[NOTES_KEY[draft.itemType]];
        expect(String(text ?? '')).not.toContain(OPEN);
        expect(JSON.stringify(report)).not.toContain(OPEN);
      }),
      propertyRun(),
    );
  });

  it('accounts for every field past the limit exactly once, by name', () => {
    fc.assert(
      fc.property(draftArbitrary, (draft) => {
        const { report } = limitImportItem(toRow(draft), draft.cap);
        const overflow = draft.fields.slice(draft.cap);
        if (overflow.length === 0) {
          expect(report, propertyBanner()).toBeNull();
          return;
        }
        expect(report?.hiddenDropped, propertyBanner()).toEqual(
          overflow.filter((field) => field.type === 'hidden').map((field) => field.name),
        );
        // Small values always fit, so every plain field is moved, none lost.
        expect(report?.movedToNotes).toEqual(
          overflow.filter((field) => field.type !== 'hidden').map((field) => field.name),
        );
        expect(report?.notWritten).toEqual([]);
      }),
      propertyRun(),
    );
  });
});
