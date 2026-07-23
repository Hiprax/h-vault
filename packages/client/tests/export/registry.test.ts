import { describe, it, expect } from 'vitest';
import {
  PORTABLE_EXPORT_FORMATS,
  serializePortableExport,
  type PortableExportFormat,
} from '../../src/services/export';
import type { PortableItem } from '../../src/services/export/portableItem';
import { parseImportData, detectCsvFormat } from '../../src/services/import';

/**
 * `PORTABLE_EXPORT_FORMATS` is the single registry of plaintext export formats,
 * and `serializePortableExport` dispatches a chosen format to its Phase 6/7
 * serializer, attaching the download `filename`/`mimeType`. These tests iterate
 * every registry entry (so a newly-added format is automatically exercised),
 * assert the metadata is well-formed, and prove each format routes to the right
 * serializer and produces the documented filename.
 */

function login(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'login',
    name: 'GitHub',
    folderPath: 'Work',
    favorite: false,
    notes: '',
    tags: [],
    login: { username: 'octocat', password: 'hunter2' },
    uris: ['https://github.com'],
    ...over,
  };
}

function card(over: Partial<PortableItem> = {}): PortableItem {
  return {
    type: 'card',
    name: 'Visa',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    card: {
      cardholderName: 'A B',
      number: '4111111111111111',
      expMonth: '12',
      expYear: '2030',
      cvv: '123',
    },
    ...over,
  };
}

/** The metadata shape and values every registry entry must satisfy. */
const KNOWN_FORMATS: readonly PortableExportFormat[] = [
  'bitwarden-json',
  'bitwarden-csv',
  'chrome-csv',
];
const CSV_MIME = 'text/csv';
const DATE_RE = /^hvault-export-\d{4}-\d{2}-\d{2}\.(json|csv)$/;

describe('PORTABLE_EXPORT_FORMATS — registry shape', () => {
  it('lists exactly the known formats, each once', () => {
    const values = PORTABLE_EXPORT_FORMATS.map((f) => f.value);
    expect(new Set(values)).toEqual(new Set(KNOWN_FORMATS));
    expect(values).toHaveLength(KNOWN_FORMATS.length);
    // No duplicate values.
    expect(new Set(values).size).toBe(values.length);
  });

  it('every entry has a non-empty label, extension, MIME type and loss note', () => {
    for (const meta of PORTABLE_EXPORT_FORMATS) {
      expect(meta.label.length, `label for ${meta.value}`).toBeGreaterThan(0);
      expect(['json', 'csv'], `extension for ${meta.value}`).toContain(meta.extension);
      expect(meta.mimeType.length, `mimeType for ${meta.value}`).toBeGreaterThan(0);
      expect(meta.lossNote.length, `lossNote for ${meta.value}`).toBeGreaterThan(0);
    }
  });

  it('maps each format to the expected extension and MIME type', () => {
    const byValue = new Map(PORTABLE_EXPORT_FORMATS.map((f) => [f.value, f]));
    expect(byValue.get('bitwarden-json')).toMatchObject({
      extension: 'json',
      mimeType: 'application/json',
    });
    expect(byValue.get('bitwarden-csv')).toMatchObject({ extension: 'csv', mimeType: CSV_MIME });
    expect(byValue.get('chrome-csv')).toMatchObject({ extension: 'csv', mimeType: CSV_MIME });
  });
});

describe('serializePortableExport — dispatch over every registry entry', () => {
  it.each(PORTABLE_EXPORT_FORMATS.map((f) => [f.value, f] as const))(
    'produces non-empty content, the registry MIME/extension and a dated filename for %s',
    (value, meta) => {
      const { content, filename, mimeType, omittedCount } = serializePortableExport(value, [
        login(),
        card(),
      ]);
      expect(content.length).toBeGreaterThan(0);
      expect(mimeType).toBe(meta.mimeType);
      expect(filename).toMatch(DATE_RE);
      expect(filename.endsWith(`.${meta.extension}`)).toBe(true);
      // omittedCount is a real, non-negative pass-through of the serializer.
      expect(omittedCount).toBeGreaterThanOrEqual(0);
    },
  );

  it('builds the filename as hvault-export-<today>.<ext>', () => {
    const today = new Date().toISOString().slice(0, 10);
    expect(serializePortableExport('bitwarden-json', [login()]).filename).toBe(
      `hvault-export-${today}.json`,
    );
    expect(serializePortableExport('chrome-csv', [login()]).filename).toBe(
      `hvault-export-${today}.csv`,
    );
  });
});

describe('serializePortableExport — routes to the correct serializer', () => {
  it('bitwarden-json emits parseable Bitwarden JSON, nothing omitted', () => {
    const { content, omittedCount } = serializePortableExport('bitwarden-json', [login(), card()]);
    const parsed = JSON.parse(content) as { items: unknown[]; folders: unknown[] };
    expect(Array.isArray(parsed.items)).toBe(true);
    expect(Array.isArray(parsed.folders)).toBe(true);
    // JSON represents every type, so nothing is dropped.
    expect(omittedCount).toBe(0);
    // …and it round-trips through the repo's own importer.
    const { items } = parseImportData('bitwarden', content);
    expect(items.some((i) => i.itemType === 'login')).toBe(true);
    expect(items.some((i) => i.itemType === 'card')).toBe(true);
  });

  it('bitwarden-csv emits the Bitwarden CSV header and omits the card', () => {
    const { content, omittedCount } = serializePortableExport('bitwarden-csv', [login(), card()]);
    expect(content.split('\r\n')[0]).toBe(
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
    );
    expect(detectCsvFormat(content)).toBe('bitwarden');
    // The card cannot be represented in Bitwarden CSV.
    expect(omittedCount).toBe(1);
  });

  it('chrome-csv emits the Chrome header and omits the card', () => {
    const { content, omittedCount } = serializePortableExport('chrome-csv', [login(), card()]);
    expect(content.split('\r\n')[0]).toBe('name,url,username,password,note');
    expect(detectCsvFormat(content)).toBe('chrome');
    expect(omittedCount).toBe(1);
  });

  it('passes the serializer omittedCount through unchanged (3 logins + 2 cards → 2)', () => {
    const portable = [login(), login(), login(), card(), card()];
    expect(serializePortableExport('chrome-csv', portable).omittedCount).toBe(2);
    expect(serializePortableExport('bitwarden-csv', portable).omittedCount).toBe(2);
    expect(serializePortableExport('bitwarden-json', portable).omittedCount).toBe(0);
  });
});

describe('serializePortableExport — runtime guard', () => {
  it('throws on a format outside the union (the exhaustive-switch default)', () => {
    // Simulate an untyped JS caller passing garbage; the `never` default rejects
    // it at runtime just as the compiler rejects it statically.
    expect(() =>
      serializePortableExport('not-a-format' as PortableExportFormat, [login()]),
    ).toThrow(/Unknown portable export format/);
  });
});
