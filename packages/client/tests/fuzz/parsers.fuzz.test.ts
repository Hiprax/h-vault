/**
 * Fuzzing the seven import parsers.
 *
 * These are the only place in H-Vault where an arbitrary, attacker-chosen FILE
 * is turned into vault data. Everything else the client parses it produced
 * itself. So there is one contract, and it has three clauses:
 *
 *   1. **Nothing untyped escapes.** `parseImportData` either returns items or
 *      throws `ImportParseError`. A TypeError, a RangeError or a bare Error
 *      reaching the caller is a crash: the UI's catch is written against the
 *      typed error, and anything else surfaces as an unhandled rejection.
 *   2. **Every item it returns passes `vaultItemDataSchemas[itemType]`.** This
 *      is the clause with teeth. An item that fails validation is not stored
 *      badly — it is DISCARDED WHOLE by `validateImportItems`, password
 *      included, because one field was a character too long. The clamps in
 *      `itemBuilders.ts` exist for exactly this, and this suite is what keeps
 *      them there.
 *   3. **It terminates.** A quadratic tokenizer or a backtracking regex on a
 *      user-supplied file is a denial of service against the person importing.
 *
 * ---------------------------------------------------------------------------
 * THE SEAM
 * ---------------------------------------------------------------------------
 *
 * The real parsers, the real `csv.ts` tokenizer, the real `itemBuilders.ts`
 * (so the real `clampNotesAndFields` and `clampAddress`), the real shared
 * schemas. Nothing is mocked and nothing is stubbed. The only injected value is
 * the fast-check seed, from `tests/harness/property.ts`, so a counterexample
 * found here is reproducible on any machine.
 *
 * Generated cases and committed corpus files do different jobs and both are
 * here: the generator explores, `corpus.ts` remembers. See that file for why
 * two of the required size-class cases are generated rather than committed.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
  MAX_CARD_BRAND_LENGTH,
  MAX_CARD_CARDHOLDER_NAME_LENGTH,
  MAX_CUSTOM_FIELDS_PER_ITEM,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_LOGIN_TOTP_LENGTH,
  MAX_LOGIN_USERNAME_LENGTH,
  MAX_TAG_LENGTH,
  MAX_URIS_PER_ITEM,
  MAX_URI_LENGTH,
  vaultItemDataSchemas,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { ImportParseError, parseImportData } from '../../src/services/import';
import type {
  CsvFieldMapping,
  ImportSourceFormat,
  ParsedImportItem,
} from '../../src/services/import';
import { parseBitwarden } from '../../src/services/import/parsers/bitwarden';
import { BITWARDEN_CSV_HEADER } from '../../src/services/export/formats/bitwardenCsv';
import { CHROME_CSV_HEADER } from '../../src/services/export/formats/chromeCsv';
import { toCsv } from '../../src/services/export/csvWriter';
import { propertyBanner, propertyRun } from '../../../../tests/harness/property';
import { CORPUS, CORPUS_FILES, FUZZ_FORMATS, readCorpus } from './corpus';

type FuzzFormat = Exclude<ImportSourceFormat, 'json'>;

/**
 * Cases per property.
 *
 * Every property below runs once per format, so a budget of `n` is `7n`
 * parses — and each file also runs a second time inside `test:unit`, which is
 * the whole client suite. Measured on the reference machine: 50 cases across
 * all seven formats costs under two seconds for the text-shaped properties.
 * The two size-class cases have their own budgets, stated where they are used.
 */
const FUZZ_RUNS = 50;

/**
 * The generated-document properties allocate a full CSV or JSON document per
 * case, so they draw fewer. Kept explicit rather than reusing `HEAVY_RUNS`
 * from the harness: this is a different heaviness (allocation, not crypto or a
 * database round trip) and the number should move for its own reasons.
 */
const DOCUMENT_RUNS = 20;

// ---------------------------------------------------------------------------
// The contract, as one assertion
// ---------------------------------------------------------------------------

/**
 * The failure messages are deliberately distinctive strings rather than test
 * names. A JUnit report carries a `<testcase name=…>` for every test that RAN,
 * so a predicate matching a NAME is satisfied by a fully green report — the
 * trap already recorded on `test:security` and `test:property`. These strings
 * appear only when the expectation fails, which is what lets
 * `verify:selftest`'s evidence check attribute a red run to its planted defect.
 */
const ESCAPED = 'import parser fuzz: an untyped exception escaped parseImportData';
const INVALID = 'import parser fuzz: a parser emitted an item that fails its own schema';

function describeError(err: unknown): string {
  if (err instanceof Error) return `${err.constructor.name}: ${err.message.slice(0, 120)}`;
  return `a non-Error value: ${String(err).slice(0, 120)}`;
}

function firstIssue(itemType: ItemType, data: Record<string, unknown>): string {
  const result = vaultItemDataSchemas[itemType].safeParse(data);
  if (result.success) return 'none';
  const issue = result.error.issues[0];
  return issue ? `${issue.path.join('.') || '(root)'}: ${issue.message}` : 'unknown issue';
}

/** The root field of every schema issue an item's data produces, deduplicated. */
function invalidPaths(itemType: ItemType, data: Record<string, unknown>): string[] {
  const result = vaultItemDataSchemas[itemType].safeParse(data);
  if (result.success) return [];
  return [...new Set(result.error.issues.map((issue) => String(issue.path[0] ?? '(root)')))];
}

/**
 * Assert the whole contract for one (format, input) pair.
 *
 * Returns the items when the parse succeeded, so a caller that wants to say
 * something more specific about them can, and `null` when the parser refused
 * the file — refusal being a legitimate outcome for a file that is not what the
 * user said it was.
 *
 * `allowedInvalidPaths` is the ONE narrowing, and it is a list rather than a
 * boolean on purpose: a corpus entry that witnesses a recorded, deferred defect
 * names exactly which fields may fail, so an eleventh field joining that defect
 * fails the run instead of disappearing into a blanket exemption. Every other
 * caller passes nothing and gets the unconditional clause.
 */
function assertParserContract(
  format: FuzzFormat,
  text: string,
  label: string,
  mapping?: CsvFieldMapping,
  allowedInvalidPaths: readonly string[] = [],
): ParsedImportItem[] | null {
  let items: ParsedImportItem[];
  try {
    items = parseImportData(format, text, mapping).items;
  } catch (err) {
    expect(
      err instanceof ImportParseError,
      `${ESCAPED} — ${format} on ${label} threw ${describeError(err)}. ${propertyBanner()}`,
    ).toBe(true);
    return null;
  }

  for (const item of items) {
    const failing = invalidPaths(item.itemType, item.data);
    const unexpected = failing.filter((path) => !allowedInvalidPaths.includes(path));
    expect(
      unexpected,
      `${INVALID} — ${format} on ${label} produced a ${item.itemType} that ` +
        `vaultItemDataSchemas rejects (${firstIssue(item.itemType, item.data)}), so ` +
        `validateImportItems would discard the whole item. ${propertyBanner()}`,
    ).toEqual([]);
  }
  return items;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Any UTF-16 code unit, INCLUDING an unpaired surrogate.
 *
 * fast-check's own `unit: 'binary'` is documented as "any possible code point
 * (except half surrogate pairs)", and half surrogate pairs are precisely what
 * a hostile file carries: they survive `JSON.parse`, they reach
 * `String.prototype.normalize` in the identity hash, and they are what a
 * naive `TextDecoder` round trip mangles. Drawing code UNITS rather than code
 * POINTS is the difference.
 */
const anyCodeUnit = fc.integer({ min: 0, max: 0xffff }).map((n) => String.fromCharCode(n));

/** Values chosen because each has already been a bug somewhere in this pipeline. */
const NASTY_LITERALS = [
  '',
  ' ',
  '\t',
  '"',
  '""',
  ',',
  '\r\n',
  '\n',
  '﻿',
  ' ',
  '__proto__',
  'constructor',
  'toString',
  '=1+1',
  'http://sn',
  'javascript:alert(1)',
  'androidapp://com.example',
  'mailto:someone@example.com',
  '//protocol.relative',
  'https://good.example\\evil.example',
  'https://ac\tcounts.example.com',
  'bare.example',
  'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP',
] as const;

/**
 * Lengths at, and one past, every bound a CSV path can reach — minus the two
 * biggest (`MAX_LOGIN_PASSWORD_LENGTH` 10,000 and `MAX_NOTE_CONTENT_LENGTH`
 * 50,000). Those two are covered EXACTLY ONCE by `one-past-bounds.csv` rather
 * than being drawn fifty times per format: a 50 kB string per case is the
 * difference between a property that costs two seconds and one that costs
 * thirty, and drawing it repeatedly proves nothing the single case does not.
 */
const BOUNDARY_LENGTHS = [
  0,
  1,
  MAX_TAG_LENGTH,
  MAX_TAG_LENGTH + 1,
  255,
  256,
  MAX_LOGIN_USERNAME_LENGTH,
  MAX_LOGIN_USERNAME_LENGTH + 1,
  MAX_LOGIN_TOTP_LENGTH + 1,
  MAX_URI_LENGTH - 'https://'.length,
  MAX_URI_LENGTH - 'https://'.length + 1,
  MAX_URI_LENGTH + 1,
] as const;

/** One cell of a generated source file. */
const hostileCell = fc.oneof(
  { arbitrary: fc.string({ unit: anyCodeUnit, maxLength: 24 }), weight: 4 },
  { arbitrary: fc.constantFrom(...NASTY_LITERALS), weight: 3 },
  {
    arbitrary: fc
      .tuple(fc.constantFrom(...BOUNDARY_LENGTHS), fc.constantFrom('a', '.', 'é'))
      .map(([length, unit]) => unit.repeat(length)),
    weight: 2,
  },
);

/** The header row each format's own parser reads, so a generated file is format-SHAPED. */
const FORMAT_HEADERS: Record<FuzzFormat, readonly string[]> = {
  bitwarden: BITWARDEN_CSV_HEADER,
  chrome: CHROME_CSV_HEADER,
  firefox: ['url', 'username', 'password', 'httpRealm', 'formActionOrigin', 'guid'],
  keepass: ['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'],
  lastpass: ['url', 'username', 'password', 'totp', 'extra', 'name', 'grouping', 'fav'],
  onepassword: ['title', 'website', 'username', 'password', 'otpauth', 'notes', 'tags'],
  csv: ['name', 'username', 'password', 'url', 'notes', 'totp', 'backupCodes', 'folder'],
};

/** The generic path is driven by a mapping; identity-mapping its own headers. */
const GENERIC_MAPPING: CsvFieldMapping = Object.fromEntries(
  FORMAT_HEADERS.csv.map((header) => [header, header]),
);

const mappingFor = (format: FuzzFormat): CsvFieldMapping | undefined =>
  format === 'csv' ? GENERIC_MAPPING : undefined;

/**
 * A format-shaped CSV document, written through the REAL RFC-4180 writer.
 *
 * Using `toCsv` rather than joining with commas is the point: it guarantees a
 * generated cell containing a quote, a comma or a newline arrives at the parser
 * INTACT, so the property is about what the parser does with a hostile VALUE
 * rather than about whether the generator managed to encode it. Hostile TEXT
 * that is not valid CSV at all is a separate property, below.
 */
function csvDocument(format: FuzzFormat): fc.Arbitrary<string> {
  const headers = FORMAT_HEADERS[format];
  return fc
    .array(fc.array(hostileCell, { minLength: headers.length, maxLength: headers.length }), {
      minLength: 1,
      maxLength: 4,
    })
    .map((rows) => toCsv(headers, rows));
}

/** A Bitwarden JSON export whose every leaf is hostile but whose shape is real. */
const bitwardenDocument = fc
  .record({
    folders: fc.array(fc.record({ id: hostileCell, name: hostileCell }), { maxLength: 2 }),
    items: fc.array(
      fc.record({
        type: fc.constantFrom(1, 2, 3, 4, 5, 0, 99),
        name: hostileCell,
        notes: hostileCell,
        favorite: fc.boolean(),
        folderId: hostileCell,
        fields: fc.array(
          fc.record({
            name: hostileCell,
            value: hostileCell,
            type: fc.constantFrom(0, 1, 2, 7),
          }),
          { maxLength: 3 },
        ),
        login: fc.record({
          username: hostileCell,
          password: hostileCell,
          totp: hostileCell,
          uris: fc.array(fc.record({ uri: hostileCell }), { maxLength: 3 }),
        }),
        // The card and identity scalars are drawn WITHIN their bounds on
        // purpose; see the KNOWN DEFECT block at the foot of this file for the
        // deferred defect that exclusion names, and for the tests that pin it.
        card: fc.record({
          cardholderName: fc.string({ maxLength: MAX_CARD_CARDHOLDER_NAME_LENGTH }),
          number: fc.string({ maxLength: 30 }),
          expMonth: fc.string({ maxLength: 2 }),
          expYear: fc.string({ maxLength: 4 }),
          code: fc.string({ maxLength: 4 }),
          brand: fc.string({ maxLength: MAX_CARD_BRAND_LENGTH }),
        }),
        identity: fc.record({
          firstName: fc.string({ maxLength: MAX_IDENTITY_NAME_LENGTH }),
          lastName: fc.string({ maxLength: MAX_IDENTITY_NAME_LENGTH }),
          company: fc.string({ maxLength: MAX_IDENTITY_COMPANY_LENGTH }),
          ssn: fc.string({ maxLength: MAX_IDENTITY_SSN_LENGTH }),
          passportNumber: fc.string({ maxLength: MAX_IDENTITY_PASSPORT_LENGTH }),
          email: hostileCell,
          phone: hostileCell,
          // Address lines ARE drawn past their bounds: `clampAddress` is the
          // clamp this half of the property exists to hold in place.
          address1: hostileCell,
          address2: hostileCell,
          address3: hostileCell,
          city: hostileCell,
          state: hostileCell,
          postalCode: hostileCell,
          country: hostileCell,
        }),
        sshKey: fc.record({
          privateKey: hostileCell,
          publicKey: hostileCell,
          keyFingerprint: hostileCell,
        }),
      }),
      { maxLength: 4 },
    ),
  })
  .map((doc) => JSON.stringify(doc));

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

describe('the committed corpus, through every parser', () => {
  // Every entry through every parser, not just the one it was written for: the
  // format is a dropdown, and picking the wrong one is an ordinary mistake.
  const pairs = CORPUS.flatMap((entry) =>
    FUZZ_FORMATS.map((format) => [entry.file, format, entry] as const),
  );

  it.each(pairs)('%s parsed as %s holds the parser contract', (file, format, entry) => {
    const items = assertParserContract(
      format,
      readCorpus(file),
      file,
      mappingFor(format),
      // Only the entry that witnesses the recorded, deferred defect carries a
      // list; for every other entry this is empty and the clause is absolute.
      entry.knownInvalidPaths ?? [],
    );
    // A refusal is allowed; silently returning nothing for a file the parser's
    // OWN format wrote is not, and that asymmetry is worth stating.
    if (entry.origin === format && file !== 'empty.csv' && file !== 'bitwarden-truncated.json') {
      expect(
        items === null || items.length > 0,
        `${format} read its own corpus entry ${file} and produced neither items nor an error`,
      ).toBe(true);
    }
  });

  it('keeps the corpus and the directory in step, in BOTH directions', () => {
    // Both directions, because they fail differently. An entry naming a file that
    // has been deleted is loud (an ENOENT), but a file dropped into `corpus/` and
    // never listed is SILENT: nothing runs it, and the reason it was added is lost
    // with the person who added it. Comparing the listing against the manifest is
    // the only thing that catches the second one.
    expect([...CORPUS_FILES].sort()).toEqual(CORPUS.map((entry) => entry.file).sort());
    expect(new Set(CORPUS.map((entry) => entry.file)).size).toBe(CORPUS.length);
    for (const entry of CORPUS) {
      expect(() => readCorpus(entry.file), entry.file).not.toThrow();
      // Every entry states WHY it exists. A corpus file with no reason is one
      // nobody can decide about later.
      expect(entry.why.length, `${entry.file} needs a reason`).toBeGreaterThan(40);
    }
  });
});

// ---------------------------------------------------------------------------
// Generated input
// ---------------------------------------------------------------------------

describe('arbitrary bytes, through every parser', () => {
  it.each(FUZZ_FORMATS)('%s never lets an untyped exception escape', (format) => {
    fc.assert(
      fc.property(fc.string({ unit: anyCodeUnit, maxLength: 400 }), (text) => {
        assertParserContract(format, text, 'arbitrary text', mappingFor(format));
      }),
      propertyRun({ numRuns: FUZZ_RUNS }),
    );
  });

  it.each(FUZZ_FORMATS)('%s survives arbitrary bytes that begin like its own format', (format) => {
    // A prefix that steers the parser down its real branch — the Bitwarden
    // parser picks JSON vs CSV on the first non-space character, and the CSV
    // parsers pick columns off the first row — so the random tail is parsed as
    // DATA rather than rejected as an unrecognised file.
    const prefixed = fc
      .tuple(
        fc.constantFrom('{', '[', `${FORMAT_HEADERS[format].join(',')}\n`, '﻿', '\r\n'),
        fc.string({ unit: anyCodeUnit, maxLength: 400 }),
      )
      .map(([prefix, tail]) => prefix + tail);

    fc.assert(
      fc.property(prefixed, (text) => {
        assertParserContract(format, text, 'prefixed arbitrary text', mappingFor(format));
      }),
      propertyRun({ numRuns: FUZZ_RUNS }),
    );
  });
});

describe('structurally valid but hostile documents', () => {
  it.each(FUZZ_FORMATS)('%s clamps every CSV-reachable field to its own schema', (format) => {
    fc.assert(
      fc.property(csvDocument(format), (text) => {
        assertParserContract(format, text, 'a generated CSV document', mappingFor(format));
      }),
      propertyRun({ numRuns: DOCUMENT_RUNS }),
    );
  });

  it('bitwarden clamps every JSON field EXCEPT the eleven the KNOWN DEFECT block names', () => {
    // The name says "except" because the generator draws the card and identity
    // scalars WITHIN their bounds; those eleven are covered by the KNOWN DEFECT
    // block at the foot of this file instead. A name claiming "every field"
    // would be the claim, and a JUnit report is where a future reader meets it.
    fc.assert(
      fc.property(bitwardenDocument, (text) => {
        assertParserContract('bitwarden', text, 'a generated Bitwarden JSON document');
      }),
      propertyRun({ numRuns: DOCUMENT_RUNS }),
    );
  });

  it('a hostile document handed to the WRONG parser still holds the contract', () => {
    // The dropdown mistake, generated rather than corpus-sized: a Bitwarden
    // JSON document read as a CSV, and a CSV read as Bitwarden.
    fc.assert(
      fc.property(
        bitwardenDocument,
        fc.constantFrom(...FUZZ_FORMATS.filter((format) => format !== 'bitwarden')),
        (text, format) => {
          assertParserContract(
            format,
            text,
            'Bitwarden JSON read as another format',
            mappingFor(format),
          );
        },
      ),
      propertyRun({ numRuns: DOCUMENT_RUNS }),
    );
  });
});

// ---------------------------------------------------------------------------
// Size classes: the "never hangs" clause
// ---------------------------------------------------------------------------

/**
 * How termination is checked, and why it is a RATIO rather than a stopwatch.
 *
 * The claim worth gating is a complexity claim: the tokenizer is a single linear
 * pass, so ten times the input costs about ten times the time and never a
 * hundred. A bare wall-clock budget cannot state that. It was measured in one
 * regime — this file alone, 2.5-3.5 s for the million-column row — and asserted
 * in another, because the file also runs inside `test:unit` beside ~115 other
 * client files in a parallel fork pool. A red run there would be attributable to
 * machine load, not to a quadratic tokenizer, and a flaky gate is a bug report
 * about the harness.
 *
 * So the real assertion compares TWO sizes measured back to back in the same
 * process under the same load: a 100,000-column row and a 1,000,000-column row.
 * Linear puts the ratio near 10; quadratic puts it near 100. The threshold sits
 * between them, far from both.
 *
 * The absolute ceilings stay, but only as HANG backstops — deliberately far
 * above any load a machine could plausibly add, because their job is to catch a
 * parser that has stopped making progress at all, not to referee a stopwatch.
 * Vitest's own `testTimeout` and the fuzz gate's 300 s deadline sit behind them.
 */
const WIDE_ROW_HANG_MS = 60_000;
const ROW_BOMB_HANG_MS = 30_000;

/**
 * The ratio that separates linear from quadratic on a 10x input step.
 *
 * MEASURED, per parser, by forcing this assertion red once: 188ms->3644ms,
 * 181->3419, 212->3068, 168->2613, 371->2609, 341->3123, 208->2558 — a spread of
 * 7x to 20x. Not the flat 10x a pure linear pass would give, because the
 * million-column case also allocates a million-element row and a million-key
 * record, and those constants are worse at scale; that is a memory profile, not
 * a complexity class.
 *
 * Forty-five is a little over twice the worst observed value and less than half
 * of the ~100x an accidentally quadratic pass produces on a 10x step, so it sits
 * in the empty band between the two. Both halves are measured back to back in
 * the same process, so machine load moves them together and largely cancels.
 */
const MAX_GROWTH_RATIO = 45;

/**
 * Rows in the repeated-row bomb.
 *
 * Fifty thousand rather than a rounder hundred thousand, and the reason is
 * runtime rather than coverage: this file also runs inside `test:unit`, and the
 * invariant being proved — that the parsers cap NOTHING, so every row survives
 * — is proved exactly as well at 50,000 as at any larger number.
 */
const ROW_BOMB_ROWS = 50_000;

/** A CSV of `columns` columns: one header row and one data row. */
function wideRow(columns: number): string {
  const header = Array.from({ length: columns }, (_, i) => `c${String(i)}`).join(',');
  const row = Array.from({ length: columns }, () => 'v').join(',');
  return `${header}\n${row}`;
}

describe('size classes terminate', () => {
  it.each(FUZZ_FORMATS)(
    '%s stays linear from 100,000 to 1,000,000 columns',
    (format) => {
      const small = Date.now();
      assertParserContract(format, wideRow(100_000), 'a 100,000-column row', mappingFor(format));
      const smallMs = Math.max(Date.now() - small, 1);

      const large = Date.now();
      assertParserContract(
        format,
        wideRow(1_000_000),
        'a 1,000,000-column row',
        mappingFor(format),
      );
      const largeMs = Date.now() - large;

      expect(
        largeMs / smallMs,
        `${format} took ${String(smallMs)}ms on 100,000 columns and ${String(largeMs)}ms on ` +
          `1,000,000 — a 10x input step. A single linear pass lands near 10x; a quadratic one ` +
          `lands near 100x.`,
      ).toBeLessThan(MAX_GROWTH_RATIO);
      expect(largeMs, `${format} did not finish a one-million-column row`).toBeLessThan(
        WIDE_ROW_HANG_MS,
      );
    },
    180_000,
  );

  it.each(FUZZ_FORMATS)(
    '%s parses a repeated-row bomb within its budget, losing no row',
    (format) => {
      const headers = FORMAT_HEADERS[format].join(',');
      const cells = FORMAT_HEADERS[format].map(() => 'v').join(',');
      const text = `${headers}\n${`${cells}\n`.repeat(ROW_BOMB_ROWS)}`;
      const started = Date.now();
      const items = assertParserContract(
        format,
        text,
        `a ${String(ROW_BOMB_ROWS)}-row bomb`,
        mappingFor(format),
      );
      expect(
        Date.now() - started,
        `${format} did not finish a ${String(ROW_BOMB_ROWS)}-row file`,
      ).toBeLessThan(ROW_BOMB_HANG_MS);

      // EVERY row, unconditionally. No parser caps the row count — the cap lives
      // further down the pipeline, at MAX_ITEMS_PER_USER on the server — and all
      // seven of these formats accept a row of `v` cells. Guarding this on
      // `items.length > 0` would let the WORST truncation, to zero rows, pass:
      // a "skip a row whose URL does not parse" filter added to any parser drops
      // all 50,000 and the test would still be green.
      expect(items, `${format} refused a file of ordinary rows`).not.toBeNull();
      expect(items).toHaveLength(ROW_BOMB_ROWS);
    },
    180_000,
  );
});

// ---------------------------------------------------------------------------
// Regressions: every crash this suite found, with its minimized input
// ---------------------------------------------------------------------------

describe('REGRESSION: a malformed member of a Bitwarden `items` array', () => {
  // Found by the arbitrary-JSON property. `parseBitwardenJson` casts
  // `root.items` to `Record<string, unknown>[]` and then reads `it.name`, so a
  // `null` member throws a TypeError out of the raw parser. It is NOT a product
  // crash — `parseImportData`'s catch converts it — and these two tests pin
  // both halves, because the wrapper is the entire reason the cast is safe.
  const text = readCorpus('bitwarden-null-item.json');

  it('throws out of the raw parser, which is what the wrapper exists to contain', () => {
    expect(() => parseBitwarden(text)).toThrow(TypeError);
  });

  it('reaches the caller as a typed ImportParseError naming the format', () => {
    expect(() => parseImportData('bitwarden', text)).toThrow(ImportParseError);
    expect(() => parseImportData('bitwarden', text)).toThrow(/Bitwarden/);
  });

  it('refuses the whole file rather than returning the items either side of it', () => {
    // Deliberate, and worth pinning: a partial import that reported success
    // would be indistinguishable from a complete one. The file names a
    // "survivor" item precisely so a future change that starts skipping bad
    // rows silently turns this red instead of shipping unnoticed.
    expect(text).toContain('survivor');
    expect(() => parseImportData('bitwarden', text)).toThrow(ImportParseError);
  });
});

describe('REGRESSION: a header named __proto__ resolves to the prototype, not a cell', () => {
  // `rowsToRecords` builds records as plain object literals, so
  // `record['__proto__'] = value` hits the INHERITED ACCESSOR: nothing is
  // polluted (the setter ignores a string), no own property is created, and the
  // key reads back as an OBJECT. `parseGenericCsv` is the one parser a user can
  // point at such a header, and its `typeof value === 'string'` guard is what
  // stops a string method being called on `Object.prototype`.
  //
  // `constructor` is deliberately in the same fixture as the CONTRAST: it is an
  // ordinary writable data property, so assignment DOES create an own property
  // and the cell reads back as the string it was. Only `__proto__` is special,
  // and a test that treated the two alike would be asserting the wrong rule.
  const text = readCorpus('header-edge.csv');

  it('drops the __proto__ column and keeps an ordinary inherited-name column', () => {
    const items = parseImportData('csv', text, {
      ['__proto__']: 'name',
      title: 'name',
      constructor: 'username',
      website: 'url',
      password: 'password',
    }).items;
    expect(items).toHaveLength(1);
    // `__proto__` mapped to `name` contributed nothing, so the `title` column
    // that follows it in the mapping supplied the name instead.
    expect(items[0]!.name).toBe('T');
    // …while `constructor` behaved like any other column.
    expect(items[0]!.data.username).toBe('polluted');
  });

  it('leaves Object.prototype untouched', () => {
    parseImportData('csv', text, { ['__proto__']: 'name' });
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});

describe('REGRESSION: one character past every CSV-reachable bound', () => {
  const text = readCorpus('one-past-bounds.csv');

  it('clamps every field so the login survives validation whole', () => {
    const items = parseImportData('lastpass', text).items;
    expect(items).toHaveLength(1);
    const item = items[0]!;
    expect(vaultItemDataSchemas.login.safeParse(item.data).success).toBe(true);

    // The password is the thing this whole clamp layer exists to protect, and
    // it is the one field whose overflow is NEVER folded into notes.
    const data = item.data as { password: string; notes?: string; uris: { uri: string }[] };
    expect(data.password.startsWith('p')).toBe(true);
    expect(data.notes ?? '').not.toContain(data.password);

    // The URI bound is measured BEFORE the scheme the schema prepends, which is
    // the defect `clampUri` exists for: a value that validated on the way in and
    // failed on the way back out left a permanently undecodable item.
    expect(data.uris[0]!.uri.length).toBeLessThanOrEqual(MAX_URI_LENGTH);
  });

  it('caps the tag list rather than dropping the item that carries it', () => {
    const items = parseImportData('lastpass', text).items;
    for (const tag of items[0]!.tags) expect(tag.length).toBeLessThanOrEqual(MAX_TAG_LENGTH);
  });
});

describe('REGRESSION: a source with more URIs and custom fields than an item may hold', () => {
  // The caps are in `buildLogin` and `clampCustomFields`, and both are the
  // difference between an item arriving trimmed and an item not arriving at all.
  // The witness is a corpus entry rather than an inline literal, so the corpus
  // loop above runs it through all seven parsers too.
  const overflowing = readCorpus('bitwarden-overfull-lists.json');

  it('trims both lists to the cap and keeps the item', () => {
    const items = parseImportData('bitwarden', overflowing).items;
    expect(items).toHaveLength(1);
    const data = items[0]!.data as {
      uris: unknown[];
      customFields: { name: string }[];
      notes?: string;
    };
    expect(data.uris).toHaveLength(MAX_URIS_PER_ITEM);
    expect(data.customFields).toHaveLength(MAX_CUSTOM_FIELDS_PER_ITEM);
    expect(vaultItemDataSchemas.login.safeParse(items[0]!.data).success).toBe(true);
    // The dropped field is reported in notes, not discarded in silence.
    expect(data.notes ?? '').toContain('additional custom field');
  });
});

describe('REGRESSION: an over-long postal address does not sink the identity', () => {
  // `clampAddress` is the choke point every card and identity passes through,
  // and Bitwarden bounds none of these columns in its own export.
  const text = readCorpus('bitwarden-scalar-bounds.json');

  it('clamps each address line and preserves the tail in notes', () => {
    const oversized = JSON.stringify({
      items: [
        {
          type: 4,
          name: 'over-long address',
          identity: {
            firstName: 'A',
            address1: 'a'.repeat(MAX_ADDRESS_STREET_LENGTH + 1),
            postalCode: 'z'.repeat(MAX_ADDRESS_ZIP_LENGTH + 1),
          },
        },
      ],
    });
    const items = parseImportData('bitwarden', oversized).items;
    expect(items).toHaveLength(1);
    expect(vaultItemDataSchemas.identity.safeParse(items[0]!.data).success).toBe(true);
    const data = items[0]!.data as { address: { street: string; zip: string }; notes?: string };
    expect(data.address.street).toHaveLength(MAX_ADDRESS_STREET_LENGTH);
    expect(data.address.zip).toHaveLength(MAX_ADDRESS_ZIP_LENGTH);
    expect(data.notes ?? '').toContain('truncated');
  });

  it('keeps the scalar-bounds corpus entry as the witness for the deferred defect', () => {
    // Pinned here so the corpus file cannot be quietly emptied: the KNOWN DEFECT
    // block below is about the fields this file carries.
    expect(text).toContain('card scalars');
    expect(text).toContain('identity scalars');
  });
});

// ---------------------------------------------------------------------------
// KNOWN DEFECT — recorded, pinned, and deliberately NOT fixed here
// ---------------------------------------------------------------------------

/**
 * Eleven scalar fields on the Bitwarden JSON path have no clamp, so a source
 * value one character too long discards the WHOLE card or identity at
 * validation.
 *
 * `itemBuilders.ts` says as much in its own words — "Other scalar columns (card
 * number, identity name, …) are still left to the parsers, which read them from
 * bounded source fields" — and that assumption is what a hostile or simply
 * unusual export breaks. Bitwarden bounds none of these columns. The failure is
 * the exact class this suite exists to catch: not a crash, not corruption, but a
 * card that never arrives and a report that says one item was skipped.
 *
 * It is NOT fixed here. Changing which values a parser accepts is production
 * behavior, and Section 0 of the plan allows that only in a task explicitly
 * designated a fix. So it is pinned in both directions instead — at the bound
 * the item survives, one past it the item is discarded — which makes the fix
 * visible when it lands: each row below turns red and is rewritten to assert
 * the clamp.
 *
 * **The fix, when it lands:** route these ten through `clampWithOverflow` in
 * `clampNotesAndFields`, exactly as the address fields already are, folding each
 * tail into `notes` — with the one exception the module already documents, that
 * a card `number` and `cvv` are clamped but never copied into notes, because
 * notes travel verbatim into the Chrome CSV `note` column.
 *
 * Recorded in `.testfortress/phase-logs/phase-10-parser-fuzz.md` and appended to
 * Phase 20 as a fix task.
 */
describe('KNOWN DEFECT: unclamped card and identity scalars discard the whole item', () => {
  interface Unclamped {
    field: string;
    itemType: 'card' | 'identity';
    bound: number;
    /** Builds a Bitwarden JSON document whose one item carries a value of `length`. */
    document: (length: number) => string;
  }

  const card = (field: string, length: number): string =>
    JSON.stringify({
      items: [{ type: 3, name: 'c', card: { [field]: 'x'.repeat(length) } }],
    });
  const identity = (field: string, length: number): string =>
    JSON.stringify({
      items: [{ type: 4, name: 'i', identity: { [field]: 'x'.repeat(length) } }],
    });

  const UNCLAMPED: Unclamped[] = [
    {
      field: 'card.cardholderName',
      itemType: 'card',
      bound: MAX_CARD_CARDHOLDER_NAME_LENGTH,
      document: (n) => card('cardholderName', n),
    },
    { field: 'card.number', itemType: 'card', bound: 30, document: (n) => card('number', n) },
    { field: 'card.expMonth', itemType: 'card', bound: 2, document: (n) => card('expMonth', n) },
    { field: 'card.expYear', itemType: 'card', bound: 4, document: (n) => card('expYear', n) },
    { field: 'card.cvv', itemType: 'card', bound: 4, document: (n) => card('code', n) },
    {
      field: 'card.brand',
      itemType: 'card',
      bound: MAX_CARD_BRAND_LENGTH,
      document: (n) => card('brand', n),
    },
    {
      field: 'identity.firstName',
      itemType: 'identity',
      bound: MAX_IDENTITY_NAME_LENGTH,
      document: (n) => identity('firstName', n),
    },
    {
      // `lastName` shares `firstName`'s bound and `firstName`'s lack of a clamp.
      // It is a separate row rather than a note on the `firstName` one because
      // this table is the ONLY mechanism that can detect the defect shrinking:
      // `knownInvalidPaths` is permissive-only (it excuses a failure, it never
      // requires one), so a field listed there but missing here would keep being
      // excused forever after Task 20.5 clamps its neighbours.
      field: 'identity.lastName',
      itemType: 'identity',
      bound: MAX_IDENTITY_NAME_LENGTH,
      document: (n) => identity('lastName', n),
    },
    {
      field: 'identity.company',
      itemType: 'identity',
      bound: MAX_IDENTITY_COMPANY_LENGTH,
      document: (n) => identity('company', n),
    },
    {
      field: 'identity.ssn',
      itemType: 'identity',
      bound: MAX_IDENTITY_SSN_LENGTH,
      document: (n) => identity('ssn', n),
    },
    {
      field: 'identity.passport',
      itemType: 'identity',
      bound: MAX_IDENTITY_PASSPORT_LENGTH,
      document: (n) => identity('passportNumber', n),
    },
  ];

  it.each(UNCLAMPED)(
    '$field survives AT its bound and is discarded ONE past it (today, wrongly)',
    ({ itemType, bound, document }) => {
      const atBound = parseImportData('bitwarden', document(bound)).items;
      expect(atBound).toHaveLength(1);
      expect(vaultItemDataSchemas[itemType].safeParse(atBound[0]!.data).success).toBe(true);

      const past = parseImportData('bitwarden', document(bound + 1)).items;
      expect(past).toHaveLength(1);
      // TODAY's behavior, asserted so the fix is a visible, deliberate change.
      expect(vaultItemDataSchemas[itemType].safeParse(past[0]!.data).success).toBe(false);
    },
  );

  it('names a bound for every unclamped field, so the list cannot quietly shrink', () => {
    // A row deleted from the table is a defect that stops being recorded. Both
    // the count and the field names are pinned; the count alone would be
    // satisfied by swapping one field for another.
    expect(UNCLAMPED.map((entry) => entry.field).sort()).toEqual([
      'card.brand',
      'card.cardholderName',
      'card.cvv',
      'card.expMonth',
      'card.expYear',
      'card.number',
      'identity.company',
      'identity.firstName',
      'identity.lastName',
      'identity.passport',
      'identity.ssn',
    ]);
    // Both directions: every path the corpus entry is allowed to fail on must
    // have a row here. A field listed as known-invalid but never pinned at its
    // bound is a defect that is excused and not recorded — which is exactly how
    // `identity.lastName` was missed in the first draft of this block.
    const fields = new Set(UNCLAMPED.map((entry) => entry.field.split('.')[1]));
    const excused = CORPUS.find(
      (entry) => entry.file === 'bitwarden-scalar-bounds.json',
    )?.knownInvalidPaths;
    expect(excused, 'the witness entry must carry the excused list').toBeDefined();
    for (const path of excused ?? []) {
      expect(fields, `${path} is excused by the corpus but pinned by no row`).toContain(path);
    }
  });

  it('is confined to the Bitwarden JSON path — no CSV parser can reach these fields', () => {
    // Every other parser produces logins and notes only, whose fields ARE
    // clamped. Stated as a test because it is what bounds the defect's blast
    // radius, and because a future parser that emits a card would widen it.
    for (const format of FUZZ_FORMATS) {
      if (format === 'bitwarden') continue;
      const document = toCsv(FORMAT_HEADERS[format], [
        FORMAT_HEADERS[format].map(() => 'x'.repeat(400)),
      ]);
      const items = parseImportData(format, document, mappingFor(format)).items;
      for (const item of items) {
        expect(['login', 'note'], `${format} produced a ${item.itemType}`).toContain(item.itemType);
        expect(vaultItemDataSchemas[item.itemType].safeParse(item.data).success).toBe(true);
      }
    }
  });
});
