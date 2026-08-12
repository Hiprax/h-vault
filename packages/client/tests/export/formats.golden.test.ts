/**
 * The export wire formats, pinned byte for byte.
 *
 * `services/export/formats/*` writes files that ANOTHER PASSWORD MANAGER reads.
 * The header names, the column order, the numeric type codes, the null-versus-
 * empty choices and the CRLF terminators are not internal details — they are the
 * contract with Bitwarden and with Chrome/Edge, and a user only discovers a
 * silent change to one of them at the moment they are leaving, when the file
 * they exported does not import.
 *
 * The existing per-serializer suites assert PROPERTIES: that the header matches
 * a literal, that a backup code never reaches the note column, that a round trip
 * preserves a username. Those are worth having and they are not enough: nothing
 * there notices a reordered row, a `null` that became `""`, a folder id scheme
 * that changed, or a field that quietly stopped being emitted. A whole-document
 * comparison notices all of it at once.
 *
 * ---------------------------------------------------------------------------
 * PROVENANCE IS MANDATORY, AND IS WHY THE SIDECARS EXIST
 * ---------------------------------------------------------------------------
 *
 * A golden recorded from unverified output promotes today's bug into tomorrow's
 * specification. So each golden carries a provenance note naming who checked it
 * against the target application's documented import format, on what date, and
 * against which source — plus, explicitly, what was NOT verified.
 *
 * The note is a SIDECAR file rather than a header comment inside the golden, for
 * the reason a byte-exact fixture always runs into: neither format has comments.
 * A `#` line in a CSV is a header row, and JSON has no comment syntax at all —
 * either would change the very bytes the assertion compares. The first `describe`
 * below makes the sidecar mandatory: a golden without one, or with one missing a
 * verifier, a date, a source or a stated limit, fails this suite.
 *
 * ---------------------------------------------------------------------------
 * THE SEAM
 * ---------------------------------------------------------------------------
 *
 * The real serializers and the real import parsers, with nothing mocked. The
 * INPUT is a hand-written `PortableItem[]` rather than a decrypted vault: these
 * goldens are about the serializers, which is where the third-party contract
 * lives, and `portableItem.test.ts` already covers the normalization that
 * produces them. A literal fixture is data, not a stub.
 *
 * The goldens are never written by this suite. They were recorded once, by hand,
 * reviewed line by line against the sources named in the sidecars, and are only
 * ever COMPARED here — no `--update`, no snapshot-regeneration flag. Changing one
 * means editing the file and saying, in the review, why each changed byte is
 * correct.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toBitwardenJson } from '../../src/services/export/formats/bitwardenJson';
import { toBitwardenCsv } from '../../src/services/export/formats/bitwardenCsv';
import { toChromeCsv } from '../../src/services/export/formats/chromeCsv';
import type { PortableItem } from '../../src/services/export/portableItem';
import { parseCsv } from '../../src/services/import/csv';
import { parseImportData } from '../../src/services/import';
import { computeItemIdentity, normalizeHost } from '../../src/services/import/identity';

const GOLDEN_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'goldens');

const readGolden = (file: string): string => readFileSync(path.join(GOLDEN_DIR, file), 'utf8');

// ---------------------------------------------------------------------------
// The fixture: one item of each of the five types, plus a folder
// ---------------------------------------------------------------------------

/**
 * Deliberately awkward values, each chosen for a rule it exercises:
 *
 *   - the login password carries a comma, a double quote, spaces and a TRAILING
 *     space, so the CSV goldens pin all three of `toCsv`'s quoting rules at once
 *     (and the trailing space is the one a naive writer silently trims);
 *   - the note body carries a newline, which must survive inside a quoted cell;
 *   - the folder path is nested, so the Bitwarden JSON folder record and the CSV
 *     `folder` column both show how a path is carried;
 *   - the login has backup codes and a custom field, which compete for the
 *     `fields` slot and have a documented order;
 *   - the identity has delivery notes, which have no Bitwarden field at all and
 *     travel as a named custom field;
 *   - the card has a billing address, which has no Bitwarden card field and is
 *     folded into notes;
 *   - the secret has an expiry, which is folded into a secure note.
 */
const FIXTURE: PortableItem[] = [
  {
    type: 'login',
    name: 'Example Mail',
    folderPath: 'Work/Accounts',
    favorite: true,
    notes: 'recovery email is example-alt@example.com',
    tags: ['work', 'email'],
    login: { username: 'alice@example.com', password: 'p@ss, "quoted" and spaced ' },
    uris: ['https://mail.example.com/login', 'https://example.com'],
    totp: 'otpauth://totp/Example%20Mail?secret=JBSWY3DPEHPK3PXP&issuer=Example',
    backupCodes: ['aaaa-1111', 'bbbb-2222'],
    customFields: [{ name: 'Security question', value: 'first pet', type: 'hidden' }],
    passwordHistory: [{ password: 'previous-password', changedAt: '2026-01-02T03:04:05.000Z' }],
  },
  {
    type: 'note',
    name: 'Wi-Fi',
    folderPath: 'Work',
    favorite: false,
    notes: 'ssid: example-net\npassphrase: hunter-two',
    tags: [],
  },
  {
    type: 'card',
    name: 'Example Card',
    folderPath: '',
    favorite: false,
    notes: 'expires next year',
    tags: [],
    card: {
      cardholderName: 'Alice Example',
      number: '4111111111111111',
      expMonth: '04',
      expYear: '2030',
      cvv: '123',
      brand: 'Visa',
      billingAddress: {
        street: '1 Example Street',
        street2: 'Flat 2',
        city: 'Exampleton',
        state: 'EX',
        zip: 'EX1 2AB',
        country: 'Exampleland',
      },
    },
  },
  {
    type: 'identity',
    name: 'Alice Example',
    folderPath: 'Work/Accounts',
    favorite: false,
    notes: '',
    tags: [],
    identity: {
      firstName: 'Alice',
      lastName: 'Example',
      email: 'alice@example.com',
      phone: '+44 20 7946 0000',
      company: 'Example Ltd',
      ssn: 'AA 12 34 56 A',
      passport: 'X1234567',
      address: {
        street: '1 Example Street',
        street2: 'Flat 2',
        city: 'Exampleton',
        state: 'EX',
        zip: 'EX1 2AB',
        country: 'Exampleland',
        deliveryNotes: 'leave with the concierge',
      },
    },
  },
  {
    type: 'secret',
    name: 'Deploy Token',
    folderPath: '',
    favorite: false,
    notes: '',
    tags: [],
    secret: {
      value: 'example-deploy-token-value',
      description: 'CI deploy token for the staging cluster',
      expiresAt: '2027-03-01',
    },
  },
];

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

interface Golden {
  /** The golden file itself. */
  file: string;
  /** The serializer under test. */
  serialize: () => { content: string; omittedCount: number };
  /** How many fixture items the format cannot represent. */
  omittedCount: number;
  /** The exact first line, as a literal — see `assertHeader`. */
  header?: string;
}

const GOLDENS: Golden[] = [
  {
    file: 'bitwarden-json.json',
    serialize: () => toBitwardenJson(FIXTURE),
    omittedCount: 0,
  },
  {
    file: 'bitwarden-csv.csv',
    serialize: () => toBitwardenCsv(FIXTURE),
    // card, identity and secret have no row shape in Bitwarden CSV.
    omittedCount: 3,
    header:
      'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
  },
  {
    file: 'chrome-csv.csv',
    serialize: () => toChromeCsv(FIXTURE),
    // Everything but the login.
    omittedCount: 4,
    header: 'name,url,username,password,note',
  },
];

/** The fields a sidecar must carry for the golden beside it to count as verified. */
const PROVENANCE_FIELDS = ['Verified-By:', 'Verified-On:', 'Source:', 'Checked:', 'Not-verified:'];

describe('every golden carries a provenance note', () => {
  it.each(GOLDENS)('$file has a sidecar naming a verifier, a date and a source', ({ file }) => {
    const note = readGolden(`${file}.provenance.md`);
    for (const field of PROVENANCE_FIELDS) {
      expect(note, `${file}.provenance.md is missing ${field}`).toContain(field);
    }
    // An ISO date, so "recently verified" is a question anyone can answer.
    expect(note, `${file}.provenance.md has no ISO Verified-On date`).toMatch(
      /Verified-On:\s*\d{4}-\d{2}-\d{2}/,
    );
    // A real source, not a shrug.
    expect(note, `${file}.provenance.md cites no source URL`).toMatch(/Source:\s*https?:\/\/\S+/);
    // `Not-verified:` must actually say something. A golden whose limits are
    // blank is a golden claiming more than anyone checked.
    const limits = /Not-verified:\s*(.+)/.exec(note)?.[1] ?? '';
    expect(limits.trim().length, `${file}.provenance.md declares no limits`).toBeGreaterThan(20);
  });
});

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

describe('export formats match their goldens byte for byte', () => {
  it.each(GOLDENS)('$file', ({ file, serialize, omittedCount }) => {
    const { content, omittedCount: omitted } = serialize();
    const golden = readGolden(file);

    // The whole document, not a shape of it. A reordered column, a renamed key,
    // a `null` that became `""` and a lost CRLF all land here.
    expect(
      content,
      `${file} drifted from its golden. This file is what another password ` +
        `manager parses, so review every changed byte against the source named in ` +
        `${file}.provenance.md before touching the golden.`,
    ).toBe(golden);
    expect(omitted, `${file}: omittedCount`).toBe(omittedCount);
  });

  it.each(GOLDENS.filter((golden) => golden.header !== undefined))(
    '$file starts with the exact documented header',
    ({ file, serialize, header }) => {
      // BOTH sides, and that is the point: the golden alone would only prove the
      // committed file has not been hand-edited, and the serializer alone would
      // not notice a golden that had. Stated as a literal as well as inside the
      // golden because the two fail differently — the byte comparison says
      // "something moved", this says WHICH line, and it is the line a migrating
      // user's other app reads first.
      expect(serialize().content.split('\r\n')[0], `${file}: the serializer's header`).toBe(header);
      expect(readGolden(file).split('\r\n')[0], `${file}: the golden's header`).toBe(header);
    },
  );

  it('terminates every CSV row with CRLF, as RFC 4180 requires', () => {
    // Pinned separately from the byte comparison because a checkout that
    // normalized line endings would make the golden itself wrong — silently, and
    // in a way that looks like a serializer change. `.gitattributes` marks this
    // directory `-text` for exactly that reason.
    //
    // A bare LF is NOT forbidden outright: the Bitwarden golden carries one
    // INSIDE a quoted cell (the `fields` blob separates its entries with a
    // newline, and the secure note's body has one of its own), which is exactly
    // what RFC 4180 quoting is for. What must not appear is a lone CR, and every
    // ROW terminator must be CRLF — which is what parsing the golden with the
    // real tokenizer and counting rows actually proves.
    for (const { file } of GOLDENS.filter((golden) => golden.file.endsWith('.csv'))) {
      const golden = readGolden(file);
      expect(golden, `${file} lost its CRLF terminators`).toContain('\r\n');
      expect(golden.replace(/\r\n/g, ''), `${file} contains a lone CR`).not.toContain('\r');
      // The row count a real consumer sees: the header plus one row per item the
      // format can carry. `parseCsv` is the repository's own RFC-4180 tokenizer,
      // so this also proves the golden is well-formed CSV rather than merely a
      // string that happens to contain commas.
      const rows = parseCsv(golden);
      const expected = 1 + (FIXTURE.length - GOLDENS.find((g) => g.file === file)!.omittedCount);
      expect(rows, `${file}: row count`).toHaveLength(expected);
      expect(rows[0], `${file}: header cells`).toEqual(
        GOLDENS.find((g) => g.file === file)!.header!.split(','),
      );
    }
  });

  it('emits the JSON golden as an object with folders first, then items', () => {
    // The two top-level keys and their order are part of what Bitwarden's
    // importer reads, and `JSON.stringify` emits insertion order.
    const parsed = JSON.parse(readGolden('bitwarden-json.json')) as Record<string, unknown>;
    expect(Object.keys(parsed)).toEqual(['folders', 'items']);
    // An individual-vault export carries no `collections` key; emitting one makes
    // Bitwarden treat the file as an organization export.
    expect(parsed).not.toHaveProperty('collections');
  });
});

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/**
 * The logical identity the fixture's login must keep through any format that can
 * carry a login at all.
 *
 * Computed with the REAL `computeItemIdentity` over the values the fixture
 * declares, rather than restated as a string: the key's shape is that function's
 * business, and a test that hard-coded `login\0mail.example.com\0alice@…` would
 * pass against an identity function that had stopped normalizing at all.
 */
async function expectedLoginIdentity(): Promise<string> {
  const login = FIXTURE[0]!;
  return computeItemIdentity({
    itemType: 'login',
    name: login.name,
    data: {
      username: login.login!.username,
      password: login.login!.password,
      uris: [{ uri: login.uris![0]!, match: 'domain' }],
    },
  });
}

describe('import(export(items)) keeps the same logical items', () => {
  /**
   * Parsed from the SERIALIZER's live output, never from the golden file.
   *
   * The distinction is load-bearing and was measured: with the round trip driven
   * from the committed bytes, swapping two columns in a serializer left every
   * round-trip assertion green — the golden had not changed, so nothing here was
   * looking at the change. The byte comparison above is what ties the live output
   * to the golden; these assertions have to exercise the live output or they are
   * testing the fixture.
   */
  const ROUND_TRIPPABLE = [
    {
      file: 'bitwarden-json.json',
      format: 'bitwarden' as const,
      serialize: () => toBitwardenJson(FIXTURE),
    },
    {
      file: 'bitwarden-csv.csv',
      format: 'bitwarden' as const,
      serialize: () => toBitwardenCsv(FIXTURE),
    },
    { file: 'chrome-csv.csv', format: 'chrome' as const, serialize: () => toChromeCsv(FIXTURE) },
  ];

  it.each(ROUND_TRIPPABLE)(
    '$file re-imports the login as the SAME logical item',
    async ({ file, format, serialize }) => {
      const { items } = parseImportData(format, serialize().content);
      const logins = items.filter((item) => item.itemType === 'login');
      expect(logins.length, `${file} lost the login entirely`).toBeGreaterThan(0);

      const keys = await Promise.all(
        logins.map((item) =>
          computeItemIdentity({ itemType: 'login', name: item.name, data: item.data }),
        ),
      );
      expect(
        keys,
        `${file}: the re-imported login does not match the original, so re-importing an ` +
          `export would INSERT a duplicate instead of matching the item it came from`,
      ).toContain(await expectedLoginIdentity());
    },
  );

  it.each(ROUND_TRIPPABLE)(
    '$file re-imports to a stable set of identity keys',
    async ({ format, serialize }) => {
      // Identity is a hash of canonicalized content, so this is what makes
      // "importing the same file twice changes nothing" true rather than hoped for.
      const keysOf = async (): Promise<string[]> => {
        const { items } = parseImportData(format, serialize().content);
        return Promise.all(
          items.map((item) =>
            computeItemIdentity({ itemType: item.itemType, name: item.name, data: item.data }),
          ),
        );
      };
      expect(await keysOf()).toEqual(await keysOf());
    },
  );

  it('carries every item type through the Bitwarden JSON round trip', async () => {
    // The one format that claims to omit nothing. `secret` has no Bitwarden type,
    // so it comes back as a note — a documented, one-way mapping, asserted here
    // so it stays deliberate.
    const { items } = parseImportData('bitwarden', toBitwardenJson(FIXTURE).content);
    const byType = items.reduce<Record<string, number>>((counts, item) => {
      counts[item.itemType] = (counts[item.itemType] ?? 0) + 1;
      return counts;
    }, {});
    expect(byType).toEqual({ login: 1, note: 2, card: 1, identity: 1 });

    const identity = items.find((item) => item.itemType === 'identity')!;
    const address = (identity.data as { address?: { deliveryNotes?: string } }).address;
    // Delivery notes have no Bitwarden field; they travel as a named custom
    // field and are hoisted back into the address on the way in. That hoist is
    // the only reason the round trip is lossless for this field.
    expect(address?.deliveryNotes).toBe('leave with the concierge');
  });

  it('keeps the login on the host its first URI names, through every format', () => {
    // The logical key is host + username, so the HOST is the half a serializer
    // can break by reordering or truncating the URI list.
    for (const { file, format, serialize } of ROUND_TRIPPABLE) {
      const { items } = parseImportData(format, serialize().content);
      const login = items.find((item) => item.itemType === 'login')!;
      const uris = (login.data as { uris: { uri: string }[] }).uris;
      expect(normalizeHost(uris[0]!.uri), `${file}: the first URI's host moved`).toBe(
        'mail.example.com',
      );
    }
  });

  it('never carries a recovery code into the Chrome note column', () => {
    // The loss note promises the codes are absent, and `notes` travels verbatim
    // into that cell — so this is the one place a folding change would leak a
    // secret into a plaintext file the user is about to hand to a browser.
    const chrome = toChromeCsv(FIXTURE).content;
    for (const code of FIXTURE[0]!.backupCodes!) {
      expect(chrome, 'a recovery code reached the Chrome CSV').not.toContain(code);
    }
    expect(chrome).not.toContain('Backup Codes');
  });
});
