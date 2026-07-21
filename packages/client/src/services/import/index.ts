import { rowsToRecords } from './csv';
import { parseFirefox } from './parsers/firefox';
import { parseChrome } from './parsers/chrome';
import { parseLastpass } from './parsers/lastpass';
import { parseKeepass } from './parsers/keepass';
import { parseOnepassword } from './parsers/onepassword';
import { parseGenericCsv } from './parsers/genericCsv';
import { parseBitwarden } from './parsers/bitwarden';
import type { CsvFieldMapping, ImportSourceFormat, ParseResult } from './types';

export type { CsvFieldMapping, ImportSourceFormat, ParsedImportItem, ParseResult } from './types';
export { buildEncryptedImportItems } from './encrypt';
export type { EncryptedImportItem, BuildResult } from './encrypt';
export { chunkBySize } from './batch';

/** Thrown when a source file cannot be parsed into vault items. */
export class ImportParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ImportParseError';
  }
}

export interface ImportFormatMeta {
  value: ImportSourceFormat;
  label: string;
  /** Whether the generic column-mapping UI applies. */
  requiresMapping?: boolean;
}

/** Registry powering the import format dropdown (order = display order). */
export const IMPORT_FORMATS: ImportFormatMeta[] = [
  { value: 'json', label: 'H-Vault (.enc / JSON)' },
  { value: 'bitwarden', label: 'Bitwarden (JSON or CSV)' },
  { value: 'lastpass', label: 'LastPass (CSV)' },
  { value: 'keepass', label: 'KeePass (CSV)' },
  { value: 'chrome', label: 'Chrome / Edge (CSV)' },
  { value: 'firefox', label: 'Firefox (CSV)' },
  { value: 'onepassword', label: '1Password (CSV)' },
  { value: 'csv', label: 'Generic CSV (map columns)', requiresMapping: true },
];

const FRIENDLY_NAMES: Record<ImportSourceFormat, string> = {
  bitwarden: 'Bitwarden',
  lastpass: 'LastPass',
  keepass: 'KeePass',
  chrome: 'Chrome/Edge',
  firefox: 'Firefox',
  onepassword: '1Password',
  csv: 'CSV',
  json: 'H-Vault',
};

/**
 * Parse a source file (any non-native format) into vault items. The native
 * H-Vault `json` format is intentionally NOT handled here — those items are
 * already encrypted and are validated/decrypted directly by the caller.
 *
 * @throws {ImportParseError} with a user-friendly message on malformed input.
 */
export function parseImportData(
  format: Exclude<ImportSourceFormat, 'json'>,
  text: string,
  mapping?: CsvFieldMapping,
): ParseResult {
  try {
    switch (format) {
      case 'firefox':
        return { items: parseFirefox(text), warnings: [] };
      case 'chrome':
        return { items: parseChrome(text), warnings: [] };
      case 'lastpass':
        return { items: parseLastpass(text), warnings: [] };
      case 'keepass':
        return { items: parseKeepass(text), warnings: [] };
      case 'onepassword':
        return { items: parseOnepassword(text), warnings: [] };
      case 'bitwarden':
        return { items: parseBitwarden(text), warnings: [] };
      case 'csv':
        return { items: parseGenericCsv(text, mapping ?? {}), warnings: [] };
      default: {
        // Exhaustiveness guard.
        const never: never = format;
        throw new ImportParseError(`Unsupported import format: ${String(never)}`);
      }
    }
  } catch (err) {
    if (err instanceof ImportParseError) throw err;
    throw new ImportParseError(
      `Unable to parse the ${FRIENDLY_NAMES[format]} file. Please confirm the file matches the selected format.`,
    );
  }
}

/**
 * Guess the source format of a CSV file from its header row, so the UI can
 * pre-select a sensible format. Returns `'csv'` (generic) when no signature
 * matches.
 */
export function detectCsvFormat(text: string): ImportSourceFormat {
  const { headers } = rowsToRecords(text);
  const set = new Set(headers.map((h) => h.trim().toLowerCase()));
  const has = (...names: string[]): boolean => names.every((n) => set.has(n));
  const any = (...names: string[]): boolean => names.some((n) => set.has(n));

  if (any('login_password', 'login_username', 'login_uri')) return 'bitwarden';
  if (has('url', 'username', 'password') && any('grouping', 'extra')) return 'lastpass';
  if (
    has('url', 'username', 'password') &&
    any('httprealm', 'formactionorigin', 'guid', 'timepasswordchanged')
  ) {
    return 'firefox';
  }
  if (has('title', 'password') && any('group', 'notes', 'url')) return 'keepass';
  if (any('otpauth') || (has('title', 'password') && any('website'))) return 'onepassword';
  if (has('name', 'url', 'username', 'password')) return 'chrome';
  return 'csv';
}
