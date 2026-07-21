import type { ItemType } from '@hvault/shared';

/**
 * A source format the importer can convert into H-Vault vault items.
 *
 * `json` is the native H-Vault export (already-encrypted items — handled
 * specially, never re-parsed here). `csv` is the generic column-mapping path.
 * The remainder are password-manager / browser exports with dedicated parsers.
 */
export type ImportSourceFormat =
  'bitwarden' | 'lastpass' | 'keepass' | 'chrome' | 'firefox' | 'onepassword' | 'csv' | 'json';

/**
 * A single vault item parsed from a source file, BEFORE encryption.
 *
 * `data` is a loose object; it is validated (and stripped/defaulted) against the
 * shared `vaultItemDataSchemas[itemType]` during the encryption step, so parsers
 * may emit minimal objects and rely on schema defaults.
 */
export interface ParsedImportItem {
  itemType: ItemType;
  name: string;
  data: Record<string, unknown>;
  tags: string[];
  favorite: boolean;
}

/** Result of parsing a source file: the items plus any non-fatal warnings. */
export interface ParseResult {
  items: ParsedImportItem[];
  warnings: string[];
}

/** Column-name → H-Vault field mapping used by the generic CSV path. */
export type CsvFieldMapping = Record<string, string>;
