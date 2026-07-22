import type { IPasswordHistoryEntry, ItemType } from '@hvault/shared';

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

/**
 * The six ciphertext fields of a row that is ALREADY encrypted under the
 * CURRENT vault key — i.e. a native H-Vault export being re-imported.
 *
 * Such a row is decrypted only to compute its identity and to resolve it
 * against the vault; the original ciphertext is then re-sent verbatim rather
 * than decrypt-and-re-encrypted, so a re-import cannot perturb bytes it had no
 * reason to touch.
 */
export interface NativeCiphertext {
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
}

/**
 * A row ready for conflict resolution: the decrypted identity fields every
 * source shares, plus how the row will be sealed for the wire.
 *
 * `cipher` is present ONLY for native re-imports (see {@link NativeCiphertext});
 * every other source is encrypted from its plaintext at send time. `folderId`
 * and `passwordHistory` likewise ride along only from a native export —
 * third-party parsers produce neither, the server strips a folder id the caller
 * does not own, and carrying the history is what stops re-importing an export
 * from erasing the previous passwords of an item it restores.
 */
export interface ResolvableImportItem extends ParsedImportItem {
  cipher?: NativeCiphertext;
  folderId?: string;
  passwordHistory?: IPasswordHistoryEntry[];
}

/** Column-name → H-Vault field mapping used by the generic CSV path. */
export type CsvFieldMapping = Record<string, string>;
