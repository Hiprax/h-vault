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

/**
 * The six ciphertext fields of a native H-Vault export row, as read from the
 * file. They are opened to recover the row's plaintext and are never re-sent: a
 * row is sealed again, in format v2, to the id and type of wherever it lands.
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
 * A native row's content exactly as the vault stored it, decrypted.
 *
 * `dataJson` is the decrypted data STRING, byte for byte, never re-serialised
 * from the parsed `data`: its content was validated when it was first stored, and
 * sealing the same string again is what guarantees a re-import cannot perturb it.
 */
interface NativeContent {
  dataJson: string;
}

/** One retained previous password, decrypted, beside the time it was replaced. */
export interface PreviousPassword {
  password: string;
  changedAt: string;
}

/**
 * A row ready for conflict resolution: the decrypted identity fields every
 * source shares, plus what sealing it needs.
 *
 * `native` is present ONLY for native re-imports (see {@link NativeContent});
 * every other source is validated and encrypted from its parsed `data`.
 * `folderId` and `previousPasswords` likewise ride along only from a native
 * export — third-party parsers produce neither, the server strips a folder id the
 * caller does not own, and carrying the history is what stops re-importing an
 * export from erasing the previous passwords of an item it restores.
 *
 * Nothing here is ciphertext, on purpose: every field a row is sent with is sealed
 * to the row it will be stored as, and that is decided only after resolution
 * (a fresh id for an insert, the matched row's id for an overwrite).
 */
export interface ResolvableImportItem extends ParsedImportItem {
  native?: NativeContent;
  folderId?: string;
  previousPasswords?: PreviousPassword[];
}

/** Column-name → H-Vault field mapping used by the generic CSV path. */
export type CsvFieldMapping = Record<string, string>;
