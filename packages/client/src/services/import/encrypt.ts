import {
  vaultItemDataSchemas,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { z } from 'zod';
import { cryptoService } from '../crypto/cryptoService';
import { encryptVaultField } from '../crypto/vaultField';
import type { ParsedImportItem } from './types';

/** How many per-row reasons an import surfaces before it stops collecting. */
export const MAX_IMPORT_WARNINGS = 10;

/** The ciphertext fields (plus search hash) a sealed row puts on the wire. */
interface SealedImportItem {
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
  searchHash: string;
}

/**
 * The row an import row will be stored as, which its fields are sealed to.
 *
 * For an insert, the id the server will derive from the nonce the insert is sent
 * with; for an overwrite, the matched row's own id and its STORED type, which is
 * the type the data will be read under from then on.
 */
export interface ImportDestination {
  rowId: string;
  itemType: ItemType;
}

/** Either a sealed row or the reason the row could not be sealed. */
export type SealImportResult =
  { ok: true; sealed: SealedImportItem } | { ok: false; reason: string };

/**
 * Validate ONE parsed item against the shared decrypted-data schema for its
 * type, then seal its name and data to their destination row (format v2) and
 * compute its search hash. This is the zero-knowledge boundary: plaintext never
 * leaves this step.
 *
 * Failure is reported, never thrown — a single unconvertible item must not
 * abort a whole import — and the reason names the item and the offending field
 * so the caller can surface it. This is the ONE place import ciphertext is
 * produced, shared by the insert and update paths, so they cannot drift.
 */
export async function sealImportItem(
  item: ParsedImportItem,
  destination: ImportDestination,
  vaultKey: CryptoKey,
): Promise<SealImportResult> {
  const schema = vaultItemDataSchemas[item.itemType];
  const result = schema.safeParse(item.data);
  if (!result.success) {
    return { ok: false, reason: `Skipped "${item.name}": ${firstIssue(result.error)}` };
  }
  return sealImportFields(item.name, JSON.stringify(result.data), destination, vaultKey);
}

/**
 * Seal a name and an already-serialised data string to their destination row,
 * with the size check and the search hash every import row needs. Shared by the
 * validated path above and a native re-import, which seals the stored data string
 * verbatim rather than re-validating it.
 */
export async function sealImportFields(
  name: string,
  dataJson: string,
  destination: ImportDestination,
  vaultKey: CryptoKey,
): Promise<SealImportResult> {
  const encName = await encryptVaultField(
    name,
    { role: 'item.name', rowId: destination.rowId },
    vaultKey,
  );
  const encData = await encryptVaultField(
    dataJson,
    { role: 'item.data', rowId: destination.rowId, itemType: destination.itemType },
    vaultKey,
  );

  if (
    encName.encrypted.length > MAX_ENCRYPTED_NAME_LENGTH ||
    encData.encrypted.length > MAX_ENCRYPTED_DATA_LENGTH
  ) {
    return { ok: false, reason: `Skipped "${name}": item is too large to store.` };
  }

  const searchHash = await cryptoService.generateSearchHash(name, vaultKey);

  return {
    ok: true,
    sealed: {
      encryptedName: encName.encrypted,
      nameIv: encName.iv,
      nameTag: encName.tag,
      encryptedData: encData.encrypted,
      dataIv: encData.iv,
      dataTag: encData.tag,
      searchHash,
    },
  };
}

/** Parsed items that passed schema validation, plus the ones that did not. */
export interface ValidationResult {
  /** The survivors, carrying the schema's TRANSFORMED output as their `data`. */
  items: ParsedImportItem[];
  skipped: number;
  warnings: string[];
}

/**
 * Validate parsed items against `vaultItemDataSchemas`, keeping the schema's
 * transformed OUTPUT as each survivor's `data`.
 *
 * This runs BEFORE conflict resolution, deliberately (PLAN §1.8 step 4): an item
 * whose data cannot be validated has no meaningful identity, so letting it into
 * the resolver could only mis-key it — and reporting it as a "duplicate" would
 * hide the real reason it never reached the vault. Carrying the transformed
 * output forward also means the row hashes exactly as the same item already
 * stored in the vault does, which is what makes a re-import a no-op.
 */
export function validateImportItems(parsed: ParsedImportItem[]): ValidationResult {
  const items: ParsedImportItem[] = [];
  const warnings: string[] = [];
  let skipped = 0;

  for (const item of parsed) {
    const result = vaultItemDataSchemas[item.itemType].safeParse(item.data);
    if (!result.success) {
      skipped++;
      if (warnings.length < MAX_IMPORT_WARNINGS) {
        warnings.push(`Skipped "${item.name}": ${firstIssue(result.error)}`);
      }
      continue;
    }
    items.push({ ...item, data: result.data as Record<string, unknown> });
  }

  return { items, skipped, warnings };
}

function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return 'invalid data';
  const path = issue.path.join('.');
  return path ? `${path}: ${issue.message}` : issue.message;
}
