import {
  vaultItemDataSchemas,
  MAX_ENCRYPTED_DATA_LENGTH,
  MAX_ENCRYPTED_NAME_LENGTH,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import { z } from 'zod';
import { cryptoService } from '../crypto/cryptoService';
import type { ParsedImportItem } from './types';

/**
 * An import item that has been encrypted client-side and is ready to POST to the
 * server. Matches the native `createVaultItemSchema` / import item shape — the
 * six ciphertext fields plus metadata. NO plaintext is present.
 */
export interface EncryptedImportItem {
  itemType: ItemType;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
  searchHash: string;
  tags: string[];
  favorite: boolean;
}

export interface BuildResult {
  items: EncryptedImportItem[];
  skipped: number;
  warnings: string[];
}

const MAX_WARNINGS = 10;

/**
 * Validate each parsed item against the shared decrypted-data schema for its
 * type, then encrypt it (name + data) with the vault key and compute its search
 * hash. This is the zero-knowledge boundary: plaintext never leaves this step.
 *
 * A single item that fails validation or exceeds the ciphertext size caps is
 * SKIPPED and counted — it never aborts the whole import. Validation also strips
 * unknown fields and applies schema defaults (e.g. normalizing URIs).
 */
export async function buildEncryptedImportItems(
  parsed: ParsedImportItem[],
  vaultKey: CryptoKey,
): Promise<BuildResult> {
  const items: EncryptedImportItem[] = [];
  const warnings: string[] = [];
  let skipped = 0;

  const warn = (message: string): void => {
    if (warnings.length < MAX_WARNINGS) warnings.push(message);
  };

  for (const item of parsed) {
    const schema = vaultItemDataSchemas[item.itemType];
    const result = schema.safeParse(item.data);
    if (!result.success) {
      skipped++;
      warn(`Skipped "${item.name}": ${firstIssue(result.error)}`);
      continue;
    }

    const encName = await cryptoService.encryptData(item.name, vaultKey);
    const encData = await cryptoService.encryptData(JSON.stringify(result.data), vaultKey);

    if (
      encName.encrypted.length > MAX_ENCRYPTED_NAME_LENGTH ||
      encData.encrypted.length > MAX_ENCRYPTED_DATA_LENGTH
    ) {
      skipped++;
      warn(`Skipped "${item.name}": item is too large to store.`);
      continue;
    }

    const searchHash = await cryptoService.generateSearchHash(item.name, vaultKey);

    items.push({
      itemType: item.itemType,
      encryptedName: encName.encrypted,
      nameIv: encName.iv,
      nameTag: encName.tag,
      encryptedData: encData.encrypted,
      dataIv: encData.iv,
      dataTag: encData.tag,
      searchHash,
      tags: item.tags,
      favorite: item.favorite,
    });
  }

  return { items, skipped, warnings };
}

function firstIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return 'invalid data';
  const path = issue.path.join('.');
  return path ? `${path}: ${issue.message}` : issue.message;
}
