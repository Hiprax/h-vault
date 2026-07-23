/**
 * The format-agnostic intermediate model for the portable plaintext export.
 *
 * The export pipeline decrypts the authoritative ciphertext set returned by
 * `POST /tools/export`, normalizes every item into a {@link PortableItem}, and
 * only then hands those records to a per-format serializer (Bitwarden JSON,
 * Bitwarden CSV, Chrome CSV). Keeping this normalization in one place means the
 * serializers never touch ciphertext, Zod schemas, or the vault key — they only
 * shape already-decrypted, already-validated data.
 *
 * Two invariants are load-bearing (PLAN §1.2 principle 8):
 *
 * - **An item that cannot be decoded is reported, never silently dropped.** A
 *   silently short export is indistinguishable from a complete one, and the user
 *   is often about to delete their account. Every undecodable or schema-invalid
 *   item lands in `skipped` with a reason.
 * - **`portable.length + skipped.length === items.length`.** Every input item is
 *   accounted for in exactly one of the two output lists.
 *
 * Password history is NOT part of the decrypted `data` object — it lives on
 * `item._raw.passwordHistory` as ciphertext and is decrypted here per entry. A
 * single entry that fails to decrypt is reported (logged) and dropped from that
 * item's history; it never throws and never skips the whole item.
 */

import { vaultItemDataSchemas } from '@hvault/shared';
import type {
  ItemType,
  CustomFieldType,
  ILoginData,
  ISecretData,
  INoteData,
  ICardData,
  IIdentityData,
  IAddress,
} from '@hvault/shared';
import { cryptoService } from '../crypto/cryptoService.js';
import { isUndecodableData } from '../../lib/vaultData.js';
import { logger } from '../../lib/logger.js';
import type { DecryptedVaultItem, DecryptedFolder } from '../../stores/vaultStore.js';
import { buildFolderPaths } from './folderPath.js';

// ---------------------------------------------------------------------------
// Portable record model
// ---------------------------------------------------------------------------

/** A custom field, carried verbatim from the decrypted item data. */
export interface PortableCustomField {
  name: string;
  value: string;
  type: CustomFieldType;
}

/** One historical password, decrypted from `item._raw.passwordHistory`. */
export interface PortablePasswordHistoryEntry {
  password: string;
  /** ISO 8601 timestamp the password was replaced (the domain `changedAt`). */
  changedAt: string;
}

/** Login-specific fields; URIs and TOTP are hoisted to the top level. */
export interface PortableLogin {
  username: string;
  password: string;
}

/** A postal address, shared by card billing and identity. */
export interface PortableAddress {
  street: string;
  city: string;
  state: string;
  zip: string;
  country: string;
}

export interface PortableCard {
  cardholderName: string;
  number: string;
  expMonth: string;
  expYear: string;
  cvv: string;
  brand?: string | undefined;
  billingAddress?: PortableAddress | undefined;
}

export interface PortableIdentity {
  firstName: string;
  lastName: string;
  email?: string | undefined;
  phone?: string | undefined;
  address?: PortableAddress | undefined;
  company?: string | undefined;
  ssn?: string | undefined;
  passport?: string | undefined;
}

export interface PortableSecret {
  value: string;
  description?: string | undefined;
  expiresAt?: string | undefined;
}

/**
 * A single vault item flattened into a normalized, format-agnostic shape. Only
 * the sub-object matching `type` is populated; the optional collections
 * (`uris`, `totp`, `customFields`, `passwordHistory`) appear only when present.
 */
export interface PortableItem {
  type: ItemType;
  name: string;
  /** Slash-joined folder path, or `''` when the item is in no folder. */
  folderPath: string;
  favorite: boolean;
  /** Free-text notes for the item (`content` for a note). */
  notes: string;
  tags: string[];
  login?: PortableLogin | undefined;
  uris?: string[] | undefined;
  /** A TOTP, always emitted as an `otpauth://` URI (see {@link toOtpauthUri}). */
  totp?: string | undefined;
  card?: PortableCard | undefined;
  identity?: PortableIdentity | undefined;
  secret?: PortableSecret | undefined;
  customFields?: PortableCustomField[] | undefined;
  passwordHistory?: PortablePasswordHistoryEntry[] | undefined;
}

/** An input item that could not be represented, reported rather than dropped. */
export interface SkippedItem {
  id: string;
  name: string;
  reason: string;
}

export interface ToPortableItemsInput {
  items: readonly DecryptedVaultItem[];
  folders: readonly DecryptedFolder[];
  vaultKey: CryptoKey;
}

export interface ToPortableItemsResult {
  portable: PortableItem[];
  skipped: SkippedItem[];
}

// ---------------------------------------------------------------------------
// TOTP → otpauth URI
// ---------------------------------------------------------------------------

/**
 * Normalize a stored TOTP value to an `otpauth://` URI. A value that is already
 * an `otpauth://` URI is passed through unchanged (it may carry an issuer,
 * algorithm, digits or period the bare secret cannot express); a bare base32
 * secret is wrapped into a standard SHA-1 / 6-digit / 30-second URI, using the
 * item name as both the label and the issuer.
 */
export function toOtpauthUri(totp: string, accountName: string): string {
  const trimmed = totp.trim();
  if (/^otpauth:\/\//i.test(trimmed)) {
    return trimmed;
  }

  const secret = trimmed.replace(/\s+/g, '').toUpperCase();
  const issuer = accountName.trim() || 'H-Vault';
  const label = encodeURIComponent(issuer);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Decryption helpers
// ---------------------------------------------------------------------------

/**
 * Decrypt an item's password history. A per-entry failure is logged and the
 * entry dropped; the item itself is never skipped for a bad history entry.
 */
async function decryptPasswordHistory(
  item: DecryptedVaultItem,
  vaultKey: CryptoKey,
): Promise<PortablePasswordHistoryEntry[]> {
  const raw = item._raw.passwordHistory;
  if (!raw || raw.length === 0) {
    return [];
  }

  const entries: PortablePasswordHistoryEntry[] = [];
  for (const entry of raw) {
    try {
      const password = await cryptoService.decryptData(
        entry.encryptedPassword,
        entry.iv,
        entry.tag,
        vaultKey,
      );
      entries.push({ password, changedAt: entry.changedAt });
    } catch (err) {
      logger.warn('Skipping undecryptable password-history entry during export', err);
    }
  }
  return entries;
}

function mapCustomFields(
  fields: readonly { name: string; value: string; type: CustomFieldType }[],
): PortableCustomField[] {
  return fields.map((f) => ({ name: f.name, value: f.value, type: f.type }));
}

function mapAddress(address: IAddress): PortableAddress {
  return {
    street: address.street,
    city: address.city,
    state: address.state,
    zip: address.zip,
    country: address.country,
  };
}

// ---------------------------------------------------------------------------
// Per-type builders
// ---------------------------------------------------------------------------

function fillLogin(record: PortableItem, data: ILoginData): void {
  record.login = { username: data.username, password: data.password };
  const uris = data.uris.map((u) => u.uri).filter((u) => u.length > 0);
  if (uris.length > 0) {
    record.uris = uris;
  }
  if (data.totp !== undefined && data.totp.trim().length > 0) {
    record.totp = toOtpauthUri(data.totp, record.name);
  }
  if (data.notes !== undefined) {
    record.notes = data.notes;
  }
  if (data.customFields.length > 0) {
    record.customFields = mapCustomFields(data.customFields);
  }
}

function fillSecret(record: PortableItem, data: ISecretData): void {
  record.secret = {
    value: data.value,
    description: data.description,
    expiresAt: data.expiresAt,
  };
  if (data.customFields.length > 0) {
    record.customFields = mapCustomFields(data.customFields);
  }
}

function fillNote(record: PortableItem, data: INoteData): void {
  // A note's body IS its notes; the `format` (markdown/plaintext) has no portable
  // equivalent, so it is intentionally not carried.
  record.notes = data.content;
}

function fillCard(record: PortableItem, data: ICardData): void {
  record.card = {
    cardholderName: data.cardholderName,
    number: data.number,
    expMonth: data.expMonth,
    expYear: data.expYear,
    cvv: data.cvv,
    brand: data.brand,
    billingAddress: data.billingAddress ? mapAddress(data.billingAddress) : undefined,
  };
  if (data.notes !== undefined) {
    record.notes = data.notes;
  }
}

function fillIdentity(record: PortableItem, data: IIdentityData): void {
  record.identity = {
    firstName: data.firstName,
    lastName: data.lastName,
    email: data.email,
    phone: data.phone,
    address: data.address ? mapAddress(data.address) : undefined,
    company: data.company,
    ssn: data.ssn,
    passport: data.passport,
  };
  if (data.notes !== undefined) {
    record.notes = data.notes;
  }
  if (data.customFields.length > 0) {
    record.customFields = mapCustomFields(data.customFields);
  }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/**
 * Flatten decrypted vault items into portable records, reporting every item that
 * cannot be represented in `skipped`. Guarantees
 * `portable.length + skipped.length === items.length`.
 */
export async function toPortableItems({
  items,
  folders,
  vaultKey,
}: ToPortableItemsInput): Promise<ToPortableItemsResult> {
  const folderPaths = buildFolderPaths(folders);
  const portable: PortableItem[] = [];
  const skipped: SkippedItem[] = [];

  for (const item of items) {
    // An undecodable placeholder is not real content — report, never export it.
    if (isUndecodableData(item.data)) {
      skipped.push({ id: item.id, name: item.name, reason: 'Item data could not be decoded' });
      continue;
    }

    const schema = vaultItemDataSchemas[item.itemType];
    const parsed = schema.safeParse(item.data);
    if (!parsed.success) {
      skipped.push({ id: item.id, name: item.name, reason: 'Item data failed validation' });
      continue;
    }

    const folderPath = item.folderId !== undefined ? (folderPaths.get(item.folderId) ?? '') : '';

    const record: PortableItem = {
      type: item.itemType,
      name: item.name,
      folderPath,
      favorite: item.favorite,
      notes: '',
      tags: [...item.tags],
    };

    switch (item.itemType) {
      case 'login':
        fillLogin(record, parsed.data as ILoginData);
        break;
      case 'secret':
        fillSecret(record, parsed.data as ISecretData);
        break;
      case 'note':
        fillNote(record, parsed.data as INoteData);
        break;
      case 'card':
        fillCard(record, parsed.data as ICardData);
        break;
      case 'identity':
        fillIdentity(record, parsed.data as IIdentityData);
        break;
    }

    const passwordHistory = await decryptPasswordHistory(item, vaultKey);
    if (passwordHistory.length > 0) {
      record.passwordHistory = passwordHistory;
    }

    portable.push(record);
  }

  return { portable, skipped };
}
