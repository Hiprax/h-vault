import { MAX_TAG_LENGTH, MAX_TAGS_PER_ITEM } from '@hvault/shared';
import type { ItemType } from '@hvault/shared';
import type { ParsedImportItem } from './types';
import { toUriEntry, hostFromUrl } from './uri';

/**
 * Plaintext display-name ceiling for imported items. Names are encrypted and the
 * server caps the *ciphertext* at MAX_ENCRYPTED_NAME_LENGTH (1000, base64); this
 * conservative plaintext bound keeps the ciphertext well under that.
 */
const MAX_IMPORT_NAME_LENGTH = 255;
/** Vault URI-list cap mirrors the shared loginDataSchema (`uris` max 100). */
const MAX_URIS_PER_ITEM = 100;

const DEFAULT_NAMES: Record<ItemType, string> = {
  login: 'Untitled login',
  secret: 'Untitled secret',
  note: 'Untitled note',
  card: 'Untitled card',
  identity: 'Untitled identity',
};

/** First value that is non-empty after trimming, or `''`. */
export function firstNonEmpty(...vals: (string | undefined | null)[]): string {
  for (const v of vals) {
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return '';
}

/** Trim and clamp a display name to {@link MAX_IMPORT_NAME_LENGTH}. */
export function clampName(name: string): string {
  return name.trim().slice(0, MAX_IMPORT_NAME_LENGTH);
}

/**
 * Normalize source group/folder names into a bounded, de-duplicated tag list
 * (trimmed, ≤ MAX_TAG_LENGTH each, ≤ MAX_TAGS_PER_ITEM total).
 */
export function toTags(tags?: (string | undefined | null)[]): string[] {
  const out: string[] = [];
  for (const t of tags ?? []) {
    const v = (t ?? '').trim().slice(0, MAX_TAG_LENGTH);
    if (v && !out.includes(v)) out.push(v);
    if (out.length >= MAX_TAGS_PER_ITEM) break;
  }
  return out;
}

/**
 * Coerce a source custom-field value to a string.
 *
 * A JSON export may carry a number (or `null`) where the vault schema requires a
 * string: `customFieldSchema.value` is a `z.string()`, so an uncoerced number
 * fails `safeParse` and discards the ENTIRE item — password included — rather
 * than just that field. Mirrors the `str()` coercion the Bitwarden parser already
 * applies on its own custom-field path.
 */
export function toFieldValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  return '';
}

/** Map a source custom-field type (Bitwarden numeric or a string) to a vault type. */
export function normalizeCustomFieldType(type?: string | number): 'text' | 'hidden' | 'boolean' {
  if (type === 1 || type === '1' || type === 'hidden') return 'hidden';
  if (type === 2 || type === '2' || type === 'boolean') return 'boolean';
  return 'text';
}

export interface LoginInput {
  name?: string;
  username?: string;
  password?: string;
  urls?: (string | undefined | null)[];
  totp?: string;
  notes?: string;
  // `value` is deliberately `unknown`: a source export may put a number (or null)
  // in a custom field, and {@link toFieldValue} coerces it rather than letting it
  // sink the whole item at schema validation.
  customFields?: { name?: string; value?: unknown; type?: string | number }[];
  tags?: (string | undefined | null)[];
  favorite?: boolean;
}

/**
 * Build a login item. URLs are filtered through {@link toUriEntry}; any URL with
 * an unsafe scheme is dropped from `uris` and preserved in the notes so no data
 * is silently lost.
 */
export function buildLogin(input: LoginInput): ParsedImportItem {
  const uris: { uri: string; match: 'domain' }[] = [];
  const dropped: string[] = [];
  for (const raw of input.urls ?? []) {
    if (typeof raw !== 'string' || !raw.trim()) continue;
    if (uris.length >= MAX_URIS_PER_ITEM) break;
    const entry = toUriEntry(raw);
    if (entry) uris.push(entry);
    else dropped.push(raw.trim());
  }

  let notes = (input.notes ?? '').trim();
  if (dropped.length > 0) {
    const extra = `Other URIs: ${dropped.join(', ')}`;
    notes = notes ? `${notes}\n\n${extra}` : extra;
  }

  const data: Record<string, unknown> = {
    username: input.username ?? '',
    password: input.password ?? '',
    uris,
  };
  const totp = (input.totp ?? '').trim();
  if (totp) data.totp = totp;
  if (notes) data.notes = notes;
  const customFields = (input.customFields ?? [])
    .filter((f) => typeof f.name === 'string' && f.name.trim())
    .map((f) => ({
      name: (f.name ?? '').trim(),
      value: toFieldValue(f.value),
      type: normalizeCustomFieldType(f.type),
    }));
  if (customFields.length > 0) data.customFields = customFields;

  return {
    itemType: 'login',
    name: deriveLoginName(input),
    data,
    tags: toTags(input.tags),
    favorite: Boolean(input.favorite),
  };
}

function deriveLoginName(input: LoginInput): string {
  const explicit = clampName(input.name ?? '');
  if (explicit) return explicit;
  const firstUrl = (input.urls ?? []).find((u) => typeof u === 'string' && u.trim());
  if (typeof firstUrl === 'string') {
    const host = clampName(hostFromUrl(firstUrl));
    if (host) return host;
  }
  const user = clampName(input.username ?? '');
  if (user) return user;
  return DEFAULT_NAMES.login;
}

export interface NoteInput {
  name?: string;
  content?: string;
  tags?: (string | undefined | null)[];
  favorite?: boolean;
}

export function buildNote(input: NoteInput): ParsedImportItem {
  return {
    itemType: 'note',
    name: clampName(input.name ?? '') || DEFAULT_NAMES.note,
    data: { content: input.content ?? '', format: 'plaintext' },
    tags: toTags(input.tags),
    favorite: Boolean(input.favorite),
  };
}

/**
 * Build an item of any type from a pre-shaped `data` object (used for Bitwarden
 * card/identity/secure-note where the parser assembles the fields directly).
 */
export function makeItem(
  itemType: ItemType,
  name: string,
  data: Record<string, unknown>,
  opts?: { tags?: (string | undefined | null)[]; favorite?: boolean },
): ParsedImportItem {
  return {
    itemType,
    name: clampName(name) || DEFAULT_NAMES[itemType],
    data,
    tags: toTags(opts?.tags),
    favorite: Boolean(opts?.favorite),
  };
}
