import {
  MAX_NOTE_CONTENT_LENGTH,
  MAX_TAG_LENGTH,
  MAX_TAGS_PER_ITEM,
  normalizeUri,
} from '@hvault/shared';
import type { CustomFieldType, ItemType } from '@hvault/shared';
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

/**
 * Per-field plaintext ceilings, mirroring the shared decrypted-data schemas
 * (`packages/shared/src/schemas/vault.ts`). A source export can carry a value
 * longer than the vault permits; if it reaches encryption unclamped the item
 * fails `vaultItemDataSchemas` and is discarded WHOLESALE — password included —
 * by `buildEncryptedImportItems`. Clamp to these bounds instead and preserve the
 * overflow in the item's notes, so a single long field can never sink the item.
 * A `password` is the one exception: it is clamped but NEVER copied into notes.
 */
const MAX_USERNAME_LENGTH = 500; // loginDataSchema.username
const MAX_PASSWORD_LENGTH = 10_000; // loginDataSchema.password
const MAX_TOTP_LENGTH = 500; // loginDataSchema.totp
const MAX_URI_LENGTH = 2048; // uriEntrySchema.uri (INPUT cap, measured pre-transform)
const MAX_CUSTOM_FIELD_NAME_LENGTH = 500; // customFieldSchema.name
const MAX_CUSTOM_FIELDS_PER_ITEM = 100; // *DataSchema.customFields array cap
// customFieldSchema.value and every `notes`/`content` field cap at
// MAX_NOTE_CONTENT_LENGTH.

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
 * Clamp a string to `max` characters, returning the clamped value together with
 * the removed tail (`''` when nothing was truncated). Callers decide whether to
 * preserve the overflow elsewhere (e.g. fold it into the item's notes).
 */
export function clampWithOverflow(value: string, max: number): { value: string; overflow: string } {
  if (value.length <= max) return { value, overflow: '' };
  return { value: value.slice(0, max), overflow: value.slice(max) };
}

/**
 * Clamp a raw URI to the vault's per-URI bound.
 *
 * `uriEntrySchema` caps the uri at {@link MAX_URI_LENGTH} on its INPUT and only
 * THEN runs the transform that prepends a scheme (`https://`, or `https:` for a
 * protocol-relative `//host`) to a scheme-less value. A 2041-2048-char bare
 * domain therefore validates on the way in but is stored several chars over the
 * cap and FAILS `safeParse` on decrypt — leaving a permanently undecodable item.
 * Clamp so the *transformed* value fits, and return the full original as overflow
 * so it can be preserved in notes.
 */
export function clampUri(raw: string): { uri: string; overflow: string } {
  // The scheme the transform prepends is fixed by the shape of the value, not its
  // length, so measuring the overhead once on the raw value is exact.
  const overhead = normalizeUri(raw).length - raw.length;
  const bound = MAX_URI_LENGTH - overhead;
  if (raw.length <= bound) return { uri: raw, overflow: '' };
  return { uri: raw.slice(0, bound), overflow: raw };
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
export function normalizeCustomFieldType(type?: string | number): CustomFieldType {
  if (type === 1 || type === '1' || type === 'hidden') return 'hidden';
  if (type === 2 || type === '2' || type === 'boolean') return 'boolean';
  return 'text';
}

interface VaultCustomField {
  name: string;
  value: string;
  type: CustomFieldType;
}

/**
 * Coerce, clamp and cap a source custom-field list to the vault bounds.
 *
 * Drops entries with an empty name; clamps each surviving `name` to
 * {@link MAX_CUSTOM_FIELD_NAME_LENGTH} and each `value` to
 * {@link MAX_NOTE_CONTENT_LENGTH}; keeps at most {@link MAX_CUSTOM_FIELDS_PER_ITEM}.
 * Truncated values and any fields beyond the cap are returned as `overflow`
 * lines so the caller can preserve them in notes rather than dropping them.
 */
export function clampCustomFields(raw: readonly unknown[]): {
  fields: VaultCustomField[];
  overflow: string[];
} {
  const fields: VaultCustomField[] = [];
  const overflow: string[] = [];
  const dropped: { name: string; value: string }[] = [];

  for (const entry of raw) {
    if (typeof entry !== 'object' || entry === null) continue;
    const rec = entry as { name?: unknown; value?: unknown; type?: unknown };
    const name = (typeof rec.name === 'string' ? rec.name : '').trim();
    if (!name) continue;
    const value = toFieldValue(rec.value);
    if (fields.length >= MAX_CUSTOM_FIELDS_PER_ITEM) {
      dropped.push({ name: name.slice(0, MAX_CUSTOM_FIELD_NAME_LENGTH), value });
      continue;
    }
    const clampedName = name.slice(0, MAX_CUSTOM_FIELD_NAME_LENGTH);
    const { value: clampedValue, overflow: valueOverflow } = clampWithOverflow(
      value,
      MAX_NOTE_CONTENT_LENGTH,
    );
    if (valueOverflow) {
      overflow.push(
        `Custom field "${clampedName}" was truncated; remaining value: ${valueOverflow}`,
      );
    }
    fields.push({
      name: clampedName,
      value: clampedValue,
      type: normalizeCustomFieldType(rec.type as string | number | undefined),
    });
  }

  if (dropped.length > 0) {
    const summary = dropped.map((d) => `${d.name}: ${d.value}`).join('\n');
    overflow.push(`${String(dropped.length)} additional custom field(s) not imported:\n${summary}`);
  }

  return { fields, overflow };
}

/**
 * Assemble the final notes for an item from its base notes plus any preserved
 * overflow, clamping the result to {@link MAX_NOTE_CONTENT_LENGTH} LAST — notes
 * are the sink for every other field's overflow, so if the accumulated text
 * itself exceeds the bound there is nowhere left to move it and the tail is
 * dropped (the one place truncation is unavoidable).
 */
function assembleNotes(base: string, sections: string[]): string {
  const parts: string[] = [];
  const trimmedBase = base.trim();
  if (trimmedBase) parts.push(trimmedBase);
  for (const s of sections) {
    if (s) parts.push(s);
  }
  return parts.join('\n\n').slice(0, MAX_NOTE_CONTENT_LENGTH);
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
 * is silently lost. Over-long field values are clamped to the shared schema
 * bounds and their overflow is preserved in the notes (except `password`, which
 * is clamped but never copied into notes) so a single long field can no longer
 * cause the whole item to be discarded at validation.
 */
export function buildLogin(input: LoginInput): ParsedImportItem {
  const overflow: string[] = [];

  const uris: { uri: string; match: 'domain' }[] = [];
  const droppedUris: string[] = [];
  for (const raw of input.urls ?? []) {
    if (typeof raw !== 'string' || !raw.trim()) continue;
    if (uris.length >= MAX_URIS_PER_ITEM) break;
    const entry = toUriEntry(raw);
    if (!entry) {
      droppedUris.push(raw.trim());
      continue;
    }
    const { uri, overflow: uriOverflow } = clampUri(entry.uri);
    uris.push({ uri, match: entry.match });
    if (uriOverflow) overflow.push(`Full URL: ${uriOverflow}`);
  }
  if (droppedUris.length > 0) overflow.push(`Other URIs: ${droppedUris.join(', ')}`);

  const rawUsername = input.username ?? '';
  const { value: username, overflow: usernameOverflow } = clampWithOverflow(
    rawUsername,
    MAX_USERNAME_LENGTH,
  );
  if (usernameOverflow) overflow.push(`Full username: ${rawUsername}`);

  // A password is clamped to the schema bound but is NEVER folded into notes.
  const password = (input.password ?? '').slice(0, MAX_PASSWORD_LENGTH);

  const { fields: customFields, overflow: fieldOverflow } = clampCustomFields(
    input.customFields ?? [],
  );
  overflow.push(...fieldOverflow);

  const data: Record<string, unknown> = { username, password, uris };
  const totp = (input.totp ?? '').trim().slice(0, MAX_TOTP_LENGTH);
  if (totp) data.totp = totp;
  if (customFields.length > 0) data.customFields = customFields;

  const notes = assembleNotes(input.notes ?? '', overflow);
  if (notes) data.notes = notes;

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
    // A note's content IS its free text, so an over-long value has nowhere else
    // to go: clamp to the schema bound rather than let it sink the whole item.
    name: clampName(input.name ?? '') || DEFAULT_NAMES.note,
    data: {
      content: (input.content ?? '').slice(0, MAX_NOTE_CONTENT_LENGTH),
      format: 'plaintext',
    },
    tags: toTags(input.tags),
    favorite: Boolean(input.favorite),
  };
}

/**
 * Build an item of any type from a pre-shaped `data` object (used for Bitwarden
 * card/identity/secure-note where the parser assembles the fields directly).
 * The two fields most likely to overflow on such an item — free-text `notes` and
 * the `customFields` list — are clamped to the shared bounds, with any trimmed
 * content folded back into `notes`, so an over-long field cannot discard the item.
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
    data: clampNotesAndFields(data),
    tags: toTags(opts?.tags),
    favorite: Boolean(opts?.favorite),
  };
}

/**
 * Defensively clamp the `notes` and `customFields` of a pre-shaped data object
 * (card / identity) to the shared schema bounds. Custom-field overflow is folded
 * into `notes`; `notes` is clamped last. Scalar, structured columns (card number,
 * identity name, …) are left to the parsers, which read them from bounded source
 * fields.
 */
function clampNotesAndFields(data: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...data };
  const overflow: string[] = [];

  if (Array.isArray(out.customFields)) {
    const { fields, overflow: fieldOverflow } = clampCustomFields(out.customFields);
    overflow.push(...fieldOverflow);
    if (fields.length > 0) out.customFields = fields;
    else delete out.customFields;
  }

  const baseNotes = typeof out.notes === 'string' ? out.notes : '';
  if (baseNotes || overflow.length > 0) {
    const notes = assembleNotes(baseNotes, overflow);
    if (notes) out.notes = notes;
    else delete out.notes;
  }

  return out;
}
