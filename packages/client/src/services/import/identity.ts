/**
 * Import identity — the key that decides whether an incoming item and an item
 * already in the vault are "the same item".
 *
 * Identity is computed CLIENT-SIDE, in memory, from DECRYPTED content. It is
 * never transmitted and never stored: the match key for a login is its site and
 * its username, both of which live inside the encrypted blob, so the server
 * physically cannot compute it. Matching on the item NAME — which is what the
 * server used to do — collapses ten different accounts on one site into one
 * item, because the name is a display label a user may edit or a parser may
 * derive, not an identity.
 *
 * Two shapes of key exist:
 *
 *   `login\0<host>\0<username>` — a login with BOTH a resolvable host AND a
 *     non-empty username. Accounts on one site are told apart by username, so
 *     ten `accounts.google.com` logins stay ten items, while an `overwrite`
 *     import can still update a changed password for the same account.
 *
 *   `<itemType>\0<sha256hex>` — everything else: the exact-content hash of
 *     `canonicalJson({ name, data })`.
 *
 * A weak logical key always falls back to the strict one. "Same site, no
 * username" would merge every account-less entry on that site, so a login
 * missing either half is matched on exact content instead. Unrelated items can
 * then never be merged, and the worst case is an extra insert — never lost data.
 *
 * The item type is part of every key, so matching can never cross item types.
 *
 * NUL is the field separator: a host cannot contain one, so `host="a b",
 * username="c"` cannot collide with `host="a", username="b c"`.
 *
 * The module is deliberately pure — no account key material, no store, no
 * network, no server import — so it is exhaustively testable and safe to call
 * from anywhere in the import pipeline.
 */

import { normalizeUri, vaultItemDataSchemas } from '@hvault/shared';
import type { ItemType } from '@hvault/shared';

/** Field separator. Cannot occur in a normalized host, so keys are unambiguous. */
const SEP = '\u0000';

const textEncoder = new TextEncoder();

export interface ItemIdentityInput {
  itemType: ItemType;
  /** Decrypted display name. */
  name: string;
  /** Decrypted item data — raw from a parser or already schema-transformed. */
  data: Record<string, unknown>;
}

/**
 * Deterministic JSON serialization: object keys sorted, every string
 * NFC-normalized, array order preserved.
 *
 * Determinism across devices, runs and browsers is what makes re-importing the
 * same file a no-op, so nothing here may depend on property insertion order or
 * on a Unicode composition form. Keys that canonicalize to `undefined` are
 * dropped, exactly as `JSON.stringify` would drop them.
 *
 * Precondition: the value is JSON-representable — strings, numbers, booleans,
 * `null`, arrays and plain objects. That holds for every caller, because item
 * data is either `JSON.parse`d from decrypted ciphertext or built by an import
 * parser. A `Date`/`Map`/`Set` would canonicalize to `{}` and a `bigint` would
 * make `JSON.stringify` throw, so do not feed one in.
 */
export function canonicalJson(value: unknown): string {
  const canonical = canonicalize(value);
  // `JSON.stringify` returns `undefined` (not a string) for a top-level
  // `undefined`; keep the signature honest rather than leaking that out.
  return canonical === undefined ? 'null' : JSON.stringify(canonical);
}

/**
 * Reduce a URI to the host it identifies, or `''` when it has none.
 *
 * Steps, in this exact order: the shared `normalizeUri` (so a bare domain
 * becomes `https://…`, the same transform `uriEntrySchema` applies), then
 * `new URL(...).hostname`, NFC, lowercase, strip ONE leading `www.`, strip a
 * trailing `.`.
 *
 * Anything that throws or yields nothing — a `mailto:` address, a regex match
 * pattern, a malformed value — returns `''`, which demotes the item to
 * exact-content matching rather than merging it with something unrelated.
 *
 * Stripping `www.` is deliberate: `www.amazon.com` and `amazon.com` are the
 * same site and two password managers commonly disagree about the prefix.
 */
export function normalizeHost(rawUri: string): string {
  const trimmed = rawUri.trim();
  if (!trimmed) return '';

  let host: string;
  try {
    host = new URL(normalizeUri(trimmed)).hostname;
  } catch {
    return '';
  }

  host = host.normalize('NFC').toLowerCase();
  if (host.startsWith('www.')) host = host.slice(4);
  if (host.endsWith('.')) host = host.slice(0, -1);
  return host;
}

/**
 * Reduce a username to its comparable form: NFC, trimmed, lowercased.
 *
 * Lowercasing is deliberate — email-style usernames are case-insensitive in
 * practice, and a case-only difference almost always means the same account
 * exported twice. `toLowerCase` (not `toLocaleLowerCase`) keeps the result
 * independent of the device locale.
 *
 * A non-string value yields `''`, which demotes the item to exact-content
 * matching.
 */
export function normalizeUsername(value: unknown): string {
  if (typeof value !== 'string') return '';
  return value.normalize('NFC').trim().toLowerCase();
}

/**
 * Compute the identity key for one item.
 *
 * The data is run through `vaultItemDataSchemas[itemType]` HERE, and the parsed
 * OUTPUT is what gets hashed. This is load-bearing, not a convenience: an item
 * already in the vault was stored through that same schema, so its `uris[].uri`
 * has been through `normalizeUri` and its optional fields have been defaulted
 * and stripped. Hashing incoming data before validation would make a source row
 * carrying `amazon.com` hash differently from the stored `https://amazon.com`
 * for the very same account, and re-importing a file would silently duplicate
 * every item. Deriving the parse internally also means callers need not care
 * whether they hold pre- or post-validation data, and an item typed into the UI
 * form hashes identically to the same item arriving from an import.
 *
 * When validation fails the raw object is hashed instead, so an item is still
 * given a stable key rather than being dropped.
 *
 * Known limitation, accepted: the host comes from the FIRST URI only. If one
 * export lists `login.example.com` first and another lists `example.com` first
 * for the same account, the keys differ and the item is inserted rather than
 * matched — a false SPLIT (a duplicate), never a false merge, so it cannot lose
 * data. Widening the key to any-host would merge two accounts that legitimately
 * share a secondary domain.
 */
export async function computeItemIdentity(input: ItemIdentityInput): Promise<string> {
  const { itemType, name } = input;
  const data = schemaValidated(itemType, input.data);

  if (itemType === 'login') {
    const host = normalizeHost(firstUri(data));
    const username = normalizeUsername(data.username);
    // Only a key with BOTH halves is discriminating enough to match on.
    if (host && username) return `login${SEP}${host}${SEP}${username}`;
  }

  return `${itemType}${SEP}${await sha256Hex(canonicalJson({ name, data }))}`;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function schemaValidated(
  itemType: ItemType,
  data: Record<string, unknown>,
): Record<string, unknown> {
  const result = vaultItemDataSchemas[itemType].safeParse(data);
  if (!result.success) return data;
  return isRecord(result.data) ? result.data : data;
}

/**
 * The first URI of a login, as a raw string. Tolerates both the stored shape
 * (`{ uri, match }`) and a bare string, so pre-validation parser output works.
 */
function firstUri(data: Record<string, unknown>): string {
  const uris = data.uris;
  if (!Array.isArray(uris)) return '';
  const first: unknown = uris[0];
  if (typeof first === 'string') return first;
  if (isRecord(first) && typeof first.uri === 'string') return first.uri;
  return '';
}

function canonicalize(value: unknown): unknown {
  if (typeof value === 'string') return value.normalize('NFC');
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!isRecord(value)) return value;

  const entries = Object.entries(value)
    .map(([key, entryValue]) => [key.normalize('NFC'), entryValue] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  // A null-prototype accumulator, so a `__proto__` key is stored as DATA. On a
  // plain object literal `out['__proto__'] = …` hits the inherited accessor,
  // sets the prototype and creates no own property, and the field vanishes from
  // the serialization — two items differing only there would hash identically.
  // `JSON.parse` does produce an own `__proto__` property, so decrypted data
  // that failed schema validation can carry one.
  const out = Object.create(null) as Record<string, unknown>;
  for (const [key, entryValue] of entries) {
    const canonical = canonicalize(entryValue);
    if (canonical !== undefined) out[key] = canonical;
  }
  return out;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function sha256Hex(input: string): Promise<string> {
  // `cryptoService`'s constructor already fails fast when SubtleCrypto is
  // missing, so a second guard here would be unreachable.
  const digest = await globalThis.crypto.subtle.digest('SHA-256', textEncoder.encode(input));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}
