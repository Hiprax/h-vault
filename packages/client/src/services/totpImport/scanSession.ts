import { MAX_LOGIN_TOTP_LENGTH } from '@hvault/shared';
import { buildOtpauthUri, encodeBase32, TOTP_DEFAULTS, type TotpAlgorithm } from '../../lib/totp';
import type { MigrationEntry } from './migrationReader';

/**
 * Where decoded TOTP secrets live while the import page is open.
 *
 * ---------------------------------------------------------------------------
 * TWO STRUCTURES, ONE TEARDOWN
 * ---------------------------------------------------------------------------
 *
 * The secrets sit in a MODULE-LEVEL map and never in React state or in a store.
 * The components receive only {@link ScannedEntry}, which carries an id and the
 * labels a person reads, and they ask for a key by id at the moment they need
 * one. This is the same split `documentsStore` uses for document keys, and for
 * the same reason: it makes "no secret is rendered into the component tree,
 * serialized into a store, or written anywhere" a property of the SHAPE of the
 * code rather than a promise each new component has to keep. A secret cannot
 * leak into React DevTools through a prop that does not exist.
 *
 * {@link endScanSession} is the one teardown, and it is wired into the page's
 * unmount, `pagehide`, `authStore.lock()` and `authStore.logout()`.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS CAN AND CANNOT PROMISE, PRECISELY
 * ---------------------------------------------------------------------------
 *
 * The CANONICAL copy of every key is a `Uint8Array` that is overwritten with
 * zeros on teardown. That is a real guarantee, and it is why the reader hands
 * back bytes rather than a string.
 *
 * It is NOT a promise that no copy survives, and the difference is worth being
 * exact about rather than waving at. A JavaScript string is immutable and is
 * collected whenever the engine decides to, so every rendering of a key is a
 * copy this module cannot reach. There are FOUR places one is made, all of them
 * deliberate, and the count is unbounded rather than one because each is made
 * per call:
 *
 *   1. {@link secretFor}, when the user presses "Show key", which also puts the
 *      base32 into the DOM. A manual text selection and copy from there does not
 *      pass through the clipboard guard and so is not covered by its single
 *      erase deadline; only the six-digit code and the "Copy key" button are.
 *   2. {@link otpauthUriFor}, each time a card is rendered or an action reads it.
 *   3. Creating a vault item, where the URI is encrypted and stored on purpose.
 *   4. "Save all to Documents", which is the largest exposure and the one that
 *      most obviously voids the zeroing: it materialises EVERY key as text in a
 *      `Blob` that the upload session then holds for the whole transfer. That is
 *      the feature working as asked, not a leak, but "short-lived" is not true
 *      of it and the confirmation says what the file contains.
 *
 * So the honest claim is the narrow one: the canonical copy is zeroable and is
 * zeroed, no key is ever persisted or logged by this module, and derived strings
 * exist at the four points above and nowhere else. A comment claiming complete
 * erasure would be false, and the next person would build on it.
 */

export interface ScannedEntry {
  /** Ephemeral, unique to this scan. Never stored and never sent anywhere. */
  readonly id: string;
  readonly type: 'totp' | 'hotp';
  readonly issuer: string;
  readonly account: string;
  readonly algorithm: string;
  readonly digits: number;
  readonly counter: string | null;
  /**
   * False when this app cannot produce codes for it, which today means MD5.
   * Such an entry is still shown and its key can still be copied, because the
   * user's other authenticator may well support it; it simply cannot be turned
   * into a vault item that would display a working code.
   */
  readonly generatable: boolean;
  /** True when the label had to be shortened for the URI to fit its bound. */
  readonly labelTruncated: boolean;
}

interface HeldSecret {
  readonly bytes: Uint8Array;
}

/** The authority on what this session is holding. {@link endScanSession} clears it. */
const held = new Map<string, HeldSecret>();

let nextId = 0;

function isGeneratable(algorithm: string): algorithm is TotpAlgorithm {
  return algorithm === 'SHA1' || algorithm === 'SHA256' || algorithm === 'SHA512';
}

/**
 * Take the accounts from a decoded export, keeping their keys out of the UI.
 *
 * Returns the display metadata, and only that. Entries whose label cannot be
 * shortened enough for a storable URI are dropped rather than returned in a form
 * that could later be written into an item and fail validation on every read.
 */
export function holdEntries(entries: readonly MigrationEntry[]): ScannedEntry[] {
  const out: ScannedEntry[] = [];
  for (const entry of entries) {
    const id = `scan-${String((nextId += 1))}`;
    const generatable = isGeneratable(entry.algorithm);

    let labelTruncated = false;
    if (generatable) {
      const built = buildStorableUri(entry, entry.algorithm);
      if (built === null) continue;
      labelTruncated = built.truncated;
    }

    held.set(id, { bytes: entry.secret });
    out.push({
      id,
      type: entry.type,
      issuer: entry.issuer,
      account: entry.name,
      algorithm: entry.algorithm,
      digits: entry.digits,
      counter: entry.counter,
      generatable,
      labelTruncated,
    });
  }
  return out;
}

function buildStorableUri(
  entry: MigrationEntry,
  algorithm: TotpAlgorithm,
): { uri: string; truncated: boolean } | null {
  return buildOtpauthUri(
    {
      type: entry.type,
      secret: encodeBase32(entry.secret),
      issuer: entry.issuer,
      account: entry.name,
      algorithm,
      digits: entry.digits,
      // The migration payload carries no period field; Google Authenticator is
      // always 30 seconds, and inventing anything else would be a guess.
      period: TOTP_DEFAULTS.period,
      counter: entry.counter,
    },
    MAX_LOGIN_TOTP_LENGTH,
  );
}

/** The base32 key for one entry, built on demand. `null` once torn down. */
export function secretFor(id: string): string | null {
  const entry = held.get(id);
  return entry ? encodeBase32(entry.bytes) : null;
}

/**
 * The storable `otpauth://` URI for one entry, built on demand.
 *
 * Needs the display metadata back, because this module deliberately does not
 * keep it: holding the labels here as well would make it a second store of the
 * same thing, and the component already has them.
 */
export function otpauthUriFor(entry: ScannedEntry): string | null {
  const secret = held.get(entry.id);
  if (!secret || !isGeneratable(entry.algorithm)) return null;
  const built = buildOtpauthUri(
    {
      type: entry.type,
      secret: encodeBase32(secret.bytes),
      issuer: entry.issuer,
      account: entry.account,
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: TOTP_DEFAULTS.period,
      counter: entry.counter,
    },
    MAX_LOGIN_TOTP_LENGTH,
  );
  return built?.uri ?? null;
}

/** How many keys are held. For the teardown tests, and for nothing else. */
export function heldSecretCount(): number {
  return held.size;
}

/** Zero every key and forget them all. Idempotent. */
export function endScanSession(): void {
  for (const secret of held.values()) secret.bytes.fill(0);
  held.clear();
}
