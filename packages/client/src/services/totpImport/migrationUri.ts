import {
  MAX_MIGRATION_PAYLOAD_BYTES,
  MAX_MIGRATION_URI_LENGTH,
  MigrationParseError,
  readMigrationPayload,
  type MigrationPayload,
} from './migrationReader';

/**
 * Turn an `otpauth-migration://offline?data=...` URI into its payload.
 *
 * ---------------------------------------------------------------------------
 * THE TRAP THAT CATCHES ALMOST EVERY IMPLEMENTATION OF THIS
 * ---------------------------------------------------------------------------
 *
 * The `data` parameter is STANDARD base64, whose alphabet contains `+`, and it
 * is percent-encoded inside the URI. The obvious way to read it,
 *
 *     new URL(uri).searchParams.get('data')
 *
 * is wrong, because `URLSearchParams` implements HTML form decoding, where `+`
 * means SPACE. Any payload containing an unencoded `+` therefore comes back
 * silently corrupted, and base64 decoding then fails in a way that looks exactly
 * like a bad scan: the user re-aims the camera at a code that was read
 * perfectly. Google Authenticator percent-encodes the `+`, so its own codes are
 * unaffected, which is what makes this so easy to ship: it only breaks for a URI
 * that has been relayed, re-typed or produced by another tool.
 *
 * So the raw substring is taken from `url.search` and decoded with
 * `decodeURIComponent`, which does not treat `+` specially.
 *
 * Both base64 alphabets are accepted and the padding is rebuilt, because the
 * cost is three lines and the failure it prevents is indistinguishable from a
 * camera problem.
 */

const STANDARD_TO_URLSAFE = /[-_]/g;

/** Pull the raw, still-percent-encoded value of one query parameter. */
function rawQueryParam(search: string, key: string): string | null {
  const query = search.startsWith('?') ? search.slice(1) : search;
  for (const pair of query.split('&')) {
    const eq = pair.indexOf('=');
    if (eq === -1) continue;
    if (pair.slice(0, eq) !== key) continue;
    return pair.slice(eq + 1);
  }
  return null;
}

function decodeBase64(value: string): Uint8Array {
  // Accept the URL-safe alphabet too, then restore the padding base64 decoding
  // wants. Neither is what Google Authenticator emits; both are what a URI that
  // has passed through another tool can arrive as.
  const normalised = value.replace(STANDARD_TO_URLSAFE, (char) => (char === '-' ? '+' : '/'));
  const padded = normalised.padEnd(Math.ceil(normalised.length / 4) * 4, '=');

  // `atob` IS the alphabet check, and it is the only one. An explicit regex
  // beside it was two validations for one question: because the padding above
  // always produces a length that is a multiple of four, the regex rejected
  // everything `atob` would have, which left `atob`'s own failure branch
  // unreachable and therefore unprovable.
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new MigrationParseError('malformed', 'That code is not a readable export link.');
  }

  if (binary.length > MAX_MIGRATION_PAYLOAD_BYTES) {
    throw new MigrationParseError('too-large', 'That export is larger than this app will read.');
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Is this string shaped like a Google Authenticator export link? */
export function isMigrationUri(value: string): boolean {
  return /^otpauth-migration:\/\//i.test(value.trim());
}

/** Read an export link, or throw a {@link MigrationParseError}. */
export function parseMigrationUri(uri: string): MigrationPayload {
  const trimmed = uri.trim();
  if (trimmed.length > MAX_MIGRATION_URI_LENGTH) {
    throw new MigrationParseError('too-large', 'That export is larger than this app will read.');
  }
  if (!isMigrationUri(trimmed)) {
    throw new MigrationParseError('malformed', 'That is not a Google Authenticator export link.');
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new MigrationParseError('malformed', 'That is not a Google Authenticator export link.');
  }

  const raw = rawQueryParam(url.search, 'data');
  if (raw === null || raw.length === 0) {
    throw new MigrationParseError('malformed', 'That export link carries no data.');
  }

  let decoded: string;
  try {
    // NOT `URLSearchParams`, and not `decodeURI`: see the header.
    decoded = decodeURIComponent(raw);
  } catch {
    throw new MigrationParseError('malformed', 'That export link carries unreadable data.');
  }

  return readMigrationPayload(decodeBase64(decoded));
}
