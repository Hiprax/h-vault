/**
 * URI helpers shared by the import parsers.
 *
 * The shared `uriEntrySchema` (packages/shared) normalizes bare domains to
 * `https://` and REJECTS any other scheme (only `http:`/`https:`/`mailto:` pass).
 * A single rejected URI fails the whole item's data validation, so parsers must
 * pre-filter here: an unsafe-scheme URL is dropped rather than allowed to sink
 * the entire login. Callers may preserve a dropped raw URL in the item's notes.
 */

const SAFE_SCHEME_RE = /^(https?:|mailto:)/i;
const ANY_SCHEME_RE = /^[a-z][a-z0-9+.-]*:/i;

/**
 * Convert a raw URL string into a vault URI entry, or `null` if it cannot be
 * represented safely.
 *
 * Accepts `http(s)`/`mailto` URLs, protocol-relative (`//host`) URLs, and bare
 * hosts/domains (which the schema will normalize to `https://`). Rejects any
 * explicit non-safe scheme (`android:`, `chrome-extension:`, `ftp:`,
 * `javascript:`, …).
 */
export function toUriEntry(raw: string): { uri: string; match: 'domain' } | null {
  const uri = raw.trim();
  if (!uri) return null;
  // Has an explicit scheme that is not one of the safe ones → cannot be stored.
  if (ANY_SCHEME_RE.test(uri) && !SAFE_SCHEME_RE.test(uri)) return null;
  return { uri, match: 'domain' };
}

/**
 * Best-effort hostname extraction, used to derive a display name when a source
 * record has no title/name column (e.g. Firefox exports).
 */
export function hostFromUrl(raw: string): string {
  const value = raw.trim();
  if (!value) return '';
  const withScheme =
    SAFE_SCHEME_RE.test(value) || ANY_SCHEME_RE.test(value) ? value : `https://${value}`;
  try {
    const host = new URL(withScheme).hostname;
    if (host) return host;
  } catch {
    // fall through to a manual strip
  }
  return (
    value
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .split('/')[0]
      ?.split('?')[0] ?? value
  );
}
