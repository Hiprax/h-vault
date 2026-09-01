export function maskEmail(email: string): string {
  const atIndex = email.lastIndexOf('@');
  if (atIndex <= 0) return '***';
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex);
  const first = local[0] ?? '';
  const last = local[local.length - 1] ?? '';
  return local.length <= 1 ? first + '***' + domain : first + '***' + last + domain;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  // Clamp the low end to 0. For 0 < bytes < 1 the logarithm is negative and
  // Math.floor rounds toward -Infinity, so the exponent would go negative:
  // Math.pow(1024, -1) then DIVIDES by 1/1024, i.e. multiplies the value by
  // 1024, and formatBytes(0.5) reported "512 B". A sufficiently small value
  // (Number.MIN_VALUE) underflowed the divisor to 0 and reported "Infinity B".
  const i = Math.min(Math.max(Math.floor(Math.log(bytes) / Math.log(k)), 0), sizes.length - 1);
  const size = sizes[i] ?? 'B';
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${size}`;
}

/**
 * If the URI has no recognized protocol, prepend https://.
 * Preserves empty strings and URIs that already have a scheme.
 */
export function normalizeUri(uri: string): string {
  if (!uri) return uri;
  if (/^(https?:|mailto:)/i.test(uri)) return uri;
  // Don't auto-prefix regex patterns or URIs with other schemes
  if (/^[a-z][a-z0-9+.-]*:/i.test(uri)) return uri;
  // Protocol-relative URIs: //example.com → https://example.com
  if (uri.startsWith('//')) return `https:${uri}`;
  return `https://${uri}`;
}

export function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID().replace(/-/g, '');
  }
  // Fallback for environments without crypto.randomUUID
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  }
  throw new Error('Cryptographic random API is unavailable. Cannot generate secure IDs.');
}

/**
 * The extension a document's name claims: the lowercased segment after the LAST
 * dot.
 *
 * ONE definition, in the shared package, because three places have to agree on it
 * and two of them cannot see each other: the browser derives `ext` for the sealed
 * metadata blob and checks it against the operator's advisory allowlist, and the
 * isolated render document keys its renderer off the same value. That document is
 * built as its own module graph and shares nothing with the application, so a copy
 * of this rule living on the app side would be a second copy by construction — and
 * the day someone teaches one of them about `.tar.gz`, the other keeps the old
 * answer.
 *
 * A name with NO dot, and a name whose only dot is LEADING, has no extension:
 * `Dockerfile`, `Makefile`, `.bashrc` and `.env` all answer `''`. That is a
 * decision rather than an oversight — recognising those would need a second lookup
 * keyed by whole filename, which is a second source of truth for one question. A
 * name with several dots keys on the last segment alone (`archive.tar.gz` is
 * `gz`), because that is what every file dialog and every content-type table in
 * general use does.
 *
 * A name ending in a dot answers `''` as well, and deliberately WITHOUT a guard of
 * its own: the slice after the final dot is empty, which is already the right
 * answer. A `lastDot === name.length - 1` check would read as caution and be
 * incapable of changing any outcome — a branch no test could ever fail on.
 *
 * Lower-cased, so `.SH` and `.sh` are one type. Nothing else is normalised: the
 * caller decides what an unrecognised extension means, and a value returned here
 * is never trusted as a claim about what a file actually contains.
 */
export function documentExtension(name: string): string {
  const lastDot = name.lastIndexOf('.');
  // `<= 0` covers both "no dot at all" (-1) and "the only dot is leading" (0).
  if (lastDot <= 0) return '';
  return name.slice(lastDot + 1).toLowerCase();
}
