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
