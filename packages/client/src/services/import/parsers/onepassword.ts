import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * 1Password CSV export (best-effort; 1Password's column set varies by version).
 *
 * Recognizes the common headers used across 1Password 7/8 CSV exports:
 * `title/name`, `website/url/urls`, `username`, `password`, `otpauth/otp/totp`,
 * `notes`, and `tags` (comma/`;`-separated). Everything is imported as a login.
 */
export function parseOnepassword(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const name = pick(lc, 'title', 'name');
    const url = pick(lc, 'url', 'urls', 'website');
    const username = pick(lc, 'username');
    const password = pick(lc, 'password');
    const totp = pick(lc, 'otpauth', 'otp', 'totp', 'one-time password');
    const notes = pick(lc, 'notes', 'note');
    const tagsRaw = pick(lc, 'tags', 'tag');

    if (!name && !url && !username && !password && !notes) continue;

    const tags = tagsRaw
      ? tagsRaw
          .split(/[,;]/)
          .map((t) => t.trim())
          .filter(Boolean)
      : [];

    items.push(buildLogin({ name, urls: [url], username, password, totp, notes, tags }));
  }
  return items;
}
