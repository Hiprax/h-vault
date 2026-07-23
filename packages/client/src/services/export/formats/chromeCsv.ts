/**
 * Chrome / Edge CSV serializer for the portable plaintext export.
 *
 * Emits the header the Chrome/Edge password importer (and the repo's own
 * `services/import/parsers/chrome.ts`) reads — verified 2026-07-23 against
 * <https://support.google.com/chrome/answer/13068232> (PLAN §1.3):
 *
 *   name,url,username,password,note
 *
 * Chrome requires `url`, `username`, `password`; its own export additionally
 * emits `name` and `note`, and the repo's importer reads all five
 * (case-insensitively), so this exact header round-trips through H-Vault too.
 *
 * This is a browser-password format: it can represent ONLY logins. Every other
 * item type — secure notes, cards, identities, secrets — has no row shape here
 * and is counted in `omittedCount` so the UI can state the loss honestly (PLAN
 * §1.2 principle 8: a silently short export is indistinguishable from a complete
 * one). Within a login it is also inherently lossy: there is no column for a
 * TOTP secret, custom fields, tags or the folder path, so those are not carried
 * — the export page's per-format "what this loses" note surfaces this, and a
 * user who needs those must choose Bitwarden JSON. Only the login's own free-text
 * `notes` maps to the `note` column.
 *
 * Values are written through {@link toCsv}, which quotes per RFC 4180 and NEVER
 * mutates a value (PLAN §1.7: the deliberate no formula-injection mitigation —
 * fidelity beats a mitigation that only half works).
 */

import { toCsv } from '../csvWriter.js';
import type { PortableItem } from '../portableItem.js';

/**
 * The Chrome / Edge password-CSV header, exact and ordered. Exported so a test
 * can assert byte-for-byte agreement with the documented format.
 */
export const CHROME_CSV_HEADER = ['name', 'url', 'username', 'password', 'note'] as const;

/**
 * Serialize normalized portable items into a Chrome / Edge password CSV string.
 *
 * Emits one row per login (its first URI, or `''` when it has none) and skips
 * every non-login item.
 *
 * @returns `{ content, omittedCount }` where `omittedCount` is the number of
 *   non-login items the CSV format cannot represent.
 */
export function toChromeCsv(portable: readonly PortableItem[]): {
  content: string;
  omittedCount: number;
} {
  const rows: string[][] = [];
  let omittedCount = 0;

  for (const p of portable) {
    if (p.type !== 'login') {
      // secure note / card / identity / secret — not representable here.
      omittedCount += 1;
      continue;
    }

    rows.push([
      p.name,
      p.uris?.[0] ?? '',
      p.login?.username ?? '',
      p.login?.password ?? '',
      p.notes,
    ]);
  }

  return { content: toCsv(CHROME_CSV_HEADER, rows), omittedCount };
}
