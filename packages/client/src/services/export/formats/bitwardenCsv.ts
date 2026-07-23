/**
 * Bitwarden CSV serializer for the portable plaintext export.
 *
 * Emits the exact, ordered individual-vault CSV header Bitwarden documents and
 * that the repo's own importer (`services/import/parsers/bitwarden.ts`) reads
 * back — verified 2026-07-23 against
 * <https://bitwarden.com/help/condition-bitwarden-import/> (PLAN §1.3):
 *
 *   folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
 *
 * The CSV format can represent only logins and secure notes. Cards, identities
 * and secrets have no row shape here, so they are counted in `omittedCount`
 * (the JSON format carries them; the UI directs a user who needs those types to
 * Bitwarden JSON). Values are written through {@link toCsv}, which quotes per
 * RFC 4180 and NEVER mutates a value (see PLAN §1.7 on the deliberate no
 * formula-injection mitigation).
 *
 * Folder paths ride in the `folder` column and re-import as a single tag, and a
 * vault item's own `tags` have no Bitwarden column — both documented losses,
 * matching the JSON serializer.
 */

import { toCsv } from '../csvWriter.js';
import type { PortableItem, PortableCustomField } from '../portableItem.js';

/**
 * The Bitwarden individual-vault CSV header, exact and ordered. Exported so a
 * test can assert byte-for-byte agreement with the documented format.
 */
export const BITWARDEN_CSV_HEADER = [
  'folder',
  'favorite',
  'type',
  'name',
  'notes',
  'fields',
  'reprompt',
  'login_uri',
  'login_username',
  'login_password',
  'login_totp',
] as const;

/**
 * Render custom fields into Bitwarden's `fields` cell: one `name: value` line
 * per field. The importer folds this blob into the item's notes, so the exact
 * layout is not load-bearing — only that no field is silently dropped.
 */
function fieldsBlob(customFields?: PortableCustomField[]): string {
  if (!customFields || customFields.length === 0) return '';
  return customFields.map((f) => `${f.name}: ${f.value}`).join('\n');
}

/**
 * Serialize normalized portable items into a Bitwarden CSV string.
 *
 * @returns `{ content, omittedCount }` where `omittedCount` is the number of
 *   items (cards, identities, secrets) the CSV format cannot represent.
 */
export function toBitwardenCsv(portable: readonly PortableItem[]): {
  content: string;
  omittedCount: number;
} {
  const rows: string[][] = [];
  let omittedCount = 0;

  for (const p of portable) {
    if (p.type === 'login') {
      rows.push([
        p.folderPath,
        p.favorite ? '1' : '',
        'login',
        p.name,
        p.notes,
        fieldsBlob(p.customFields),
        '0',
        (p.uris ?? []).join(','),
        p.login?.username ?? '',
        p.login?.password ?? '',
        p.totp ?? '',
      ]);
    } else if (p.type === 'note') {
      rows.push([
        p.folderPath,
        p.favorite ? '1' : '',
        'note',
        p.name,
        p.notes,
        fieldsBlob(p.customFields),
        '0',
        '',
        '',
        '',
        '',
      ]);
    } else {
      // card / identity / secret — not representable in Bitwarden CSV.
      omittedCount += 1;
    }
  }

  return { content: toCsv(BITWARDEN_CSV_HEADER, rows), omittedCount };
}
