import { identityDataSchema } from '@hvault/shared';
import { rowsToRecords, toLowerKeyed, pick } from '../csv';
import { buildLogin, buildNote, makeItem, normalizeCustomFieldType } from '../itemBuilders';
import type { ParsedImportItem } from '../types';

/**
 * Bitwarden export parser — handles both the JSON export (`.json`) and the CSV
 * export. JSON is the richer format and preserves item types (login / secure
 * note / card / identity), URIs, TOTP, folders, and custom fields.
 */
export function parseBitwarden(text: string): ParsedImportItem[] {
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    return parseBitwardenJson(trimmed);
  }
  return parseBitwardenCsv(text);
}

interface BwField {
  name?: string;
  value?: string;
  type?: number;
}

// The `email`/`phone` fields on identityDataSchema carry strict refinements
// (zod's email regex; a phone regex that forbids letters). Validating a candidate
// against the SHARED field schema — rather than a looser local regex — is what
// makes the "fold into notes instead of sinking the whole identity" fallback
// below actually hold: a value the local check accepted but the schema rejects
// would otherwise fail `identityDataSchema.safeParse` in the encrypt step and
// drop the entire identity.
function identityFieldValid(field: 'email' | 'phone', value: string): boolean {
  return identityDataSchema.shape[field].safeParse(value).success;
}

function parseBitwardenJson(text: string): ParsedImportItem[] {
  const root = JSON.parse(text) as Record<string, unknown>;
  const rawItems = Array.isArray(root.items)
    ? (root.items as Record<string, unknown>[])
    : Array.isArray(root)
      ? (root as unknown as Record<string, unknown>[])
      : [];

  const folderMap = new Map<string, string>();
  for (const f of (root.folders as ({ id?: string; name?: string } | undefined)[] | undefined) ??
    []) {
    if (f?.id != null && typeof f.name === 'string') folderMap.set(f.id, f.name);
  }

  const items: ParsedImportItem[] = [];
  for (const it of rawItems) {
    const name = str(it.name);
    const favorite = Boolean(it.favorite);
    const folderId = str(it.folderId);
    const folderName = folderId ? folderMap.get(folderId) : undefined;
    const tags = folderName ? [folderName] : [];
    const notes = str(it.notes);
    const fields = (Array.isArray(it.fields) ? it.fields : []) as BwField[];

    switch (it.type) {
      case 1: {
        const login = (it.login ?? {}) as Record<string, unknown>;
        const uris = Array.isArray(login.uris)
          ? (login.uris as ({ uri?: string } | undefined)[]).map((u) => str(u?.uri)).filter(Boolean)
          : [];
        items.push(
          buildLogin({
            name,
            username: str(login.username),
            password: str(login.password),
            urls: uris,
            totp: str(login.totp),
            notes,
            customFields: fields,
            tags,
            favorite,
          }),
        );
        break;
      }
      case 3: {
        const card = (it.card ?? {}) as Record<string, unknown>;
        const data: Record<string, unknown> = {
          cardholderName: str(card.cardholderName),
          number: str(card.number),
          expMonth: str(card.expMonth),
          expYear: str(card.expYear),
          cvv: str(card.code),
        };
        const brand = str(card.brand);
        if (brand) data.brand = brand;
        const foldedNotes = appendFields(notes, fields);
        if (foldedNotes) data.notes = foldedNotes;
        items.push(makeItem('card', name, data, { tags, favorite }));
        break;
      }
      case 4: {
        const id = (it.identity ?? {}) as Record<string, unknown>;
        const street = [str(id.address1), str(id.address2), str(id.address3)]
          .filter(Boolean)
          .join(', ');
        const data: Record<string, unknown> = {
          firstName: str(id.firstName),
          lastName: str(id.lastName),
        };
        if (street || str(id.city) || str(id.state) || str(id.postalCode) || str(id.country)) {
          data.address = {
            street,
            city: str(id.city),
            state: str(id.state),
            zip: str(id.postalCode),
            country: str(id.country),
          };
        }
        const company = str(id.company);
        if (company) data.company = company;
        const ssn = str(id.ssn);
        if (ssn) data.ssn = ssn;
        const passport = str(id.passportNumber);
        if (passport) data.passport = passport;

        // email/phone have strict shared validators; only set them when they look
        // valid, otherwise fold them into notes so a malformed value never sinks
        // the whole identity.
        let extraNote = '';
        const email = str(id.email);
        if (email && identityFieldValid('email', email)) data.email = email;
        else if (email) extraNote += `Email: ${email}\n`;
        const phone = str(id.phone);
        if (phone && identityFieldValid('phone', phone)) data.phone = phone;
        else if (phone) extraNote += `Phone: ${phone}\n`;

        const cf = mapCustomFields(fields);
        if (cf.length > 0) data.customFields = cf;
        const combinedNotes = [notes, extraNote.trim()].filter(Boolean).join('\n\n');
        if (combinedNotes) data.notes = combinedNotes;

        const derivedName = name || [str(id.firstName), str(id.lastName)].filter(Boolean).join(' ');
        items.push(makeItem('identity', derivedName, data, { tags, favorite }));
        break;
      }
      default: {
        // type 2 (secure note) and any unknown type → note
        items.push(buildNote({ name, content: appendFields(notes, fields), tags, favorite }));
        break;
      }
    }
  }
  return items;
}

function parseBitwardenCsv(text: string): ParsedImportItem[] {
  const { records } = rowsToRecords(text);
  const items: ParsedImportItem[] = [];
  for (const rec of records) {
    const lc = toLowerKeyed(rec);
    const type = pick(lc, 'type').toLowerCase();
    const name = pick(lc, 'name');
    const notes = pick(lc, 'notes');
    const folder = pick(lc, 'folder');
    const favorite = pick(lc, 'favorite') === '1';
    const fieldsBlob = pick(lc, 'fields');
    const tags = folder ? [folder] : [];
    const combinedNotes = [notes, fieldsBlob].filter(Boolean).join('\n\n');

    if (type === 'note') {
      if (!name && !combinedNotes) continue;
      items.push(buildNote({ name, content: combinedNotes, tags, favorite }));
      continue;
    }

    const uriBlob = pick(lc, 'login_uri', 'login_uris');
    const urls = uriBlob
      ? uriBlob
          .split(',')
          .map((u) => u.trim())
          .filter(Boolean)
      : [];
    const username = pick(lc, 'login_username');
    const password = pick(lc, 'login_password');
    const totp = pick(lc, 'login_totp');
    if (!name && !username && !password && urls.length === 0 && !combinedNotes) continue;
    items.push({
      ...buildLogin({ name, urls, username, password, totp, notes: combinedNotes, tags, favorite }),
    });
  }
  return items;
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '';
}

function mapCustomFields(
  fields: BwField[],
): { name: string; value: string; type: 'text' | 'hidden' | 'boolean' }[] {
  return fields
    .filter((f) => typeof f.name === 'string' && f.name.trim())
    .map((f) => ({
      name: (f.name ?? '').trim(),
      value: str(f.value),
      type: normalizeCustomFieldType(f.type),
    }));
}

function appendFields(notes: string, fields: BwField[]): string {
  const lines = fields
    .filter((f) => typeof f.name === 'string' && f.name.trim())
    .map((f) => `${(f.name ?? '').trim()}: ${str(f.value)}`);
  return [notes, ...lines].filter(Boolean).join('\n');
}
