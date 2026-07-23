/**
 * Bitwarden unencrypted-JSON serializer for the portable plaintext export.
 *
 * Emits the individual-vault export shape Bitwarden documents and that the
 * repo's own importer (`services/import/parsers/bitwarden.ts`) reads back:
 * a top-level `{ folders, items }` object. An individual-vault export has NO
 * `collections` key, so this serializer deliberately does not emit one
 * (PLAN §1.3).
 *
 * The field names and numeric codes here were verified 2026-07-23 against
 * <https://bitwarden.com/help/condition-bitwarden-import/> AND against the
 * repo's own `parsers/bitwarden.ts`, because emitting the wrong key silently
 * produces an empty item on re-import. Two names in particular:
 *
 * - a card's CVV field is **`code`**, never `cvv` (the importer reads
 *   `card.code`);
 * - an identity uses **`address1`/`address2`/`address3`**, **`postalCode`** and
 *   **`passportNumber`** — not `address`, `zip` or `passport`.
 *
 * Item `type` is numeric (1 = login, 2 = secure note, 3 = card, 4 = identity);
 * `fields[].type` is numeric (0 = text, 1 = hidden, 2 = boolean);
 * `passwordHistory[]` entries are `{ lastUsedDate, password }`.
 *
 * `secret` items have no Bitwarden equivalent, so they are mapped to secure
 * notes (type 2) with their value (and description/expiry) folded into `notes`
 * — the UI copy says so. Because every H-Vault item type is representable one
 * way or another, `omittedCount` is always 0 for this format.
 *
 * Folder hierarchy: Bitwarden folders are flat `{ id, name }` records, so each
 * distinct `folderPath` becomes one folder whose `name` IS the full slash path.
 * The importer maps an item's `folderId` to a single tag, so on re-import the
 * path resurfaces as a tag rather than a folder — a documented loss, not a bug.
 * A vault item's own `tags` have no Bitwarden home and are not carried.
 */

import type { ItemType } from '@hvault/shared';
import type {
  PortableItem,
  PortableLogin,
  PortableCard,
  PortableIdentity,
  PortableSecret,
  PortableCustomField,
  PortablePasswordHistoryEntry,
} from '../portableItem.js';

/** Numeric item-type codes, exactly as Bitwarden's importer expects. */
function typeCode(type: ItemType): number {
  switch (type) {
    case 'login':
      return 1;
    case 'note':
      return 2;
    case 'card':
      return 3;
    case 'identity':
      return 4;
    case 'secret':
      // No Bitwarden equivalent — mapped to a secure note (type 2).
      return 2;
  }
}

/** `fields[].type` codes: 0 = text, 1 = hidden, 2 = boolean. */
const FIELD_TYPE_CODE: Record<PortableCustomField['type'], number> = {
  text: 0,
  hidden: 1,
  boolean: 2,
};

// Fallbacks used only when a caller hands over a `PortableItem` whose `type`
// says login/card/identity/secret but whose sub-object is missing — a shape
// `toPortableItems` never produces, but the serializer must still emit a
// well-formed (empty) record rather than crash.
const EMPTY_LOGIN: PortableLogin = { username: '', password: '' };
const EMPTY_CARD: PortableCard = {
  cardholderName: '',
  number: '',
  expMonth: '',
  expYear: '',
  cvv: '',
};
const EMPTY_IDENTITY: PortableIdentity = { firstName: '', lastName: '' };
const EMPTY_SECRET: PortableSecret = { value: '' };

interface BitwardenFolder {
  id: string;
  name: string;
}

interface BitwardenUri {
  match: null;
  uri: string;
}

interface BitwardenLogin {
  uris: BitwardenUri[];
  username: string;
  password: string;
  totp: string | null;
}

interface BitwardenCard {
  cardholderName: string;
  brand: string | null;
  number: string;
  expMonth: string;
  expYear: string;
  /** The CVV. Bitwarden names this `code`, NOT `cvv` (PLAN §1.3). */
  code: string;
}

interface BitwardenIdentity {
  title: string | null;
  firstName: string;
  middleName: string | null;
  lastName: string;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
}

interface BitwardenField {
  name: string;
  value: string;
  type: number;
}

interface BitwardenPasswordHistoryEntry {
  lastUsedDate: string;
  password: string;
}

interface BitwardenItem {
  id: string;
  organizationId: null;
  folderId: string | null;
  type: number;
  name: string;
  notes: string | null;
  favorite: boolean;
  reprompt: number;
  fields?: BitwardenField[];
  passwordHistory?: BitwardenPasswordHistoryEntry[];
  login?: BitwardenLogin;
  card?: BitwardenCard;
  identity?: BitwardenIdentity;
  secureNote?: { type: number };
}

interface BitwardenExport {
  folders: BitwardenFolder[];
  items: BitwardenItem[];
}

/**
 * Deterministic UUID-shaped id from a counter. The ids only need to be unique
 * within the file and to link an item's `folderId` to a folder's `id`; both
 * Bitwarden and the repo's importer regenerate them on import, so a stable
 * synthetic value keeps the output deterministic without pulling in a random
 * source.
 */
function synthUuid(n: number): string {
  return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
}

function mapFields(customFields?: PortableCustomField[]): BitwardenField[] | undefined {
  if (!customFields || customFields.length === 0) return undefined;
  return customFields.map((f) => ({
    name: f.name,
    value: f.value,
    type: FIELD_TYPE_CODE[f.type],
  }));
}

function mapPasswordHistory(
  history?: PortablePasswordHistoryEntry[],
): BitwardenPasswordHistoryEntry[] | undefined {
  if (!history || history.length === 0) return undefined;
  return history.map((h) => ({ lastUsedDate: h.changedAt, password: h.password }));
}

/**
 * Serialize normalized portable items into a Bitwarden unencrypted-JSON string.
 *
 * @returns `{ content, omittedCount: 0 }` — every H-Vault type maps to some
 *   Bitwarden type, so nothing is omitted.
 */
export function toBitwardenJson(portable: readonly PortableItem[]): {
  content: string;
  omittedCount: number;
} {
  const folders: BitwardenFolder[] = [];
  const folderIdByPath = new Map<string, string>();
  let idCounter = 0;
  const nextId = (): string => synthUuid(++idCounter);

  /** Resolve a folder path to a folder id, minting the folder on first use. */
  const folderIdFor = (path: string): string | null => {
    if (path === '') return null;
    const existing = folderIdByPath.get(path);
    if (existing !== undefined) return existing;
    const id = nextId();
    folderIdByPath.set(path, id);
    folders.push({ id, name: path });
    return id;
  };

  const items: BitwardenItem[] = [];

  for (const p of portable) {
    const item: BitwardenItem = {
      id: nextId(),
      organizationId: null,
      folderId: folderIdFor(p.folderPath),
      type: typeCode(p.type),
      name: p.name,
      notes: p.notes.length > 0 ? p.notes : null,
      favorite: p.favorite,
      reprompt: 0,
    };

    // `toPortableItems` always populates the sub-object matching `type`; the
    // single `?? DEFAULT` per branch is one defensive guard against a malformed
    // input record, keeping each field read below unconditional.
    switch (p.type) {
      case 'login': {
        const login = p.login ?? EMPTY_LOGIN;
        item.login = {
          uris: (p.uris ?? []).map((uri) => ({ match: null, uri })),
          username: login.username,
          password: login.password,
          totp: p.totp ?? null,
        };
        break;
      }
      case 'note':
        item.secureNote = { type: 0 };
        break;
      case 'secret': {
        item.secureNote = { type: 0 };
        // A secret has no Bitwarden type of its own; fold its value, description
        // and expiry into the note body, the only place a secure note carries
        // free text.
        const secret = p.secret ?? EMPTY_SECRET;
        const parts = [
          secret.description ?? '',
          secret.value,
          secret.expiresAt !== undefined ? `Expires: ${secret.expiresAt}` : '',
        ].filter((s) => s.length > 0);
        if (parts.length > 0) item.notes = parts.join('\n\n');
        break;
      }
      case 'card': {
        const card = p.card ?? EMPTY_CARD;
        item.card = {
          cardholderName: card.cardholderName,
          brand: card.brand ?? null,
          number: card.number,
          expMonth: card.expMonth,
          expYear: card.expYear,
          code: card.cvv,
        };
        // A card's billing address has no Bitwarden card field; preserve it in
        // notes rather than drop it silently.
        if (card.billingAddress) {
          const a = card.billingAddress;
          const line = [a.street, a.city, a.state, a.zip, a.country]
            .filter((v) => v.length > 0)
            .join(', ');
          if (line) {
            item.notes = item.notes !== null ? `${item.notes}\n\nBilling address: ${line}` : line;
          }
        }
        break;
      }
      case 'identity': {
        const identity = p.identity ?? EMPTY_IDENTITY;
        const address = identity.address;
        item.identity = {
          title: null,
          firstName: identity.firstName,
          middleName: null,
          lastName: identity.lastName,
          address1: address ? address.street : null,
          address2: null,
          address3: null,
          city: address ? address.city : null,
          state: address ? address.state : null,
          postalCode: address ? address.zip : null,
          country: address ? address.country : null,
          company: identity.company ?? null,
          email: identity.email ?? null,
          phone: identity.phone ?? null,
          ssn: identity.ssn ?? null,
          username: null,
          passportNumber: identity.passport ?? null,
          licenseNumber: null,
        };
        break;
      }
    }

    const fields = mapFields(p.customFields);
    if (fields) item.fields = fields;
    const passwordHistory = mapPasswordHistory(p.passwordHistory);
    if (passwordHistory) item.passwordHistory = passwordHistory;

    items.push(item);
  }

  const doc: BitwardenExport = { folders, items };
  return { content: JSON.stringify(doc, null, 2), omittedCount: 0 };
}
