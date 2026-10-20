import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  useForm,
  useFieldArray,
  useController,
  type Control,
  type SubmitHandler,
  type UseFormRegister,
  type FieldErrors,
  type FieldValues,
} from 'react-hook-form';
import type { UseFormSetError } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from '@hvault/shared/zod';
import {
  Key,
  FileText,
  CreditCard,
  User,
  Lock,
  Trash2,
  Star,
  Eye,
  EyeOff,
  Undo2,
  AlertTriangle,
} from 'lucide-react';
import { cn, getApiErrorMessage } from '../../lib/utils';
import { hasAnyValue, isUndecodableData } from '../../lib/vaultData';
import {
  BASE_ADDRESS_FIELDS,
  BILLING_ADDRESS_FIELD_NAMES,
  addressSearchText,
  billingFieldName,
  formatAddressSummary,
  hasBaseAddressValue,
  isBaseAddressField,
  readBaseAddress,
} from '../../lib/address';
import { getItemSubtitle } from '../../lib/vaultDisplay';
import {
  useVaultStore,
  EncryptedFieldTooLargeError,
  VaultItemDataInvalidError,
  type DecryptedVaultItem,
} from '../../stores/vaultStore';
import { useToast } from '../ui/Toast';
import { FormAlert } from '../ui/FormAlert';
import { TagEditor } from '../ui/TagEditor';
import { useTagField } from '../../hooks/useTagField';
import { CardExpiryNotice } from './CardExpiry';
import { readCardExpiry } from '../../lib/cardExpiry';
import { describeTotpFailure, parseTotpValue } from '../../lib/totp';
import {
  CARD_CVV_PATTERN,
  CARD_MONTH_PATTERN,
  CARD_NUMBER_INPUT_MAX_LENGTH,
  CARD_YEAR_PATTERN,
  cardNumberDigits,
  countFieldErrors,
  customFieldHasContent,
  expandCardYear,
  formatCardNumber,
  isCardNumberLength,
  isCleanCardNumber,
  isUntouched,
  isValidLuhn,
  shouldRecheckPartner,
  utf8ByteLength,
} from '../../lib/itemFormRules';
import { PasswordGenerator } from './PasswordGenerator';
import { BackupCodesEditor } from './BackupCodesEditor';
import { SavedAddressPicker, type SavedAddressOption } from './SavedAddressPicker';
import { inputClass } from './formStyles';
import { NoteContent } from './NoteContent';
import {
  MAX_ADDRESS_CITY_LENGTH,
  MAX_ADDRESS_COUNTRY_LENGTH,
  MAX_ADDRESS_DELIVERY_NOTES_LENGTH,
  MAX_ADDRESS_STATE_LENGTH,
  MAX_ADDRESS_STREET_LENGTH,
  MAX_ADDRESS_ZIP_LENGTH,
  MAX_CARD_BRAND_LENGTH,
  MAX_CARD_CARDHOLDER_NAME_LENGTH,
  MAX_CUSTOM_FIELD_NAME_LENGTH,
  MAX_IDENTITY_COMPANY_LENGTH,
  MAX_IDENTITY_EMAIL_LENGTH,
  MAX_IDENTITY_NAME_LENGTH,
  MAX_IDENTITY_PASSPORT_LENGTH,
  MAX_IDENTITY_PHONE_LENGTH,
  MAX_IDENTITY_SSN_LENGTH,
  MAX_ITEM_NAME_BYTES,
  MAX_LOGIN_BACKUP_CODES,
  MAX_LOGIN_BACKUP_CODE_LENGTH,
  MAX_LOGIN_PASSWORD_LENGTH,
  MAX_LOGIN_TOTP_LENGTH,
  MAX_LOGIN_USERNAME_LENGTH,
  MAX_NOTE_CONTENT_LENGTH,
  MAX_SECRET_DESCRIPTION_LENGTH,
  MAX_TAGS_PER_ITEM,
  DEFAULT_CUSTOM_FIELDS_LIMIT,
  URI_TOO_LONG_MESSAGE,
  isValidIdentityEmail,
  isValidIdentityPhone,
  isValidUriLength,
  normalizeUri,
} from '@hvault/shared';
import type { INoteData, ItemType } from '@hvault/shared';

/**
 * The custom-field limit hook, re-exported so the two pages that host the editor
 * import it FROM HERE. Not a convenience: the bundler gives code shared by the same
 * set of importers one chunk named after one of its modules, and with the pages
 * importing the hook directly that shared chunk (this editor plus the hook) was
 * named after the hook and measured against the default chunk budget instead of
 * the editor's own.
 */
export { useCustomFieldsLimit } from '../../hooks/useCustomFieldsLimit';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

const TYPE_TABS: { type: ItemType; label: string; icon: typeof Key }[] = [
  { type: 'login', label: 'Login', icon: Key },
  { type: 'secret', label: 'Secret', icon: Lock },
  { type: 'note', label: 'Note', icon: FileText },
  { type: 'card', label: 'Card', icon: CreditCard },
  { type: 'identity', label: 'Identity', icon: User },
];

// ---------------------------------------------------------------------------
// Zod schemas (one per item type)
// ---------------------------------------------------------------------------

/**
 * `YYYY-MM-DD` with a FOUR-digit year — all `secretDataSchema.expiresAt` represents,
 * and all `toISOString()` emits without switching to its extended-year form.
 *
 * Declared up here because the secret form schema refines against it, not only
 * `combineExpiry`: a year the vault cannot store has to be refused with a message
 * rather than quietly dropped.
 */
const EXPIRY_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;

/**
 * One bounded, optional free-text field for the local form schemas.
 *
 * A single factory rather than a bound repeated per field: the message wording and
 * the `.optional().default('')` shape then cannot drift between fields, and the
 * `max` always comes from the SHARED constant the stored schema uses, so "input
 * cap == stored cap" is provable rather than eyeballed.
 *
 * Every bound declared through this helper MUST have a control that renders its
 * message (see {@link BoundedTextField}). A bound with no visible message is worse
 * than no bound at all: react-hook-form simply refuses to call `onSubmit`, so Save
 * becomes a dead button with no toast and no explanation. That is why the ARRAY
 * caps (`uris`, `customFields`) are deliberately NOT mirrored here — no control
 * could show an array-level message, so those stay with the store's pre-flight
 * check, which reports them in a toast.
 */
function boundedField(max: number, label: string) {
  return z
    .string()
    .max(max, `${label} must be ${String(max)} characters or fewer`)
    .optional()
    .default('');
}

const uriEntrySchema = z
  .object({
    // Unbounded here, then bounded by the SHARED `isValidUriLength` after the
    // transform, exactly as the stored schema does. Bounding the input at
    // `MAX_URI_LENGTH` was a real defect rather than a cosmetic mismatch: the
    // transform prepends `https://` to a bare domain, so a 2041-2048 character one
    // passed this control, was stored eight characters longer, and every later save
    // of that item was refused by the write pre-flight with "Too big" on
    // `uris.0.uri` — an item the editor could open and never save again.
    uri: z.string().optional().default(''),
    match: z.enum(['domain', 'exact', 'startsWith', 'regex']).default('domain'),
  })
  .transform((entry) => ({
    ...entry,
    uri: entry.match === 'regex' ? entry.uri : normalizeUri(entry.uri),
  }))
  .refine((entry) => isValidUriLength(entry.uri, entry.match), {
    message: URI_TOO_LONG_MESSAGE,
    path: ['uri'],
  })
  .refine(
    (entry) => {
      if (entry.match === 'regex') return true;
      return !entry.uri || /^(https?:|mailto:)/i.test(entry.uri);
    },
    { message: 'URI must start with http://, https://, or mailto:', path: ['uri'] },
  )
  // The stored `uriEntrySchema` carries this refine too, and the local one did not, so
  // an uncompilable `match: 'regex'` pattern reached the store's write-side pre-flight
  // and came back as a toast rather than a message on the offending row. (Before that
  // pre-flight existed it was worse: the pattern was encrypted and only failed on the
  // next decrypt, degrading the whole login.) Same alignment argument as the identity
  // email/phone predicates.
  .refine(
    (entry) => {
      if (entry.match !== 'regex') return true;
      try {
        // eslint-disable-next-line security/detect-non-literal-regexp -- intentional: validating that the user's pattern compiles, exactly as the stored schema does
        new RegExp(entry.uri);
        return true;
      } catch {
        return false;
      }
    },
    { message: 'Invalid regular expression pattern', path: ['uri'] },
  );

// `name` keeps NO `.min(1)` on purpose — a blank "+ Add Field" row the user never
// filled in is STRIPPED before encryption (`stripEmptyCustomFields`) rather than
// blocking the save. The two length bounds do mirror the stored schema, and
// `CustomFieldsSection` renders their messages per row.
const customFieldBaseSchema = z.object({
  name: boundedField(MAX_CUSTOM_FIELD_NAME_LENGTH, 'Field name'),
  value: boundedField(MAX_NOTE_CONTENT_LENGTH, 'Field value'),
  type: z.enum(['text', 'hidden', 'boolean']).default('text'),
});

/**
 * A row with something in it must have a name.
 *
 * Only a COMPLETELY blank row is stripped before encryption. A row whose value was
 * filled in but whose name was left empty used to be stripped too, which threw away
 * what the person typed with no word about it; it is now refused, on the name, where
 * the fix goes. The message sits on the name rather than the value because the value
 * is the part that is right.
 */
function requireNameForContent(
  row: { name: string; value: string; type: string },
  ctx: z.RefinementCtx,
): void {
  if (row.name.trim() === '' && customFieldHasContent(row)) {
    ctx.addIssue({
      code: 'custom',
      path: ['name'],
      message: 'Give this field a name, or remove it',
    });
  }
}

const customFieldSchema = customFieldBaseSchema.superRefine(requireNameForContent);

/**
 * What the per-type schemas need to know about the entry being edited: the values
 * the form OPENED with (`getDefaultValues` for the stored item), or `null` while
 * creating. A blocking rule passes a control that still holds its opening value (see
 * `isUntouched`), so a field the person never touched can never stop them saving an
 * edit somewhere else in the entry.
 */
interface FormRuleContext {
  initial: Readonly<Record<string, unknown>> | null;
}

const CREATE_RULES: FormRuleContext = { initial: null };

/**
 * The item name, shared by all five types: required, and short enough to encrypt.
 *
 * The length is measured in UTF-8 BYTES because that is what the name's ciphertext is
 * as long as, and the bound is derived from the stored ciphertext cap
 * (`MAX_ITEM_NAME_BYTES`). Before, an over-long name was refused only after it had
 * been encrypted, in a toast, with nothing on the Name control. No stored name can
 * exceed it (its ciphertext fit the cap), so this never blocks an existing entry.
 */
function itemNameSchema(rules: FormRuleContext) {
  return z
    .string()
    .refine((value) => value.trim() !== '' || isUntouched(rules.initial, 'name', value), {
      message: 'Name is required',
    })
    .refine((value) => utf8ByteLength(value) <= MAX_ITEM_NAME_BYTES, {
      message: 'Name is too long. Shorten it to save this item.',
    });
}

/**
 * A required text field that tolerates an UNTOUCHED stored blank: imports store
 * these verbatim and may store them empty, and a value the person did not touch must
 * not block an edit elsewhere in the entry.
 */
function requiredText(rules: FormRuleContext, key: string, max: number, label: string) {
  return z
    .string()
    .max(max, `${label} must be ${String(max)} characters or fewer`)
    .refine((value) => value.trim() !== '' || isUntouched(rules.initial, key, value), {
      message: `${label} is required`,
    });
}

const loginSchema = (rules: FormRuleContext) =>
  z.object({
    name: itemNameSchema(rules),
    username: boundedField(MAX_LOGIN_USERNAME_LENGTH, 'Username'),
    password: boundedField(MAX_LOGIN_PASSWORD_LENGTH, 'Password'),
    uris: z.array(uriEntrySchema).optional().default([]),
    // Checked with the SAME parser the code display uses (`lib/totp.ts`), so a value
    // the editor accepts is one that can actually generate codes. A stored value that
    // fails it and was not touched is left alone (a warning under the control says
    // so) rather than blocking the save.
    totp: boundedField(MAX_LOGIN_TOTP_LENGTH, 'TOTP secret').superRefine((value, ctx) => {
      if (value.trim() === '' || isUntouched(rules.initial, 'totp', value)) return;
      const parsed = parseTotpValue(value);
      if (!parsed.ok) ctx.addIssue({ code: 'custom', message: describeTotpFailure(parsed.reason) });
    }),
    // Declaring this is not optional: zodResolver returns the PARSED values, so a
    // field the form schema does not know is stripped before `buildDataPayload` ever
    // sees it, and editing a login would silently destroy its stored codes. Kept
    // lenient (no bounds) like every other field here; `parseBackupCodes` gates what
    // can enter the array, and `sanitizeBackupCodes` bounds what leaves it.
    backupCodes: z.array(z.string()).optional().default([]),
    notes: boundedField(MAX_NOTE_CONTENT_LENGTH, 'Notes'),
    customFields: z.array(customFieldSchema).optional().default([]),
  });

// A secret's custom fields keep the NARROWER two-value type enum the form has always
// offered (`SecretDetail` has no boolean renderer), so its rows are driven with
// `allowBoolean={false}`.
//
// The shared `customFieldSchema` DOES permit `boolean` on a secret, so a stored
// secret carrying one would populate the form and then fail this enum on save with
// no rendered message — a dead Save button. It is unreachable, and the reason is
// structural rather than incidental: **no import parser can produce a `secret` item
// at all** (every parser routes through `buildLogin`/`buildNote`/`makeItem`, and the
// only `makeItem` call sites are `'card'` and `'identity'`), and an `overwrite`
// import cannot cross into one either, because the identity key is prefixed with the
// item type. A secret can only be created by this form, which already restricts the
// type. Widening the enum would be mildly WORSE, not better: `SecretDetail` would
// then render the value as a bare "true"/"false". Revisit the day a secret-producing
// parser is added — that is the day it becomes reachable.
//
// Extended from the UNREFINED base and refined afterwards: zod refuses `.extend()`
// that overwrites a key of a schema that already carries a refinement.
const secretCustomFieldSchema = customFieldBaseSchema
  .extend({ type: z.enum(['text', 'hidden']).default('text') })
  .superRefine(requireNameForContent);

/**
 * What an incomplete `<input type="date">` or `type="time"` is recorded as.
 *
 * The form validates itself (`noValidate`), so the browser no longer blocks a save
 * on a half-typed date, and a half-typed date READS as empty. Left alone, saving
 * would silently store "no expiry" (or midnight) for a date the person was in the
 * middle of entering. The control's own `validity.badInput` is the only signal, so
 * the form records it as this value, which no real date or time can equal and which
 * the schema refuses with a message on the control.
 */
const INCOMPLETE_INPUT = '\u0000incomplete';

const secretSchema = (rules: FormRuleContext) =>
  z
    .object({
      name: itemNameSchema(rules),
      value: z
        .string()
        .max(
          MAX_NOTE_CONTENT_LENGTH,
          `Value must be ${String(MAX_NOTE_CONTENT_LENGTH)} characters or fewer`,
        )
        .refine((value) => value !== '' || isUntouched(rules.initial, 'value', value), {
          message: 'Value is required',
        }),
      description: boundedField(MAX_SECRET_DESCRIPTION_LENGTH, 'Description'),
      // Bounded to a FOUR-digit year, which is all `secretDataSchema.expiresAt` can
      // represent. Chrome's date picker accepts years up to 275760, and without this the
      // value failed `EXPIRY_DATE_PATTERN`, `combineExpiry` returned `undefined`, and the
      // expiry was SILENTLY DELETED by a save that reported success — the exact class of
      // failure this whole area exists to eliminate. Now it is an inline message on the
      // control, which is where every other bound in this form reports itself. No `max`
      // attribute: the form is `noValidate`, so the browser would only mark the control
      // invalid without saying why, and the in-app message is the one that explains it.
      // A HALF-typed date reads as empty to script; `INCOMPLETE_INPUT` is how it is
      // told apart from a cleared one (see `syncIncompleteInputs`).
      expiryDate: z
        .string()
        .superRefine((value, ctx) => {
          if (value === INCOMPLETE_INPUT) {
            ctx.addIssue({ code: 'custom', message: 'Enter a complete date, or clear it' });
          } else if (value !== '' && !EXPIRY_DATE_PATTERN.test(value)) {
            ctx.addIssue({
              code: 'custom',
              message: 'Enter a date between 0001-01-01 and 9999-12-31',
            });
          }
        })
        .optional()
        .default(''),
      expiryTime: z
        .string()
        .refine((value) => value !== INCOMPLETE_INPUT, {
          message: 'Enter a complete time, or clear it',
        })
        .optional()
        .default(''),
      customFields: z.array(secretCustomFieldSchema).optional().default([]),
    })
    .superRefine((values, ctx) => {
      // A time on its own was silently ignored: `combineExpiry` needs a date, so the
      // save reported success and stored no expiry. The message goes on the DATE,
      // the control that is missing. A time left as it was is exempt: clearing the
      // DATE of a stored expiry is how its owner removes the expiry, and the stored
      // time must not turn that into an error.
      if (
        values.expiryTime !== '' &&
        values.expiryDate === '' &&
        !isUntouched(rules.initial, 'expiryTime', values.expiryTime)
      ) {
        ctx.addIssue({
          code: 'custom',
          path: ['expiryDate'],
          message: 'Add a date for this time, or clear the time',
        });
      }
    });

const noteSchema = (rules: FormRuleContext) =>
  z
    .object({
      name: itemNameSchema(rules),
      content: z
        .string()
        .max(
          MAX_NOTE_CONTENT_LENGTH,
          `Content must be ${String(MAX_NOTE_CONTENT_LENGTH)} characters or fewer`,
        ),
      // `format` is an undotted non-array root, so a store-side issue on it WOULD be
      // claimed by `formFieldForStoredPath` — and the `<select>` renders no message, so
      // it would be swallowed. Unreachable, and the reason is worth stating: the local
      // enum and `noteDataSchema.format` hold the same two values, and the only sources
      // are the two `<option>`s or already-parsed stored data. Widening either enum
      // without giving the control an error line would make it reachable.
      format: z.enum(['markdown', 'plaintext']).default('markdown'),
      customFields: z.array(customFieldSchema).optional().default([]),
    })
    .superRefine((values, ctx) => {
      // A note needs SOMETHING in it: its text, or at least one named custom field (a
      // note can now be nothing but fields, which is what a Bitwarden secure note with
      // fields and no text imports as). An untouched empty note is left alone.
      const hasNamedField = values.customFields.some((field) => field.name.trim() !== '');
      if (
        values.content === '' &&
        !hasNamedField &&
        !isUntouched(rules.initial, 'content', values.content)
      ) {
        ctx.addIssue({
          code: 'custom',
          path: ['content'],
          message: 'Write the note, or add a custom field',
        });
      }
    });

/** Convert empty string to undefined while preserving non-empty string values. */
function emptyToUndefined(value: unknown): string | undefined {
  if (typeof value !== 'string' || value === '') return undefined;
  return value;
}

/**
 * A card field with a FORMAT rule that an untouched stored value is exempt from:
 * empty passes (whether a value is required is decided elsewhere), an untouched
 * value passes, and anything else must match `pattern`.
 */
function cardFormatField(rules: FormRuleContext, key: string, pattern: RegExp, message: string) {
  return z
    .string()
    .refine(
      (value) => value === '' || isUntouched(rules.initial, key, value) || pattern.test(value),
      { message },
    )
    .optional()
    .default('');
}

const cardSchema = (rules: FormRuleContext) =>
  z
    .object({
      name: itemNameSchema(rules),
      cardholderName: requiredText(
        rules,
        'cardholderName',
        MAX_CARD_CARDHOLDER_NAME_LENGTH,
        'Cardholder name',
      ),
      // The RAW control text, never transformed here: the "untouched" test compares it
      // with the text the form opened with, and `buildModelledFields` is the one place
      // it is normalised for storage. 12 to 19 digits, because real cards span that
      // range (some Maestro cards have 12). The Luhn checksum is NOT a rule here: a
      // failure is shown as a warning beside the control, because some brands carry no
      // check digit and the vault must be able to store the card a person holds.
      number: z.string().superRefine((value, ctx) => {
        if (isUntouched(rules.initial, 'number', value)) return;
        const digits = cardNumberDigits(value);
        if (digits === '') {
          ctx.addIssue({ code: 'custom', message: 'Card number is required' });
        } else if (!isCardNumberLength(digits)) {
          ctx.addIssue({ code: 'custom', message: 'Card numbers have 12 to 19 digits' });
        }
      }),
      expMonth: cardFormatField(
        rules,
        'expMonth',
        CARD_MONTH_PATTERN,
        'Enter a month from 1 to 12',
      ),
      expYear: cardFormatField(rules, 'expYear', CARD_YEAR_PATTERN, 'Enter a year like 2029 or 29'),
      cvv: cardFormatField(rules, 'cvv', CARD_CVV_PATTERN, 'CVV must be 3 or 4 digits'),
      brand: boundedField(MAX_CARD_BRAND_LENGTH, 'Brand'),
      notes: boundedField(MAX_NOTE_CONTENT_LENGTH, 'Notes'),
      billingStreet: boundedField(MAX_ADDRESS_STREET_LENGTH, 'Street address'),
      billingStreet2: boundedField(MAX_ADDRESS_STREET_LENGTH, 'Street address line 2'),
      billingCity: boundedField(MAX_ADDRESS_CITY_LENGTH, 'City'),
      billingState: boundedField(MAX_ADDRESS_STATE_LENGTH, 'State'),
      billingZip: boundedField(MAX_ADDRESS_ZIP_LENGTH, 'ZIP'),
      billingCountry: boundedField(MAX_ADDRESS_COUNTRY_LENGTH, 'Country'),
      customFields: z.array(customFieldSchema).optional().default([]),
    })
    .superRefine((values, ctx) => {
      // An expiry is a month AND a year: either alone cannot say when the card expires,
      // so the expiry warnings could never fire for it. The message goes on the MISSING
      // half. A stored pair the person did not touch is left as it is.
      const month = values.expMonth;
      const year = values.expYear;
      if (
        isUntouched(rules.initial, 'expMonth', month) &&
        isUntouched(rules.initial, 'expYear', year)
      ) {
        return;
      }
      if (month !== '' && year === '') {
        ctx.addIssue({ code: 'custom', path: ['expYear'], message: 'Add the expiry year too' });
      } else if (year !== '' && month === '') {
        ctx.addIssue({ code: 'custom', path: ['expMonth'], message: 'Add the expiry month too' });
      }
    });

const identitySchema = (rules: FormRuleContext) =>
  z.object({
    name: itemNameSchema(rules),
    firstName: requiredText(rules, 'firstName', MAX_IDENTITY_NAME_LENGTH, 'First name'),
    lastName: requiredText(rules, 'lastName', MAX_IDENTITY_NAME_LENGTH, 'Last name'),
    // The FORMAT check is the shared predicate `identityDataSchema` itself uses, not
    // a local regex that approximates it. The old local regexes admitted values the
    // stored refines reject — a quoted email local part, a `+` that is not leading, a
    // punctuation-only phone with no digit — so the form accepted them, they were
    // encrypted, and the next decrypt degraded the whole identity to the "could not
    // be fully decoded" notice. Only the user-facing MESSAGE is local now.
    email: z
      .string()
      .max(MAX_IDENTITY_EMAIL_LENGTH, 'Email too long')
      .refine(isValidIdentityEmail, 'Enter a valid email address, like name@example.com')
      .optional()
      .default(''),
    phone: z
      .string()
      .max(MAX_IDENTITY_PHONE_LENGTH, 'Phone number too long')
      .refine(
        isValidIdentityPhone,
        'Enter a valid phone number: digits, spaces, ( ) . - and an optional leading +',
      )
      .optional()
      .default(''),
    street: boundedField(MAX_ADDRESS_STREET_LENGTH, 'Street address'),
    street2: boundedField(MAX_ADDRESS_STREET_LENGTH, 'Street address line 2'),
    city: boundedField(MAX_ADDRESS_CITY_LENGTH, 'City'),
    state: boundedField(MAX_ADDRESS_STATE_LENGTH, 'State'),
    zip: boundedField(MAX_ADDRESS_ZIP_LENGTH, 'ZIP'),
    country: boundedField(MAX_ADDRESS_COUNTRY_LENGTH, 'Country'),
    deliveryNotes: boundedField(MAX_ADDRESS_DELIVERY_NOTES_LENGTH, 'Delivery notes'),
    company: boundedField(MAX_IDENTITY_COMPANY_LENGTH, 'Company'),
    ssn: boundedField(MAX_IDENTITY_SSN_LENGTH, 'Social Security number'),
    passport: boundedField(MAX_IDENTITY_PASSPORT_LENGTH, 'Passport number'),
    notes: boundedField(MAX_NOTE_CONTENT_LENGTH, 'Notes'),
    customFields: z.array(customFieldSchema).optional().default([]),
  });

/**
 * Return the Zod schema that corresponds to a given item type, built for the entry
 * being edited (`rules.initial`) or for a new one (`CREATE_RULES`).
 */
function getSchemaForType(itemType: ItemType, rules: FormRuleContext = CREATE_RULES) {
  switch (itemType) {
    case 'login':
      return loginSchema(rules);
    case 'secret':
      return secretSchema(rules);
    case 'note':
      return noteSchema(rules);
    case 'card':
      return cardSchema(rules);
    case 'identity':
      return identitySchema(rules);
    default:
      return z.object({ name: z.string().min(1, 'Name is required') });
  }
}

// ---------------------------------------------------------------------------
// Secret expiry: an ABSOLUTE INSTANT, split across two local-time controls
//
// `expiresAt` drives a live countdown (`VaultItemDetail.formatRemainingTime`) and
// a `toLocaleString` display, both of which read it through `new Date(value)`. It
// is therefore an instant on the timeline, not a wall-clock reading, and the two
// controls are a LOCAL-TIME VIEW of that instant.
//
// The form used to treat it as neither: it captured only the date and `HH:mm` with
// a regex, threw away any `Z`, any `+HH:MM` offset and any seconds, and recombined
// the pieces as a zone-less `${date}T${time}`. ES2015 parses a zone-less date-TIME
// as LOCAL, so opening a secret stored as `…T23:59:00.000Z` and pressing Update
// without touching the expiry moved the deadline by the browser's UTC offset —
// silently, every time, and cumulatively across devices in different zones.
//
// Two decisions, stated rather than implied:
//
//  1. **A stored value is read through `new Date`, exactly as the countdown reads
//     it, and rendered in LOCAL time.** That is the only rule under which the
//     controls and the countdown describe the same instant for every stored form —
//     including a legacy zone-less `…T14:30` (which ES2015 defines as local, so it
//     still shows `14:30`) and a DATE-ONLY value (which ES2015 defines as UTC
//     midnight, so in a non-UTC zone the controls honestly show the neighbouring
//     local date and time rather than a date that lies about the instant).
//  2. **An untouched value is written back BYTE-IDENTICALLY.** When the recombined
//     local reading denotes the same instant as the stored string, the stored
//     string is returned verbatim. That keeps sub-minute precision the controls
//     cannot express, keeps a date-only value date-only (no silent promotion to
//     local midnight), and makes an edit that does not touch the expiry a true
//     no-op for the import content hash. Only a REAL change to either control
//     produces a fresh `toISOString()` instant — and an empty time control then
//     means LOCAL midnight of the chosen date, which is what picking a bare
//     calendar date means to the person picking it.
//
// The "untouched" test compares the CONTROL STRINGS, not the instants. That
// distinction is load-bearing during the AMBIGUOUS hour of a fall-back DST
// transition, where two distinct instants render to the same date + time pair: an
// instant comparison necessarily fails for one of them, so an untouched save
// rewrote that deadline an hour earlier — and moved the item's import content hash
// with it. String comparison has no ambiguous case.
// ---------------------------------------------------------------------------

/**
 * `HH:MM`, matched as a PREFIX rather than anchored at the end.
 *
 * `<input type="time">` with no `step` produces exactly `HH:MM` (a seconds-bearing
 * value is not one such a control yields, and a half-typed time is recorded as
 * `INCOMPLETE_INPUT` and refused by the schema — which is why there is no seconds
 * group to parse). The
 * prefix match is what keeps that true if a `step` is ever added: `HH:MM:SS` would
 * then still yield the right hour and minute, dropping only the precision this
 * control cannot express, instead of failing to match and silently collapsing the
 * expiry to local midnight.
 */
const EXPIRY_TIME_PATTERN = /^(\d{2}):(\d{2})/;

/** The item's stored `expiresAt` as a string, or `''` when it has none. */
function storedExpiry(data: Record<string, unknown>): string {
  return typeof data.expiresAt === 'string' ? data.expiresAt : '';
}

/**
 * The instant a stored `expiresAt` denotes, or `null` when there is none or it
 * cannot be parsed.
 *
 * The unparseable arm is not reachable from the UI — `secretDataSchema` rejects a
 * malformed `expiresAt` on decrypt, which degrades the item and both Edit guards
 * then refuse to open the form — but it is what keeps a hand-built or
 * future-format value from producing `NaN-NaN-NaN` in a date control.
 */
function parseExpiryInstant(value: string): Date | null {
  if (!value) return null;
  const instant = new Date(value);
  return Number.isNaN(instant.getTime()) ? null : instant;
}

function pad(value: number, width: number): string {
  return String(value).padStart(width, '0');
}

/**
 * `YYYY-MM-DD` for the LOCAL calendar date of `instant`.
 *
 * Exported for the property suite, which has to build the two control values the
 * way {@link getDefaultValues} builds them — a test that recomputed them from its
 * own copy of this formatting would be asserting against itself rather than
 * against the composition that actually runs.
 */
export function localDateValue(instant: Date): string {
  return `${pad(instant.getFullYear(), 4)}-${pad(instant.getMonth() + 1, 2)}-${pad(instant.getDate(), 2)}`;
}

/** `HH:MM` for the LOCAL wall-clock time of `instant`. Exported with {@link localDateValue}. */
export function localTimeValue(instant: Date): string {
  return `${pad(instant.getHours(), 2)}:${pad(instant.getMinutes(), 2)}`;
}

/**
 * Recombine the two local-time controls into the value to store: the stored
 * string verbatim when nothing moved, else a fresh absolute ISO instant.
 *
 * `undefined` (which {@link omitUndefined} then drops) means "no expiry", which in
 * practice is only an EMPTY date control: `secretSchema.expiryDate` now refines
 * against the same pattern, so a non-empty value that fails it is refused inline and
 * never reaches here. The pattern check below is therefore the empty-string gate plus
 * defense in depth — deliberately not removed, because it is what keeps a caller that
 * bypasses the form from producing an Invalid Date.
 *
 * Exported for the property suite: the repeated-hour case this function exists
 * for is reachable only in a DST-observing zone, and driving it through a
 * rendered form for hundreds of generated instants is not.
 */
export function combineExpiry(date: string, time: string, stored: string): string | undefined {
  const dateParts = EXPIRY_DATE_PATTERN.exec(date);
  if (!dateParts) return undefined;
  const timeParts = EXPIRY_TIME_PATTERN.exec(time);

  // "Untouched" is decided by comparing the CONTROL STRINGS with what the stored
  // instant renders as — not by comparing instants. The two agree everywhere except
  // the repeated hour of a fall-back DST transition, where two distinct instants
  // render to the SAME pair of control values: an instant comparison can satisfy at
  // most one of them, so the other fell through and was silently rewritten an hour
  // earlier. Comparing the rendered strings is an exact test of "the user did not
  // change either control", has no ambiguous case, and still preserves sub-minute
  // precision and a date-only value, because `getDefaultValues` produced the control
  // values with these very functions from this very instant.
  const storedInstant = parseExpiryInstant(stored);
  if (
    storedInstant !== null &&
    localDateValue(storedInstant) === date &&
    localTimeValue(storedInstant) === time
  ) {
    return stored;
  }

  // Built by mutation rather than `new Date(y, m, d, …)`, whose two-digit-year legacy
  // behaviour maps year 50 to 1950.
  const local = new Date(0);
  local.setFullYear(Number(dateParts[1]), Number(dateParts[2]) - 1, Number(dateParts[3]));
  local.setHours(Number(timeParts?.[1] ?? 0), Number(timeParts?.[2] ?? 0), 0, 0);
  return local.toISOString();
}

// ---------------------------------------------------------------------------
// Card number: shown grouped, stored as it was unless the person changed it
// ---------------------------------------------------------------------------

/** The item's stored card number as a string, or `''` when it has none. */
function storedCardNumber(data: Record<string, unknown>): string {
  return typeof data.number === 'string' ? data.number : '';
}

/**
 * The text the card-number control opens with: the stored number grouped in fours
 * when that changes nothing but spacing, and EXACTLY as stored otherwise.
 *
 * Formatting every stored number used to cost data: the formatter kept only 19
 * digits, so opening an imported 20-digit card and saving a change to its notes
 * silently stored a different number. A value that cannot be shown grouped without
 * changing it (letters, more than 19 digits) is now shown as it is, and
 * `buildModelledFields` writes it back byte for byte while the control is untouched.
 */
function cardNumberForDisplay(stored: string): string {
  return isCleanCardNumber(stored) ? formatCardNumber(stored) : stored;
}

/**
 * A custom-field list as a note or a card stores it: the rows worth keeping, or
 * `undefined` when there are none, which DELETES the key rather than storing `[]`.
 * The two older owners of the key default it to `[]` in their stored schema; these
 * two deliberately do not (see `noteDataSchema`), so an untouched note or card keeps
 * the byte-identical payload, and import identity, it had before the key existed.
 */
function storedCustomFieldsOrNothing(fields: unknown): unknown {
  const kept = stripEmptyCustomFields(fields);
  return Array.isArray(kept) && kept.length > 0 ? kept : undefined;
}

// ---------------------------------------------------------------------------
// Default values helper
// ---------------------------------------------------------------------------

function getDefaultValues(itemType: ItemType, item?: DecryptedVaultItem): Record<string, unknown> {
  const data: Record<string, unknown> = item?.data ?? {};

  switch (itemType) {
    case 'login':
      return {
        name: item?.name ?? '',
        username: data.username ?? '',
        password: data.password ?? '',
        uris: data.uris ?? [{ uri: '', match: 'domain' as const }],
        totp: data.totp ?? '',
        backupCodes: Array.isArray(data.backupCodes) ? data.backupCodes : [],
        notes: data.notes ?? '',
        customFields: data.customFields ?? [],
      };
    case 'secret': {
      // The stored instant, rendered in LOCAL time across the two controls — see
      // the "Secret expiry" section above for why this is not a string split.
      const instant = parseExpiryInstant(storedExpiry(data));
      return {
        name: item?.name ?? '',
        value: data.value ?? '',
        description: data.description ?? '',
        expiryDate: instant === null ? '' : localDateValue(instant),
        expiryTime: instant === null ? '' : localTimeValue(instant),
        customFields: data.customFields ?? [],
      };
    }
    case 'note':
      return {
        name: item?.name ?? '',
        content: data.content ?? '',
        format: data.format ?? 'markdown',
        customFields: data.customFields ?? [],
      };
    case 'card': {
      const billing = (data.billingAddress as Record<string, string> | undefined) ?? {};
      return {
        name: item?.name ?? '',
        cardholderName: data.cardholderName ?? '',
        number: cardNumberForDisplay(storedCardNumber(data)),
        expMonth: data.expMonth ?? '',
        expYear: data.expYear ?? '',
        cvv: data.cvv ?? '',
        brand: data.brand ?? '',
        notes: data.notes ?? '',
        billingStreet: billing.street ?? '',
        billingStreet2: billing.street2 ?? '',
        billingCity: billing.city ?? '',
        billingState: billing.state ?? '',
        billingZip: billing.zip ?? '',
        billingCountry: billing.country ?? '',
        customFields: data.customFields ?? [],
      };
    }
    case 'identity': {
      const address = (data.address as Record<string, string> | undefined) ?? {};
      return {
        name: item?.name ?? '',
        firstName: data.firstName ?? '',
        lastName: data.lastName ?? '',
        email: data.email ?? '',
        phone: data.phone ?? '',
        street: address.street ?? '',
        street2: address.street2 ?? '',
        city: address.city ?? '',
        state: address.state ?? '',
        zip: address.zip ?? '',
        country: address.country ?? '',
        deliveryNotes: address.deliveryNotes ?? '',
        // Read back for the same reason they are now emitted: declaring a field in
        // the local schema transfers ownership of it from `buildDataPayload`'s
        // merge to the form, so a field declared but NOT read here would be fed
        // back as `''` and destroyed by the first save.
        company: data.company ?? '',
        ssn: data.ssn ?? '',
        passport: data.passport ?? '',
        notes: data.notes ?? '',
        customFields: data.customFields ?? [],
      };
    }
    default:
      return { name: item?.name ?? '' };
  }
}

// ---------------------------------------------------------------------------
// Build data payload helper
// ---------------------------------------------------------------------------

/**
 * Drop custom-field entries whose name is blank after trimming.
 *
 * The shared `customFieldSchema` requires `name` to be a non-empty string
 * (`min(1)`). A blank-named entry (e.g. an "+ Add Field" row the user never
 * filled in) would pass the lenient form schema, get encrypted, and then fail
 * the shared schema on read-back — degrading the whole item to the "could not
 * be fully decoded" notice even though its ciphertext is intact. Stripping the
 * entry before encryption keeps the item readable; a field with a real name
 * but an empty value is intentionally retained.
 */
function stripEmptyCustomFields(fields: unknown): unknown {
  if (!Array.isArray(fields)) return fields;
  return (fields as Record<string, unknown>[]).filter((field) => {
    const name = field.name;
    return typeof name === 'string' && name.trim().length > 0;
  });
}

/**
 * Bound a login's backup codes to what the shared schema will accept on read-back.
 *
 * The editor already refuses anything out of bounds, so nothing here is reachable
 * through the UI, and that is exactly the point: it is the last line of defence
 * against the one failure this feature must never cause. A stored `backupCodes`
 * value the shared schema rejects makes `vaultStore.decryptItem` stamp
 * `_validationError`, and the detail view then replaces the WHOLE item with the
 * "could not be fully decoded" notice — costing the user UI access to the password
 * of a working account. `stripEmptyCustomFields` above exists for the same reason.
 *
 * Exported so its bounds are unit-tested directly rather than only through the UI
 * paths that cannot reach them.
 */
export function sanitizeBackupCodes(codes: unknown): string[] {
  if (!Array.isArray(codes)) return [];
  return (codes as unknown[])
    .filter(
      (code): code is string =>
        typeof code === 'string' && code.length > 0 && code.length <= MAX_LOGIN_BACKUP_CODE_LENGTH,
    )
    .slice(0, MAX_LOGIN_BACKUP_CODES);
}

/**
 * Drop every key whose value is `undefined`, so the payload's key set is exactly
 * what will be encrypted.
 *
 * `vaultStore` runs `JSON.stringify` over this object, which already omits
 * `undefined` values — but the object itself is also what a caller (and every
 * test) inspects, and, decisively, it is now MERGED over the item's existing
 * decrypted data (see {@link buildDataPayload}). An explicit `undefined` is how a
 * type branch says "delete this key": leaving it in place would make
 * `{...preserved, backupCodes: undefined}` still report `'backupCodes' in payload`
 * even though the encrypted blob has none.
 */
function omitUndefined(payload: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(payload)) {
    if (value !== undefined) out[key] = value;
  }
  return out;
}

/**
 * Build the decrypted `data` blob to encrypt, from the form values MERGED OVER the
 * item's existing decrypted data.
 *
 * The merge is the whole point and is not an optimization. `vaultStore.updateItem`
 * encrypts `JSON.stringify(data)` WHOLESALE with no merge of its own, so whatever
 * this function omits is destroyed permanently — and there is no server-side copy
 * of the plaintext to recover it from. The type branches below emit only the fields
 * their local form schema declares, which can be fewer than the shared schemas
 * store. Before the merge, correcting a typo in an imported identity's city
 * silently and permanently erased its SSN, passport, company, notes and every
 * custom field, all of which the Bitwarden importer populates.
 *
 * Those six fields now HAVE controls, so the merge no longer carries them — but it
 * is not thereby redundant, and must not be removed. It is what makes the next
 * field added to a shared schema safe by default rather than destructive until
 * someone remembers to wire it up, which is exactly how that class of loss arose.
 *
 * `zodResolver` is the contributing cause: it hands `onSubmit` the PARSED values, so
 * a key the local schema does not declare never reaches `values` at all. Declaring
 * every stored field in every local schema would work but has to be redone for each
 * field anyone ever adds; spreading the stored blob closes the class once.
 *
 * Two constraints, both load-bearing:
 *
 * - The spread is guarded by `isUndecodableData`. `vaultStore.decryptItem` leaves a
 *   PLACEHOLDER in `item.data` (`{...parsed, _validationError: true}` or
 *   `{_raw: …}`) for a payload that failed schema validation, and re-encrypting that
 *   wrapper over real ciphertext is exactly the destruction `updateItemMeta` exists
 *   to avoid. (The Edit affordance is itself gated on the same predicate, so this is
 *   the second of two independent guards.)
 * - A CREATE has nothing to preserve, hence the explicit `item != null` arm.
 *
 * A branch that wants a key GONE must set it to `undefined`; {@link omitUndefined}
 * then removes it from the merged result. Simply omitting it from the branch would
 * now leave the previous value in place.
 */
function buildDataPayload(
  itemType: ItemType,
  values: Record<string, unknown>,
  item?: DecryptedVaultItem,
): Record<string, unknown> {
  const preserved = item != null && !isUndecodableData(item.data) ? item.data : {};
  return omitUndefined({ ...preserved, ...buildModelledFields(itemType, values, preserved) });
}

/**
 * The subset of a payload the form actually renders controls for.
 *
 * `preserved` is the item's existing decrypted data (`{}` for a create, and `{}`
 * for an undecodable item — {@link buildDataPayload} substitutes it, so nothing
 * here can read a placeholder). The secret and card branches consult it, to decide
 * whether a value the user did not touch (an expiry, a card number, an expiry year)
 * can be written back verbatim.
 *
 * No branch emits `name`. The item name is encrypted SEPARATELY as
 * `encryptedName`; no decrypted data schema declares a `name` key, so every one of
 * these strips it on read-back and `item.data.name` is never present after
 * `decryptItem`. It was dead weight in every item's ciphertext.
 */
function buildModelledFields(
  itemType: ItemType,
  values: Record<string, unknown>,
  preserved: Record<string, unknown>,
): Record<string, unknown> {
  switch (itemType) {
    case 'login': {
      const backupCodes = sanitizeBackupCodes(values.backupCodes);
      return {
        username: values.username,
        password: values.password,
        uris: values.uris,
        totp: emptyToUndefined(values.totp),
        // `undefined` rather than an omitted key, so clearing the section DELETES a
        // stored list instead of letting the merge above put it back. Absent (not
        // `[]`) is still what gets encrypted, the same way `billingAddress` is
        // absent below: an untouched login's payload stays byte-identical to what
        // it was before this field existed.
        backupCodes: backupCodes.length > 0 ? backupCodes : undefined,
        notes: emptyToUndefined(values.notes),
        customFields: stripEmptyCustomFields(values.customFields),
      };
    }
    case 'secret': {
      return {
        value: values.value,
        description: emptyToUndefined(values.description),
        expiresAt: combineExpiry(
          (values.expiryDate as string) || '',
          (values.expiryTime as string) || '',
          storedExpiry(preserved),
        ),
        customFields: stripEmptyCustomFields(values.customFields),
      };
    }
    case 'note':
      return {
        content: values.content,
        format: values.format,
        customFields: storedCustomFieldsOrNothing(values.customFields),
      };
    case 'card': {
      const billingStreet = (values.billingStreet as string) || '';
      const billingStreet2 = (values.billingStreet2 as string) || '';
      const billingCity = (values.billingCity as string) || '';
      const billingState = (values.billingState as string) || '';
      const billingZip = (values.billingZip as string) || '';
      const billingCountry = (values.billingCountry as string) || '';
      // `billingStreet2` belongs in this list: without it, a billing address whose
      // ONLY entry is a second line (an apartment or a PO box) emits no
      // `billingAddress` at all and the value is silently discarded on save.
      const hasBilling = hasAnyValue([
        billingStreet,
        billingStreet2,
        billingCity,
        billingState,
        billingZip,
        billingCountry,
      ]);
      // The number and the year are written back VERBATIM while the control still
      // holds what the form opened with, so an edit elsewhere never rewrites them
      // (an imported 20-digit number, a 2-digit year). A changed number is stored as
      // its digits; a changed 2-digit year as `20YY`.
      const storedNumber = storedCardNumber(preserved);
      const number = values.number as string;
      const storedYear = typeof preserved.expYear === 'string' ? preserved.expYear : undefined;
      const year = values.expYear as string;
      return {
        cardholderName: values.cardholderName,
        number:
          number === cardNumberForDisplay(storedNumber) && storedNumber !== ''
            ? storedNumber
            : cardNumberDigits(number),
        expMonth: values.expMonth,
        expYear: year === storedYear ? year : expandCardYear(year),
        cvv: values.cvv,
        brand: emptyToUndefined(values.brand),
        notes: emptyToUndefined(values.notes),
        // `undefined`, not an omitted key: removing the section must DELETE a
        // stored address, which the merge in buildDataPayload would otherwise
        // restore.
        billingAddress: hasBilling
          ? {
              street: billingStreet,
              street2: billingStreet2,
              city: billingCity,
              state: billingState,
              zip: billingZip,
              country: billingCountry,
            }
          : undefined,
        customFields: storedCustomFieldsOrNothing(values.customFields),
      };
    }
    case 'identity': {
      const street = (values.street as string) || '';
      const street2 = (values.street2 as string) || '';
      const city = (values.city as string) || '';
      const state = (values.state as string) || '';
      const zip = (values.zip as string) || '';
      const country = (values.country as string) || '';
      const deliveryNotes = (values.deliveryNotes as string) || '';
      // Conditional, exactly like the card's `billingAddress` — and for a reason
      // that goes beyond symmetry. `identityDataSchema.address` is `.optional()`
      // with NO default, so an ABSENT address and a present all-empty one parse to
      // different objects and hash differently. The Bitwarden importer omits the key
      // entirely for a source entry with no address, so emitting it unconditionally
      // made the FIRST save of such an identity change its import identity: the same
      // file re-imported afterwards no longer matched and inserted a duplicate.
      //
      // The other five fields need no such guard: `customFields` defaults to `[]` (so
      // `[]` and absent parse identically) and the three strings plus `notes` collapse
      // to `undefined` here, which `omitUndefined` removes.
      const hasAddress = hasAnyValue([street, street2, city, state, zip, country, deliveryNotes]);
      return {
        firstName: values.firstName,
        lastName: values.lastName,
        email: emptyToUndefined(values.email),
        phone: emptyToUndefined(values.phone),
        // `undefined`, not an omitted key: clearing every address field on an
        // identity that HAD one must delete it rather than let the merge restore it.
        address: hasAddress
          ? { street, street2, city, state, zip, country, deliveryNotes }
          : undefined,
        company: emptyToUndefined(values.company),
        ssn: emptyToUndefined(values.ssn),
        passport: emptyToUndefined(values.passport),
        notes: emptyToUndefined(values.notes),
        customFields: stripEmptyCustomFields(values.customFields),
      };
    }
    default:
      return values;
  }
}

/**
 * Title for the failure toast, keyed on the store's two typed pre-flight errors.
 *
 * Both are raised BEFORE anything is sent, so their titles say what the user has
 * to change rather than reporting a network failure they cannot act on.
 */
function resolveSaveErrorTitle(err: unknown): string {
  if (err instanceof EncryptedFieldTooLargeError) return 'Item too large to save';
  if (err instanceof VaultItemDataInvalidError) return 'Item could not be saved';
  return 'Failed to save item';
}

// ---------------------------------------------------------------------------
// Mapping a STORE-side validation failure back onto a form control
//
// `assertValidItemData` throws from the store, not from `zodResolver`, so
// `formState.errors` is empty and no control gets an inline message or
// `aria-invalid`: the user saw only a toast, truncated at 200 characters by
// `getApiErrorMessage`. Mirroring the stored bounds into the local schemas (above)
// catches the common cases before submit; this handles whatever is left.
//
// The hard part is that the issue paths are STORED-schema paths, and several do not
// match the form's field names. `setError('address.city', …)` binds to nothing and
// renders nothing — strictly worse than the toast, because the message simply
// vanishes. So the mapping is explicit, and a path with no mapping deliberately
// falls back to the toast.
// ---------------------------------------------------------------------------

/**
 * How many issues are mapped onto controls before the rest fall back to the toast.
 *
 * Bounded because each `setError` re-renders, and a payload built from a 100-entry
 * `customFields` array could otherwise produce hundreds. Five is more than any
 * hand-edited item produces and comfortably more than the two the error MESSAGE
 * lists.
 */
const MAX_MAPPED_FIELD_ISSUES = 5;

/**
 * An identity's address adds `deliveryNotes`. Kept as a separate list rather than a
 * spread-plus-extra so a card can never map a `billingAddress.deliveryNotes` path
 * onto a `billingDeliveryNotes` control that does not exist — the base
 * `addressSchema` strips that key, so such a path cannot arise, and this makes it
 * unrepresentable too.
 *
 * `BASE_ADDRESS_FIELDS` and `billingFieldName` now live in `lib/address` because a
 * third consumer joined this one and the billing controls: the saved-address
 * picker, which writes those very control names.
 */
const IDENTITY_ADDRESS_FIELDS = [...BASE_ADDRESS_FIELDS, 'deliveryNotes'] as const;

/**
 * Roots that hold an ARRAY.
 *
 * A stored issue on one of these WITHOUT an index is an array-level message — a
 * length cap — and no control renders one, so it must fall back to the toast. This
 * is not hypothetical: the `customFields` (100) and `uris` (100) caps are
 * deliberately not mirrored into the local schemas for exactly the same reason, so
 * the store's pre-flight is the only thing that reports them.
 */
const ARRAY_FIELD_ROOTS = new Set(['uris', 'customFields', 'backupCodes']);

/**
 * The indexed leaves that DO render a message: a custom-field row's name/value
 * (`CustomFieldsSection`) and a URI row's uri (the login URI block). Every other
 * leaf below an array — a URI's `match`, a custom field's `type` — is a `<select>`
 * with no message, so it stays unmapped.
 */
const RENDERED_INDEXED_LEAF = /^(?:customFields\.\d+\.(?:name|value)|uris\.\d+\.uri)$/;

/**
 * The form field name for a stored-schema issue path, or `null` when the form has
 * no control that would render the message.
 *
 * `null` is not a failure mode — it is the signal to keep the toast. Claiming a path
 * the form cannot render is strictly WORSE than the toast it replaces, because
 * `setError` on an unbound path silently swallows the message.
 */
function formFieldForStoredPath(itemType: ItemType, path: string): string | null {
  // An identity's nested `address.<field>` is flat on the form: `city`, not
  // `address.city`.
  if (itemType === 'identity' && path.startsWith('address.')) {
    const field = path.slice('address.'.length);
    return (IDENTITY_ADDRESS_FIELDS as readonly string[]).includes(field) ? field : null;
  }
  // A card's `billingAddress.<field>` is prefixed on the form: `billingCity`.
  if (itemType === 'card' && path.startsWith('billingAddress.')) {
    const field = path.slice('billingAddress.'.length);
    return isBaseAddressField(field) ? billingFieldName(field) : null;
  }
  // One stored instant, two controls. The date owns the message because it is the
  // control that decides whether an expiry exists at all.
  if (itemType === 'secret' && path === 'expiresAt') return 'expiryDate';

  // Everything else shares the name with the form, but only where a control exists.
  const shape = getSchemaForType(itemType).shape as Record<string, unknown>;
  const root = path.split('.')[0] ?? '';
  if (!Object.hasOwn(shape, root)) return null;
  // An indexed leaf the form renders a message for — the exact string `register`
  // was called with.
  if (RENDERED_INDEXED_LEAF.test(path)) return path;
  // Any other dotted path is below a scalar the form models flat, so nothing would
  // render it; an array root on its own has no control either.
  if (root !== path || ARRAY_FIELD_ROOTS.has(root)) return null;
  return path;
}

/**
 * Put each store-side issue on its control. Returns true only when EVERY issue
 * landed somewhere visible, which is the caller's signal that the toast would be
 * redundant; anything unmapped (or beyond the cap) keeps the toast, so a failure is
 * never silent.
 */
function applyStoreValidationErrors(
  err: unknown,
  itemType: ItemType,
  setError: UseFormSetError<Record<string, unknown>>,
): boolean {
  if (!(err instanceof VaultItemDataInvalidError) || err.fieldIssues.length === 0) return false;
  const mapped = err.fieldIssues.slice(0, MAX_MAPPED_FIELD_ISSUES).map((issue) => ({
    issue,
    field: formFieldForStoredPath(itemType, issue.path),
  }));
  for (const { issue, field } of mapped) {
    if (field !== null) setError(field, { type: 'server', message: issue.message });
  }
  return (
    err.fieldIssues.length <= MAX_MAPPED_FIELD_ISSUES && mapped.every(({ field }) => field !== null)
  );
}

// ---------------------------------------------------------------------------
// Reusable form field wrapper
// ---------------------------------------------------------------------------

function FormField({
  label,
  name,
  children,
  error,
}: {
  label: string;
  name?: string | undefined;
  children: React.ReactNode;
  error?: string | undefined;
}) {
  const fieldId = name ? `field-${name}` : undefined;
  const errorId = name && error ? `field-${name}-error` : undefined;
  return (
    <div>
      <label
        htmlFor={fieldId}
        className="mb-1.5 block text-sm font-medium text-[hsl(var(--foreground))]"
      >
        {label}
      </label>
      {children}
      {error && (
        <p id={errorId} role="alert" className="mt-1 text-xs text-[hsl(var(--destructive))]">
          {error}
        </p>
      )}
    </div>
  );
}

/** Whether an event target is a control a registered field can live in. */
function isFormControl(
  target: EventTarget,
): target is HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement {
  return (
    target instanceof HTMLInputElement ||
    target instanceof HTMLTextAreaElement ||
    target instanceof HTMLSelectElement
  );
}

/**
 * Whether a mouse or touch press on `target` leaves focus where it is: a button, or
 * a label around a checkbox or a button (a yes/no field, "Mark as favorite").
 *
 * Leaving a field shows what it got wrong (a message, the card number's checksum
 * warning, a two-digit year written out, the expiry hint), and that can push what
 * is below it down the page. Were the press itself to take focus, that would
 * happen between the press and its release, under the pointer: the button would
 * move away and the click would never happen. So such a press keeps focus in the
 * field, the click goes through, and the field is checked when focus really
 * leaves it, or by the save the click starts. A field, a list or a slider takes
 * focus as usual (preventing it would stop a list from opening).
 */
function pressKeepsFocus(target: EventTarget): boolean {
  if (!(target instanceof Element)) return false;
  const control = target.closest('button, label');
  if (control === null) return false;
  return (
    control.tagName !== 'LABEL' || control.querySelector('input[type="checkbox"], button') !== null
  );
}

interface ExpiryControlProps {
  control: Control<Record<string, unknown>>;
  name: 'expiryDate' | 'expiryTime';
  label: string;
  type: 'date' | 'time';
  /** The DOM node, which the form reads `validity.badInput` from. */
  inputRef: React.RefObject<HTMLInputElement | null>;
  /** Called when the control is left, after react-hook-form has seen the blur. */
  onLeave: () => void;
  onValueChange?: (() => void) | undefined;
}

/**
 * A secret's expiry date or time, CONTROLLED rather than `register`ed, and that is
 * the point of it.
 *
 * A half-typed date reads as empty to script, so the form records it as
 * `INCOMPLETE_INPUT` and the schema refuses it. A `register`ed control would have
 * that value WRITTEN INTO the element, where the browser sanitises it to `''` and
 * wipes what the person had typed, after which nothing remembers the date was ever
 * incomplete and the next save stores no expiry. Here the element shows `''` for
 * the recorded value, which React does not write over a half-typed date (the node
 * already reads `''`), so the person's partial entry stays on screen.
 */
function ExpiryControl({
  control,
  name,
  label,
  type,
  inputRef,
  onLeave,
  onValueChange,
}: ExpiryControlProps) {
  const { field, fieldState } = useController({ name, control });
  const value =
    typeof field.value === 'string' && field.value !== INCOMPLETE_INPUT ? field.value : '';
  const error = fieldState.error?.message;
  return (
    <FormField label={label} name={name} error={error}>
      <input
        id={`field-${name}`}
        ref={(node) => {
          field.ref(node);
          inputRef.current = node;
        }}
        name={field.name}
        type={type}
        value={value}
        onChange={(e) => {
          field.onChange(e.target.value);
          onValueChange?.();
        }}
        onBlur={() => {
          field.onBlur();
          onLeave();
        }}
        className={inputClass}
        aria-describedby={error ? `field-${name}-error` : undefined}
        aria-invalid={error ? true : undefined}
      />
    </FormField>
  );
}

/** The message react-hook-form holds for `name`, when it is a string. */
function fieldErrorMessage(errors: FieldErrors, name: string): string | undefined {
  const message = errors[name]?.message;
  return typeof message === 'string' ? message : undefined;
}

interface BoundedTextFieldProps {
  name: string;
  label: string;
  placeholder: string;
  maxLength: number;
  register: UseFormRegister<FieldValues>;
  errors: FieldErrors;
  multiline?: boolean;
  rows?: number;
  /**
   * A caller's own handle on the control, MERGED with the one `register`
   * installs rather than replacing it.
   *
   * Exists for focus management: a section that appears in response to an action
   * has to be given focus explicitly, and react-hook-form's `setFocus` was
   * verified to be a silent no-op for these controls — it resolves the node
   * through its own registry and returned nothing, so focus stayed on `<body>`
   * while the code read as though it had been moved.
   */
  inputRef?: React.RefObject<HTMLElement | null> | undefined;
}

/**
 * One bounded free-text control: a `maxLength`, and the SAME three-part error
 * plumbing every other bounded field needs (the visible message,
 * `aria-describedby`, `aria-invalid`).
 *
 * Centralized rather than repeated per field, and the reason is not tidiness. A
 * bound with no visible message is worse than no bound at all: react-hook-form
 * refuses to call `onSubmit`, so Save becomes a dead button with no toast and no
 * explanation. Every field whose stored cap is now mirrored into the local schema
 * therefore has to render that message, and doing it inline would multiply the same
 * two conditionals across two dozen controls.
 *
 * Grew out of the address-only `AddressInput`: the thirteen address controls are
 * still its main client, joined by the login/card/identity `notes`, a secret's
 * `description`, a card's `brand`, and an identity's `company`.
 */
function BoundedTextField({
  name,
  label,
  placeholder,
  maxLength,
  register,
  errors,
  multiline = false,
  rows = 2,
  inputRef,
}: BoundedTextFieldProps) {
  const error = fieldErrorMessage(errors, name);
  const shared = {
    id: `field-${name}`,
    placeholder,
    maxLength,
    autoComplete: 'off',
    'aria-describedby': error ? `field-${name}-error` : undefined,
    'aria-invalid': error ? true : undefined,
  };
  const registration = register(name);
  /**
   * Declared AFTER the `registration` spread at both call sites so it wins, and it
   * forwards to `registration.ref` FIRST — dropping that call would silently
   * unregister the field. `register` already returns a fresh `ref` on every
   * render, so this adds no re-attachment churn.
   *
   * Applied to BOTH branches. Forwarding only on the `<input>` one would leave a
   * caller that passes `inputRef` to a multiline field holding a ref that stays
   * `null` and a focus call that quietly does nothing — the exact silent no-op
   * this prop exists to replace.
   */
  const setNode = (node: HTMLInputElement | HTMLTextAreaElement | null): void => {
    registration.ref(node);
    if (inputRef) inputRef.current = node;
  };
  return (
    <FormField label={label} name={name} error={error}>
      {multiline ? (
        <textarea
          {...shared}
          {...registration}
          ref={setNode}
          rows={rows}
          className={cn(inputClass, 'resize-y')}
        />
      ) : (
        <input {...shared} {...registration} ref={setNode} className={inputClass} />
      )}
    </FormField>
  );
}

/**
 * A bounded control for a value that must not be readable over the user's shoulder:
 * an identity's Social Security and passport numbers.
 *
 * Follows the login password field's reveal toggle rather than the CVV's bare
 * `type="password"`, because these are values a user types from a document and needs
 * to proof-read. Same error plumbing as {@link BoundedTextField} — one component for
 * both fields, so the masking, the toggle label and the wiring cannot drift between
 * them.
 *
 * `getItemSubtitle` must never put either value on a vault-list row; that is
 * asserted separately.
 */
function SensitiveTextField({
  name,
  label,
  placeholder,
  maxLength,
  register,
  errors,
}: Omit<BoundedTextFieldProps, 'multiline' | 'rows'>) {
  const [revealed, setRevealed] = useState(false);
  const error = fieldErrorMessage(errors, name);
  return (
    <FormField label={label} name={name} error={error}>
      <div className="relative">
        <input
          id={`field-${name}`}
          {...register(name)}
          type={revealed ? 'text' : 'password'}
          placeholder={placeholder}
          maxLength={maxLength}
          className={cn(inputClass, 'pr-10 font-mono')}
          autoComplete="off"
          aria-describedby={error ? `field-${name}-error` : undefined}
          aria-invalid={error ? true : undefined}
        />
        <button
          type="button"
          onClick={() => setRevealed((p) => !p)}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
          aria-label={revealed ? `Hide ${label}` : `Show ${label}`}
        >
          {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </FormField>
  );
}

interface CustomFieldsSectionProps {
  fields: readonly { id: string }[];
  onAppend: () => void;
  onRemove: (index: number) => void;
  register: UseFormRegister<FieldValues>;
  errors: FieldErrors;
  /** Reads a dynamic form path; the parent owns the cast react-hook-form needs. */
  watchField: (path: string) => string;
  /** Writes a dynamic form path; same reason. */
  setField: (path: string, value: string) => void;
  /**
   * Offer the Boolean type. False for a SECRET, whose local schema has always
   * restricted the enum to text/hidden because `SecretDetail` renders no boolean
   * control.
   */
  allowBoolean: boolean;
  /** The operator's custom-field limit (`CUSTOM_FIELDS_LIMIT`). */
  limit: number;
  /** How many custom fields the entry had when the form opened (0 while creating). */
  initialCount: number;
  /**
   * Called when a row's value or type changes, so the parent can re-check that
   * row's NAME: the "give this field a name" rule depends on the value.
   */
  onRowContentChange: (index: number) => void;
  /** Called when a row's name changes: a note's content rule reads the names. */
  onRowNameChange: () => void;
}

/**
 * The "+ Add Field" block, rendered ONCE for every item type (it used to be three
 * copies inside the login, secret and identity blocks, which had already drifted).
 *
 * The limit: "+ Add Field" stops at the operator's `limit`, with a counter and a
 * line saying why. It is `aria-disabled` rather than `disabled`, so it stays in the
 * tab order and the reason stays discoverable. An entry that ALREADY had more fields
 * (an import before the limit, or a lowered limit) keeps every one of them: it is
 * told so, and simply cannot gain fields until it is under the limit.
 */
function CustomFieldsSection({
  fields,
  onAppend,
  onRemove,
  register,
  errors,
  watchField,
  setField,
  allowBoolean,
  limit,
  initialCount,
  onRowContentChange,
  onRowNameChange,
}: CustomFieldsSectionProps) {
  const rowErrors = errors.customFields as
    | Record<number, { name?: { message?: string }; value?: { message?: string } } | undefined>
    | undefined;
  const count = fields.length;
  const atLimit = count >= limit;
  const helpId = 'custom-fields-limit-help';
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-sm font-medium text-[hsl(var(--foreground))]">
          Custom Fields{' '}
          <span className="font-normal text-[hsl(var(--muted-foreground))]">
            ({count} of {limit})
          </span>
        </span>
        <button
          type="button"
          onClick={atLimit ? undefined : onAppend}
          aria-disabled={atLimit ? true : undefined}
          aria-describedby={atLimit ? helpId : undefined}
          className={cn(
            'text-xs text-[hsl(var(--primary))]',
            atLimit ? 'cursor-not-allowed opacity-50' : 'hover:underline',
          )}
        >
          + Add Field
        </button>
      </div>
      {atLimit && (
        <p id={helpId} className="mb-2 text-xs text-[hsl(var(--muted-foreground))]">
          {initialCount > limit && count > limit
            ? `This entry has ${String(count)} custom fields, more than the limit of ${String(limit)}. It keeps all of them, but no more can be added until it has fewer than ${String(limit)}.`
            : `An entry can have up to ${String(limit)} custom fields.`}
        </p>
      )}
      <div className="space-y-2">
        {fields.map((field, idx) => {
          const row = String(idx);
          const fieldType = watchField(`customFields.${row}.type`) || 'text';
          const fieldValue = watchField(`customFields.${row}.value`);
          const showBooleanControl = allowBoolean && fieldType === 'boolean';
          const isBooleanTrue = showBooleanControl && fieldValue === 'true';
          const nameError = rowErrors?.[idx]?.name?.message;
          const valueError = rowErrors?.[idx]?.value?.message;
          const nameErrorId = `field-customFields-${row}-name-error`;
          const valueErrorId = `field-customFields-${row}-value-error`;
          return (
            <div key={field.id}>
              <div className="flex gap-2">
                <input
                  {...register(`customFields.${row}.name`, { onChange: onRowNameChange })}
                  placeholder="Field name"
                  aria-label={`Custom field ${String(idx + 1)} name`}
                  maxLength={MAX_CUSTOM_FIELD_NAME_LENGTH}
                  className={cn(inputClass, 'w-1/3')}
                  aria-invalid={nameError ? true : undefined}
                  aria-describedby={nameError ? nameErrorId : undefined}
                />
                {showBooleanControl ? (
                  <label className="flex flex-1 items-center gap-2 rounded-md border border-[hsl(var(--input))] bg-[hsl(var(--background))] px-3 py-2">
                    <input
                      type="checkbox"
                      checked={isBooleanTrue}
                      onChange={(e) => {
                        setField(`customFields.${row}.value`, String(e.target.checked));
                        onRowContentChange(idx);
                      }}
                      className="h-4 w-4 rounded border-[hsl(var(--input))] text-[hsl(var(--primary))] focus:ring-[hsl(var(--ring))]"
                    />
                    <span className="text-sm text-[hsl(var(--foreground))]">
                      {isBooleanTrue ? 'True' : 'False'}
                    </span>
                  </label>
                ) : (
                  <input
                    {...register(`customFields.${row}.value`, {
                      onChange: () => onRowContentChange(idx),
                    })}
                    placeholder="Value"
                    aria-label={`Custom field ${String(idx + 1)} value`}
                    maxLength={MAX_NOTE_CONTENT_LENGTH}
                    className={cn(inputClass, 'flex-1')}
                    aria-invalid={valueError ? true : undefined}
                    aria-describedby={valueError ? valueErrorId : undefined}
                  />
                )}
                {/* Named per row, because several rows carry an identical
                    control: a bare `<select>` has no implicit label and axe
                    grades a nameless one CRITICAL — a screen-reader user hears
                    "combo box, Text" with nothing saying which field it types. */}
                <select
                  {...register(`customFields.${row}.type`, {
                    onChange: () => onRowContentChange(idx),
                  })}
                  aria-label={`Custom field ${String(idx + 1)} type`}
                  className={cn(inputClass, 'w-24')}
                >
                  <option value="text">Text</option>
                  <option value="hidden">Hidden</option>
                  {allowBoolean && <option value="boolean">Boolean</option>}
                </select>
                <button
                  type="button"
                  onClick={() => onRemove(idx)}
                  className="shrink-0 rounded p-2 text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
                  aria-label="Remove custom field"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
              {nameError !== undefined && (
                <p
                  id={nameErrorId}
                  role="alert"
                  className="mt-1 text-xs text-[hsl(var(--destructive))]"
                >
                  {nameError}
                </p>
              )}
              {valueError !== undefined && (
                <p
                  id={valueErrorId}
                  role="alert"
                  className="mt-1 text-xs text-[hsl(var(--destructive))]"
                >
                  {valueError}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface CardNumberFieldProps {
  control: Control<Record<string, unknown>>;
  /** Show the checksum warning: once the field was left, or a save was attempted. */
  showWarning: boolean;
}

/**
 * The card number: grouped in fours as it is typed, validated by length only (12 to
 * 19 digits), and WARNED about, never refused, when the Luhn checksum fails.
 *
 * Its own component with its own `useController`, for two reasons. The control is
 * reformatted on every keystroke, so it cannot be a plain `register`ed input; and
 * mounting the controller only for a card keeps the field out of the other types'
 * forms entirely. `field.onBlur` is wired so the field is marked touched when it is
 * left, which the "show the warning once the field was left" rule reads.
 */
function CardNumberField({ control, showWarning }: CardNumberFieldProps) {
  const { field, fieldState } = useController({ name: 'number', control });
  const value = typeof field.value === 'string' ? field.value : '';
  const digits = cardNumberDigits(value);
  const luhnWarning =
    (showWarning || fieldState.isTouched) && isCardNumberLength(digits) && !isValidLuhn(digits);
  const error = fieldState.error?.message;
  const describedBy =
    [error ? 'field-number-error' : '', luhnWarning ? 'field-number-warning' : '']
      .filter(Boolean)
      .join(' ') || undefined;
  return (
    <FormField label="Card Number" name="number" error={error}>
      <input
        id="field-number"
        ref={field.ref}
        name={field.name}
        value={value}
        onChange={(e) => field.onChange(formatCardNumber(e.target.value))}
        onBlur={field.onBlur}
        placeholder="1234 5678 9012 3456"
        inputMode="numeric"
        maxLength={CARD_NUMBER_INPUT_MAX_LENGTH}
        className={cn(inputClass, 'font-mono tracking-wider')}
        autoComplete="off"
        aria-describedby={describedBy}
        aria-invalid={error ? true : undefined}
      />
      {luhnWarning && (
        <p
          id="field-number-warning"
          className="mt-1 flex items-center gap-1 text-xs text-amber-700 dark:text-amber-300"
        >
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          This number fails the standard card check. Check it for a typo; you can still save it.
        </p>
      )}
    </FormField>
  );
}

// ---------------------------------------------------------------------------
// Main form component
// ---------------------------------------------------------------------------

interface VaultItemFormProps {
  /** Existing item for editing; undefined means creating new */
  item?: DecryptedVaultItem;
  /** Default item type for new items (e.g. pre-select based on active type filter) */
  defaultType?: ItemType | undefined;
  /** Default folder ID for new items (e.g. pre-select based on active folder) */
  defaultFolderId?: string | undefined;
  /** Called on successful save */
  onSaved: () => void;
  /** Called on cancel */
  onCancel: () => void;
  /**
   * The level of the form's own title. `h2` where the form sits on a page that
   * is already named — the create dialog over the vault list — and `h1` where
   * the form IS the page, as on the edit view of `/vault/:id`, which has no
   * other heading to name it.
   */
  titleLevel?: 'h1' | 'h2';
  /**
   * The operator's custom-field limit (`CUSTOM_FIELDS_LIMIT`), read by the host page
   * through `useCustomFieldsLimit` so that this component issues no request of its
   * own. Defaults to the documented default.
   */
  customFieldsLimit?: number;
}

/**
 * The QR scanner, loaded only when somebody presses the button.
 *
 * `lazy` rather than a direct import, and not for elegance: this component's
 * chunk has a measured size budget, and the scanner pulls in the sandbox driver,
 * the camera module and the migration reader behind it. A static import would
 * put all of that into the bundle every person editing any item downloads.
 */
const TotpScanDialog = lazy(() =>
  import('../tools/TotpScanDialog').then((m) => ({ default: m.TotpScanDialog })),
);

export function VaultItemForm({
  item,
  defaultType,
  defaultFolderId,
  onSaved,
  onCancel,
  titleLevel: Title = 'h2',
  customFieldsLimit = DEFAULT_CUSTOM_FIELDS_LIMIT,
}: VaultItemFormProps) {
  const { toast } = useToast();
  const createItem = useVaultStore((s) => s.createItem);
  const updateItem = useVaultStore((s) => s.updateItem);
  const folders = useVaultStore((s) => s.folders);
  // Read for ONE purpose: the addresses already saved on identity items, offered
  // as a source for a card's billing address. `items` holds every non-trashed
  // item of every type (the sidebar's type filter is view state the store never
  // applies), and both mount sites guarantee it is populated — `VaultPage`
  // fetches on mount and `VaultItemPage` fetches when it is empty.
  const items = useVaultStore((s) => s.items);

  const [itemType, setItemType] = useState<ItemType>(item?.itemType ?? defaultType ?? 'login');
  const [folderId, setFolderId] = useState(item?.folderId ?? defaultFolderId ?? '');
  // The one tag editor, shared with the document details. A tag that is not
  // added says why, instead of the input simply emptying: at the limit, or
  // already on the item.
  const tagField = useTagField(item?.tags ?? [], MAX_TAGS_PER_ITEM);
  const [favorite, setFavorite] = useState(item?.favorite ?? false);
  const [saving, setSaving] = useState(false);
  const [showPasswordGen, setShowPasswordGen] = useState(false);
  const [scanningTotp, setScanningTotp] = useState(false);
  const [showPasswordField, setShowPasswordField] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [showBillingAddress, setShowBillingAddress] = useState(() => {
    if (item?.itemType !== 'card') return false;
    const billing = item.data.billingAddress as Record<string, string> | undefined;
    // See `hasAnyValue` (lib/vaultData) for why this is a list and not a `??` chain:
    // it was the shipped bug that hid a populated billing address behind
    // "+ Add billing address" whenever the street line happened to be empty.
    return hasAnyValue([
      billing?.street,
      billing?.street2,
      billing?.city,
      billing?.state,
      billing?.zip,
      billing?.country,
    ]);
  });
  // Optional-section toggle, following showBillingAddress: collapsed for the great
  // majority of logins that have no recovery codes, but already open when editing
  // one that does, so it is never hidden from someone who needs it.
  const [showBackupCodes, setShowBackupCodes] = useState(() => {
    if (item?.itemType !== 'login') return false;
    const codes = item.data.backupCodes;
    return Array.isArray(codes) && codes.length > 0;
  });
  const addBackupCodesRef = useRef<HTMLButtonElement>(null);
  /** Set when the section is dismissed, so focus can follow it to the reveal link. */
  const restoreAddBackupCodesFocus = useRef(false);

  // The reveal link is not mounted while the section is open, so its ref is still
  // null at the moment Remove is pressed; focusing has to wait for the re-render.
  // Without this, dismissing the section drops focus to the top of the form.
  useEffect(() => {
    if (showBackupCodes || !restoreAddBackupCodesFocus.current) return;
    restoreAddBackupCodesFocus.current = false;
    addBackupCodesRef.current?.focus();
  }, [showBackupCodes]);

  const isEditing = item != null;

  const defaultValues = useMemo(
    () => getDefaultValues(itemType, item),
    // Only compute defaults once on mount (empty deps is intentional)
    [],
  );

  // The values the form opened with, while EDITING: the schema lets a control that
  // still holds its opening value through every blocking rule (see `isUntouched`).
  // `null` while creating, where every rule applies.
  const rules = useMemo<FormRuleContext>(
    () => ({ initial: isEditing ? defaultValues : null }),
    // The opening values never change after mount, exactly like `defaultValues`.
    [isEditing, defaultValues],
  );
  const schema = useMemo(() => getSchemaForType(itemType, rules), [itemType, rules]);

  const {
    register,
    handleSubmit,
    control,
    setValue,
    setError,
    clearErrors,
    watch,
    reset,
    trigger,
    getFieldState,
    getValues,
    formState: { errors, submitCount, isSubmitted },
  } = useForm({
    defaultValues,
    // The form validates itself: `noValidate` on the element keeps the browser's
    // own constraint check from blocking the submit before this runs (an identity
    // email the browser disliked used to stop the save with no message and with
    // every other field unvalidated). When each control is checked is decided by
    // `checkLeftField` / `recheckInvalidField` below, not by a validation `mode`.
    //
    // react-hook-form focuses the first error in REGISTRATION order, which is not
    // the order on screen; the `submitCount` effect below focuses in DOM order.
    shouldFocusError: false,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any -- dynamic form schema requires broad resolver type
    resolver: zodResolver(schema) as any,
  });

  /**
   * Whether the CURRENT values give `name` an issue, checked synchronously against
   * the schema the resolver uses. A re-check is asked of react-hook-form only when it
   * would change what is on screen (an issue to show, or a shown one to clear):
   * re-validating a valid control that shows nothing schedules a render that shows
   * nothing either.
   */
  const fieldHasIssue = useCallback(
    (name: string): boolean => {
      const result = schema.safeParse(getValues());
      return !result.success && result.error.issues.some((issue) => issue.path.join('.') === name);
    },
    [schema, getValues],
  );

  /**
   * Re-check a field whose rule depends on the one just edited, but only when that
   * re-check can show the person something they should see now (see
   * `shouldRecheckPartner`): never an error on a field they have not reached yet,
   * and never one left standing after they fixed its cause.
   */
  const recheckPartner = useCallback(
    (partner: string) => {
      const state = getFieldState(partner);
      if (
        shouldRecheckPartner({
          hasError: state.invalid,
          isTouched: state.isTouched,
          isSubmitted,
        }) &&
        (state.invalid || fieldHasIssue(partner))
      ) {
        void trigger(partner);
      }
    },
    [getFieldState, trigger, isSubmitted, fieldHasIssue],
  );

  /**
   * When a control is checked, before the first save attempt: on LEAVING it, but
   * only once the person has changed it, and then live on every change while it
   * shows an error. ("Reward early, punish late": a mistake is reported as soon as
   * the person moves on from it, and its message disappears as soon as it is fixed,
   * but tabbing past a field nobody has filled in yet is not an error until a save
   * is attempted.) After a save attempt, react-hook-form re-checks every change by
   * itself (`reValidateMode`), and every rule runs again on the next save.
   *
   * Delegated from the `<form>` (React's `onBlur`/`onChange` bubble), so every
   * registered control is covered by its `name`, including rows added later.
   */
  const checkLeftField = useCallback(
    (target: EventTarget) => {
      if (isSubmitted || !isFormControl(target) || target.name === '') return;
      const state = getFieldState(target.name);
      if (state.isDirty && (state.invalid || fieldHasIssue(target.name))) {
        void trigger(target.name);
      }
    },
    [isSubmitted, getFieldState, trigger, fieldHasIssue],
  );
  const recheckInvalidField = useCallback(
    (target: EventTarget) => {
      if (isSubmitted || !isFormControl(target) || target.name === '') return;
      if (getFieldState(target.name).invalid) void trigger(target.name);
    },
    [isSubmitted, getFieldState, trigger],
  );

  // How many custom fields the entry had when the form opened: an entry already over
  // the limit keeps them all, and the section says so.
  const initialCustomFieldCount =
    isEditing && Array.isArray(item.data.customFields) ? item.data.customFields.length : 0;
  const errorCount = countFieldErrors(errors);

  // After a refused save, focus the first invalid control ON SCREEN.
  //
  // Keyed on `submitCount`, which react-hook-form publishes in the SAME update as
  // the refused save's errors, and only after `onInvalid` has run. A state bump made
  // inside `onInvalid` itself rendered one microtask too early: the effect then saw
  // only the controls that were ALREADY invalid (a changed field checked as it was
  // left, such as the email the person had just typed before pressing Create) and
  // focused that one instead of the first problem on the form.
  const formRef = useRef<HTMLFormElement>(null);
  const focusAfterRefusal = useRef(false);
  useEffect(() => {
    if (!focusAfterRefusal.current) return;
    focusAfterRefusal.current = false;
    formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
  }, [submitCount]);
  const onInvalid = useCallback(() => {
    focusAfterRefusal.current = true;
  }, []);

  // Field arrays for login URIs and custom fields
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-explicit-any -- dynamic form shape requires broad control type
  const typedControl = control as any;
  /* eslint-disable @typescript-eslint/no-unsafe-assignment -- dynamic form control type from zodResolver */
  const {
    fields: uriFields,
    append: appendUri,
    remove: removeUri,
  } = useFieldArray({ control: typedControl, name: 'uris' });

  const {
    fields: customFields,
    append: appendCustomField,
    remove: removeCustomField,
  } = useFieldArray({ control: typedControl, name: 'customFields' });
  /* eslint-enable @typescript-eslint/no-unsafe-assignment */

  const handleAppendCustomField = useCallback(() => {
    appendCustomField({ name: '', value: '', type: 'text' });
  }, [appendCustomField]);
  // A note's "write the note, or add a custom field" rule reads every row's NAME, so
  // a shown error is re-checked as names change: naming a field clears it at once.
  const recheckNoteContent = useCallback(() => {
    if (itemType === 'note' && getFieldState('content').invalid) void trigger('content');
  }, [itemType, getFieldState, trigger]);
  // A row's name is re-checked as its value or type changes only once it SHOWS an
  // error, or a save was attempted. Not on "visited", unlike the other pairs: adding
  // a row puts focus in its name, so the name counts as visited the moment the
  // person moves on to the value, and "give this field a name" would appear while
  // the value is still being typed.
  const recheckCustomFieldName = useCallback(
    (index: number) => {
      const name = `customFields.${String(index)}.name`;
      if (getFieldState(name).invalid || (isSubmitted && fieldHasIssue(name))) {
        void trigger(name);
      }
      recheckNoteContent();
    },
    [getFieldState, isSubmitted, fieldHasIssue, trigger, recheckNoteContent],
  );

  // react-hook-form types a DYNAMIC path's `watch`/`setValue` as `void`/never for a
  // `Record<string, unknown>` form, so the cast has to live somewhere. It lives
  // HERE, once, and `CustomFieldsSection` receives two plainly-typed closures —
  // rather than four separate eslint-disable comments inside the row loop.
  const watchField = useCallback(
    (path: string): string => {
      const value = (watch as unknown as (p: string) => unknown)(path);
      return typeof value === 'string' ? value : '';
    },
    [watch],
  );
  const setField = useCallback(
    (path: string, value: string): void => {
      (setValue as unknown as (p: string, v: string) => void)(path, value);
    },
    [setValue],
  );

  const noteContent = watch('content') as string | undefined;
  // The Preview shows the note the way it will be saved, so it follows the
  // chosen format instead of always interpreting the text as Markdown.
  const noteFormat = watch('format') as INoteData['format'];
  // A static path, so no cast gymnastics are needed on setValue. react-hook-form
  // returns the STORED array, so the reference is stable while the contents are —
  // which is what lets the list re-mask only on a real change.
  const backupCodes = (watch('backupCodes') ?? []) as string[];

  // The card's expiry as it is being typed: warned about here (expired, or within
  // the expiring window) exactly as the list and the item view will warn about it.
  const watchedExpMonth = watchField('expMonth');
  const watchedExpYear = watchField('expYear');
  // Only for a WHOLE year: while "2029" is being typed it passes through "20", which
  // would announce a card that expired in 2020. A stored two-digit year the person
  // has not touched is whole as it stands.
  const editorCardExpiry =
    itemType === 'card' &&
    (/^\d{4}$/.test(watchedExpYear) || isUntouched(rules.initial, 'expYear', watchedExpYear))
      ? readCardExpiry(watchedExpMonth, watchedExpYear)
      : null;

  // A stored TOTP value the parser cannot use, left untouched: not a reason to
  // block the save (the rule exempts it), but the person should know codes cannot
  // be generated from it.
  const watchedTotp = watchField('totp');
  const untouchedTotpFailure = useMemo(() => {
    if (itemType !== 'login' || watchedTotp.trim() === '') return null;
    if (!isUntouched(rules.initial, 'totp', watchedTotp)) return null;
    const parsed = parseTotpValue(watchedTotp);
    return parsed.ok ? null : describeTotpFailure(parsed.reason);
  }, [itemType, watchedTotp, rules]);

  // A secret expiry already in the past: allowed (the person may be recording an
  // expired token), but said, because the item will show as expired at once.
  const watchedExpiryDate = watchField('expiryDate');
  const watchedExpiryTime = watchField('expiryTime');
  const secretExpiryPassed = useMemo(() => {
    if (itemType !== 'secret') return false;
    const combined = combineExpiry(
      watchedExpiryDate,
      watchedExpiryTime,
      item ? storedExpiry(item.data) : '',
    );
    const instant = combined === undefined ? null : parseExpiryInstant(combined);
    return instant !== null && instant.getTime() <= Date.now();
  }, [itemType, watchedExpiryDate, watchedExpiryTime, item]);

  const expiryDateRef = useRef<HTMLInputElement | null>(null);
  const expiryTimeRef = useRef<HTMLInputElement | null>(null);
  /** The controls currently recorded as incomplete, so their refusal can be withdrawn. */
  const recordedIncomplete = useRef(new Set<string>());
  /**
   * Record an incomplete date or time control as `INCOMPLETE_INPUT`, so the schema
   * refuses it with a message instead of a half-typed date silently reading as "no
   * expiry". Called when such a control is left and before every save (pressing
   * Enter inside the control submits without leaving it).
   */
  const syncIncompleteInputs = useCallback(
    (validate: boolean) => {
      const write = setValue as unknown as (
        path: string,
        value: string,
        options: { shouldValidate: boolean },
      ) => void;
      for (const [name, node] of [
        ['expiryDate', expiryDateRef.current],
        ['expiryTime', expiryTimeRef.current],
      ] as const) {
        if (node === null) continue;
        if (node.validity.badInput) {
          recordedIncomplete.current.add(name);
          write(name, INCOMPLETE_INPUT, { shouldValidate: validate });
        } else if (recordedIncomplete.current.delete(name)) {
          // Recorded as incomplete before, and complete (or cleared) now. Clearing
          // a half-typed control fires no change event, and on leaving it the form
          // has already taken the control's value; re-check it so the refusal goes.
          write(name, node.value, { shouldValidate: validate });
        }
      }
    },
    [setValue],
  );

  // -------------------------------------------------------------------------
  // Filling a card's billing address from an address saved on an identity
  //
  // The vault already holds the address most people would retype: they entered
  // it once on an identity. Copying it is safe by construction rather than by
  // clamping — an identity's address is `addressSchema.extend({ deliveryNotes })`,
  // so every field copied here is one a card can hold, under the same name, with
  // the SAME `MAX_ADDRESS_*` bound on both sides. `deliveryNotes` is the one
  // field that is not shared and it is never read (see `lib/address`).
  // -------------------------------------------------------------------------

  /**
   * The identity addresses on offer, alphabetical by item name.
   *
   * Alphabetical rather than the store's `updatedAt desc` order: a picker is
   * scanned, and a list that reorders itself as unrelated identities are edited
   * is one the user cannot build a habit around. `id` is the tiebreaker so the
   * order is TOTAL, the same rule `sortItems` follows.
   */
  const savedAddressOptions = useMemo<SavedAddressOption[]>(() => {
    if (itemType !== 'card') return [];
    const options: SavedAddressOption[] = [];
    for (const candidate of items) {
      if (candidate.itemType !== 'identity') continue;
      // A placeholder is not content: its `address` is either absent or the
      // unvalidated original, and offering either would copy a value the card
      // may not be able to store.
      if (isUndecodableData(candidate.data)) continue;
      const address = readBaseAddress(candidate.data.address);
      if (!hasBaseAddressValue(address)) continue;
      const title = candidate.name.trim() || 'Untitled identity';
      const personLabel = getItemSubtitle({ itemType: 'identity', data: candidate.data });
      // Suppressed when it would merely repeat the item name, which is the common
      // case for an identity named after its owner.
      const subtitle = personLabel === title ? '' : personLabel;
      const summary = formatAddressSummary(address);
      options.push({
        id: candidate.id,
        title,
        subtitle,
        address,
        summary,
        // Exactly the three strings this row renders — never more. See
        // `addressSearchText`.
        searchText: addressSearchText([title, subtitle, summary]),
      });
    }
    return options.sort((a, b) => a.title.localeCompare(b.title) || a.id.localeCompare(b.id));
  }, [items, itemType]);

  /**
   * The last fill, kept so it can be undone.
   *
   * `before` is what the six controls held beforehand and `after` is what the
   * fill wrote. Undo is offered only while the controls still hold `after`
   * exactly — the moment the user edits any of the six, the snapshot no longer
   * describes anything on screen, and restoring `before` would silently discard
   * an edit the user made deliberately.
   */
  const [lastFill, setLastFill] = useState<{
    optionId: string;
    before: string[];
    after: string[];
    /** Whether the section was already open, so Undo is a true inverse. */
    sectionWasOpen: boolean;
  } | null>(null);

  /**
   * Focus has to be moved EXPLICITLY after a fill, and after a collapse.
   *
   * Both switch the billing section between the two arms of a ternary whose
   * children are unkeyed, so React reconciles them by position: the arms differ
   * by element type at index 1, every fiber from there on is destroyed, and the
   * control the user just activated — the picker's trigger, the Undo button, the
   * Remove button — is unmounted from under `document.activeElement`. Focus then
   * falls to `<body>`, which inside the create dialog is worse than untidy: the
   * dialog's focus trap listens on the dialog CONTAINER, so a Tab raised on
   * `body` never reaches it and the next Tab escapes the modal entirely.
   *
   * This is the pattern `addBackupCodesRef` above already uses for the same
   * class of problem: mark the intent, then act in an effect that runs after the
   * new arm has mounted.
   */
  const addBillingAddressRef = useRef<HTMLButtonElement>(null);
  /**
   * The street control, focused after a fill.
   *
   * A real ref rather than react-hook-form's `setFocus`: `setFocus` resolves the
   * node through its own field registry and was verified to be a silent no-op for
   * these controls, which would have made the fix look applied while focus still
   * fell to `<body>`. `BoundedTextField` merges this with `register`'s own ref, so
   * nothing about the registration changes.
   */
  const billingStreetRef = useRef<HTMLElement>(null);
  /** Set when the section is collapsed, so focus can follow it to the reveal link. */
  const restoreAddBillingFocus = useRef(false);
  /**
   * Bumped by every transition that reveals or re-populates the billing controls:
   * a fill, the "+ Add billing address" reveal, and an Undo that leaves the
   * section open.
   *
   * A counter rather than a boolean ref because two of those three change no
   * other state — a fill into an already-open section and a non-collapsing Undo
   * both leave `showBillingAddress` true — so there would be nothing for an
   * effect to depend on. Each of the three unmounts the control that was
   * activated (the ternary arms are unkeyed, and `canUndoFill` withdraws the Undo
   * button), so each would otherwise drop focus to `<body>`.
   */
  const [billingFocusToken, setBillingFocusToken] = useState(0);

  useEffect(() => {
    if (showBillingAddress || !restoreAddBillingFocus.current) return;
    restoreAddBillingFocus.current = false;
    addBillingAddressRef.current?.focus();
  }, [showBillingAddress]);

  useEffect(() => {
    if (billingFocusToken === 0 || !showBillingAddress) return;
    // The street line, not the trigger: the six fields that just appeared are
    // what the user now has to check, and landing on the first of them is what
    // announces to a screen reader that the fill happened and where it went.
    billingStreetRef.current?.focus();
  }, [billingFocusToken, showBillingAddress]);

  const currentBillingValues = BILLING_ADDRESS_FIELD_NAMES.map((name) => watchField(name));
  /**
   * The saved address the six controls currently hold VERBATIM, or `null`.
   *
   * One derivation drives both affordances, so the check mark in the picker and
   * the Undo button can never disagree about whether the fill is still intact.
   */
  const appliedAddressOptionId =
    lastFill?.after.every((value, index) => value === currentBillingValues[index]) === true
      ? lastFill.optionId
      : null;
  const canUndoFill = appliedAddressOptionId !== null;

  const handleFillBillingAddress = useCallback(
    (option: SavedAddressOption) => {
      const before = BILLING_ADDRESS_FIELD_NAMES.map((name) => watchField(name));
      const after = BASE_ADDRESS_FIELDS.map((field) => option.address[field]);
      BILLING_ADDRESS_FIELD_NAMES.forEach((name, index) => {
        setField(name, after[index] ?? '');
      });
      // The copied values are bounded by the same constants as the controls they
      // land in, so nothing new can be invalid — but a message left over from
      // what the user had typed before would now describe a value that is gone.
      clearErrors([...BILLING_ADDRESS_FIELD_NAMES]);
      // Captured BEFORE the section is opened, so Undo can put the form back
      // exactly as it was rather than leaving an empty section behind.
      setLastFill({ optionId: option.id, before, after, sectionWasOpen: showBillingAddress });
      setShowBillingAddress(true);
      setBillingFocusToken((token) => token + 1);
      toast({
        title: 'Billing address filled',
        description: `Copied from ${option.title}. Delivery notes are not copied to a card.`,
        type: 'success',
      });
    },
    [watchField, setField, clearErrors, toast, showBillingAddress],
  );

  const handleUndoFillBillingAddress = useCallback(() => {
    if (lastFill === null) return;
    lastFill.before.forEach((value, index) => {
      const name = BILLING_ADDRESS_FIELD_NAMES[index];
      if (name !== undefined) setField(name, value);
    });
    clearErrors([...BILLING_ADDRESS_FIELD_NAMES]);
    // A fill that OPENED the section is only fully undone by closing it again;
    // otherwise Undo leaves an empty billing panel the user never asked for.
    // Nothing is lost by closing: the section was shut, so `before` is all empty.
    if (lastFill.sectionWasOpen) {
      // The section stays open, but the Undo button still unmounts — clearing
      // `lastFill` makes `canUndoFill` false — so focus has to be re-homed into
      // the fields it belonged to.
      setBillingFocusToken((token) => token + 1);
    } else {
      // The Undo button lives in the header that is about to unmount with the
      // whole section.
      restoreAddBillingFocus.current = true;
      setShowBillingAddress(false);
    }
    setLastFill(null);
  }, [lastFill, setField, clearErrors]);

  /** Clear the six billing controls and forget any fill they came from. */
  const clearBillingAddress = useCallback(() => {
    BILLING_ADDRESS_FIELD_NAMES.forEach((name) => {
      setField(name, '');
    });
    clearErrors([...BILLING_ADDRESS_FIELD_NAMES]);
    setLastFill(null);
  }, [setField, clearErrors]);

  // Type tab change (new items only)
  const handleTypeChange = useCallback(
    (type: ItemType) => {
      if (isEditing) return;
      setItemType(type);
      reset(getDefaultValues(type));
      // The reset already empties the billing controls, so `canUndoFill` would
      // go false on its own; dropping the snapshot as well keeps "there is
      // nothing to undo" a fact about state rather than a coincidence of
      // comparison.
      setLastFill(null);
    },
    [isEditing, reset],
  );

  // Submit handler
  const onSubmit: SubmitHandler<Record<string, unknown>> = useCallback(
    async (values) => {
      // A tag typed but never added is saved with the item rather than silently
      // dropped; at the limit nothing is saved and the tag field says why.
      const tags = tagField.commitPending();
      if (tags === null) return;
      setSaving(true);
      try {
        const name = values.name as string;
        const data = buildDataPayload(itemType, values, item);

        if (item != null) {
          // `itemType` is passed EXPLICITLY: the store no longer infers it from its
          // own `items` array, so its pre-flight schema check can never be skipped.
          await updateItem(item.id, itemType, name, data, {
            folderId: folderId || null,
            tags,
            favorite,
          });
          toast({ title: 'Item updated', type: 'success' });
        } else {
          await createItem(itemType, name, data, {
            ...(folderId ? { folderId } : {}),
            tags,
            favorite,
          });
          toast({ title: 'Item created', type: 'success' });
        }
        onSaved();
      } catch (err) {
        // A store-side schema rejection is put on the offending CONTROL when the
        // form has one, which is where a "this value is too long" message belongs.
        // Everything else — an oversize ciphertext, a network failure, or an issue
        // path with no matching control — still gets the toast, so no failure is
        // ever silent.
        if (!applyStoreValidationErrors(err, itemType, setError)) {
          toast({
            title: resolveSaveErrorTitle(err),
            description: getApiErrorMessage(err, 'An unexpected error occurred. Please try again.'),
            type: 'error',
          });
        }
      } finally {
        setSaving(false);
      }
    },
    [
      itemType,
      isEditing,
      item,
      folderId,
      tagField,
      favorite,
      createItem,
      updateItem,
      onSaved,
      toast,
      setError,
    ],
  );

  return (
    <form
      ref={formRef}
      noValidate
      onMouseDownCapture={(e) => {
        if (pressKeepsFocus(e.target)) e.preventDefault();
      }}
      onBlur={(e) => checkLeftField(e.target)}
      onChange={(e) => recheckInvalidField(e.target)}
      onSubmit={(e) => {
        syncIncompleteInputs(false);
        void handleSubmit(onSubmit, onInvalid)(e);
      }}
      className="space-y-6"
    >
      <Title className="text-lg font-semibold text-[hsl(var(--foreground))]">
        {isEditing ? 'Edit Item' : 'New Item'}
      </Title>

      {/* Type tabs (only for new items) */}
      {!isEditing && (
        <div
          className="flex gap-1 overflow-x-auto rounded-lg border border-[hsl(var(--border))] p-1"
          role="tablist"
          aria-label="Item type"
        >
          {TYPE_TABS.map(({ type, label, icon: Icon }) => (
            <button
              key={type}
              type="button"
              role="tab"
              aria-selected={itemType === type}
              onClick={() => handleTypeChange(type)}
              className={cn(
                'flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium whitespace-nowrap transition-colors',
                itemType === type
                  ? 'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))]'
                  : 'text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]',
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Name field (common to all types) */}
      <FormField label="Name" name="name" error={errors.name?.message}>
        <input
          id="field-name"
          {...register('name')}
          placeholder="Item name"
          maxLength={MAX_ITEM_NAME_BYTES}
          className={inputClass}
          autoFocus
          autoComplete="off"
          aria-describedby={errors.name ? 'field-name-error' : undefined}
          aria-invalid={errors.name ? true : undefined}
        />
      </FormField>

      {/* --- Login fields --- */}
      {itemType === 'login' && (
        <div className="space-y-4">
          <BoundedTextField
            name="username"
            label="Username"
            placeholder="Username or email"
            maxLength={MAX_LOGIN_USERNAME_LENGTH}
            register={register}
            errors={errors}
          />

          <FormField label="Password" name="password" error={errors.password?.message}>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  id="field-password"
                  {...register('password')}
                  type={showPasswordField ? 'text' : 'password'}
                  placeholder="Password"
                  maxLength={MAX_LOGIN_PASSWORD_LENGTH}
                  className={cn(inputClass, 'pr-10')}
                  autoComplete="new-password"
                  aria-describedby={errors.password ? 'field-password-error' : undefined}
                  aria-invalid={errors.password ? true : undefined}
                />
                <button
                  type="button"
                  onClick={() => setShowPasswordField((p) => !p)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                  aria-label={showPasswordField ? 'Hide password' : 'Show password'}
                >
                  {showPasswordField ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => setShowPasswordGen((p) => !p)}
                className="shrink-0 rounded-md border border-[hsl(var(--input))] px-3 py-2 text-sm text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
              >
                Generate
              </button>
            </div>
            {showPasswordGen && (
              <div className="mt-2 rounded-lg border border-[hsl(var(--border))] p-4">
                <PasswordGenerator
                  onSelect={(pw) => {
                    setValue('password', pw);
                    setShowPasswordGen(false);
                  }}
                />
              </div>
            )}
          </FormField>

          {/* URIs */}
          <div>
            <div className="mb-1.5 flex items-center justify-between">
              <span className="text-sm font-medium text-[hsl(var(--foreground))]">URIs</span>
              <button
                type="button"
                onClick={() => appendUri({ uri: '', match: 'domain' })}
                className="text-xs text-[hsl(var(--primary))] hover:underline"
              >
                + Add URI
              </button>
            </div>
            <div className="space-y-2">
              {uriFields.map((field, idx) => {
                // react-hook-form's error object is sparse, so the indexed entry
                // may be absent. Type the intermediate as explicitly nullable so
                // each optional-chain link guards a genuinely nullable value.
                const uriFieldError: { uri?: { message?: string } } | undefined = (
                  errors.uris as Record<string, { uri?: { message?: string } }> | undefined
                )?.[idx];
                const uriError = uriFieldError?.uri?.message;
                const uriErrorId = `field-uris-${String(idx)}-uri-error`;
                return (
                  <div key={field.id}>
                    <div className="flex gap-2">
                      <input
                        {...register(`uris.${idx}.uri` as const)}
                        placeholder="example.com"
                        aria-label={`URI ${String(idx + 1)}`}
                        className={cn(inputClass, 'flex-1')}
                        aria-invalid={uriError ? true : undefined}
                        aria-describedby={uriError ? uriErrorId : undefined}
                      />
                      {/* Named per row, for the reason the custom-field type
                          select records: one of several identical controls, and
                          a `<select>` takes no implicit label from anything. */}
                      <select
                        {...register(`uris.${idx}.match` as const)}
                        aria-label={`URI ${String(idx + 1)} match type`}
                        className={cn(inputClass, 'w-28')}
                      >
                        <option value="domain">Domain</option>
                        <option value="exact">Exact</option>
                        <option value="startsWith">Starts with</option>
                        <option value="regex">Regex</option>
                      </select>
                      <button
                        type="button"
                        onClick={() => removeUri(idx)}
                        className="shrink-0 rounded p-2 text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive)/0.1)]"
                        aria-label="Remove URI"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                    {uriError && (
                      <p
                        id={uriErrorId}
                        role="alert"
                        className="mt-1 text-xs text-[hsl(var(--destructive))]"
                      >
                        {uriError}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          <div className="space-y-2">
            <BoundedTextField
              name="totp"
              label="TOTP Secret"
              placeholder="TOTP secret key (optional)"
              maxLength={MAX_LOGIN_TOTP_LENGTH}
              register={register}
              errors={errors}
            />
            {untouchedTotpFailure !== null && (
              <p className="flex items-center gap-1 text-xs text-amber-700 dark:text-amber-300">
                <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                {`${untouchedTotpFailure}, so no codes can be generated from it.`}
              </p>
            )}
            <button
              type="button"
              onClick={() => setScanningTotp(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[hsl(var(--input))] px-2.5 py-1.5 text-xs text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))]"
            >
              Scan QR code
            </button>
            {scanningTotp && (
              <div className="rounded-lg border border-[hsl(var(--border))] p-3">
                <Suspense
                  fallback={
                    <p className="text-sm text-[hsl(var(--muted-foreground))]">Loading scanner…</p>
                  }
                >
                  <TotpScanDialog
                    onCancel={() => setScanningTotp(false)}
                    onScanned={(value) => {
                      // The whole `otpauth://` URI, not just its secret: it
                      // carries the algorithm, digit count and period, and a
                      // bare secret would silently generate wrong codes for any
                      // service that does not use the defaults.
                      setValue('totp', value, { shouldDirty: true });
                      setScanningTotp(false);
                    }}
                  />
                </Suspense>
              </div>
            )}
          </div>

          {/* Backup codes: the 2FA recovery codes for the account this login
              unlocks. Sits with TOTP because they are the same concept, and in the
              same order the detail view shows them. */}
          {!showBackupCodes ? (
            <button
              type="button"
              ref={addBackupCodesRef}
              onClick={() => setShowBackupCodes(true)}
              className="text-sm text-[hsl(var(--primary))] hover:underline"
            >
              + Add backup codes
            </button>
          ) : (
            <BackupCodesEditor
              codes={backupCodes}
              onChangeCodes={(next) => setValue('backupCodes', next)}
              onRemoveSection={() => {
                restoreAddBackupCodesFocus.current = true;
                setShowBackupCodes(false);
                // Clearing the value matters: collapsing alone would hide codes that
                // would still be saved. Same trap the billing section avoids.
                setValue('backupCodes', []);
              }}
            />
          )}

          <BoundedTextField
            name="notes"
            label="Notes"
            placeholder="Additional notes"
            maxLength={MAX_NOTE_CONTENT_LENGTH}
            register={register}
            errors={errors}
            multiline
            rows={3}
          />
        </div>
      )}

      {/* --- Secret fields --- */}
      {itemType === 'secret' && (
        <div className="space-y-4">
          <FormField label="Value" name="value" error={errors.value?.message}>
            <textarea
              id="field-value"
              {...register('value')}
              placeholder="Secret value (API key, token, etc.)"
              rows={3}
              maxLength={MAX_NOTE_CONTENT_LENGTH}
              className={cn(inputClass, 'font-mono resize-y')}
              aria-describedby={errors.value ? 'field-value-error' : undefined}
              aria-invalid={errors.value ? true : undefined}
            />
          </FormField>
          <BoundedTextField
            name="description"
            label="Description"
            placeholder="Description (optional)"
            maxLength={MAX_SECRET_DESCRIPTION_LENGTH}
            register={register}
            errors={errors}
            multiline
          />
          <div className="grid grid-cols-2 gap-3">
            {/* Both controls render their error: a store-side `expiresAt` rejection is
                mapped onto `expiryDate`, and without a message there it would vanish. */}
            <ExpiryControl
              control={control}
              name="expiryDate"
              label="Expiry Date"
              type="date"
              inputRef={expiryDateRef}
              onLeave={() => syncIncompleteInputs(true)}
            />
            <ExpiryControl
              control={control}
              name="expiryTime"
              label="Time (optional)"
              type="time"
              inputRef={expiryTimeRef}
              onLeave={() => syncIncompleteInputs(true)}
              // The "time without a date" message lives on the DATE.
              onValueChange={() => recheckPartner('expiryDate')}
            />
          </div>
          {secretExpiryPassed && (
            <p className="flex items-center gap-1 text-xs text-amber-700 dark:text-amber-300">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              This date has passed, so the secret will show as expired.
            </p>
          )}
        </div>
      )}

      {/* --- Note fields --- */}
      {itemType === 'note' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            {/* The only control on the note form with no visible label beside
                it: without a name it is announced as an unlabelled combo box. */}
            <select
              {...register('format')}
              aria-label="Note format"
              className={cn(inputClass, 'w-36')}
            >
              <option value="markdown">Markdown</option>
              <option value="plaintext">Plain Text</option>
            </select>
            <button
              type="button"
              onClick={() => setShowPreview((p) => !p)}
              className="text-sm text-[hsl(var(--primary))] hover:underline"
            >
              {showPreview ? 'Edit' : 'Preview'}
            </button>
          </div>
          {showPreview && noteContent ? (
            <NoteContent content={noteContent} format={noteFormat} />
          ) : (
            <FormField label="Content" name="content" error={errors.content?.message}>
              <textarea
                id="field-content"
                {...register('content')}
                placeholder="Write your note..."
                rows={10}
                maxLength={MAX_NOTE_CONTENT_LENGTH}
                className={cn(inputClass, 'font-mono resize-y')}
                aria-describedby={errors.content ? 'field-content-error' : undefined}
                aria-invalid={errors.content ? true : undefined}
              />
            </FormField>
          )}
        </div>
      )}

      {/* --- Card fields --- */}
      {itemType === 'card' && (
        <div className="space-y-4">
          <FormField
            label="Cardholder Name"
            name="cardholderName"
            error={errors.cardholderName?.message}
          >
            <input
              id="field-cardholderName"
              {...register('cardholderName')}
              placeholder="Name on card"
              maxLength={MAX_CARD_CARDHOLDER_NAME_LENGTH}
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.cardholderName ? 'field-cardholderName-error' : undefined}
              aria-invalid={errors.cardholderName ? true : undefined}
            />
          </FormField>
          <CardNumberField control={control} showWarning={isSubmitted} />
          <div>
            <div className="grid grid-cols-3 gap-3">
              <FormField label="Exp Month" name="expMonth" error={errors.expMonth?.message}>
                <input
                  id="field-expMonth"
                  {...register('expMonth', { onChange: () => recheckPartner('expYear') })}
                  placeholder="MM"
                  inputMode="numeric"
                  maxLength={2}
                  className={inputClass}
                  autoComplete="off"
                  aria-describedby={errors.expMonth ? 'field-expMonth-error' : undefined}
                  aria-invalid={errors.expMonth ? true : undefined}
                />
              </FormField>
              <FormField label="Exp Year" name="expYear" error={errors.expYear?.message}>
                <input
                  id="field-expYear"
                  {...register('expYear', {
                    onChange: () => recheckPartner('expMonth'),
                    onBlur: (e: React.FocusEvent<HTMLInputElement>) => {
                      // "27" means 2027, said back to the person as soon as they leave
                      // the field. Only a year they changed: an untouched stored "27"
                      // is written back exactly as it was.
                      const year = e.target.value;
                      if (/^\d{2}$/.test(year) && !isUntouched(rules.initial, 'expYear', year)) {
                        setValue('expYear', expandCardYear(year), {
                          shouldValidate: true,
                          shouldDirty: true,
                        });
                        recheckPartner('expMonth');
                      }
                    },
                  })}
                  placeholder="YYYY"
                  inputMode="numeric"
                  maxLength={4}
                  className={inputClass}
                  autoComplete="off"
                  aria-describedby={errors.expYear ? 'field-expYear-error' : undefined}
                  aria-invalid={errors.expYear ? true : undefined}
                />
              </FormField>
              <FormField label="CVV" name="cvv" error={errors.cvv?.message}>
                <input
                  id="field-cvv"
                  {...register('cvv')}
                  type="password"
                  placeholder="CVV"
                  inputMode="numeric"
                  maxLength={4}
                  className={cn(inputClass, 'font-mono')}
                  autoComplete="off"
                  aria-describedby={errors.cvv ? 'field-cvv-error' : undefined}
                  aria-invalid={errors.cvv ? true : undefined}
                />
              </FormField>
            </div>
            {/* Always mounted, so a screen reader hears the hint when it appears; it
              holds nothing until the month and the year both read as a date. */}
            <div role="status" className="mt-1.5">
              <CardExpiryNotice expiry={editorCardExpiry} variant="editor" />
            </div>
          </div>
          <BoundedTextField
            name="brand"
            label="Brand"
            placeholder="Visa, Mastercard, etc."
            maxLength={MAX_CARD_BRAND_LENGTH}
            register={register}
            errors={errors}
          />

          {/* Stored by `cardDataSchema` and written by the Bitwarden importer, but no
              control edited it until now: it was preserved by the payload merge yet
              invisible in the editor and removable only by deleting the whole card. */}
          <BoundedTextField
            name="notes"
            label="Notes"
            placeholder="Additional notes"
            maxLength={MAX_NOTE_CONTENT_LENGTH}
            register={register}
            errors={errors}
            multiline
            rows={3}
          />

          {/* Billing Address (optional, collapsible) */}
          {!showBillingAddress ? (
            <div className="space-y-3 rounded-lg border border-dashed border-[hsl(var(--border))] p-4">
              <div>
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">Billing Address</p>
                {/* Only when it earns its space: a lone "Optional." under the
                    heading reads like an unfinished string. */}
                {savedAddressOptions.length > 0 && (
                  <p className="mt-0.5 text-xs text-[hsl(var(--muted-foreground))]">
                    Optional. Type one in, or reuse an address you already saved on an identity.
                  </p>
                )}
              </div>
              <button
                type="button"
                ref={addBillingAddressRef}
                onClick={() => {
                  setShowBillingAddress(true);
                  // This button is in the arm that is about to be replaced, so
                  // revealing the section unmounts the control that revealed it.
                  setBillingFocusToken((token) => token + 1);
                }}
                className="text-sm text-[hsl(var(--primary))] hover:underline"
              >
                + Add billing address
              </button>
              {/* Hidden outright when the vault holds no addressed identity: a
                  control that can only report "there is nothing here" is worse
                  than no control. */}
              {savedAddressOptions.length > 0 && (
                <SavedAddressPicker
                  options={savedAddressOptions}
                  onSelect={handleFillBillingAddress}
                  appliedOptionId={appliedAddressOptionId}
                />
              )}
            </div>
          ) : (
            <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium text-[hsl(var(--foreground))]">Billing Address</p>
                <div className="flex items-center gap-3">
                  {/* Offered only while the six controls still hold exactly what
                      the fill wrote — see `canUndoFill`. */}
                  {canUndoFill && (
                    <button
                      type="button"
                      onClick={handleUndoFillBillingAddress}
                      className="inline-flex items-center gap-1 text-xs text-[hsl(var(--muted-foreground))] transition-colors hover:text-[hsl(var(--foreground))]"
                    >
                      <Undo2 className="h-3.5 w-3.5" aria-hidden="true" />
                      Undo fill
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => {
                      // Remove unmounts its own button along with the section, so
                      // focus has to be handed to the reveal link that replaces it.
                      restoreAddBillingFocus.current = true;
                      setShowBillingAddress(false);
                      // Without this, collapsing the section leaves the values in
                      // form state and `hasBilling` re-encrypts an address the user
                      // deleted. `clearBillingAddress` also forgets the last fill,
                      // so re-opening the section does not offer an Undo that would
                      // restore an address into a section the user just removed.
                      clearBillingAddress();
                    }}
                    className="text-xs text-[hsl(var(--muted-foreground))] hover:text-[hsl(var(--foreground))]"
                  >
                    Remove
                  </button>
                </div>
              </div>
              {savedAddressOptions.length > 0 && (
                <SavedAddressPicker
                  options={savedAddressOptions}
                  onSelect={handleFillBillingAddress}
                  appliedOptionId={appliedAddressOptionId}
                />
              )}
              <BoundedTextField
                name="billingStreet"
                label="Street"
                placeholder="Street address"
                maxLength={MAX_ADDRESS_STREET_LENGTH}
                register={register}
                errors={errors}
                inputRef={billingStreetRef}
              />
              <BoundedTextField
                name="billingStreet2"
                label="Street 2"
                placeholder="Apartment, suite, unit"
                maxLength={MAX_ADDRESS_STREET_LENGTH}
                register={register}
                errors={errors}
              />
              <div className="grid grid-cols-2 gap-3">
                <BoundedTextField
                  name="billingCity"
                  label="City"
                  placeholder="City"
                  maxLength={MAX_ADDRESS_CITY_LENGTH}
                  register={register}
                  errors={errors}
                />
                <BoundedTextField
                  name="billingState"
                  label="State"
                  placeholder="State"
                  maxLength={MAX_ADDRESS_STATE_LENGTH}
                  register={register}
                  errors={errors}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <BoundedTextField
                  name="billingZip"
                  label="ZIP"
                  placeholder="ZIP code"
                  maxLength={MAX_ADDRESS_ZIP_LENGTH}
                  register={register}
                  errors={errors}
                />
                <BoundedTextField
                  name="billingCountry"
                  label="Country"
                  placeholder="Country"
                  maxLength={MAX_ADDRESS_COUNTRY_LENGTH}
                  register={register}
                  errors={errors}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* --- Identity fields --- */}
      {itemType === 'identity' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <FormField label="First Name" name="firstName" error={errors.firstName?.message}>
              <input
                id="field-firstName"
                {...register('firstName')}
                placeholder="First name"
                maxLength={MAX_IDENTITY_NAME_LENGTH}
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.firstName ? 'field-firstName-error' : undefined}
                aria-invalid={errors.firstName ? true : undefined}
              />
            </FormField>
            <FormField label="Last Name" name="lastName" error={errors.lastName?.message}>
              <input
                id="field-lastName"
                {...register('lastName')}
                placeholder="Last name"
                maxLength={MAX_IDENTITY_NAME_LENGTH}
                className={inputClass}
                autoComplete="off"
                aria-describedby={errors.lastName ? 'field-lastName-error' : undefined}
                aria-invalid={errors.lastName ? true : undefined}
              />
            </FormField>
          </div>
          <FormField label="Email" name="email" error={errors.email?.message}>
            <input
              id="field-email"
              {...register('email')}
              type="email"
              placeholder="Email address"
              maxLength={MAX_IDENTITY_EMAIL_LENGTH}
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.email ? 'field-email-error' : undefined}
              aria-invalid={errors.email ? true : undefined}
            />
          </FormField>
          <FormField label="Phone" name="phone" error={errors.phone?.message}>
            <input
              id="field-phone"
              {...register('phone')}
              type="tel"
              placeholder="Phone number"
              maxLength={MAX_IDENTITY_PHONE_LENGTH}
              className={inputClass}
              autoComplete="off"
              aria-describedby={errors.phone ? 'field-phone-error' : undefined}
              aria-invalid={errors.phone ? true : undefined}
            />
          </FormField>
          <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
            <p className="text-sm font-medium text-[hsl(var(--foreground))]">Address</p>
            <BoundedTextField
              name="street"
              label="Street"
              placeholder="Street address"
              maxLength={MAX_ADDRESS_STREET_LENGTH}
              register={register}
              errors={errors}
            />
            <BoundedTextField
              name="street2"
              label="Street 2"
              placeholder="Apartment, suite, unit"
              maxLength={MAX_ADDRESS_STREET_LENGTH}
              register={register}
              errors={errors}
            />
            <div className="grid grid-cols-2 gap-3">
              <BoundedTextField
                name="city"
                label="City"
                placeholder="City"
                maxLength={MAX_ADDRESS_CITY_LENGTH}
                register={register}
                errors={errors}
              />
              <BoundedTextField
                name="state"
                label="State"
                placeholder="State"
                maxLength={MAX_ADDRESS_STATE_LENGTH}
                register={register}
                errors={errors}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <BoundedTextField
                name="zip"
                label="ZIP"
                placeholder="ZIP code"
                maxLength={MAX_ADDRESS_ZIP_LENGTH}
                register={register}
                errors={errors}
              />
              <BoundedTextField
                name="country"
                label="Country"
                placeholder="Country"
                maxLength={MAX_ADDRESS_COUNTRY_LENGTH}
                register={register}
                errors={errors}
              />
            </div>
            {/* Full width, NOT inside a two-column grid: delivery instructions are
                free text about the address rather than a component of it, and a
                textarea at half width misaligns against the inputs above. */}
            <BoundedTextField
              name="deliveryNotes"
              label="Delivery Notes"
              placeholder="e.g. leave with the concierge, ring twice"
              maxLength={MAX_ADDRESS_DELIVERY_NOTES_LENGTH}
              register={register}
              errors={errors}
              multiline
            />
          </div>

          {/* Company, SSN, passport, notes and custom fields are all stored by
              `identityDataSchema` and written by the Bitwarden importer. Until now no
              control edited them and only `notes` was even displayed, so a retained
              SSN or passport number could not be viewed, corrected or removed short of
              deleting the whole identity. Declaring each one in the local schema hands
              ownership of it from `buildDataPayload`'s merge to this form, which is
              why each is also read in `getDefaultValues` and emitted (as `undefined`
              when empty) from `buildModelledFields`. */}
          <BoundedTextField
            name="company"
            label="Company"
            placeholder="Employer or organization"
            maxLength={MAX_IDENTITY_COMPANY_LENGTH}
            register={register}
            errors={errors}
          />
          <div className="grid grid-cols-2 gap-3">
            <SensitiveTextField
              name="ssn"
              label="Social Security Number"
              placeholder="SSN or national ID"
              maxLength={MAX_IDENTITY_SSN_LENGTH}
              register={register}
              errors={errors}
            />
            <SensitiveTextField
              name="passport"
              label="Passport Number"
              placeholder="Passport number"
              maxLength={MAX_IDENTITY_PASSPORT_LENGTH}
              register={register}
              errors={errors}
            />
          </div>
          <BoundedTextField
            name="notes"
            label="Notes"
            placeholder="Additional notes"
            maxLength={MAX_NOTE_CONTENT_LENGTH}
            register={register}
            errors={errors}
            multiline
            rows={3}
          />
        </div>
      )}

      {/* One custom-field block for every type, after the type's own fields. */}
      <CustomFieldsSection
        fields={customFields}
        onAppend={handleAppendCustomField}
        onRemove={removeCustomField}
        register={register}
        errors={errors}
        watchField={watchField}
        setField={setField}
        allowBoolean={itemType !== 'secret'}
        limit={customFieldsLimit}
        initialCount={initialCustomFieldCount}
        onRowContentChange={recheckCustomFieldName}
        onRowNameChange={recheckNoteContent}
      />

      {/* Common: Folder, Tags, Favorite */}
      <div className="space-y-4 border-t border-[hsl(var(--border))] pt-4">
        {/* Folder selector */}
        <FormField label="Folder" name="folder">
          <select
            id="field-folder"
            value={folderId}
            onChange={(e) => setFolderId(e.target.value)}
            className={inputClass}
          >
            <option value="">No folder</option>
            {folders.map((folder) => (
              <option key={folder.id} value={folder.id}>
                {folder.name}
              </option>
            ))}
          </select>
        </FormField>

        {/* Tags */}
        <TagEditor id="field-tags" field={tagField} subject="item" />

        {/* Favorite toggle */}
        <label className="flex cursor-pointer items-center gap-2">
          <button
            type="button"
            onClick={() => setFavorite((p) => !p)}
            className="rounded p-0.5"
            aria-pressed={favorite}
          >
            <Star
              className={cn(
                'h-5 w-5 transition-colors',
                favorite
                  ? 'fill-yellow-400 text-yellow-400'
                  : 'text-[hsl(var(--muted-foreground))]',
              )}
            />
          </button>
          <span className="text-sm text-[hsl(var(--foreground))]">Mark as favorite</span>
        </label>
      </div>

      {/* After a refused save: how many controls need attention, beside the button
          that was pressed. The messages themselves sit on the controls. */}
      {submitCount > 0 && errorCount > 0 && (
        <FormAlert
          message={
            errorCount === 1
              ? '1 field needs your attention before this item can be saved.'
              : `${String(errorCount)} fields need your attention before this item can be saved.`
          }
        />
      )}

      {/* Actions */}
      <div className="flex justify-end gap-2 border-t border-[hsl(var(--border))] pt-4">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md px-4 py-2 text-sm font-medium text-[hsl(var(--foreground))] hover:bg-[hsl(var(--accent))] transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving}
          className="rounded-md bg-[hsl(var(--primary))] px-4 py-2 text-sm font-medium text-[hsl(var(--primary-foreground))] hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          {saving ? 'Saving...' : isEditing ? 'Update' : 'Create'}
        </button>
      </div>
    </form>
  );
}
