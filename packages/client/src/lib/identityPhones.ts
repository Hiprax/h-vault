/**
 * An identity's phone numbers: the ONE place that reads them and the ONE place
 * that decides how they are stored.
 *
 * Two stored shapes exist, and both stay valid. An identity with one unlabelled
 * number keeps it in `phone`, exactly as every identity did before 0.22.0, so an
 * entry nobody gave a second number to is stored byte for byte as it always was
 * and an older client reads it unchanged. An identity with more numbers, or a
 * label, ALSO carries `phones`, and then `phone` is always `phones[0].number`, so
 * that older client still shows the first number.
 */

/** One number as the form edits it: a label (possibly empty) and the number. */
export interface PhoneRow {
  label: string;
  number: string;
}

/** One number as it is stored. */
export interface StoredPhone {
  label?: string;
  number: string;
}

/** The numbers an identity holds, in order: `phones` when it has any, else its one `phone`. */
export function readIdentityPhones(data: { phone?: unknown; phones?: unknown }): StoredPhone[] {
  if (Array.isArray(data.phones) && data.phones.length > 0) {
    return (data.phones as StoredPhone[]).map((phone) =>
      phone.label === undefined
        ? { number: phone.number }
        : { label: phone.label, number: phone.number },
    );
  }
  return typeof data.phone === 'string' && data.phone !== '' ? [{ number: data.phone }] : [];
}

/** The form's rows for an identity: its numbers, or one empty row for none. */
export function identityPhoneRows(data: { phone?: unknown; phones?: unknown }): PhoneRow[] {
  const stored = readIdentityPhones(data);
  return stored.length === 0
    ? [{ label: '', number: '' }]
    : stored.map((phone) => ({ label: phone.label ?? '', number: phone.number }));
}

/**
 * The `phone` and `phones` keys to store for `rows`.
 *
 * BOTH keys, always: the item's data is saved by merging these over what is
 * stored, and an `undefined` is what deletes a key there, so going from three
 * numbers to one must say `phones: undefined` or the old list would survive.
 * A row with no number is dropped (the form refuses one that has a label), and an
 * empty label is not stored.
 */
export function writeIdentityPhones(rows: readonly PhoneRow[]): {
  phone: string | undefined;
  phones: StoredPhone[] | undefined;
} {
  const stored = rows
    .filter((row) => row.number !== '')
    .map((row): StoredPhone => {
      const label = row.label.trim();
      return label === '' ? { number: row.number } : { label, number: row.number };
    });
  const [first] = stored;
  if (first === undefined) return { phone: undefined, phones: undefined };
  if (stored.length === 1 && first.label === undefined) {
    return { phone: first.number, phones: undefined };
  }
  return { phone: first.number, phones: stored };
}

/**
 * What a stored number is called on screen and in an export: "Phone" for the first
 * when it has no label, "Phone (Work)" for a labelled one, "Phone 2" onwards for
 * the rest.
 */
export function phoneDisplayLabel(phone: { label?: string | undefined }, index: number): string {
  if (phone.label !== undefined) return `Phone (${phone.label})`;
  return index === 0 ? 'Phone' : `Phone ${String(index + 1)}`;
}
