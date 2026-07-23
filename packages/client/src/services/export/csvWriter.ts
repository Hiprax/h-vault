/**
 * A correct RFC 4180 CSV writer — the serialization counterpart to
 * {@link parseCsv} in `services/import/csv.ts`.
 *
 * Rules:
 * - Rows are joined with CRLF (`\r\n`), the line ending RFC 4180 mandates.
 * - A field is quoted only when it must be: when it contains a double quote,
 *   a comma, a CR or an LF, or when it has leading or trailing whitespace
 *   (an unquoted leading/trailing space is ambiguous to, or silently trimmed
 *   by, many CSV consumers).
 * - Inside a quoted field every `"` is doubled to `""`.
 *
 * Values are emitted VERBATIM. In particular a value that begins with `=`,
 * `+`, `-` or `@` is NOT prefixed, escaped, or otherwise altered to defuse a
 * spreadsheet formula: doing so would corrupt passwords that legitimately
 * begin with those characters, and quoting does not stop a spreadsheet from
 * evaluating a formula anyway. The plaintext export warns the user that the
 * file must not be opened in a spreadsheet instead. See PLAN §1.7 and
 * `SECURITY.md`. Fidelity beats a mitigation that only half works.
 *
 * Round-trip guarantee: `parseCsv(toCsv(headers, rows))` reproduces
 * `[headers, ...rows]` exactly, for every matrix EXCEPT a row that is a single
 * empty field (`['']`) or an empty row (`[]`) — `parseCsv` treats a one-cell
 * empty line as a blank line and drops it by design, and no serialization can
 * make it survive. Real exports always emit a multi-column header and
 * rectangular rows, so this degenerate case does not arise in practice.
 *
 * @param headers the column headers, emitted as row 0 of the output
 * @param rows the data rows; every cell must already be a string — callers pass
 *   `''` for an absent value. `null`/`undefined` are not accepted.
 * @returns the CSV document as a single string (no trailing newline)
 */
export function toCsv(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  const lines: string[] = [encodeRow(headers)];
  for (const row of rows) {
    lines.push(encodeRow(row));
  }
  return lines.join('\r\n');
}

/** Encode one record: each field escaped, joined by a comma. */
function encodeRow(row: readonly string[]): string {
  return row.map(encodeField).join(',');
}

/**
 * Quote a single field per RFC 4180 when — and only when — it needs quoting,
 * doubling any embedded `"`. The value itself is never modified beyond this
 * lossless quoting.
 */
function encodeField(value: string): string {
  const needsQuoting =
    value.includes('"') ||
    value.includes(',') ||
    value.includes('\r') ||
    value.includes('\n') ||
    value !== value.trim();

  if (!needsQuoting) return value;

  return `"${value.replace(/"/g, '""')}"`;
}
