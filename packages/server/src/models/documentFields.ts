/**
 * The field groups the `documents` row and the `document_uploads` staging row
 * both carry, declared ONCE.
 *
 * Two rows hold the same wrapped document key and the same plaintext framing
 * fields, because the staging row is what the committed row is built from: the
 * DEK is wrapped before the first byte is sealed, and the salt and nonce prefix
 * are chosen at the same moment. Writing those five paths out in both schemas
 * would put every bound in two places, and a bound edited in one copy and not the
 * other is a document that uploads and will not open — the exact failure
 * `schemas/document.ts` factors `wrappedDekFields` and `streamFramingFields` out
 * for on the wire side. This module is that same rule for the storage side.
 *
 * The paths are returned by FUNCTIONS rather than exported as shared object
 * literals. Mongoose keeps a reference to the options object it is handed
 * (`SchemaType.prototype.options`), so one literal shared by two schemas would be
 * one object owned by two SchemaTypes; a fresh literal per call costs nothing at
 * module load and removes the question entirely.
 *
 * Neither group is a sub-schema (`deviceInfo.ts` is, and this deliberately is
 * not): these are top-level columns of both rows, and nesting them would change
 * the wire shape of every response and every query predicate for a cosmetic gain.
 */

/**
 * The wrapped document key: `DEK` sealed under a wrapping key derived from the
 * vault key and bound to the document id.
 *
 * The bounds are the vault's existing ciphertext conventions — 200 for a wrapped
 * 256-bit key, 24 for a base64 12-byte IV, 32 for a base64 16-byte tag — the same
 * three `User.encryptedVaultKey` / `vaultKeyIv` / `vaultKeyTag` carry, because
 * this is the same shape of value. They are inline for the reason
 * `schemas/document.ts` records beside its own `max(24)` / `max(32)`: no named
 * document constant describes them, and inventing one here would leave the bound
 * written two ways in neighbouring files.
 */
export interface IWrappedDekFields {
  encryptedDek: string;
  dekIv: string;
  dekTag: string;
}

/** {@link IWrappedDekFields} as Mongoose schema paths. */
export const wrappedDekPaths = () => ({
  encryptedDek: { type: String, required: true, maxlength: 200 },
  dekIv: { type: String, required: true, maxlength: 24 },
  dekTag: { type: String, required: true, maxlength: 32 },
});

/**
 * The two PLAINTEXT framing fields, stored base64.
 *
 * Neither is a secret — a salt and a nonce prefix are public parameters — but
 * both are covered by every segment's own authentication: substituting either one
 * makes the segment fail to decrypt, which is what stops a hostile server
 * swapping them. The exact byte counts (`DOCUMENT_STREAM_SALT_BYTES` 32,
 * `DOCUMENT_NONCE_PREFIX_BYTES` 7, so 44 and 12 base64 characters) are pinned by
 * `streamFramingFields` in `@hvault/shared`, which every request carrying them is
 * validated against BEFORE it reaches a model.
 *
 * These bounds are therefore deliberately slack rather than exact. A storage
 * `maxlength` is a backstop against an unbounded write, and pinning it to today's
 * byte count would mean a future format revision that widened either field
 * failed at the database with a message naming neither the format nor the
 * revision. The wire schema is where an exact length belongs, and it has one.
 */
export interface IStreamFramingFields {
  streamSalt: string;
  noncePrefix: string;
}

/** {@link IStreamFramingFields} as Mongoose schema paths. */
export const streamFramingPaths = () => ({
  streamSalt: { type: String, required: true, maxlength: 64 },
  noncePrefix: { type: String, required: true, maxlength: 16 },
});
