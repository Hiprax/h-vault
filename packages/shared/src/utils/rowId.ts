import { ROW_ID_DERIVATION_PREFIX, ROW_ID_NONCE_PATTERN } from '../constants/index.js';

/** A 24-character hex ObjectId, in either case. */
const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

/**
 * A fresh row-id nonce: eight hex characters of seconds since the epoch, then
 * thirty-two of randomness from the platform's cryptographic generator.
 *
 * The timestamp is taken modulo 2^32 so it always fits the eight characters an
 * ObjectId gives it. Throws, never falls back, without a cryptographic generator:
 * a guessable nonce would let a second session of the same account race for the
 * id, and a collision is a refused create rather than anything worse, but there
 * is no reason to allow it.
 */
export function generateRowIdNonce(nowMs: number = Date.now()): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Cryptographic random API is unavailable. Cannot generate a row id.');
  }
  const seconds = Math.floor(nowMs / 1000) % 2 ** 32;
  const random = crypto.getRandomValues(new Uint8Array(16));
  return (
    seconds.toString(16).padStart(8, '0') +
    Array.from(random, (b) => b.toString(16).padStart(2, '0')).join('')
  );
}

/**
 * The `_id` a row created with `idNonce` by `userId` is stored under.
 *
 * The ONE definition, computed by the browser before it seals the row's fields
 * and by the server when it stores the row, so the two cannot disagree. See
 * `ROW_ID_DERIVATION_PREFIX` for the layout and for why the id is derived rather
 * than chosen. The user id is lower-cased first, the canonical form
 * `objectIdSchema` gives every id, so the same account always derives the same
 * row id however its id happens to be spelled.
 *
 * Rejects a user id that is not an ObjectId and a nonce outside
 * `ROW_ID_NONCE_PATTERN`: both are read from places the type system cannot vouch
 * for, and the layout is only unambiguous for those alphabets.
 */
export async function deriveRowId(userId: string, idNonce: string): Promise<string> {
  if (!OBJECT_ID_RE.test(userId)) {
    throw new Error('A row id is derived from an ObjectId user id');
  }
  if (!ROW_ID_NONCE_PATTERN.test(idNonce)) {
    throw new Error('A row id nonce is 40 lower-case hex characters');
  }
  const input = new TextEncoder().encode(
    `${ROW_ID_DERIVATION_PREFIX}${userId.toLowerCase()}|${idNonce}`,
  );
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  const tail = Array.from(digest.subarray(0, 8), (b) => b.toString(16).padStart(2, '0')).join('');
  return idNonce.slice(0, 8) + tail;
}
