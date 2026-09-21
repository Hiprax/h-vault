import type { MigrationEntry, MigrationPayload } from './migrationReader';

/**
 * Collecting the several QR codes one Google Authenticator export produces.
 *
 * A batched export shows its codes one at a time, and the payload carries
 * `batch_id`, `batch_size` and `batch_index` so a reader can tell the parts of
 * one export apart from another's.
 *
 * ---------------------------------------------------------------------------
 * COMPLETION DOES NOT DEPEND ON THE INDEX BASE
 * ---------------------------------------------------------------------------
 *
 * `batch_index` is 0-based in every implementation that has been examined, but
 * nothing published says so, and getting it wrong in either direction produces
 * an export that can never complete or one that completes a part early. So this
 * never asks what the first index is: it collects DISTINCT indices and finishes
 * when it holds `batch_size` of them. That is correct under either convention,
 * and it also tolerates the parts being scanned out of order, which matters
 * because a person holding a phone up to a webcam will not reliably get them in
 * sequence.
 *
 * Progress is reported from how many distinct parts are held, never from
 * `batchIndex + 1`, for the same reason.
 */

export interface BatchState {
  /** `null` until the first part fixes it. */
  readonly batchId: number | null;
  readonly batchSize: number;
  /** Entries by `batchIndex`. */
  readonly parts: ReadonlyMap<number, readonly MigrationEntry[]>;
}

export type BatchOutcome =
  /** A new part was taken. */
  | { readonly kind: 'added'; readonly state: BatchState }
  /** The same part again, byte for byte. Re-scanning one code is normal. */
  | { readonly kind: 'duplicate'; readonly state: BatchState }
  /** A part of a DIFFERENT export. Mixing two would produce a mangled set. */
  | { readonly kind: 'wrong-export' }
  /** The same index with different contents: two exports made moments apart. */
  | { readonly kind: 'conflicting-part' };

export function emptyBatch(): BatchState {
  return { batchId: null, batchSize: 0, parts: new Map() };
}

function sameSecret(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Are these the same accounts?
 *
 * Compared field by field rather than through a fingerprint string, so no
 * rendering of a secret is created merely to decide whether two scans match.
 */
function sameEntries(a: readonly MigrationEntry[], b: readonly MigrationEntry[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((entry, index) => {
    const other = b[index];
    if (other === undefined) return false;
    return (
      entry.type === other.type &&
      entry.name === other.name &&
      entry.issuer === other.issuer &&
      entry.algorithm === other.algorithm &&
      entry.digits === other.digits &&
      entry.counter === other.counter &&
      sameSecret(entry.secret, other.secret)
    );
  });
}

/** Take one scanned part into the set, or say why it was refused. */
export function acceptPart(state: BatchState, payload: MigrationPayload): BatchOutcome {
  if (state.batchId !== null && state.batchId !== payload.batchId) {
    return { kind: 'wrong-export' };
  }

  const existing = state.parts.get(payload.batchIndex);
  if (existing !== undefined) {
    return sameEntries(existing, payload.entries)
      ? { kind: 'duplicate', state }
      : { kind: 'conflicting-part' };
  }

  const parts = new Map(state.parts);
  parts.set(payload.batchIndex, payload.entries);
  return {
    kind: 'added',
    state: { batchId: payload.batchId, batchSize: payload.batchSize, parts },
  };
}

/** How many distinct parts are held. This is what progress is reported from. */
export function capturedParts(state: BatchState): number {
  return state.parts.size;
}

export function isComplete(state: BatchState): boolean {
  return state.batchSize > 0 && state.parts.size >= state.batchSize;
}

/**
 * Every account in the set, in part order.
 *
 * Sorted by index rather than by arrival, so the list a person reads is the
 * order the export defined no matter which code they happened to scan first.
 */
export function collectedEntries(state: BatchState): MigrationEntry[] {
  return [...state.parts.entries()]
    .sort(([a], [b]) => a - b)
    .flatMap(([, entries]) => [...entries]);
}
