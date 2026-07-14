import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';
import {
  ITEM_TYPES,
  MAX_TAGS_PER_ITEM,
  MAX_TAG_LENGTH,
  PASSWORD_HISTORY_MAX,
} from '@hvault/shared';
import type { ItemType } from '@hvault/shared';

// ----- Sub-interfaces -----

export interface IPasswordHistoryEntry {
  encryptedPassword: string;
  iv: string;
  tag: string;
  changedAt: Date;
}

// ----- Main Interface -----

export interface IVaultItem {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  itemType: ItemType;
  folderId?: Types.ObjectId | undefined;
  tags: string[];
  favorite: boolean;
  encryptedData: string;
  dataIv: string;
  dataTag: string;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash?: string | undefined;
  // Restore provenance: the backup row's original `_id` (as a string), set ONLY
  // when the server fresh-inserts a NON-owned row during restore so a repeat
  // restore of the same backup can match `(userId, sourceRefId)` instead of
  // duplicating. Server-internal and privacy-sensitive (it is another account's
  // ObjectId): NEVER serialized to clients — excluded via `.select('-sourceRefId')`
  // on every lean read/export/backup path, with the `toJSON` strip as
  // defense-in-depth for the hydrated create path.
  sourceRefId?: string | undefined;
  passwordHistory?: IPasswordHistoryEntry[] | undefined;
  deletedAt?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

export type VaultItemDocument = HydratedDocument<IVaultItem>;

// ----- Sub-Schemas -----

const passwordHistoryEntrySchema = new Schema<IPasswordHistoryEntry>(
  {
    encryptedPassword: { type: String, required: true, maxlength: 5_000 },
    iv: { type: String, required: true, maxlength: 24 },
    tag: { type: String, required: true, maxlength: 32 },
    changedAt: { type: Date, required: true, default: Date.now },
  },
  { _id: false },
);

// ----- Main Schema -----

const vaultItemSchema = new Schema<IVaultItem>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    itemType: {
      type: String,
      required: true,
      enum: ITEM_TYPES,
    },
    folderId: {
      type: Schema.Types.ObjectId,
      ref: 'Folder',
      default: undefined,
    },
    tags: {
      type: [{ type: String, maxlength: MAX_TAG_LENGTH }],
      default: [],
      validate: {
        validator: (v: string[]) => v.length <= MAX_TAGS_PER_ITEM,
        message: `tags cannot exceed ${String(MAX_TAGS_PER_ITEM)} entries`,
      },
    },
    favorite: {
      type: Boolean,
      default: false,
    },
    encryptedData: { type: String, required: true, maxlength: 500_000 },
    dataIv: { type: String, required: true, maxlength: 24 },
    dataTag: { type: String, required: true, maxlength: 32 },
    encryptedName: { type: String, required: true, maxlength: 1000 },
    nameIv: { type: String, required: true, maxlength: 24 },
    nameTag: { type: String, required: true, maxlength: 32 },
    searchHash: { type: String, match: /^[a-f0-9]{64}$/ },
    sourceRefId: { type: String },
    passwordHistory: {
      type: [passwordHistoryEntrySchema],
      default: undefined,
      validate: {
        validator: (v: IPasswordHistoryEntry[]) => v.length <= PASSWORD_HISTORY_MAX,
        message: `passwordHistory cannot exceed ${PASSWORD_HISTORY_MAX} entries`,
      },
    },
    deletedAt: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'vault_items',
    toJSON: {
      transform(_doc, ret) {
        // Strip server-only fields that have no client purpose. `userId` is
        // implied by the authenticated session and would only widen the leak
        // surface (logs, error reports, shared-browser caches).
        const { __v: _v, userId: _userId, sourceRefId: _sourceRefId, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

vaultItemSchema.index({ userId: 1, itemType: 1 });
vaultItemSchema.index({ userId: 1, folderId: 1 });
vaultItemSchema.index({ userId: 1, favorite: 1 });
vaultItemSchema.index({ userId: 1, deletedAt: -1 });
vaultItemSchema.index({ userId: 1, updatedAt: -1 });
vaultItemSchema.index({ userId: 1, createdAt: -1 });
vaultItemSchema.index({ userId: 1, searchHash: 1 }, { sparse: true });
vaultItemSchema.index({ userId: 1, tags: 1 });

// Restore idempotency: matches a repeat-restored, non-owned row by its origin
// `_id` so `skip`/`overwrite` do not duplicate. NON-unique (keep_both may mint
// several rows from one source). `partialFilterExpression` (NOT `sparse`) is
// required: a compound sparse index would index EVERY document because `userId`
// is always present, whereas the partial filter restricts the index to only the
// restore-provenance rows that actually carry a `sourceRefId`.
vaultItemSchema.index(
  { userId: 1, sourceRefId: 1 },
  { partialFilterExpression: { sourceRefId: { $type: 'string' } } },
);

// Supports the trash auto-purge cron (`jobs/trashCleanup.ts`), which scans
// `{ deletedAt: { $lte: cutoff } }` across ALL users with no `userId` predicate.
// None of the `userId`-prefixed compound indexes above can seek that query, so it
// would otherwise COLLSCAN the whole collection every 500-item batch.
//
// `sparse` is chosen over a `{ deletedAt: { $exists: true } }` partial filter on
// purpose: MongoDB will not use such a partial index for a `$lte` *range*
// predicate (the planner can't prove the range is a subset of `$exists`), so the
// partial index would be built yet never selected — dead weight. A sparse index
// has no such restriction and is reliably chosen for the range query. It also
// stays small: every write to `deletedAt` in the codebase is `$set: new Date()`
// (soft delete) or `$unset` (restore) — it is absent on the active majority — so
// only soft-deleted rows are indexed. Even if a row ever carried `deletedAt:
// null`, `{ $lte: <Date> }` type-brackets to dates and would not return it, so
// results stay correct regardless of the index's contents.
vaultItemSchema.index({ deletedAt: 1 }, { sparse: true });

// ----- Discriminator base setup -----
// The itemType field serves as the discriminator key.
// Consumers can create discriminators on the exported model for type-specific
// validation or virtual fields if needed:
//   const LoginItem = VaultItem.discriminator('login', loginSchema);

// ----- Model -----

export const VaultItem: Model<IVaultItem> = mongoose.model<IVaultItem>(
  'VaultItem',
  vaultItemSchema,
);
