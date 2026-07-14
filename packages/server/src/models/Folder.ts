import mongoose, { Schema, type Model, type HydratedDocument, type Types } from 'mongoose';

// ----- Interface -----

export interface IFolder {
  _id: Types.ObjectId;
  userId: Types.ObjectId;
  encryptedName: string;
  nameIv: string;
  nameTag: string;
  searchHash?: string | undefined;
  // Restore provenance: the backup row's original `_id` (as a string), set ONLY
  // when the server fresh-inserts a NON-owned folder during restore so a repeat
  // restore of the same backup can match `(userId, sourceRefId)` instead of
  // duplicating. Server-internal and privacy-sensitive (it is another account's
  // ObjectId): NEVER serialized to clients — excluded via `.select('-sourceRefId')`
  // on every lean read/export/backup path, with the `toJSON` strip as
  // defense-in-depth for the hydrated create path.
  sourceRefId?: string | undefined;
  parentId?: Types.ObjectId | undefined;
  icon?: string | undefined;
  color?: string | undefined;
  sortOrder: number;
  createdAt: Date;
  updatedAt: Date;
}

export type FolderDocument = HydratedDocument<IFolder>;

// ----- Schema -----

const folderSchema = new Schema<IFolder>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    encryptedName: { type: String, required: true, maxlength: 1000 },
    nameIv: { type: String, required: true, maxlength: 24 },
    nameTag: { type: String, required: true, maxlength: 32 },
    searchHash: { type: String, sparse: true, maxlength: 128, match: /^[a-f0-9]{64}$/ },
    sourceRefId: { type: String },
    parentId: {
      type: Schema.Types.ObjectId,
      ref: 'Folder',
      default: undefined,
    },
    icon: { type: String, maxlength: 50 },
    color: { type: String, maxlength: 20 },
    sortOrder: { type: Number, default: 0 },
  },
  {
    timestamps: true,
    collection: 'folders',
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

folderSchema.index({ userId: 1, parentId: 1 });
folderSchema.index({ userId: 1, sortOrder: 1 });
folderSchema.index(
  { userId: 1, searchHash: 1 },
  {
    unique: true,
    partialFilterExpression: { searchHash: { $type: 'string' } },
  },
);

// Restore idempotency: matches a repeat-restored, non-owned folder by its origin
// `_id` so `skip`/`overwrite` do not duplicate. NON-unique (keep_both may mint
// several rows from one source). `partialFilterExpression` (NOT `sparse`) is
// required: a compound sparse index would index EVERY document because `userId`
// is always present, whereas the partial filter restricts the index to only the
// restore-provenance rows that actually carry a `sourceRefId`.
folderSchema.index(
  { userId: 1, sourceRefId: 1 },
  { partialFilterExpression: { sourceRefId: { $type: 'string' } } },
);

// ----- Model -----

export const Folder: Model<IFolder> = mongoose.model<IFolder>('Folder', folderSchema);
