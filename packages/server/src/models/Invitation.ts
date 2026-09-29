import mongoose, { Schema, type Model, type Types } from 'mongoose';

// ----- Interface -----

/**
 * One invitation to register, minted while `REGISTRATION_MODE` is `invite`.
 *
 * The token itself is never stored: the link carries it in its fragment and the
 * row keeps only a keyed hash of it (`utils/invitations.ts`), so a copy of this
 * collection admits nobody. It is bound to ONE address and spent by the first
 * registration of that address.
 */
export interface IInvitation {
  _id: Types.ObjectId;
  /** Keyed hash of the token (hex). Unique: one row per token. */
  tokenHash: string;
  /** The only address this invitation admits, lower-cased as accounts are stored. */
  email: string;
  /**
   * The INVITING account, or `null` for an invitation the operator minted with
   * the CLI.
   *
   * Named `userId` rather than `inviterId` for one reason: the row belongs to the
   * inviter, and the account erasure (`utils/cascadeDelete.ts`) erases every
   * per-account collection by `userId`, in both its batch loop and its final
   * sweep. Under any other name this collection would need a special case in
   * both, and a special case is the one a later edit forgets.
   */
  userId: Types.ObjectId | null;
  /** When the invitation stops working; the TTL index removes the row after it. */
  expiresAt: Date;
  /** When a registration spent it. Absent while it is still usable. */
  consumedAt?: Date | undefined;
  createdAt: Date;
  updatedAt: Date;
}

// ----- Schema -----

const invitationSchema = new Schema<IInvitation>(
  {
    tokenHash: { type: String, required: true },
    email: { type: String, required: true, lowercase: true, trim: true, maxlength: 254 },
    userId: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    expiresAt: { type: Date, required: true },
    consumedAt: { type: Date, default: undefined },
  },
  {
    timestamps: true,
    collection: 'invitations',
    toJSON: {
      transform(_doc, ret) {
        const { __v, tokenHash: _tokenHash, ...rest } = ret;
        return rest;
      },
    },
  },
);

// ----- Indexes -----

// One row per token, and the lookup a registration makes.
invitationSchema.index({ tokenHash: 1 }, { unique: true });
// The per-inviter daily count, and the account erasure's batch walk.
invitationSchema.index({ userId: 1, createdAt: -1 });
// Expired invitations remove themselves, spent or not.
invitationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ----- Model -----

export const Invitation: Model<IInvitation> = mongoose.model<IInvitation>(
  'Invitation',
  invitationSchema,
);
