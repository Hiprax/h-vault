import { Schema } from 'mongoose';

// ----- Sub-interface -----

export interface IDeviceInfo {
  userAgent: string;
  ip: string;
  fingerprint: string;
}

// ----- Sub-Schema -----

/**
 * Shared, embedded device-info sub-schema (`{ _id: false }`) for any model
 * that records the device a credential was issued to — used by `RefreshToken`.
 * The length caps mirror the boundary
 * truncation performed by `getRequestContext` (userAgent 512, ip 45) plus the
 * device fingerprint (128); they are defense-in-depth against a writer that
 * bypasses that helper.
 */
export const deviceInfoSchema = new Schema<IDeviceInfo>(
  {
    userAgent: { type: String, default: '', maxlength: 512 },
    ip: { type: String, default: '', maxlength: 45 },
    fingerprint: { type: String, default: '', maxlength: 128 },
  },
  { _id: false },
);
