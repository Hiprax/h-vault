/**
 * Phase 12 — the device-info sub-schema now lives in its own module
 * (`models/deviceInfo.ts`) and is shared by every model that records the
 * device a credential was issued to. These checks pin the extracted schema's
 * caps and `{ _id: false }`, and assert that `IDeviceInfo` is STILL exported
 * from its original module (`RefreshToken.ts`) so no existing importer breaks.
 */
import { describe, it, expect, expectTypeOf } from 'vitest';
import { deviceInfoSchema, type IDeviceInfo } from '../src/models/deviceInfo.js';
// Type-level check: IDeviceInfo must remain importable from its original module.
import type { IDeviceInfo as IDeviceInfoFromRefreshToken } from '../src/models/RefreshToken.js';

describe('deviceInfoSchema (shared sub-schema)', () => {
  it('preserves the exact length caps 512/45/128', () => {
    expect(deviceInfoSchema.path('userAgent').options.maxlength).toBe(512);
    expect(deviceInfoSchema.path('ip').options.maxlength).toBe(45);
    expect(deviceInfoSchema.path('fingerprint').options.maxlength).toBe(128);
  });

  it("defaults every field to '' ", () => {
    expect(deviceInfoSchema.path('userAgent').options.default).toBe('');
    expect(deviceInfoSchema.path('ip').options.default).toBe('');
    expect(deviceInfoSchema.path('fingerprint').options.default).toBe('');
  });

  it('is an embedded sub-document with no _id', () => {
    expect(deviceInfoSchema.options._id).toBe(false);
  });

  it('re-exports IDeviceInfo from its original module unchanged', () => {
    // Compile-time proof the type is still exported from RefreshToken.ts and
    // is structurally identical to the one defined in deviceInfo.ts.
    expectTypeOf<IDeviceInfoFromRefreshToken>().toEqualTypeOf<IDeviceInfo>();
    const sample: IDeviceInfoFromRefreshToken = { userAgent: 'a', ip: 'b', fingerprint: 'c' };
    expect(sample.userAgent).toBe('a');
  });
});
