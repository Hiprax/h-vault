/**
 * Single source of truth for the Mongoose models whose indexes must be created
 * explicitly in production.
 *
 * In production `autoIndex` is disabled (see config/database.ts), so indexes are
 * never built implicitly. The `create-indexes` script iterates this list to call
 * `model.createIndexes()` for each model. Keeping the list here — rather than
 * inline in the script — lets a drift test assert that EVERY registered model
 * with declared indexes is present, so a newly added model (e.g. `Migration`)
 * can never silently miss index creation in production.
 *
 * Importing this module registers every listed model on the shared Mongoose
 * instance as a side effect.
 */
import { User } from '../src/models/User.js';
import { VaultItem } from '../src/models/VaultItem.js';
import { Folder } from '../src/models/Folder.js';
import { RefreshToken } from '../src/models/RefreshToken.js';
import { AuditLog } from '../src/models/AuditLog.js';
import { BackupLog } from '../src/models/BackupLog.js';
import { JobLock } from '../src/models/JobLock.js';
import { Migration } from '../src/models/Migration.js';
import { PwnedRangeCache } from '../src/models/PwnedRangeCache.js';

export const indexedModels = [
  { name: 'User', model: User },
  { name: 'VaultItem', model: VaultItem },
  { name: 'Folder', model: Folder },
  { name: 'RefreshToken', model: RefreshToken },
  { name: 'AuditLog', model: AuditLog },
  { name: 'BackupLog', model: BackupLog },
  { name: 'JobLock', model: JobLock },
  { name: 'Migration', model: Migration },
  { name: 'PwnedRangeCache', model: PwnedRangeCache },
];
