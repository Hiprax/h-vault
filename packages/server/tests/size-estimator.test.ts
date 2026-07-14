/**
 * Phase 3.6 — sizeEstimator utility tests.
 *
 * Verifies that the shared estimator helpers produce conservative (>= actual)
 * byte-size estimates and are exercised by both the backup controller and the
 * backup scheduler so the export/backup paths share a single implementation.
 */
import { describe, it, expect } from 'vitest';

import { estimateItemJsonSize, estimateFolderJsonSize } from '../src/utils/sizeEstimator.js';

describe('sizeEstimator helpers', () => {
  it('estimateItemJsonSize is >= JSON.stringify byte length for a typical item', () => {
    const item = {
      _id: '507f1f77bcf86cd799439011',
      userId: '507f1f77bcf86cd799439012',
      itemType: 'login',
      encryptedData: 'x'.repeat(2_000),
      dataIv: 'a'.repeat(16),
      dataTag: 'b'.repeat(24),
      encryptedName: 'y'.repeat(200),
      nameIv: 'c'.repeat(16),
      nameTag: 'd'.repeat(24),
      searchHash: 'e'.repeat(64),
      tags: ['banking', 'work', 'archive'],
      favorite: true,
      folderId: '507f1f77bcf86cd799439013',
      passwordHistory: [
        {
          encryptedPassword: 'p'.repeat(100),
          iv: 'i'.repeat(16),
          tag: 't'.repeat(24),
          changedAt: new Date().toISOString(),
        },
        {
          encryptedPassword: 'q'.repeat(100),
          iv: 'i'.repeat(16),
          tag: 't'.repeat(24),
          changedAt: new Date().toISOString(),
        },
      ],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const actualBytes = Buffer.byteLength(JSON.stringify(item), 'utf-8');
    const estimated = estimateItemJsonSize(item);
    expect(estimated).toBeGreaterThanOrEqual(actualBytes);
  });

  it('estimateFolderJsonSize is >= JSON.stringify byte length for a typical folder', () => {
    const folder = {
      _id: '507f1f77bcf86cd799439014',
      userId: '507f1f77bcf86cd799439015',
      encryptedName: 'name'.repeat(50),
      nameIv: 'iv'.repeat(8),
      nameTag: 'tag'.repeat(8),
      searchHash: 'h'.repeat(64),
      icon: 'lock',
      color: '#ff8800',
      parentId: '507f1f77bcf86cd799439016',
      sortOrder: 3,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    const actualBytes = Buffer.byteLength(JSON.stringify(folder), 'utf-8');
    const estimated = estimateFolderJsonSize(folder);
    expect(estimated).toBeGreaterThanOrEqual(actualBytes);
  });

  it('handles items without optional fields (no tags, no passwordHistory)', () => {
    const item = {
      _id: '507f1f77bcf86cd799439011',
      itemType: 'note',
      encryptedData: 'x'.repeat(50),
      dataIv: 'a'.repeat(16),
      dataTag: 'b'.repeat(24),
      encryptedName: 'y'.repeat(50),
      nameIv: 'c'.repeat(16),
      nameTag: 'd'.repeat(24),
    };

    const estimated = estimateItemJsonSize(item);
    expect(estimated).toBeGreaterThan(0);
    expect(estimated).toBeGreaterThanOrEqual(Buffer.byteLength(JSON.stringify(item), 'utf-8'));
  });

  it('handles folders missing optional fields (icon/color/searchHash)', () => {
    const folder = {
      _id: '507f1f77bcf86cd799439014',
      encryptedName: 'minimal',
      nameIv: 'iv',
      nameTag: 'tag',
    };
    const estimated = estimateFolderJsonSize(folder);
    expect(estimated).toBeGreaterThan(0);
    expect(estimated).toBeGreaterThanOrEqual(Buffer.byteLength(JSON.stringify(folder), 'utf-8'));
  });
});

// NOTE: The former "sizeEstimator usage by callers (Task 3.6)" describe block
// was removed. Those three tests read the caller source files as TEXT and
// regex-matched their import statements — they asserted nothing about behavior
// (a caller could import the helpers, drop the size guard, and still pass) and
// were fragile to harmless refactors (module-path rename, namespace import).
// The behavior they claimed to guard is exercised by real integration tests:
//   • backupController.collectBackupData 413 size guard → backup.test.ts
//     ("reject backup download when item/folder data exceeds max size during
//     streaming", asserting 413 + the "during collection" streaming message).
//   • backupScheduler.processUserBackup size guard → background-jobs.test.ts
//     and coverage-cascade-scheduler.test.ts (BACKUP_MAX_SIZE_MB override +
//     final-buffer under-count check).
//   • toolsController export size guard → tools.test.ts ("reject export when
//     payload exceeds EXPORT_MAX_SIZE_MB" → 413).
