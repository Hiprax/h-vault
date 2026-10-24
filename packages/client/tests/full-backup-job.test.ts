/**
 * The full backup's code as the Backup page reaches it: the ONE lazy loader
 * (`loadFullBackupJob.ts`) and the module it loads (`fullBackupJob.ts`), which
 * opens the file a backup is written into.
 *
 * What each case would catch:
 *   - a wrong path in the `import()`: the real module would not load at all;
 *   - dropping the translation: the panel would show a bundler's "Failed to fetch
 *     dynamically imported module" to a person;
 *   - an await before the save dialog: a real browser refuses a dialog opened
 *     outside the click's activation;
 *   - the wrong file type or name offered in the dialog.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/stores/encryptedStorage', () => ({
  encryptedStorage: {
    getItem: vi.fn().mockResolvedValue(null),
    setItem: vi.fn().mockResolvedValue(undefined),
    removeItem: vi.fn(),
  },
}));

const JOB = '../src/services/backup/fullBackupJob.js';

afterEach(() => {
  vi.doUnmock(JOB);
  vi.resetModules();
  delete (window as unknown as Record<string, unknown>)['showSaveFilePicker'];
});

describe('loadFullBackupJob', () => {
  it('loads the real full backup code', async () => {
    vi.resetModules();
    const { loadFullBackupJob } = await import('../src/services/backup/loadFullBackupJob');

    const job = await loadFullBackupJob();

    expect(job.createFullBackup).toBeTypeOf('function');
    expect(job.restoreFullBackupDocuments).toBeTypeOf('function');
    expect(job.openFullBackupFile).toBeTypeOf('function');
    expect(job.deriveFullBackupSigningKey).toBeTypeOf('function');
    expect(job.verifyFullBackupManifest).toBeTypeOf('function');
    expect(job.openFullBackupTarget).toBeTypeOf('function');
    expect(job.hasSaveDialog).toBeTypeOf('function');
    expect(job.FullBackupFormatError).toBeTypeOf('function');
  });

  it('says what happened in words a person can act on, keeping the failure as the cause', async () => {
    vi.resetModules();
    vi.doMock(JOB, () => {
      throw new Error('Failed to fetch dynamically imported module');
    });
    const { loadFullBackupJob } = await import('../src/services/backup/loadFullBackupJob');

    const failure: unknown = await loadFullBackupJob().catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe(
      'Part of H-Vault needed for full backups did not load. Try again; if it keeps failing, reload the page.',
    );
    expect((failure as Error).cause).toBeInstanceOf(Error);
  });
});

describe('fullBackupJob', () => {
  it('reports whether this browser offers a save dialog', async () => {
    const { hasSaveDialog } = await import(JOB);
    expect(hasSaveDialog()).toBe(false);
    Object.assign(window, { showSaveFilePicker: vi.fn() });
    expect(hasSaveDialog()).toBe(true);
  });

  it('opens the save dialog synchronously, offering today’s name and the .hvbackup type', async () => {
    const writable = { write: vi.fn(), close: vi.fn(), abort: vi.fn() };
    const picker = vi.fn().mockResolvedValue({
      name: 'chosen.hvbackup',
      createWritable: () => Promise.resolve(writable),
    });
    Object.assign(window, { showSaveFilePicker: picker });
    const { openFullBackupTarget } = (await import(
      JOB
    )) as typeof import('../src/services/backup/fullBackupJob');

    const opening = openFullBackupTarget(new Date('2026-10-24T23:30:00.000Z'));
    // Before any await: the dialog needs the click's own activation.
    expect(picker).toHaveBeenCalledTimes(1);
    expect(picker).toHaveBeenCalledWith({
      suggestedName: 'hvault-full-backup-2026-10-24.hvbackup',
      startIn: 'downloads',
      types: [
        {
          description: 'H-Vault full backup',
          accept: { 'application/octet-stream': ['.hvbackup'] },
        },
      ],
    });
    const target = await opening;
    expect(target).toMatchObject({ kind: 'file', name: 'chosen.hvbackup' });
  });

  it('builds the file in memory, under today’s name, where there is no save dialog', async () => {
    const { openFullBackupTarget } = (await import(
      JOB
    )) as typeof import('../src/services/backup/fullBackupJob');

    const target = await openFullBackupTarget(new Date('2026-10-24T01:00:00.000Z'));

    expect(target).toMatchObject({
      kind: 'download',
      name: 'hvault-full-backup-2026-10-24.hvbackup',
      limitBytes: 512 * 1024 * 1024,
    });
  });
});
