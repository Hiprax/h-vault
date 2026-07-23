import { describe, it, expect } from 'vitest';
import { buildFolderPaths } from '../../src/services/export/folderPath';
import type { DecryptedFolder } from '../../src/stores/vaultStore';
import type { IFolderResponse } from '@hvault/shared';

/**
 * `buildFolderPaths` flattens the `parentId` pointer graph into slash-joined
 * paths. It must be cycle-safe (self-parent and longer cycles yield a truncated
 * path, never infinite recursion), treat an unresolvable `parentId` as a root
 * (matching `FolderSidebar.buildTree`), and escape a literal `/` in a name.
 */

function mkFolder(id: string, name: string, parentId?: string): DecryptedFolder {
  const raw: IFolderResponse = {
    _id: id,
    encryptedName: 'enc',
    nameIv: 'iv',
    nameTag: 'tag',
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
  };
  return {
    id,
    name,
    parentId,
    sortOrder: 0,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
    _raw: raw,
  };
}

describe('buildFolderPaths', () => {
  it('returns an empty map for no folders', () => {
    expect(buildFolderPaths([]).size).toBe(0);
  });

  it('maps a root folder to its own name', () => {
    const paths = buildFolderPaths([mkFolder('a', 'Work')]);
    expect(paths.get('a')).toBe('Work');
  });

  it('joins nested folders with a slash', () => {
    const paths = buildFolderPaths([
      mkFolder('a', 'Work'),
      mkFolder('b', 'Clients', 'a'),
      mkFolder('c', 'Acme', 'b'),
    ]);
    expect(paths.get('a')).toBe('Work');
    expect(paths.get('b')).toBe('Work/Clients');
    expect(paths.get('c')).toBe('Work/Clients/Acme');
  });

  it('treats a missing parent as a root (matching buildTree)', () => {
    const paths = buildFolderPaths([mkFolder('b', 'Orphan', 'does-not-exist')]);
    expect(paths.get('b')).toBe('Orphan');
  });

  it('treats a self-parent as a root without recursing', () => {
    const paths = buildFolderPaths([mkFolder('x', 'Loop', 'x')]);
    expect(paths.get('x')).toBe('Loop');
  });

  it('breaks a two-node cycle with a truncated path', () => {
    const paths = buildFolderPaths([mkFolder('a', 'A', 'b'), mkFolder('b', 'B', 'a')]);
    // Neither hangs; each stops the moment it revisits a folder.
    expect(paths.get('a')).toBe('B/A');
    expect(paths.get('b')).toBe('A/B');
  });

  it('escapes a literal slash in a folder name so a segment is unambiguous', () => {
    const paths = buildFolderPaths([mkFolder('a', 'a/b'), mkFolder('c', 'child', 'a')]);
    expect(paths.get('a')).toBe('a\\/b');
    expect(paths.get('c')).toBe('a\\/b/child');
  });

  it('escapes a backslash before a slash so the escape is reversible', () => {
    const paths = buildFolderPaths([mkFolder('a', 'a\\b')]);
    expect(paths.get('a')).toBe('a\\\\b');
  });

  it('produces exactly one entry per input folder', () => {
    const folders = [mkFolder('a', 'A'), mkFolder('b', 'B', 'a'), mkFolder('c', 'C')];
    expect(buildFolderPaths(folders).size).toBe(folders.length);
  });
});
