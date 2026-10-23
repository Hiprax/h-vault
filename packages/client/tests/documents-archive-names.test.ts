/**
 * The paths documents get inside an archive: each segment safe on its own, every
 * path unique in its directory, folders mirrored, and names reserved only for an
 * archive that was really saved.
 */
import { describe, expect, it } from 'vitest';
import { validateFileName } from 'yauzl';
import {
  ArchivePathAllocator,
  FALLBACK_DOCUMENT_SEGMENT,
  FALLBACK_FOLDER_SEGMENT,
  archiveSegment,
} from '../src/services/documents/archiveNames';
import type { DecryptedFolder } from '../src/stores/vaultStore';

const F_WORK = '66c0f1a2b3c4d5e6f7a8b901';
const F_CONTRACTS = '66c0f1a2b3c4d5e6f7a8b902';
const F_WORK_AGAIN = '66c0f1a2b3c4d5e6f7a8b903';
const F_A = '66c0f1a2b3c4d5e6f7a8b904';
const F_B = '66c0f1a2b3c4d5e6f7a8b905';

function folder(id: string, name: string, parentId?: string): DecryptedFolder {
  return {
    id,
    name,
    ...(parentId === undefined ? {} : { parentId }),
    sortOrder: 0,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    _raw: {} as DecryptedFolder['_raw'],
  };
}

const bytes = (text: string): number => new TextEncoder().encode(text).length;

/** Place and reserve, as a run does for a document that made it into the archive. */
function take(allocator: ArchivePathAllocator, name: string, folderId?: string): string {
  const placement = allocator.place(name, folderId);
  allocator.reserve(placement);
  return placement.path;
}

describe('archiveSegment — one name, safe as a single path segment', () => {
  const doc = (name: string) => archiveSegment(name, FALLBACK_DOCUMENT_SEGMENT);

  it('keeps an ordinary name exactly as it is', () => {
    expect(doc('Quarterly report.pdf')).toBe('Quarterly report.pdf');
    expect(doc('.env')).toBe('.env');
  });

  it('turns both separators into underscores, so a name can never climb or nest', () => {
    expect(doc('../../etc/passwd')).toBe('.._.._etc_passwd');
    expect(doc('windows\\system32\\cmd.exe')).toBe('windows_system32_cmd.exe');
    expect(validateFileName(doc('../../etc/passwd'))).toBeNull();
  });

  it('replaces every character Windows refuses in a name', () => {
    expect(doc('a<b>c:d"e|f?g*h.txt')).toBe('a_b_c_d_e_f_g_h.txt');
  });

  it('replaces the look-alikes some conversions map back onto a separator', () => {
    expect(doc('a\u2215b\uff0fc\uff3cd\u2044e\u29f8f')).toBe('a_b_c_d_e_f');
  });

  it('replaces control and direction-changing characters, so a disguise shows', () => {
    expect(doc('report\u202egnp.exe')).toBe('report_gnp.exe');
    expect(doc('a\u0000b\nc')).toBe('a_b_c');
  });

  it('replaces a lone surrogate, which has no UTF-8 form, and keeps a paired one', () => {
    expect(doc('a\ud800b.txt')).toBe('a\ufffdb.txt');
    expect(doc('x\udc00')).toBe('x\ufffd');
    expect(doc('smile 😀.txt')).toBe('smile 😀.txt');
  });

  it('writes a name in its composed (NFC) form', () => {
    expect(doc('cafe\u0301.txt')).toBe('caf\u00e9.txt');
  });

  it('prefixes a Windows device name, with or without an extension', () => {
    expect(doc('CON')).toBe('_CON');
    expect(doc('con.txt')).toBe('_con.txt');
    expect(doc('Com1.log')).toBe('_Com1.log');
    expect(doc('LPT\u00b9')).toBe('_LPT\u00b9');
    expect(doc('nul .tar.gz')).toBe('_nul .tar.gz');
    // ...and leaves names that merely start the same way.
    expect(doc('CONSOLE.txt')).toBe('CONSOLE.txt');
    expect(doc('COM10.txt')).toBe('COM10.txt');
    expect(doc('auxiliary')).toBe('auxiliary');
  });

  it('falls back when nothing safe is left, or only dots in any form', () => {
    expect(doc('   ')).toBe(FALLBACK_DOCUMENT_SEGMENT);
    expect(doc('...')).toBe(FALLBACK_DOCUMENT_SEGMENT);
    expect(doc('\uff0e\uff0e')).toBe(FALLBACK_DOCUMENT_SEGMENT);
    expect(doc('\u2024')).toBe(FALLBACK_DOCUMENT_SEGMENT);
    expect(doc('.\uff0e')).toBe(FALLBACK_DOCUMENT_SEGMENT);
    expect(archiveSegment('...', FALLBACK_FOLDER_SEGMENT)).toBe(FALLBACK_FOLDER_SEGMENT);
    // A real name that happens to equal a fallback is still that name.
    expect(archiveSegment('document', FALLBACK_FOLDER_SEGMENT)).toBe('document');
  });

  it('cuts a long name to 255 UTF-8 bytes, keeping its extension', () => {
    const cut = doc(`${'a'.repeat(300)}.pdf`);
    expect(bytes(cut)).toBe(255);
    expect(cut).toBe(`${'a'.repeat(251)}.pdf`);
  });

  it('cuts only between whole characters', () => {
    const cut = doc(`${'😀'.repeat(70)}.txt`);
    expect(cut).toBe(`${'😀'.repeat(62)}.txt`);
    expect(bytes(cut)).toBe(252);
    const cjk = doc(`${'文'.repeat(100)}.pdf`);
    expect(cjk).toBe(`${'文'.repeat(83)}.pdf`);
  });

  it('treats an "extension" longer than any real one as part of the name', () => {
    const name = `${'a'.repeat(250)}.${'b'.repeat(40)}`;
    expect(doc(name)).toBe(name.slice(0, 255));
  });

  it('trims the dots and spaces a cut leaves at the end of the name', () => {
    const cut = doc(`${'a'.repeat(240)}${'.'.repeat(11)} ${'z'.repeat(9)}.txt`);
    expect(cut).toBe(`${'a'.repeat(240)}.txt`);
  });

  it('keeps a reserved name prefixed within the byte limit', () => {
    const cut = doc(`CON.${'x'.repeat(251)}`);
    expect(bytes(cut)).toBe(255);
    expect(cut.startsWith('_CON.')).toBe(true);
  });

  it('falls back for a stem the cut empties, rather than leaving a bare extension', () => {
    expect(doc(`${'.'.repeat(300)}x.pdf`)).toBe(`${FALLBACK_DOCUMENT_SEGMENT}.pdf`);
  });
});

describe('archiveSegment — the whole-name rules apply to the FINAL segment', () => {
  const doc = (name: string) => archiveSegment(name, FALLBACK_DOCUMENT_SEGMENT);

  it('never lets a cut leave a bare device name', () => {
    // 3 + 250 + 3 = 256 bytes: the cut drops the wide character, the trim drops
    // the spaces, and what is left would be CON.
    expect(doc(`CON${' '.repeat(250)}\u20ac`)).toBe('_CON');
    expect(doc(`CON${' '.repeat(247)}\u20ac.pdf`)).toBe('_CON.pdf');
  });

  it('never lets a cut leave only dots', () => {
    expect(doc(`${'\uff0e'.repeat(85)}x`)).toBe(FALLBACK_DOCUMENT_SEGMENT);
  });
});

describe('ArchivePathAllocator — every document one unique path', () => {
  const FOLDERS = [
    folder(F_WORK, 'Work'),
    folder(F_CONTRACTS, 'Contracts', F_WORK),
    folder(F_WORK_AGAIN, 'work'),
  ];

  it('mirrors the folder a document is filed in, and puts the rest at the root', () => {
    const allocator = new ArchivePathAllocator(FOLDERS);

    expect(take(allocator, 'deal.pdf', F_CONTRACTS)).toBe('Work/Contracts/deal.pdf');
    expect(take(allocator, 'notes.md', F_WORK)).toBe('Work/notes.md');
    expect(take(allocator, 'loose.txt')).toBe('loose.txt');
    // A folder this run cannot resolve is the root.
    expect(take(allocator, 'orphan.txt', '66c0f1a2b3c4d5e6f7a8b9ff')).toBe('orphan.txt');
  });

  it('numbers a name already taken in its directory, ignoring case and composition', () => {
    const allocator = new ArchivePathAllocator([]);

    expect(take(allocator, 'report.pdf')).toBe('report.pdf');
    expect(take(allocator, 'report.pdf')).toBe('report (2).pdf');
    expect(take(allocator, 'REPORT.PDF')).toBe('REPORT (3).PDF');
    expect(take(allocator, 'caf\u00e9')).toBe('caf\u00e9');
    expect(take(allocator, 'cafe\u0301')).toBe('caf\u00e9 (2)');
  });

  it('numbers names that differ only in case even where lower case keeps them apart', () => {
    const allocator = new ArchivePathAllocator([]);

    // A word-final capital sigma lowers to the FINAL form and a medial small one
    // stays medial, so lower case keeps them apart; a case-insensitive
    // filesystem does not.
    expect(take(allocator, '\u03b1\u03c3')).toBe('\u03b1\u03c3');
    expect(take(allocator, '\u0391\u03a3')).toBe('\u0391\u03a3 (2)');
  });

  it('puts a document whose folder chain is deeper than the server allows at the root', () => {
    const ids = Array.from(
      { length: 51 },
      (_, index) => `66c0f1a2b3c4d5e6f7a8${index.toString(16).padStart(4, '0')}`,
    );
    const chain = ids.map((id, index) => folder(id, 'f', index === 0 ? undefined : ids[index - 1]));
    const allocator = new ArchivePathAllocator(chain);

    // Exactly at the limit, the path is mirrored in full...
    expect(take(allocator, 'deep.txt', ids[49])).toBe(
      `${Array.from({ length: 50 }, () => 'f').join('/')}/deep.txt`,
    );
    // ...one level past it, the chain is not one the account built.
    expect(take(allocator, 'deeper.txt', ids[50])).toBe('deeper.txt');
  });

  it('gives two folders of one name two directories, each the same for every document in it', () => {
    const allocator = new ArchivePathAllocator(FOLDERS);

    expect(take(allocator, 'a.txt', F_WORK)).toBe('Work/a.txt');
    expect(take(allocator, 'b.txt', F_WORK_AGAIN)).toBe('work (2)/b.txt');
    expect(take(allocator, 'c.txt', F_WORK_AGAIN)).toBe('work (2)/c.txt');
    expect(take(allocator, 'd.txt', F_WORK)).toBe('Work/d.txt');
  });

  it('keeps a document and a folder of the same name apart', () => {
    const allocator = new ArchivePathAllocator([folder(F_WORK, 'Work')]);

    expect(take(allocator, 'inside.txt', F_WORK)).toBe('Work/inside.txt');
    expect(take(allocator, 'Work')).toBe('Work (2)');
  });

  it('makes each folder name safe on its own, so it cannot add or escape a level', () => {
    const allocator = new ArchivePathAllocator([
      folder(F_A, '../evil/name'),
      folder(F_B, '...', F_A),
    ]);

    const path = take(allocator, 'x.txt', F_B);
    expect(path).toBe(`.._evil_name/${FALLBACK_FOLDER_SEGMENT}/x.txt`);
    expect(validateFileName(path)).toBeNull();
  });

  it('survives a cycle in the folder tree', () => {
    const allocator = new ArchivePathAllocator([folder(F_A, 'A', F_B), folder(F_B, 'B', F_A)]);

    expect(take(allocator, 'one.txt', F_A)).toBe('B/A/one.txt');
    expect(take(allocator, 'two.txt', F_B)).toBe('A/B/two.txt');
  });

  it('reserves nothing until a placement is reserved', () => {
    const allocator = new ArchivePathAllocator([]);

    expect(allocator.place('a.txt', undefined).path).toBe('a.txt');
    expect(allocator.place('a.txt', undefined).path).toBe('a.txt');
  });

  it('reports the path and its length in UTF-8 bytes', () => {
    const allocator = new ArchivePathAllocator([folder(F_WORK, 'Übersicht')]);
    const placement = allocator.place('文書.md', F_WORK);

    expect(placement.path).toBe('Übersicht/文書.md');
    expect(placement.pathBytes).toBe(bytes('Übersicht/文書.md'));
  });

  it('gives back the names of an archive that was thrown away', () => {
    const allocator = new ArchivePathAllocator([]);

    take(allocator, 'a.txt');
    allocator.dropArchive();

    expect(take(allocator, 'a.txt')).toBe('a.txt');
  });

  it('keeps the names of a saved archive for every later archive of the run', () => {
    const allocator = new ArchivePathAllocator([]);

    take(allocator, 'a.txt');
    allocator.keepArchive();
    // A later archive that is thrown away gives back only its own names.
    expect(take(allocator, 'a.txt')).toBe('a (2).txt');
    allocator.dropArchive();

    expect(take(allocator, 'a.txt')).toBe('a (2).txt');
  });

  it('keeps a numbered name within the byte limit', () => {
    const allocator = new ArchivePathAllocator([]);
    const long = `${'n'.repeat(300)}.pdf`;

    take(allocator, long);
    const second = take(allocator, long);

    expect(bytes(second)).toBe(255);
    expect(second.endsWith(' (2).pdf')).toBe(true);
  });
});
