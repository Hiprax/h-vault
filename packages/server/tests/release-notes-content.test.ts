/**
 * The curated release notes (`src/content/releaseNotes.ts`) against the rules
 * that make them safe to show and impossible to forget.
 *
 * Why each rule exists:
 *  - ONE ENTRY PER RELEASED VERSION, SAME DATE, BOTH DIRECTIONS against
 *    `CHANGELOG.md`: a release cut without its notes, or notes for a release that
 *    never happened, fails here, which is what turns "write the notes" into a
 *    step no release can skip.
 *  - NEWEST ENTRY IS THE RUNNING VERSION: the notes a user is shown after an
 *    update are the notes of that update.
 *  - EVERY ENTRY PASSES THE WIRE SCHEMA the browser parses with, and every code is
 *    from the closed lists: an entry the client would refuse must never ship.
 *  - PLAIN TEXT: no markup, no links. The client renders these as text, so markup
 *    would show up as literal characters, and a URL has no place in notes a user
 *    cannot verify the destination of.
 *  - BALANCED AUDIENCE: accounts outside the administrator list receive only the
 *    items not marked `administrators`, and the client requires a highlight and a
 *    change in every release it shows. So a release either has both kinds of
 *    item for everyone, or is entirely for administrators.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  APP_VERSION,
  RELEASE_AUDIENCES,
  RELEASE_CHANGE_KINDS,
  RELEASE_ICONS,
  compareReleaseVersions,
  releaseNoteSchema,
} from '@hvault/shared';
import { RELEASE_NOTES } from '../src/content/releaseNotes.js';

const repoFile = (name: string) => fileURLToPath(new URL(`../../../${name}`, import.meta.url));
const changelog = readFileSync(repoFile('CHANGELOG.md'), 'utf8');
const rootVersion = (
  JSON.parse(readFileSync(repoFile('package.json'), 'utf8')) as { version: string }
).version;

/** Every released version in the CHANGELOG, with its date, newest first. */
const released = [...changelog.matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})$/gm)].map(
  (match) => ({ version: match[1]!, date: match[2]! }),
);

/** Every text an entry carries, labelled for the failure message. */
function textsOf(note: (typeof RELEASE_NOTES)[number]): [string, string][] {
  return [
    [`${note.version} title`, note.title],
    [`${note.version} summary`, note.summary],
    ...note.highlights.flatMap((highlight, index): [string, string][] => [
      [`${note.version} highlight ${String(index)} title`, highlight.title],
      [`${note.version} highlight ${String(index)} body`, highlight.body],
    ]),
    ...note.changes.map((change, index): [string, string] => [
      `${note.version} change ${String(index)}`,
      change.text,
    ]),
  ];
}

describe('the release notes content', () => {
  it('reads the CHANGELOG it is checked against (the denominator is not empty)', () => {
    expect(released.length).toBeGreaterThanOrEqual(19);
    expect(released[released.length - 1]).toEqual({ version: '0.1.0', date: '2026-07-14' });
  });

  it('has exactly one entry per released version, with the same date, in the same order', () => {
    expect(RELEASE_NOTES.map((note) => ({ version: note.version, date: note.date }))).toEqual(
      released,
    );
  });

  it('starts at the running version, which is the root package version', () => {
    expect(RELEASE_NOTES[0]?.version).toBe(APP_VERSION);
    expect(APP_VERSION).toBe(rootVersion);
  });

  it('is strictly newest first, with no version twice', () => {
    for (let index = 1; index < RELEASE_NOTES.length; index += 1) {
      expect(
        compareReleaseVersions(RELEASE_NOTES[index - 1]!.version, RELEASE_NOTES[index]!.version),
        `${RELEASE_NOTES[index - 1]!.version} before ${RELEASE_NOTES[index]!.version}`,
      ).toBe(1);
    }
  });

  it.each(RELEASE_NOTES.map((note) => [note.version, note] as const))(
    '%s passes the schema the browser parses it with',
    (_version, note) => {
      const result = releaseNoteSchema.safeParse(note);
      expect(result.error?.issues ?? []).toEqual([]);
    },
  );

  it.each(RELEASE_NOTES.map((note) => [note.version, note] as const))(
    '%s uses only the closed lists of kinds, icons and audiences',
    (_version, note) => {
      for (const highlight of note.highlights) {
        expect(RELEASE_ICONS).toContain(highlight.icon);
        if (highlight.audience !== undefined)
          expect(RELEASE_AUDIENCES).toContain(highlight.audience);
      }
      for (const change of note.changes) {
        expect(RELEASE_CHANGE_KINDS).toContain(change.kind);
        if (change.audience !== undefined) expect(RELEASE_AUDIENCES).toContain(change.audience);
      }
    },
  );

  it.each(RELEASE_NOTES.map((note) => [note.version, note] as const))(
    '%s is plain text with no markup, link or stray whitespace',
    (_version, note) => {
      for (const [label, text] of textsOf(note)) {
        expect(text, label).not.toMatch(/https?:|www\./i);
        expect(text, label).not.toMatch(/[<>`]/);
        expect(text, label).not.toContain('**');
        expect(text, label).not.toContain('—');
        expect(text, label).toBe(text.trim());
        expect(text, label).not.toMatch(/\s{2,}/);
      }
    },
  );

  it.each(RELEASE_NOTES.map((note) => [note.version, note] as const))(
    '%s gives everyone both a highlight and a change, or is entirely for administrators',
    (_version, note) => {
      const forEveryone = (audience: string | undefined) => audience !== 'administrators';
      const everyoneHighlights = note.highlights.filter((item) =>
        forEveryone(item.audience),
      ).length;
      const everyoneChanges = note.changes.filter((item) => forEveryone(item.audience)).length;
      expect(everyoneHighlights > 0).toBe(everyoneChanges > 0);
    },
  );

  it('has at least one release every account can read', () => {
    expect(
      RELEASE_NOTES.some((note) =>
        note.highlights.some((item) => item.audience !== 'administrators'),
      ),
    ).toBe(true);
  });
});
