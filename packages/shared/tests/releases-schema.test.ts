/**
 * The release-notes and update-status wire schemas.
 *
 * The client parses every response from `/releases/*` with these before it shows
 * anything, and the server's content test parses every authored entry with the
 * same entry schema. So each bound here is pinned the way `schema-bounds.test.ts`
 * pins the others: AT the limit (accepted) and ONE PAST it (refused), because
 * either half alone is satisfied by a mutant that moved the number.
 *
 * Two behaviours are pinned deliberately rather than incidentally:
 *  - kinds, icons and update states are bounded STRINGS, so an unknown value is
 *    ACCEPTED (a tab on the previous release must not reject a newer server's
 *    notes), while an empty or over-long one is refused;
 *  - every text is measured after trimming, so whitespace cannot stand in for
 *    content.
 */
import { describe, expect, it } from 'vitest';
import {
  markReleaseNotesSeenSchema,
  releaseChangeSchema,
  releaseHighlightSchema,
  releaseNoteSchema,
  releaseNoteViewSchema,
  releaseNotesDataSchema,
  releaseNotesResponseSchema,
  releaseNotesSeenDataSchema,
  releaseNotesSeenResponseSchema,
  releaseStatusDataSchema,
  releaseStatusResponseSchema,
  releaseVersionSchema,
  updateCheckDataSchema,
  updateCheckResponseSchema,
  updateStatusSchema,
} from '../src/schemas/releases.js';
import { updateSettingsSchema } from '../src/schemas/user.js';
import {
  MAX_RELEASE_CHANGES,
  MAX_RELEASE_HIGHLIGHTS,
  MAX_RELEASE_HIGHLIGHT_TITLE_LENGTH,
  MAX_RELEASE_NOTES_LISTED,
  MAX_RELEASE_SUMMARY_LENGTH,
  MAX_RELEASE_TEXT_LENGTH,
  MAX_RELEASE_TITLE_LENGTH,
  MAX_RELEASE_URL_LENGTH,
  MAX_RELEASE_VERSION_LENGTH,
  MAX_RELEASE_WIRE_CODE_LENGTH,
  MIN_RELEASE_HIGHLIGHT_TITLE_LENGTH,
  MIN_RELEASE_SUMMARY_LENGTH,
  MIN_RELEASE_TEXT_LENGTH,
  MIN_RELEASE_TITLE_LENGTH,
} from '../src/constants/index.js';

const highlight = { icon: 'sparkles', title: 'A new thing', body: 'It does something useful.' };
const change = { kind: 'added', text: 'Something was added here.' };
const note = {
  version: '0.15.0',
  date: '2026-09-28',
  title: 'See what is new',
  summary: 'The app now explains each update.',
  highlights: [highlight],
  changes: [change],
};
const status = {
  state: 'current',
  latestVersion: '0.15.0',
  publishedAt: '2026-09-28T10:00:00.000Z',
  releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
  lastCheckedAt: '2026-09-28T11:00:00.000Z',
  lastSuccessAt: '2026-09-28T11:00:00.000Z',
  canCheckNow: true,
};

/** A string of exactly `length` characters. */
const text = (length: number) => 'x'.repeat(length);

describe('releaseVersionSchema', () => {
  it('accepts a release version', () => {
    expect(releaseVersionSchema.parse('0.15.0')).toBe('0.15.0');
  });

  it.each(['1.2', 'v1.2.3', '1.2.3-rc.1', '01.2.3', ''])(
    'refuses %j with its own message',
    (value) => {
      const result = releaseVersionSchema.safeParse(value);
      expect(result.success).toBe(false);
      expect(result.error?.issues.map((issue) => issue.message)).toContain(
        'Must be a release version such as 1.4.0',
      );
    },
  );

  it('refuses an over-long value with a length issue, not only the format issue', () => {
    const result = releaseVersionSchema.safeParse(text(MAX_RELEASE_VERSION_LENGTH + 1));
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.code)).toContain('too_big');
  });
});

describe('releaseNoteSchema', () => {
  it('accepts a complete entry and returns it unchanged', () => {
    expect(releaseNoteSchema.parse(note)).toEqual(note);
  });

  it.each([
    ['2026-02-30', 'Must be a real calendar date'],
    ['2026-13-01', 'Must be a real calendar date'],
    ['2026-9-28', 'Must be a date written YYYY-MM-DD'],
    ['28-09-2026', 'Must be a date written YYYY-MM-DD'],
    ['2026-09-28T00:00:00Z', 'Must be a date written YYYY-MM-DD'],
  ])('refuses the date %j (%s) without throwing', (date, message) => {
    const result = releaseNoteSchema.safeParse({ ...note, date });
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.message)).toContain(message);
  });

  it('accepts the last day of a leap February and refuses it in a common year', () => {
    expect(releaseNoteSchema.safeParse({ ...note, date: '2028-02-29' }).success).toBe(true);
    expect(releaseNoteSchema.safeParse({ ...note, date: '2027-02-29' }).success).toBe(false);
  });

  it('refuses a malformed version', () => {
    expect(releaseNoteSchema.safeParse({ ...note, version: '0.15' }).success).toBe(false);
  });

  it.each([
    ['title', MIN_RELEASE_TITLE_LENGTH, MAX_RELEASE_TITLE_LENGTH],
    ['summary', MIN_RELEASE_SUMMARY_LENGTH, MAX_RELEASE_SUMMARY_LENGTH],
  ] as const)('bounds %s between %d and %d characters', (field, min, max) => {
    expect(releaseNoteSchema.safeParse({ ...note, [field]: text(min) }).success).toBe(true);
    expect(releaseNoteSchema.safeParse({ ...note, [field]: text(min - 1) }).success).toBe(false);
    expect(releaseNoteSchema.safeParse({ ...note, [field]: text(max) }).success).toBe(true);
    expect(releaseNoteSchema.safeParse({ ...note, [field]: text(max + 1) }).success).toBe(false);
  });

  it('measures a text after trimming, so padding cannot stand in for content', () => {
    const padded = `  ${text(MIN_RELEASE_TITLE_LENGTH - 1)}  `;
    const result = releaseNoteSchema.safeParse({ ...note, title: padded });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.message).toBe(
      `Must hold at least ${String(MIN_RELEASE_TITLE_LENGTH)} characters`,
    );
  });

  it('requires between 1 and MAX_RELEASE_HIGHLIGHTS highlights', () => {
    const many = Array.from({ length: MAX_RELEASE_HIGHLIGHTS }, () => highlight);
    expect(releaseNoteSchema.safeParse({ ...note, highlights: many }).success).toBe(true);
    expect(releaseNoteSchema.safeParse({ ...note, highlights: [...many, highlight] }).success).toBe(
      false,
    );
    expect(releaseNoteSchema.safeParse({ ...note, highlights: [] }).success).toBe(false);
  });

  it('requires between 1 and MAX_RELEASE_CHANGES changes', () => {
    const many = Array.from({ length: MAX_RELEASE_CHANGES }, () => change);
    expect(releaseNoteSchema.safeParse({ ...note, changes: many }).success).toBe(true);
    expect(releaseNoteSchema.safeParse({ ...note, changes: [...many, change] }).success).toBe(
      false,
    );
    expect(releaseNoteSchema.safeParse({ ...note, changes: [] }).success).toBe(false);
  });
});

describe('releaseHighlightSchema and releaseChangeSchema', () => {
  it('bound a highlight title and body at their limits', () => {
    const at = (title: string, body: string) =>
      releaseHighlightSchema.safeParse({ ...highlight, title, body }).success;
    expect(at(text(MIN_RELEASE_HIGHLIGHT_TITLE_LENGTH), highlight.body)).toBe(true);
    expect(at(text(MIN_RELEASE_HIGHLIGHT_TITLE_LENGTH - 1), highlight.body)).toBe(false);
    expect(at(text(MAX_RELEASE_HIGHLIGHT_TITLE_LENGTH), highlight.body)).toBe(true);
    expect(at(text(MAX_RELEASE_HIGHLIGHT_TITLE_LENGTH + 1), highlight.body)).toBe(false);
    expect(at(highlight.title, text(MIN_RELEASE_TEXT_LENGTH))).toBe(true);
    expect(at(highlight.title, text(MIN_RELEASE_TEXT_LENGTH - 1))).toBe(false);
    expect(at(highlight.title, text(MAX_RELEASE_TEXT_LENGTH))).toBe(true);
    expect(at(highlight.title, text(MAX_RELEASE_TEXT_LENGTH + 1))).toBe(false);
  });

  it('bounds a change text at its limits', () => {
    const at = (value: string) => releaseChangeSchema.safeParse({ ...change, text: value }).success;
    expect(at(text(MIN_RELEASE_TEXT_LENGTH))).toBe(true);
    expect(at(text(MIN_RELEASE_TEXT_LENGTH - 1))).toBe(false);
    expect(at(text(MAX_RELEASE_TEXT_LENGTH))).toBe(true);
    expect(at(text(MAX_RELEASE_TEXT_LENGTH + 1))).toBe(false);
  });

  it('accepts an unknown kind or icon, so an older tab can read a newer server', () => {
    expect(releaseChangeSchema.safeParse({ ...change, kind: 'deprecated' }).success).toBe(true);
    expect(releaseHighlightSchema.safeParse({ ...highlight, icon: 'rocket' }).success).toBe(true);
  });

  it('refuses an empty or over-long kind or icon code', () => {
    const code = (length: number) => text(length);
    expect(releaseChangeSchema.safeParse({ ...change, kind: '' }).success).toBe(false);
    expect(
      releaseChangeSchema.safeParse({ ...change, kind: code(MAX_RELEASE_WIRE_CODE_LENGTH) })
        .success,
    ).toBe(true);
    expect(
      releaseChangeSchema.safeParse({ ...change, kind: code(MAX_RELEASE_WIRE_CODE_LENGTH + 1) })
        .success,
    ).toBe(false);
    expect(releaseHighlightSchema.safeParse({ ...highlight, icon: '' }).success).toBe(false);
    expect(
      releaseHighlightSchema.safeParse({
        ...highlight,
        icon: code(MAX_RELEASE_WIRE_CODE_LENGTH + 1),
      }).success,
    ).toBe(false);
  });

  it('accepts only the two known audiences, and no audience at all', () => {
    expect(releaseChangeSchema.safeParse({ ...change, audience: 'administrators' }).success).toBe(
      true,
    );
    expect(releaseChangeSchema.safeParse({ ...change, audience: 'everyone' }).success).toBe(true);
    expect(releaseChangeSchema.safeParse({ ...change, audience: 'admins' }).success).toBe(false);
    expect(releaseHighlightSchema.safeParse({ ...highlight, audience: 'owner' }).success).toBe(
      false,
    );
    expect(releaseHighlightSchema.parse(highlight)).not.toHaveProperty('audience');
  });
});

describe('releaseNoteViewSchema and releaseNotesDataSchema', () => {
  it('requires isNew on a viewed entry', () => {
    expect(releaseNoteViewSchema.safeParse({ ...note, isNew: true }).success).toBe(true);
    expect(releaseNoteViewSchema.safeParse(note).success).toBe(false);
    expect(releaseNoteViewSchema.safeParse({ ...note, isNew: 'yes' }).success).toBe(false);
  });

  it('caps the number of listed releases', () => {
    const entry = { ...note, isNew: false };
    const list = (length: number) => ({
      version: '0.15.0',
      seenVersion: '0.14.1',
      releases: Array.from({ length }, () => entry),
    });
    expect(releaseNotesDataSchema.safeParse(list(MAX_RELEASE_NOTES_LISTED)).success).toBe(true);
    expect(releaseNotesDataSchema.safeParse(list(MAX_RELEASE_NOTES_LISTED + 1)).success).toBe(
      false,
    );
  });

  it('requires both the running version and the seen version to be release versions', () => {
    const base = { version: '0.15.0', seenVersion: '0.14.1', releases: [] };
    expect(releaseNotesDataSchema.safeParse(base).success).toBe(true);
    expect(releaseNotesDataSchema.safeParse({ ...base, version: 'latest' }).success).toBe(false);
    expect(releaseNotesDataSchema.safeParse({ ...base, seenVersion: '0.14' }).success).toBe(false);
  });
});

describe('updateStatusSchema', () => {
  it('accepts a full status and one before any successful check', () => {
    expect(updateStatusSchema.parse(status)).toEqual(status);
    const empty = {
      state: 'unknown',
      latestVersion: null,
      publishedAt: null,
      releaseUrl: null,
      lastCheckedAt: null,
      lastSuccessAt: null,
      canCheckNow: false,
    };
    expect(updateStatusSchema.parse(empty)).toEqual(empty);
  });

  it('accepts an unknown state code but refuses an empty one', () => {
    expect(updateStatusSchema.safeParse({ ...status, state: 'paused' }).success).toBe(true);
    expect(updateStatusSchema.safeParse({ ...status, state: '' }).success).toBe(false);
  });

  it('refuses a timestamp that is not an ISO instant', () => {
    expect(updateStatusSchema.safeParse({ ...status, publishedAt: '2026-09-28' }).success).toBe(
      false,
    );
    expect(updateStatusSchema.safeParse({ ...status, lastCheckedAt: 'yesterday' }).success).toBe(
      false,
    );
    expect(updateStatusSchema.safeParse({ ...status, lastSuccessAt: 12 }).success).toBe(false);
  });

  it('bounds the release link', () => {
    const url = (length: number) => `https://github.com/${text(length - 19)}`;
    expect(
      updateStatusSchema.safeParse({ ...status, releaseUrl: url(MAX_RELEASE_URL_LENGTH) }).success,
    ).toBe(true);
    expect(
      updateStatusSchema.safeParse({ ...status, releaseUrl: url(MAX_RELEASE_URL_LENGTH + 1) })
        .success,
    ).toBe(false);
  });

  it('refuses a latest version that is not a release version', () => {
    expect(updateStatusSchema.safeParse({ ...status, latestVersion: 'v0.16.0' }).success).toBe(
      false,
    );
  });

  it('requires canCheckNow to be a boolean', () => {
    const { canCheckNow: _omitted, ...withoutFlag } = status;
    expect(updateStatusSchema.safeParse(withoutFlag).success).toBe(false);
  });
});

describe('the status, seen and update-check payloads', () => {
  const statusData = {
    version: '0.15.0',
    releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
    releaseNotes: { seenVersion: '0.14.1', unseenCount: 1, showOnUpdate: true },
    update: null,
  };

  it('accepts a status with and without update information', () => {
    expect(releaseStatusDataSchema.parse(statusData)).toEqual(statusData);
    expect(releaseStatusDataSchema.parse({ ...statusData, update: status }).update).toEqual(status);
  });

  it.each([-1, 1.5])('refuses an unseen count of %d', (unseenCount) => {
    expect(
      releaseStatusDataSchema.safeParse({
        ...statusData,
        releaseNotes: { ...statusData.releaseNotes, unseenCount },
      }).success,
    ).toBe(false);
    expect(
      releaseNotesSeenDataSchema.safeParse({ seenVersion: '0.15.0', unseenCount }).success,
    ).toBe(false);
  });

  it('accepts a zero unseen count', () => {
    expect(releaseNotesSeenDataSchema.parse({ seenVersion: '0.15.0', unseenCount: 0 })).toEqual({
      seenVersion: '0.15.0',
      unseenCount: 0,
    });
  });

  it('requires the seen request to name a release version', () => {
    expect(markReleaseNotesSeenSchema.parse({ version: '0.15.0' })).toEqual({ version: '0.15.0' });
    expect(markReleaseNotesSeenSchema.safeParse({ version: '0.15.0-rc.1' }).success).toBe(false);
    expect(markReleaseNotesSeenSchema.safeParse({}).success).toBe(false);
  });

  it('requires the update-check result to say whether it fetched', () => {
    expect(updateCheckDataSchema.parse({ update: status, fetched: false })).toEqual({
      update: status,
      fetched: false,
    });
    expect(updateCheckDataSchema.safeParse({ update: status }).success).toBe(false);
  });

  it('wraps each payload in the success envelope and refuses a failure envelope', () => {
    const cases = [
      [releaseStatusResponseSchema, statusData],
      [releaseNotesResponseSchema, { version: '0.15.0', seenVersion: '0.15.0', releases: [] }],
      [releaseNotesSeenResponseSchema, { seenVersion: '0.15.0', unseenCount: 0 }],
      [updateCheckResponseSchema, { update: status, fetched: true }],
    ] as const;
    for (const [schema, data] of cases) {
      expect(schema.safeParse({ success: true, data }).success).toBe(true);
      expect(schema.safeParse({ success: true, data, message: 'ok' }).success).toBe(true);
      expect(schema.safeParse({ success: false, data }).success).toBe(false);
      expect(schema.safeParse({ success: true }).success).toBe(false);
    }
  });
});

describe('updateSettingsSchema.showReleaseNotes', () => {
  it('accepts a boolean and refuses anything else', () => {
    expect(updateSettingsSchema.parse({ showReleaseNotes: false })).toEqual({
      showReleaseNotes: false,
    });
    expect(updateSettingsSchema.safeParse({ showReleaseNotes: 'no' }).success).toBe(false);
    expect(updateSettingsSchema.safeParse({ showReleaseNotes: 0 }).success).toBe(false);
  });
});
