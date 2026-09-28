/**
 * The release-notes view rules (`utils/releaseNotes.ts`) on synthetic content,
 * so each rule is pinned on its own rather than only through whatever the real
 * notes happen to contain: the baseline for a missing watermark, the audience
 * test, administrator items withheld, a release left without a highlight
 * dropped, an entry newer than the running version never shown, and `isNew`.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { APP_VERSION, parseReleaseVersion, type ReleaseNote } from '@hvault/shared';
import { config } from '../src/config/index.js';
import { RELEASE_NOTES_BASELINE_VERSION } from '../src/constants/index.js';
import {
  countUnseen,
  effectiveSeenVersion,
  isUpdateAudience,
  notesForViewer,
  releaseUrlFor,
} from '../src/utils/releaseNotes.js';

const mutableConfig = config as unknown as {
  UPDATE_NOTIFY_EMAILS: string[];
  UPDATE_CHECK_REPOSITORY: string;
};
const original = {
  emails: mutableConfig.UPDATE_NOTIFY_EMAILS,
  repository: mutableConfig.UPDATE_CHECK_REPOSITORY,
};

beforeEach(() => {
  mutableConfig.UPDATE_NOTIFY_EMAILS = [];
  mutableConfig.UPDATE_CHECK_REPOSITORY = 'Hiprax/h-vault';
});

afterEach(() => {
  mutableConfig.UPDATE_NOTIFY_EMAILS = original.emails;
  mutableConfig.UPDATE_CHECK_REPOSITORY = original.repository;
});

const [major] = parseReleaseVersion(APP_VERSION)!;
const FUTURE = `${String(major + 1)}.0.0`;

function note(version: string, overrides: Partial<ReleaseNote> = {}): ReleaseNote {
  return {
    version,
    date: '2026-09-28',
    title: `Release ${version}`,
    summary: `What changed in ${version}.`,
    highlights: [{ icon: 'sparkles', title: 'For everyone', body: 'A change everyone sees.' }],
    changes: [{ kind: 'added', text: 'Something for everyone.' }],
    ...overrides,
  };
}

const content: ReleaseNote[] = [
  note(FUTURE),
  note(APP_VERSION, {
    highlights: [
      { icon: 'sparkles', title: 'For everyone', body: 'A change everyone sees.' },
      { icon: 'server', title: 'For the operator', body: 'A setting.', audience: 'administrators' },
    ],
    changes: [
      { kind: 'added', text: 'Something for everyone.' },
      { kind: 'changed', text: 'A deployment step.', audience: 'administrators' },
    ],
  }),
  note('0.0.2', {
    highlights: [
      {
        icon: 'server',
        title: 'Operator only',
        body: 'Nothing for users.',
        audience: 'administrators',
      },
    ],
    changes: [{ kind: 'changed', text: 'Operator detail.', audience: 'administrators' }],
  }),
  note('0.0.1'),
];

describe('effectiveSeenVersion', () => {
  it('keeps a stored release version', () => {
    expect(effectiveSeenVersion('0.3.0')).toBe('0.3.0');
  });

  it.each([undefined, null, '', 'latest', '1.2', 7])('reads %j as the baseline', (stored) => {
    expect(effectiveSeenVersion(stored)).toBe(RELEASE_NOTES_BASELINE_VERSION);
  });
});

describe('isUpdateAudience', () => {
  it('includes every account when no administrator list is configured', () => {
    expect(isUpdateAudience('anyone@example.com')).toBe(true);
  });

  it('includes only the listed accounts, compared lower-cased', () => {
    mutableConfig.UPDATE_NOTIFY_EMAILS = ['owner@example.com'];
    expect(isUpdateAudience('owner@example.com')).toBe(true);
    expect(isUpdateAudience('Owner@Example.COM')).toBe(true);
    expect(isUpdateAudience('someone@example.com')).toBe(false);
  });
});

describe('releaseUrlFor', () => {
  it('builds the release page from the configured repository', () => {
    expect(releaseUrlFor('0.15.0')).toBe('https://github.com/Hiprax/h-vault/releases/tag/v0.15.0');
    mutableConfig.UPDATE_CHECK_REPOSITORY = 'someone/fork';
    expect(releaseUrlFor('1.0.0')).toBe('https://github.com/someone/fork/releases/tag/v1.0.0');
  });
});

describe('notesForViewer', () => {
  it('never shows an entry newer than the running version', () => {
    const versions = notesForViewer(content, { isAudience: true, seenVersion: '0.0.1' }).map(
      (view) => view.version,
    );
    expect(versions).not.toContain(FUTURE);
    expect(versions).toEqual([APP_VERSION, '0.0.2', '0.0.1']);
  });

  it('gives the audience every item, and marks releases newer than the watermark', () => {
    const views = notesForViewer(content, { isAudience: true, seenVersion: '0.0.1' });
    expect(views[0]!.highlights).toHaveLength(2);
    expect(views[0]!.changes).toHaveLength(2);
    expect(views.map((view) => view.isNew)).toEqual([true, true, false]);
    // The view carries the authored fields and nothing else.
    expect(Object.keys(views[0]!).sort()).toEqual(
      ['changes', 'date', 'highlights', 'isNew', 'summary', 'title', 'version'].sort(),
    );
  });

  it('withholds administrator items from others, and drops a release left with no highlight', () => {
    const views = notesForViewer(content, { isAudience: false, seenVersion: '0.0.1' });
    expect(views.map((view) => view.version)).toEqual([APP_VERSION, '0.0.1']);
    expect(views[0]!.highlights.map((item) => item.title)).toEqual(['For everyone']);
    expect(views[0]!.changes.map((item) => item.text)).toEqual(['Something for everyone.']);
  });

  it('marks nothing new for an account caught up to the running version', () => {
    const views = notesForViewer(content, { isAudience: true, seenVersion: APP_VERSION });
    expect(views.every((view) => !view.isNew)).toBe(true);
  });

  it('copies the items, so a view can never alter the authored content', () => {
    const [view] = notesForViewer(content, { isAudience: true, seenVersion: '0.0.1' });
    expect(view!.highlights[0]).not.toBe(content[1]!.highlights[0]);
    expect(view!.changes[0]).not.toBe(content[1]!.changes[0]);
  });
});

describe('countUnseen', () => {
  it('counts the visible releases newer than the watermark', () => {
    expect(countUnseen(content, { isAudience: true, seenVersion: '0.0.1' })).toBe(2);
    expect(countUnseen(content, { isAudience: false, seenVersion: '0.0.1' })).toBe(1);
    expect(countUnseen(content, { isAudience: true, seenVersion: APP_VERSION })).toBe(0);
  });
});
