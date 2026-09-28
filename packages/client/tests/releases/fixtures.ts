import type {
  ReleaseNoteView,
  ReleaseNotesList,
  ReleaseStatus,
  UpdateStatus,
} from '@hvault/shared';

/** A status for a signed-in account; every field overridable. */
export function makeStatus(
  overrides: Partial<Omit<ReleaseStatus, 'releaseNotes'>> & {
    releaseNotes?: Partial<ReleaseStatus['releaseNotes']>;
  } = {},
): ReleaseStatus {
  const { releaseNotes, ...rest } = overrides;
  return {
    version: '0.15.0',
    releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
    update: null,
    ...rest,
    releaseNotes: { seenVersion: '0.14.1', unseenCount: 1, showOnUpdate: true, ...releaseNotes },
  };
}

export function makeUpdate(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    state: 'current',
    latestVersion: '0.15.0',
    publishedAt: '2026-09-28T09:00:00.000Z',
    releaseUrl: 'https://github.com/Hiprax/h-vault/releases/tag/v0.15.0',
    lastCheckedAt: '2026-09-28T10:00:00.000Z',
    lastSuccessAt: '2026-09-28T10:00:00.000Z',
    canCheckNow: true,
    ...overrides,
  };
}

export function makeRelease(
  version: string,
  overrides: Partial<ReleaseNoteView> = {},
): ReleaseNoteView {
  return {
    version,
    date: '2026-09-28',
    title: `Release ${version} title`,
    summary: `What changed in ${version}, in a sentence.`,
    highlights: [
      { icon: 'sparkles', title: `Highlight of ${version}`, body: 'Something useful happened.' },
    ],
    changes: [
      { kind: 'added', text: `A new thing in ${version}.` },
      { kind: 'fixed', text: `A fix in ${version}.` },
    ],
    isNew: false,
    ...overrides,
  };
}

export function makeNotes(
  releases: ReleaseNoteView[],
  overrides: Partial<ReleaseNotesList> = {},
): ReleaseNotesList {
  return {
    version: releases[0]?.version ?? '0.15.0',
    seenVersion: '0.14.1',
    releases,
    ...overrides,
  };
}
