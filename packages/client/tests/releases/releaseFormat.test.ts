/**
 * Formatting for the release notes: dates, relative times, anchors, and the one
 * check that decides whether a release link is rendered at all.
 */
import { describe, expect, it } from 'vitest';
import {
  formatRelativeTime,
  formatReleaseDate,
  isGithubReleaseUrl,
  releaseAnchorId,
} from '../../src/lib/releaseFormat';

describe('formatReleaseDate', () => {
  it('writes the day in the reader’s language', () => {
    expect(formatReleaseDate('2026-09-28', 'en-US')).toBe('September 28, 2026');
    expect(formatReleaseDate('2026-09-28', 'en-GB')).toBe('28 September 2026');
  });

  it('keeps the day the CHANGELOG names, never the day before in a zone west of UTC', () => {
    // A release dated the 1st must not print as the 31st of the previous month.
    expect(formatReleaseDate('2026-10-01', 'en-US')).toBe('October 1, 2026');
  });

  it('shows an unreadable value as written rather than as "Invalid Date"', () => {
    expect(formatReleaseDate('soon', 'en-US')).toBe('soon');
  });
});

describe('formatRelativeTime', () => {
  const now = Date.parse('2026-09-28T12:00:00Z');
  const ago = (ms: number) => new Date(now - ms).toISOString();

  it.each([
    [59_000, 'just now'],
    [60_000, '1 minute ago'],
    [5 * 60_000, '5 minutes ago'],
    [3_600_000, '1 hour ago'],
    [3 * 3_600_000 + 59 * 60_000, '3 hours ago'],
    [86_400_000, 'yesterday'],
    [3 * 86_400_000, '3 days ago'],
  ])('says %d ms ago is "%s"', (ms, words) => {
    expect(formatRelativeTime(ago(ms), now, 'en-US')).toBe(words);
  });

  it('reads a moment in the future (a skewed clock) as just now', () => {
    expect(formatRelativeTime(ago(-120_000), now, 'en-US')).toBe('just now');
  });

  it('shows an unreadable value as written', () => {
    expect(formatRelativeTime('yesterday-ish', now, 'en-US')).toBe('yesterday-ish');
  });
});

describe('releaseAnchorId', () => {
  it('turns every dot into a hyphen and prefixes a v', () => {
    expect(releaseAnchorId('0.15.0')).toBe('v0-15-0');
    expect(releaseAnchorId('10.2.33')).toBe('v10-2-33');
  });
});

describe('isGithubReleaseUrl', () => {
  it('accepts an https link to GitHub', () => {
    expect(isGithubReleaseUrl('https://github.com/Hiprax/h-vault/releases/tag/v0.15.0')).toBe(true);
  });

  it.each([
    ['plain http', 'http://github.com/Hiprax/h-vault'],
    ['another host', 'https://example.com/Hiprax/h-vault'],
    ['a look-alike host', 'https://github.com.example.com/x'],
    ['a script URL', 'javascript:alert(1)'],
    ['an empty string', ''],
  ])('refuses %s', (_label, url) => {
    expect(isGithubReleaseUrl(url)).toBe(false);
  });

  it('refuses a missing link', () => {
    expect(isGithubReleaseUrl(null)).toBe(false);
    expect(isGithubReleaseUrl(undefined)).toBe(false);
  });
});
