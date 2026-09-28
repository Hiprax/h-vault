import { isSafeUrl } from './utils';

/**
 * A release date (`YYYY-MM-DD`, as the CHANGELOG writes it) in the reader's
 * language, e.g. "27 September 2026" or "September 27, 2026".
 *
 * Read and formatted in UTC: the date names a day, not an instant, and reading it
 * in a zone west of UTC would print the day before. An unreadable value is shown
 * as written rather than as "Invalid Date".
 */
export function formatReleaseDate(date: string, locale?: string): string {
  const time = Date.parse(`${date}T00:00:00Z`);
  if (Number.isNaN(time)) return date;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'long', timeZone: 'UTC' }).format(time);
}

const RELATIVE_UNITS: readonly [Intl.RelativeTimeFormatUnit, number][] = [
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
];

/**
 * How long ago `iso` was, in words ("3 hours ago", "yesterday", "just now").
 * The largest whole unit wins; anything under a minute is "just now". A moment
 * in the future (a clock skewed ahead of the server's) reads as "just now" too,
 * rather than "in 2 minutes", which would be nonsense for a past event.
 */
export function formatRelativeTime(iso: string, now: number = Date.now(), locale?: string): string {
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return iso;
  const elapsed = now - time;
  const words = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  for (const [unit, size] of RELATIVE_UNITS) {
    if (elapsed >= size) return words.format(-Math.floor(elapsed / size), unit);
  }
  return 'just now';
}

/** The anchor a release is linked by on the About page: `v0.15.0` becomes `v0-15-0`. */
export function releaseAnchorId(version: string): string {
  return `v${version.replaceAll('.', '-')}`;
}

/**
 * Whether `url` may be rendered as a link to a release page. The server builds
 * these, but the client still refuses anything that is not an https link to
 * GitHub, so a compromised or confused server cannot turn the notes into a
 * pointer to somewhere else.
 */
export function isGithubReleaseUrl(url: string | null | undefined): url is string {
  return typeof url === 'string' && isSafeUrl(url) && url.startsWith('https://github.com/');
}
