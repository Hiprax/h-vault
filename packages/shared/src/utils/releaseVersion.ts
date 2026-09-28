import { RELEASE_VERSION_PATTERN } from '../constants/index.js';

/**
 * The three parts of a release version, or `null` for anything that is not one.
 *
 * Deliberately strict, and deliberately `null` rather than a guess: the value may
 * come from a request body, a database field written by an older release, or a
 * GitHub tag, and reading "1.2", "1.2.3-rc.1" or a stray string as `0.0.0` (or
 * as `1.2.0`) would move a watermark or claim an update on the strength of a
 * value nobody wrote. Only {@link RELEASE_VERSION_PATTERN} is a version.
 */
export function parseReleaseVersion(
  value: unknown,
): readonly [major: number, minor: number, patch: number] | null {
  // The type check is not redundant with the pattern: `exec` coerces its argument,
  // so an object whose `toString()` returns "1.2.3" would otherwise match. There is
  // no separate length check because the anchored pattern cannot match more than
  // twenty characters, and it is linear, so a long input costs one failed scan.
  if (typeof value !== 'string') {
    return null;
  }
  const match = RELEASE_VERSION_PATTERN.exec(value);
  if (match === null) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** Whether `value` is a release version this project would cut. */
export function isReleaseVersion(value: unknown): value is string {
  return parseReleaseVersion(value) !== null;
}

/**
 * Orders two release versions: negative when `a` is older, positive when newer,
 * zero when they are the same release. Always -1, 0 or 1.
 *
 * Throws `RangeError` on anything that is not a release version, instead of
 * ranking it. Every caller holds values it has already validated; a comparison
 * that quietly ranked garbage would be the one place a malformed value could
 * still decide something.
 */
export function compareReleaseVersions(a: string, b: string): number {
  const left = parseReleaseVersion(a);
  const right = parseReleaseVersion(b);
  if (left === null || right === null) {
    const offending = left === null ? a : b;
    throw new RangeError(`Not a release version: ${JSON.stringify(offending.slice(0, 40))}`);
  }
  const [leftMajor, leftMinor, leftPatch] = left;
  const [rightMajor, rightMinor, rightPatch] = right;
  return Math.sign(leftMajor - rightMajor || leftMinor - rightMinor || leftPatch - rightPatch);
}
