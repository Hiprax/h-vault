/**
 * The release-version parser and comparator.
 *
 * Every watermark, "is this update newer" decision and CHANGELOG cross-check in
 * the application goes through these two functions, so the cases below pin the
 * two ways they could quietly go wrong: accepting something that is not a version
 * (and ranking it as if it were), and ranking two real versions in the wrong
 * order. A parser that read "1.2.3-rc.1" as "1.2.3", or garbage as "0.0.0", would
 * let a malformed value move a user's watermark or claim an update that does not
 * exist; a comparator that compared parts as strings would put 0.10.0 before 0.9.0.
 */
import { describe, expect, it } from 'vitest';
import {
  compareReleaseVersions,
  isReleaseVersion,
  parseReleaseVersion,
} from '../src/utils/releaseVersion.js';
import { MAX_RELEASE_VERSION_LENGTH, RELEASE_VERSION_PATTERN } from '../src/constants/index.js';

describe('parseReleaseVersion', () => {
  it.each([
    ['0.0.0', [0, 0, 0]],
    ['0.15.0', [0, 15, 0]],
    ['1.22.333', [1, 22, 333]],
    ['999999.999999.999999', [999999, 999999, 999999]],
  ] as const)('reads %s as its three numeric parts', (value, parts) => {
    expect(parseReleaseVersion(value)).toEqual(parts);
  });

  it.each([
    ['', 'empty'],
    ['1.2', 'two parts'],
    ['1.2.3.4', 'four parts'],
    ['v1.2.3', 'a tag prefix'],
    ['1.2.3-rc.1', 'a prerelease suffix'],
    ['1.2.3+build.5', 'build metadata'],
    ['01.2.3', 'a leading zero in MAJOR'],
    ['1.02.3', 'a leading zero in MINOR'],
    ['1.2.03', 'a leading zero in PATCH'],
    ['1000000.0.0', 'seven digits in MAJOR'],
    ['0.1000000.0', 'seven digits in MINOR'],
    ['0.0.1000000', 'seven digits in PATCH'],
    [' 1.2.3', 'a leading space'],
    ['1.2.3 ', 'a trailing space'],
    ['1.2.3\n', 'a trailing newline'],
    ['١.2.3', 'a non-ASCII digit'],
    ['1.2.x', 'a letter'],
    ['1..3', 'an empty part'],
    ['-1.2.3', 'a sign'],
  ])('refuses %j (%s)', (value) => {
    expect(parseReleaseVersion(value)).toBeNull();
    expect(isReleaseVersion(value)).toBe(false);
  });

  it('refuses a non-string even when it stringifies to a version', () => {
    // `RegExp.exec` coerces its argument, so without the type check an object
    // whose toString() is "1.2.3" would be read as that version.
    const impostor = { toString: () => '1.2.3' };
    expect(parseReleaseVersion(impostor)).toBeNull();
    expect(parseReleaseVersion(123)).toBeNull();
    expect(parseReleaseVersion(null)).toBeNull();
    expect(parseReleaseVersion(undefined)).toBeNull();
    expect(isReleaseVersion(impostor)).toBe(false);
  });

  it('never matches more characters than MAX_RELEASE_VERSION_LENGTH', () => {
    // The parser has no length check of its own because the anchored pattern
    // bounds the match; this pins that the bound the schemas use really is an
    // upper bound on what the pattern accepts.
    const longest = '999999.999999.999999';
    expect(longest).toHaveLength(MAX_RELEASE_VERSION_LENGTH);
    expect(RELEASE_VERSION_PATTERN.test(longest)).toBe(true);
    expect(RELEASE_VERSION_PATTERN.test(`${longest}9`)).toBe(false);
  });

  it('accepts exactly what isReleaseVersion accepts', () => {
    expect(isReleaseVersion('0.15.0')).toBe(true);
    expect(isReleaseVersion('0.15')).toBe(false);
  });
});

describe('compareReleaseVersions', () => {
  it.each([
    ['0.9.0', '0.10.0', -1],
    ['0.10.0', '0.9.0', 1],
    ['1.0.0', '3.0.0', -1],
    ['3.0.0', '1.0.0', 1],
    ['2.0.0', '1.9.9', 1],
    ['1.9.9', '2.0.0', -1],
    ['1.2.0', '1.10.0', -1],
    ['1.2.9', '1.3.0', -1],
    ['1.2.3', '1.2.10', -1],
    ['1.2.10', '1.2.3', 1],
    ['0.14.1', '0.14.1', 0],
    ['0.0.0', '0.0.0', 0],
  ] as const)('orders %s against %s as %d, numerically part by part', (a, b, expected) => {
    expect(compareReleaseVersions(a, b)).toBe(expected);
  });

  it('returns exactly -1, 0 or 1 however far apart the versions are', () => {
    expect(compareReleaseVersions('0.0.1', '900000.0.0')).toBe(-1);
    expect(compareReleaseVersions('900000.0.0', '0.0.1')).toBe(1);
    expect(compareReleaseVersions('5.0.0', '5.0.7')).toBe(-1);
  });

  it('throws RangeError naming the left operand when it is not a version', () => {
    expect(() => compareReleaseVersions('1.2', '1.2.3')).toThrow(RangeError);
    expect(() => compareReleaseVersions('1.2', '1.2.3')).toThrow('Not a release version: "1.2"');
  });

  it('throws RangeError naming the right operand when only it is not a version', () => {
    expect(() => compareReleaseVersions('1.2.3', 'v1.2.4')).toThrow(
      'Not a release version: "v1.2.4"',
    );
  });

  it('caps the offending value at forty characters in the message', () => {
    const garbage = `${'a'.repeat(40)}TAIL`;
    let message = '';
    try {
      compareReleaseVersions(garbage, '1.0.0');
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toBe(`Not a release version: "${'a'.repeat(40)}"`);
    expect(message).not.toContain('TAIL');
  });
});
