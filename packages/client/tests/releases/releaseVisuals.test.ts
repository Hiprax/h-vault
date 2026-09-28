/**
 * The icon and kind lookups. The server sends both as plain strings, so each
 * lookup must refuse a name that would resolve through the prototype and must
 * give an unknown value a neutral fallback rather than nothing.
 */
import { describe, expect, it } from 'vitest';
import { RELEASE_CHANGE_KINDS, RELEASE_ICONS } from '@hvault/shared';
import { Sparkles, CircleDot } from 'lucide-react';
import { releaseIconFor, releaseKindFor } from '../../src/components/releases/releaseVisuals';

describe('releaseIconFor', () => {
  it('gives every icon name in the closed list its own picture', () => {
    const pictures = RELEASE_ICONS.map((name) => releaseIconFor(name));
    expect(new Set(pictures).size).toBe(RELEASE_ICONS.length);
    expect(releaseIconFor('sparkles')).toBe(Sparkles);
  });

  it.each(['rocket', '', 'toString', '__proto__', 'constructor'])(
    'falls back to the sparkles picture for %j',
    (name) => {
      expect(releaseIconFor(name)).toBe(Sparkles);
    },
  );
});

describe('releaseKindFor', () => {
  it.each([
    ['added', 'New', 'release-kind-added'],
    ['improved', 'Improved', 'release-kind-improved'],
    ['changed', 'Changed', 'release-kind-changed'],
    ['fixed', 'Fixed', 'release-kind-fixed'],
    ['security', 'Security', 'release-kind-security'],
  ])('labels %s as %s with its own colour class', (kind, label, className) => {
    expect(releaseKindFor(kind)).toMatchObject({ label, className });
  });

  it('covers every kind in the closed list with a distinct picture', () => {
    const icons = RELEASE_CHANGE_KINDS.map((kind) => releaseKindFor(kind).icon);
    expect(new Set(icons).size).toBe(RELEASE_CHANGE_KINDS.length);
  });

  it.each(['deprecated', 'toString', '__proto__'])('gives %j the neutral "Other" look', (kind) => {
    expect(releaseKindFor(kind)).toEqual({
      label: 'Other',
      className: 'release-kind-other',
      icon: CircleDot,
    });
  });
});
