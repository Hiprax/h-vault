/**
 * The five release-note kind colours, measured.
 *
 * Each kind is TEXT painted on a tint of its own colour (`.release-chip` in
 * `styles/globals.css`: 12% in the light theme, 16% in the dark one), so each is
 * checked against that composited background in both themes, against the WCAG
 * 1.4.3 floor of 4.5:1 for small text. The values are read from the stylesheet
 * itself, so a token edited there is measured here; the accessibility gate scans
 * the light theme only and could not see a dark-theme regression.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RELEASE_CHANGE_KINDS } from '@hvault/shared';

// Anchored on this module rather than on the working directory, like
// `theme-contrast.test.ts`, and through `resolve` rather than `new URL`: under
// jsdom the global `URL` is jsdom's, which `fileURLToPath` refuses.
const css = readFileSync(
  resolve(dirname(fileURLToPath(import.meta.url)), '../src/styles/globals.css'),
  'utf8',
);

/** The body of the first top-level block opened by `selector {`. */
function block(selector: string): string {
  const start = css.indexOf(`\n${selector} {`);
  expect(start, `${selector} block`).toBeGreaterThanOrEqual(0);
  return css.slice(start, css.indexOf('\n}', start));
}

function token(body: string, name: string): [number, number, number] {
  const match = new RegExp(`--${name}:\\s*([\\d.]+)\\s+([\\d.]+)%\\s+([\\d.]+)%;`).exec(body);
  expect(match, `--${name}`).not.toBeNull();
  return [Number(match![1]), Number(match![2]), Number(match![3])];
}

function hslToRgb([h, s, l]: [number, number, number]): [number, number, number] {
  const sat = s / 100;
  const light = l / 100;
  const a = sat * Math.min(light, 1 - light);
  const channel = (n: number) => {
    const k = (n + h / 30) % 12;
    return light - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [channel(0), channel(8), channel(4)];
}

function luminance(rgb: [number, number, number]): number {
  const [r, g, b] = rgb.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)) as [
    number,
    number,
    number,
  ];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: [number, number, number], b: [number, number, number]): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

function over(fg: [number, number, number], bg: [number, number, number], alpha: number) {
  return fg.map((c, i) => alpha * c + (1 - alpha) * bg[i]!) as [number, number, number];
}

const themes = [
  { name: 'light', body: block(':root'), tint: 0.12 },
  { name: 'dark', body: block('.dark'), tint: 0.16 },
] as const;

describe('release-note kind colours', () => {
  it.each(
    themes.flatMap((theme) =>
      RELEASE_CHANGE_KINDS.map((kind) => [theme.name, kind, theme] as const),
    ),
  )('%s theme: %s clears 4.5:1 on its own tint and on the page', (_theme, kind, theme) => {
    const background = hslToRgb(token(theme.body, 'background'));
    const text = hslToRgb(token(theme.body, `release-${kind}`));
    const tint = over(text, background, theme.tint);
    expect(contrast(text, tint)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(text, background)).toBeGreaterThanOrEqual(4.5);
  });

  it('measures real colours, so a clean result means something', () => {
    // Black on white is 21:1; a broken conversion would not produce it.
    expect(contrast([0, 0, 0], [1, 1, 1])).toBeCloseTo(21, 5);
    expect(contrast(hslToRgb([0, 0, 100]), hslToRgb([222.2, 84, 4.9]))).toBeGreaterThan(18);
  });

  it('keeps the tint strengths the measurement assumes', () => {
    expect(css).toContain('background-color: hsl(var(--release-kind) / 0.12);');
    expect(css).toContain(
      '.dark .release-chip {\n    background-color: hsl(var(--release-kind) / 0.16);',
    );
  });
});
