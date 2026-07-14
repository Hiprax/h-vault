import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  FAVICON_HREFS,
  faviconStateFor,
  setFaviconState,
  resetFaviconStateForTests,
} from '../src/utils/favicon';

describe('faviconStateFor', () => {
  it('is "unlocked" only when authenticated AND not locked', () => {
    expect(faviconStateFor(true, false)).toBe('unlocked');
  });

  it('is "locked" when locked, logged out, or both', () => {
    expect(faviconStateFor(true, true)).toBe('locked');
    expect(faviconStateFor(false, false)).toBe('locked');
    expect(faviconStateFor(false, true)).toBe('locked');
  });
});

describe('FAVICON_HREFS', () => {
  it('maps each state to a shipped public asset', () => {
    expect(FAVICON_HREFS.locked).toBe('/favicon.svg');
    expect(FAVICON_HREFS.unlocked).toBe('/favicon-unlocked.svg');
  });
});

describe('setFaviconState', () => {
  beforeEach(() => {
    resetFaviconStateForTests();
    document.head.innerHTML = '';
  });
  afterEach(() => {
    resetFaviconStateForTests();
    document.head.innerHTML = '';
  });

  it('creates an icon link when the document has none', () => {
    setFaviconState('unlocked');
    const link = document.querySelector('link[rel="icon"]');
    expect(link).toBeTruthy();
    expect(link).toHaveAttribute('href', '/favicon-unlocked.svg');
    expect(link).toHaveAttribute('type', 'image/svg+xml');
  });

  it('updates the existing icon link in place instead of duplicating it', () => {
    const existing = document.createElement('link');
    existing.setAttribute('rel', 'icon');
    existing.setAttribute('href', '/favicon.svg');
    document.head.appendChild(existing);

    setFaviconState('unlocked');

    const links = document.querySelectorAll('link[rel="icon"]');
    expect(links.length).toBe(1);
    expect(links[0]).toHaveAttribute('href', '/favicon-unlocked.svg');
  });

  it('switches back to the locked icon', () => {
    setFaviconState('unlocked');
    setFaviconState('locked');
    expect(document.querySelector('link[rel="icon"]')).toHaveAttribute('href', '/favicon.svg');
  });

  it('is a no-op when the requested state is unchanged (memoised)', () => {
    setFaviconState('unlocked');
    const link = document.querySelector('link[rel="icon"]')!;
    link.setAttribute('href', 'SENTINEL');
    setFaviconState('unlocked'); // same state -> should not touch the link
    expect(link).toHaveAttribute('href', 'SENTINEL');
  });
});

describe('shipped favicon assets encode the intended states', () => {
  const publicDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
  const locked = fs.readFileSync(path.resolve(publicDir, 'favicon.svg'), 'utf8');
  const unlocked = fs.readFileSync(path.resolve(publicDir, 'favicon-unlocked.svg'), 'utf8');

  it('locked favicon is red with a closed shackle', () => {
    expect(locked).toContain('#ef4444'); // red gradient stop
    expect(locked).toContain('M196 220V176'); // closed shackle path
    expect(locked).not.toContain('rotate('); // shackle is not opened
  });

  it('unlocked favicon is green with an open (rotated) shackle', () => {
    expect(unlocked).toContain('#22c55e'); // green gradient stop
    expect(unlocked).toContain('rotate(-32'); // shackle rotated open on its hinge
  });
});
