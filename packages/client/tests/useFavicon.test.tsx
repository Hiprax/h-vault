import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render } from '@testing-library/react';

// Controllable auth state consumed by the mocked store selector.
const authState = { isAuthenticated: false, isLocked: false };
vi.mock('../src/stores/authStore', () => ({
  useAuthStore: (selector: (s: typeof authState) => unknown) => selector(authState),
}));

import { useFavicon } from '../src/hooks/useFavicon';
import { resetFaviconStateForTests } from '../src/utils/favicon';

function Probe() {
  useFavicon();
  return null;
}

function currentIconHref() {
  return document.querySelector('link[rel="icon"]')?.getAttribute('href');
}

describe('useFavicon', () => {
  beforeEach(() => {
    resetFaviconStateForTests();
    document.head.innerHTML = '';
    authState.isAuthenticated = false;
    authState.isLocked = false;
  });
  afterEach(() => {
    resetFaviconStateForTests();
    document.head.innerHTML = '';
  });

  it('shows the locked favicon when logged out', () => {
    render(<Probe />);
    expect(currentIconHref()).toBe('/favicon.svg');
  });

  it('shows the unlocked favicon when authenticated and unlocked', () => {
    authState.isAuthenticated = true;
    authState.isLocked = false;
    render(<Probe />);
    expect(currentIconHref()).toBe('/favicon-unlocked.svg');
  });

  it('shows the locked favicon when authenticated but locked', () => {
    authState.isAuthenticated = true;
    authState.isLocked = true;
    render(<Probe />);
    expect(currentIconHref()).toBe('/favicon.svg');
  });
});
