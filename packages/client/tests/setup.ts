import '@testing-library/jest-dom';

// Ensure Web Crypto API is available in jsdom environment
if (!globalThis.crypto?.subtle) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { webcrypto } = require('node:crypto');
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
  });
}

// Polyfill scrollIntoView for jsdom, which implements no layout and therefore
// ships no implementation of it. Any component that keeps a keyboard-active row
// inside a scrollport calls it (the saved-address picker does), and without this
// the call is a TypeError rather than a no-op. Polyfilled here rather than
// guarded at each call site: a `?.()` on a method the DOM lib types as always
// present is exactly the redundant condition `no-unnecessary-condition` flags,
// and production browsers all have it.
if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function scrollIntoView(): void {
    /* no layout in jsdom, so there is nothing to scroll */
  };
}

// Polyfill matchMedia for jsdom (required by uiStore and other components)
if (typeof window !== 'undefined' && !window.matchMedia) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
