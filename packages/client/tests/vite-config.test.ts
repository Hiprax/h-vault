// @vitest-environment node
import { describe, expect, it } from 'vitest';
import {
  manualChunks,
  resolveDevHost,
  resolveDevPort,
  DEFAULT_DEV_PORT,
} from '../vite.config.helpers';

// T31 — the Vite dev-server host must be overridable via VITE_HOST so the dev
// Docker container can bind 0.0.0.0 (and thus be reachable through Docker's
// published port), while every other context keeps the safe loopback default.
describe('resolveDevHost (T31 — dev Docker reachability)', () => {
  it('defaults to loopback when VITE_HOST is unset', () => {
    expect(resolveDevHost({})).toBe('127.0.0.1');
  });

  it('treats an empty VITE_HOST as unset', () => {
    expect(resolveDevHost({ VITE_HOST: '' })).toBe('127.0.0.1');
  });

  it('binds the configured VITE_HOST when set (e.g. 0.0.0.0 in Docker)', () => {
    expect(resolveDevHost({ VITE_HOST: '0.0.0.0' })).toBe('0.0.0.0');
  });

  it('reads from process.env by default', () => {
    const original = process.env.VITE_HOST;
    try {
      process.env.VITE_HOST = '0.0.0.0';
      expect(resolveDevHost()).toBe('0.0.0.0');
      delete process.env.VITE_HOST;
      expect(resolveDevHost()).toBe('127.0.0.1');
    } finally {
      if (original === undefined) {
        delete process.env.VITE_HOST;
      } else {
        process.env.VITE_HOST = original;
      }
    }
  });
});

// The dev-server port must be overridable via VITE_PORT (Docker dev, or a host
// where the default is taken) and must NEVER silently resolve to 0 — Vite would
// then bind a RANDOM free port and Playwright's fixed probe URL would hang until
// its 180s webServer timeout. The default is deliberately not 3000: Windows
// reserves dynamic TCP ranges that routinely include it, and a reserved port
// fails to bind with EACCES, which aborts a `strictPort: true` dev server.
describe('resolveDevPort (dev-server port resolution)', () => {
  it('defaults to Vite’s 5173 when VITE_PORT is unset', () => {
    expect(resolveDevPort({})).toBe(5173);
    expect(DEFAULT_DEV_PORT).toBe(5173);
  });

  it('never defaults to a Windows-reserved 3000', () => {
    expect(resolveDevPort({})).not.toBe(3000);
  });

  it('uses a valid VITE_PORT override', () => {
    expect(resolveDevPort({ VITE_PORT: '5180' })).toBe(5180);
  });

  it('treats an empty VITE_PORT as unset', () => {
    expect(resolveDevPort({ VITE_PORT: '' })).toBe(DEFAULT_DEV_PORT);
  });

  it('falls back rather than binding a random port on a non-numeric value', () => {
    expect(resolveDevPort({ VITE_PORT: 'not-a-port' })).toBe(DEFAULT_DEV_PORT);
  });

  it('rejects out-of-range and non-integer values', () => {
    expect(resolveDevPort({ VITE_PORT: '0' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '70000' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '-1' })).toBe(DEFAULT_DEV_PORT);
    expect(resolveDevPort({ VITE_PORT: '5173.5' })).toBe(DEFAULT_DEV_PORT);
  });

  it('reads from process.env by default', () => {
    const original = process.env.VITE_PORT;
    try {
      process.env.VITE_PORT = '5181';
      expect(resolveDevPort()).toBe(5181);
      delete process.env.VITE_PORT;
      expect(resolveDevPort()).toBe(DEFAULT_DEV_PORT);
    } finally {
      if (original === undefined) {
        delete process.env.VITE_PORT;
      } else {
        process.env.VITE_PORT = original;
      }
    }
  });
});

// T30 — manualChunks must split eager vendors into cacheable chunks while
// leaving heavy on-demand deps (zxcvbn, qrcode, react-markdown, otpauth) in
// their own dynamic chunks, so no eager chunk trips the size advisory.
describe('manualChunks (T30 — vendor splitting)', () => {
  it('groups the React runtime + router into vendor-react', () => {
    expect(manualChunks('/repo/node_modules/react/index.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/react-dom/client.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/react-router-dom/dist/index.js')).toBe('vendor-react');
    expect(manualChunks('/repo/node_modules/scheduler/index.js')).toBe('vendor-react');
  });

  it('matches Windows (backslash) module paths too', () => {
    expect(manualChunks('C:\\repo\\node_modules\\react-dom\\client.js')).toBe('vendor-react');
    expect(manualChunks('C:\\repo\\node_modules\\zod\\index.js')).toBe('vendor-core');
  });

  it('groups always-eager data/form vendors into vendor-core', () => {
    expect(manualChunks('/repo/node_modules/zod/lib/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/axios/lib/axios.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/zustand/esm/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/react-hook-form/dist/index.js')).toBe('vendor-core');
    expect(manualChunks('/repo/node_modules/@hookform/resolvers/zod/dist/index.js')).toBe(
      'vendor-core',
    );
  });

  it('keeps heavy lazy-only deps out of any eager vendor chunk', () => {
    expect(manualChunks('/repo/node_modules/zxcvbn/lib/main.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/qrcode/lib/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/react-markdown/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/micromark/index.js')).toBeUndefined();
    expect(manualChunks('/repo/node_modules/otpauth/dist/otpauth.esm.js')).toBeUndefined();
  });

  it('leaves application source to default chunking', () => {
    expect(manualChunks('/repo/packages/client/src/stores/authStore.ts')).toBeUndefined();
    expect(manualChunks('/repo/packages/client/src/components/ui/Button.tsx')).toBeUndefined();
  });
});

// Confirm the real Vite config wires the tested helpers (faithfulness) and the
// chunk-size advisory limit that accommodates the lazy zxcvbn dictionary chunk.
describe('vite.config wiring', () => {
  it('wires the dev host, manualChunks, and chunk-size limit', async () => {
    const mod = await import('../vite.config');
    const config = mod.default as {
      server?: { host?: unknown; strictPort?: unknown; port?: unknown };
      build?: {
        chunkSizeWarningLimit?: unknown;
        rollupOptions?: { output?: { manualChunks?: unknown } };
      };
    };

    expect(config.server?.host).toBe(resolveDevHost());
    expect(config.server?.strictPort).toBe(true);
    // Resolved through the shared helper (the same one playwright.config.ts uses),
    // never a second hardcoded literal that could drift from the probe URL. Compared
    // against the helper rather than the 5173 literal so a developer running with
    // VITE_PORT set does not see a spurious failure; the default itself is pinned
    // environment-independently in the resolveDevPort suite above.
    expect(config.server?.port).toBe(resolveDevPort());
    expect(config.build?.rollupOptions?.output?.manualChunks).toBe(manualChunks);
    expect(config.build?.chunkSizeWarningLimit).toBe(850);
  });
});
