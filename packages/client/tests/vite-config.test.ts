// @vitest-environment node
import { describe, expect, it } from 'vitest';
import { manualChunks, resolveDevHost } from '../vite.config.helpers';

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
    expect(config.server?.port).toBe(3000);
    expect(config.build?.rollupOptions?.output?.manualChunks).toBe(manualChunks);
    expect(config.build?.chunkSizeWarningLimit).toBe(850);
  });
});
