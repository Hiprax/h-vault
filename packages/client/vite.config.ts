import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';
import { manualChunks, resolveDevHost } from './vite.config.helpers';

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: 'prompt',
      includeAssets: ['favicon.ico', 'favicon.svg'],
      manifest: {
        name: 'H-Vault',
        short_name: 'H-Vault',
        description: 'Zero-knowledge password manager',
        theme_color: '#3b82f6',
        background_color: '#0a0f1e',
        display: 'standalone',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: '/pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png',
          },
          {
            src: '/pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
          },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        cleanupOutdatedCaches: true,
        runtimeCaching: [
          {
            urlPattern: /^https?:\/\/.*\/api\//,
            handler: 'NetworkOnly',
          },
        ],
      },
    }),
  ],
  server: {
    port: 3000,
    // Loopback by default (local dev / E2E / CI). Docker dev sets VITE_HOST=0.0.0.0
    // so the container's published port is reachable from the host.
    host: resolveDevHost(),
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: process.env.NODE_ENV !== 'production',
    // zxcvbn ships an irreducible ~820 kB dictionary that is loaded lazily
    // (only for password-strength checks), so the advisory is raised just above
    // it. Eager chunks stay far below this via manualChunks below.
    chunkSizeWarningLimit: 850,
    rollupOptions: {
      output: {
        // Split eager vendors into cacheable chunks and keep lazy deps in their
        // own on-demand chunks (see vite.config.helpers.ts).
        manualChunks,
      },
    },
  },
});
