import { defineConfig, devices } from '@playwright/test';
import { resolveDevPort } from './packages/client/vite.config.helpers';

/**
 * Playwright E2E test configuration for H-Vault.
 *
 * Tests run against the full stack (server + client) to verify critical
 * security flows: registration, login, 2FA, vault CRUD, and lock/unlock.
 *
 * Usage:
 *   npx playwright test            # Run all E2E tests
 *   npx playwright test --ui       # Run with UI mode
 *   npx playwright test --headed   # Run with visible browser
 */

/**
 * The client dev-server port, resolved from the SAME helper Vite uses, so the
 * probe URL below and the server Vite actually binds can never disagree (a
 * mismatch shows up as an unexplained 180s "Timed out waiting from
 * config.webServer"). Override both at once with `VITE_PORT`.
 */
const CLIENT_PORT = resolveDevPort();
const CLIENT_ORIGIN = `http://127.0.0.1:${String(CLIENT_PORT)}`;
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'html',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: process.env.E2E_BASE_URL ?? CLIENT_ORIGIN,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'on-first-retry',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: process.env.E2E_BASE_URL
    ? undefined
    : {
        command: 'npx tsx e2e/start-server.ts',
        url: `${CLIENT_ORIGIN}/api/v1/health`,
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      },
});
