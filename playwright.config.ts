import { defineConfig, devices } from '@playwright/test';

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
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:3000',
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
        url: 'http://127.0.0.1:3000/api/v1/health',
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      },
});
