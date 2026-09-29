/**
 * The refresh-token secret the E2E server is started with (`start-server.ts`).
 *
 * One definition, because a spec that has to mint a one-time link the way the
 * server's mailer would (there is no SMTP under E2E) signs it with the same
 * purpose key the server verifies with. A throwaway value for a throwaway server;
 * it guards nothing outside this harness.
 */
export const E2E_JWT_REFRESH_SECRET = 'e2e-test-refresh-secret-minimum-32-characters-long';
