import type zxcvbnType from 'zxcvbn';

let cachedZxcvbn: typeof zxcvbnType | null = null;

/**
 * Lazily loads the zxcvbn library on first use and caches it for subsequent
 * calls. This avoids bundling the ~400KB library in the main chunk.
 */
export async function getZxcvbn(): Promise<typeof zxcvbnType> {
  if (cachedZxcvbn) return cachedZxcvbn;
  const mod = await import('zxcvbn');
  cachedZxcvbn = mod.default;
  return cachedZxcvbn;
}
