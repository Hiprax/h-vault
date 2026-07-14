/**
 * Generates a stable device fingerprint from browser properties.
 *
 * The fingerprint is a 16-character hex string derived from a SHA-256 hash of
 * stable browser characteristics. It is cached in localStorage so it persists
 * across sessions on the same browser.
 */

const STORAGE_KEY = '__hv_device_fingerprint';

export async function getDeviceFingerprint(): Promise<string> {
  // Check localStorage for existing fingerprint
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored?.length === 16) return stored;
  } catch {
    // localStorage may be unavailable (e.g. private browsing)
  }

  // Generate from stable browser properties
  const components = [
    navigator.userAgent,
    navigator.language,
    String(screen.width) + 'x' + String(screen.height),
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    String(navigator.hardwareConcurrency),
  ].join('|');

  // Hash with SHA-256
  const encoded = new TextEncoder().encode(components);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const fingerprint = hashArray
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, 16);

  try {
    localStorage.setItem(STORAGE_KEY, fingerprint);
  } catch {
    // localStorage may be unavailable
  }

  return fingerprint;
}
