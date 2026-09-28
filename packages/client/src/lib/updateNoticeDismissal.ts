/**
 * Which "a newer release is available" notice this browser dismissed. Remembered
 * per RELEASE, so dismissing the notice for 0.16.0 does not hide the one for
 * 0.17.0. A per-browser convenience only: storage that is blocked or full simply
 * means the notice comes back.
 */

const DISMISSED_UPDATE_KEY = 'hvault_dismissed_update';

export function isUpdateNoticeDismissed(version: string): boolean {
  try {
    return localStorage.getItem(DISMISSED_UPDATE_KEY) === version;
  } catch {
    return false;
  }
}

export function dismissUpdateNotice(version: string): void {
  try {
    localStorage.setItem(DISMISSED_UPDATE_KEY, version);
  } catch {
    return;
  }
}
