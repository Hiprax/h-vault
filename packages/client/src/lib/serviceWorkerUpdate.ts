/**
 * A handle on the service worker registration, so code that learns the SERVER was
 * updated can ask the browser to look for the new build straight away instead of
 * waiting for the hourly check in `ReloadPrompt`. The update prompt then appears
 * on its own, because a waiting worker is what it listens for.
 *
 * Module-level on purpose: the registration belongs to the page, not to any
 * component, and there is at most one.
 */

let registration: ServiceWorkerRegistration | null = null;

/** Called by `ReloadPrompt` once the worker is registered. */
export function rememberServiceWorkerRegistration(value: ServiceWorkerRegistration): void {
  registration = value;
}

/**
 * Asks the browser to check for a newer service worker now. Does nothing before
 * registration (in development, or in a browser without service workers), and a
 * failed check is dropped: the hourly check will try again.
 */
export function requestServiceWorkerUpdate(): void {
  registration?.update().catch(() => undefined);
}
