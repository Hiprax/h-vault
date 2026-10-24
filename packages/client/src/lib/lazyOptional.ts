import { lazy, type ComponentType } from 'react';

/** Renders nothing: what an optional component becomes when its chunk cannot be fetched. */
function Nothing(): null {
  return null;
}

/**
 * A component loaded after the first render that is not worth the page: if its
 * chunk cannot be fetched, it renders nothing instead of reaching the error
 * boundary that would replace the whole app. For a surface nothing else depends
 * on, such as the update prompt.
 */
export function lazyOptional(load: () => Promise<{ default: ComponentType }>): ComponentType {
  return lazy(() => load().catch(() => ({ default: Nothing })));
}
