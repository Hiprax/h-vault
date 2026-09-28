import { Link } from 'react-router';
import { ExternalLink, Sparkles, X } from 'lucide-react';
import { isGithubReleaseUrl } from '../../lib/releaseFormat';

interface UpdateAvailableBannerProps {
  /** The version this server runs. */
  current: string;
  /** The newer release GitHub has. */
  latest: string;
  releaseUrl: string | null;
  onDismiss: () => void;
}

/**
 * The notice an administrator sees while a newer release is published. Loaded
 * lazily: most sessions never render it.
 */
export default function UpdateAvailableBanner({
  current,
  latest,
  releaseUrl,
  onDismiss,
}: UpdateAvailableBannerProps) {
  return (
    <div className="mx-4 mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-[hsl(var(--primary)/0.35)] bg-[hsl(var(--sidebar-accent))] px-4 py-2 text-sm text-[hsl(var(--sidebar-accent-foreground))] lg:mx-6">
      <Sparkles className="h-4 w-4 shrink-0" aria-hidden="true" />
      <p className="min-w-0 flex-1">
        <span className="font-semibold">H-Vault {latest} is available.</span> This server runs{' '}
        {current}.
      </p>
      <div className="flex items-center gap-3">
        <Link to="/settings/about" className="font-medium underline-offset-2 hover:underline">
          How to update
        </Link>
        {isGithubReleaseUrl(releaseUrl) && (
          <a
            href={releaseUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-medium underline-offset-2 hover:underline"
          >
            View release
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        )}
        <button
          type="button"
          onClick={onDismiss}
          aria-label={`Dismiss the notice about H-Vault ${latest}`}
          className="cursor-pointer rounded p-1 hover:bg-[hsl(var(--primary)/0.12)]"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
