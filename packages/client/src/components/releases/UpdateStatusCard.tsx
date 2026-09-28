import { useState } from 'react';
import {
  CheckCircle2,
  CircleHelp,
  ExternalLink,
  PowerOff,
  RefreshCw,
  Sparkles,
} from 'lucide-react';
import type { UpdateStatus } from '@hvault/shared';
import { Button } from '../ui/Button';
import { useToast } from '../ui/Toast';
import { checkForUpdateNowApi } from '../../services/api/releaseStatusApi';
import { useReleaseStore } from '../../stores/releaseStore';
import { getApiErrorMessage } from '../../lib/utils';
import { formatRelativeTime, formatReleaseDate, isGithubReleaseUrl } from '../../lib/releaseFormat';

interface UpdateStatusCardProps {
  userId: string;
  /** The version this server runs. */
  current: string;
  update: UpdateStatus;
}

/** The repository page a release page belongs to, for the full update guide. */
function repositoryUrlOf(releaseUrl: string): string | null {
  const index = releaseUrl.indexOf('/releases/');
  return index > 0 ? releaseUrl.slice(0, index) : null;
}

function ExternalAnchor({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 text-sm font-medium text-[hsl(var(--primary))] hover:underline"
    >
      {children}
      <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

/**
 * What the server knows about newer releases, for its administrators: whether
 * this installation is current, what a newer release is and how to update to it,
 * and a "Check now" that the server throttles by itself.
 *
 * "Up to date" is only ever said after a recent SUCCESSFUL check; with none, the
 * card says the server could not check, and since when.
 */
export function UpdateStatusCard({ userId, current, update }: UpdateStatusCardProps) {
  const { toast } = useToast();
  const [checking, setChecking] = useState(false);
  const lastSuccess =
    update.lastSuccessAt === null ? null : formatRelativeTime(update.lastSuccessAt);

  const checkNow = async () => {
    setChecking(true);
    try {
      const result = await checkForUpdateNowApi();
      useReleaseStore.getState().applyUpdateStatus(userId, result.update);
      toast(
        result.fetched
          ? { title: 'Checked GitHub just now', type: 'success' }
          : {
              title: 'Checked a moment ago',
              description:
                'The server asks GitHub at most once every five minutes; this is its latest answer.',
              type: 'success',
            },
      );
    } catch (error: unknown) {
      toast({
        title: 'Could not check for updates',
        description: getApiErrorMessage(error),
        type: 'error',
      });
    } finally {
      setChecking(false);
    }
  };

  const latest = update.latestVersion;
  const releaseLink = isGithubReleaseUrl(update.releaseUrl) ? update.releaseUrl : null;
  const repositoryUrl = releaseLink === null ? null : repositoryUrlOf(releaseLink);

  let body: React.ReactNode;
  if (update.state === 'disabled') {
    body = (
      <p className="flex items-start gap-2 text-sm text-[hsl(var(--muted-foreground))]">
        <PowerOff className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        Update checks are turned off on this server. Set UPDATE_CHECK_ENABLED to true in its
        environment to turn them back on.
      </p>
    );
  } else if (update.state === 'available' && latest !== null) {
    body = (
      <div className="space-y-3">
        <p className="flex items-start gap-2 text-sm font-semibold text-[hsl(var(--foreground))]">
          <Sparkles
            className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--primary))]"
            aria-hidden="true"
          />
          H-Vault {latest} is available. This server runs {current}.
        </p>
        {update.publishedAt !== null && (
          <p className="text-sm text-[hsl(var(--muted-foreground))]">
            Published {formatReleaseDate(update.publishedAt.slice(0, 10))}.
          </p>
        )}
        <div>
          <p className="text-sm text-[hsl(var(--foreground))]">
            To update a Docker installation, run these in its directory:
          </p>
          <pre
            tabIndex={0}
            className="mt-2 overflow-x-auto rounded-md bg-[hsl(var(--muted))] px-3 py-2 text-xs leading-relaxed text-[hsl(var(--foreground))]"
          >
            {`git pull\n# set HVAULT_VERSION=${latest} in .env, then:\ndocker compose up -d --build --wait`}
          </pre>
        </div>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {releaseLink !== null && (
            <ExternalAnchor href={releaseLink}>What changed in {latest}</ExternalAnchor>
          )}
          {repositoryUrl !== null && (
            <ExternalAnchor href={`${repositoryUrl}#update`}>Full update guide</ExternalAnchor>
          )}
        </div>
      </div>
    );
  } else if (update.state === 'current') {
    body = (
      <p className="flex items-start gap-2 text-sm text-[hsl(var(--foreground))]">
        <CheckCircle2
          className="mt-0.5 h-4 w-4 shrink-0 text-[hsl(var(--release-security))]"
          aria-hidden="true"
        />
        This server runs the latest release.
        {lastSuccess !== null && ` Checked ${lastSuccess}.`}
      </p>
    );
  } else {
    body = (
      <p className="flex items-start gap-2 text-sm text-[hsl(var(--muted-foreground))]">
        <CircleHelp className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        {lastSuccess === null
          ? 'The server has not been able to check GitHub for a newer release yet.'
          : `The server could not reach GitHub recently. Its last successful check was ${lastSuccess}.`}
        {latest !== null && ` The newest release it knew of then was ${latest}.`}
      </p>
    );
  }

  return (
    <div className="space-y-3 rounded-lg border border-[hsl(var(--border))] p-4">
      <h3 className="text-sm font-semibold text-[hsl(var(--foreground))]">Updates</h3>
      {body}
      {update.canCheckNow && (
        <Button variant="outline" size="sm" loading={checking} onClick={() => void checkNow()}>
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          Check now
        </Button>
      )}
    </div>
  );
}
