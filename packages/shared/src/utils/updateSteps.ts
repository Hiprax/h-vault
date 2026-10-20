import { isReleaseVersion } from './releaseVersion.js';

/**
 * The commands that update a Docker installation to `version`, exactly as the
 * About page and the update email both print them. ONE definition, because the
 * two must say the same thing as each other and as README.md's "Update" section.
 *
 * - `git checkout v<version>` rather than `git pull`: the compose file and the
 *   images then belong to the same release, whatever `main` holds by then.
 * - `HVAULT_VERSION` names the tag the stack pulls, so it must name the release
 *   checked out.
 * - `docker compose pull &&` before `up`: every release publishes its images, so
 *   nothing is compiled on the server, and `pull` fails loudly when a download
 *   does, where `up` alone would quietly fall back to building the images from
 *   source, which a small server cannot do.
 *
 * Throws on anything but a plain release version: every line is meant to be
 * pasted into a shell.
 */
export function dockerUpdateSteps(version: string): string {
  if (!isReleaseVersion(version)) {
    throw new Error(`not a release version: ${JSON.stringify(version)}`);
  }
  return [
    'git fetch --tags',
    `git checkout v${version}`,
    `# set HVAULT_VERSION=${version} in .env, then:`,
    'docker compose pull && docker compose up -d --wait',
  ].join('\n');
}
