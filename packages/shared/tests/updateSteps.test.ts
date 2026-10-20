/**
 * The update commands the About page and the update email both print.
 *
 * They are what an operator types on their server, so the exact text is the
 * contract: these cases pin every line, and the one property the commands exist
 * to have (nothing is compiled on the server, and a failed download stops the
 * update instead of turning into a build).
 */
import { describe, expect, it } from 'vitest';
import { dockerUpdateSteps } from '../src/utils/updateSteps.js';

describe('dockerUpdateSteps', () => {
  it('checks out the release, points HVAULT_VERSION at it, then pulls before it starts', () => {
    expect(dockerUpdateSteps('0.21.0')).toBe(
      [
        'git fetch --tags',
        'git checkout v0.21.0',
        '# set HVAULT_VERSION=0.21.0 in .env, then:',
        'docker compose pull && docker compose up -d --wait',
      ].join('\n'),
    );
  });

  it('downloads the published images and never builds on the server', () => {
    const steps = dockerUpdateSteps('1.0.0');
    // `up` alone would ignore a failed download and compile the images instead,
    // which is what a small server cannot afford; `pull &&` stops there.
    expect(steps).toContain('docker compose pull && ');
    expect(steps).not.toContain('--build');
    expect(steps).not.toContain('git pull');
  });

  it('names the version it was given, in every line that needs one', () => {
    const steps = dockerUpdateSteps('12.3.45');
    expect(steps.match(/12\.3\.45/g)).toHaveLength(2);
    expect(steps).toContain('git checkout v12.3.45\n');
    expect(steps).toContain('HVAULT_VERSION=12.3.45 ');
  });

  it.each(['v0.21.0', '0.21', '0.21.0-rc.1', '', '0.21.0\nrm -rf /', '01.2.3'])(
    'refuses %j, which is not a release version',
    (value) => {
      expect(() => dockerUpdateSteps(value)).toThrow(
        `not a release version: ${JSON.stringify(value)}`,
      );
    },
  );
});
