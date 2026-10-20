/**
 * The release images' decisions: what the release workflow builds, when it may
 * publish, what an index must hold, what an anonymous client must be able to
 * pull, and which scanner findings are accepted.
 *
 * `scripts/ci/release-images.mjs` runs the docker commands; everything it
 * decides lives in `scripts/ci/lib/release-images.mjs`, `lib/images.mjs` and
 * `lib/trivy.mjs`, which this file exercises without a registry, a runner or a
 * second architecture. The digests below are deliberately low-entropy: the
 * secret scan reads committed history, and a random-looking 64-hex string next
 * to a key-like name is exactly what it flags.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import {
  IMAGE_DOCKERFILE,
  IMAGE_REGISTRY,
  PUBLISHED_IMAGES,
  RELEASE_PLATFORMS,
  SOURCE_REPOSITORY,
  imageRepository,
} from '../../../scripts/ci/lib/images.mjs';
import {
  bakeArgs,
  bakeDefinition,
  confirmedIndexDigest,
  decisionChangeProblem,
  digestsFromMetadata,
  githubOutputLines,
  imagetoolsCreateArgs,
  indexProblems,
  ociMetadata,
  packageSettingsUrl,
  parseCreated,
  parseDigest,
  parseFlag,
  parseLegDigests,
  parsePlatform,
  parseRevision,
  parseVersion,
  planImages,
  publicImageProblems,
  pullOnlyServices,
  releaseTagState,
  sha256Digest,
  shellScriptPath,
  smokeTag,
  smokeUpArgs,
  trivyRunArgs,
} from '../../../scripts/ci/lib/release-images.mjs';
import {
  TRIVY_IMAGE,
  TRIVY_SCAN_ARGS,
  acceptedBy,
  extractFindings,
  judgeFindings,
  parseBaseline,
  scanCoverageProblem,
} from '../../../scripts/ci/lib/trivy.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** A well-formed, low-entropy digest: `sha256:000…0<n>`. */
const digest = (n: number): string => `sha256:${String(n).padStart(64, '0')}`;
const REVISION = '0123456789abcdef0123456789abcdef01234567';
const CREATED = '2026-10-20T08:00:00Z';
const RELEASE = { version: '0.20.0', revision: REVISION, created: CREATED };
const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';

const [APP, WEB, BOOTSTRAP] = PUBLISHED_IMAGES;

describe('the published image catalogue', () => {
  it('publishes the three images that compile, each from its own Dockerfile stage', () => {
    expect(
      PUBLISHED_IMAGES.map((image) => [image.key, image.name, image.target, image.service]),
    ).toEqual([
      ['app', 'hvault-app', 'app', 'hvault-app'],
      ['web', 'hvault-web', 'web', 'hvault-nginx'],
      ['bootstrap', 'hvault-bootstrap', 'bootstrap', 'hvault-bootstrap'],
    ]);
    // The database and storage images are local builds of pinned upstream images,
    // and never published (no MongoDB or Garage binaries redistributed).
    expect(PUBLISHED_IMAGES.map((image) => image.name)).not.toContain('hvault-db');
    expect(PUBLISHED_IMAGES.map((image) => image.name)).not.toContain('hvault-s3');
    expect(IMAGE_DOCKERFILE).toBe('docker/Dockerfile');
  });

  it('names a lower-case GHCR namespace, which the registry requires, for the Hiprax repository', () => {
    expect(IMAGE_REGISTRY).toBe('ghcr.io/hiprax');
    expect(SOURCE_REPOSITORY).toBe('Hiprax/h-vault');
    expect(imageRepository('hvault-app')).toBe('ghcr.io/hiprax/hvault-app');
    expect(imageRepository('hvault-app', '127.0.0.1:5555/test')).toBe(
      '127.0.0.1:5555/test/hvault-app',
    );
  });

  it('builds for exactly 64-bit x86 and 64-bit ARM', () => {
    expect(RELEASE_PLATFORMS).toEqual(['linux/amd64', 'linux/arm64']);
  });
});

describe('release image inputs', () => {
  it('accepts a plain X.Y.Z version and refuses every other spelling', () => {
    expect(parseVersion('0.20.0')).toBe('0.20.0');
    for (const bad of ['v0.20.0', '0.20', '0.20.0-rc.1', ' 0.20.0', '', undefined]) {
      expect(() => parseVersion(bad), String(bad)).toThrow(/not a release version/);
    }
  });

  it('accepts only a lower-case sha256 digest, and names the value it refused', () => {
    expect(parseDigest(digest(1), 'x')).toBe(digest(1));
    for (const bad of [
      digest(1).toUpperCase(),
      `sha256:${'0'.repeat(63)}`,
      `sha256:${'0'.repeat(65)}`,
      `sha512:${'0'.repeat(64)}`,
      '0'.repeat(64),
      undefined,
    ]) {
      expect(() => parseDigest(bad, 'the web digest'), String(bad)).toThrow(
        /^the web digest is not a sha256 digest/,
      );
    }
  });

  it('accepts only a full commit id', () => {
    expect(parseRevision(REVISION)).toBe(REVISION);
    expect(() => parseRevision(REVISION.slice(1))).toThrow(/not a full commit id/);
    expect(() => parseRevision(REVISION.toUpperCase())).toThrow(/not a full commit id/);
  });

  it('accepts a UTC timestamp to the second, the form OCI `created` uses', () => {
    expect(parseCreated(CREATED)).toBe(CREATED);
    for (const bad of ['2026-10-20T08:00:00.000Z', '2026-10-20T08:00:00+02:00', '2026-10-20', '']) {
      expect(() => parseCreated(bad), bad).toThrow(/not a UTC timestamp/);
    }
  });

  it('accepts the two release platforms and nothing else', () => {
    expect(parsePlatform('linux/amd64')).toBe('linux/amd64');
    expect(parsePlatform('linux/arm64')).toBe('linux/arm64');
    for (const bad of ['linux/arm/v7', 'arm64', 'linux/386', '']) {
      expect(() => parsePlatform(bad), bad).toThrow(/not a release platform/);
    }
  });

  it('reads a flag only from the exact words true and false, never a lookalike', () => {
    expect(parseFlag('true', 'STAGE')).toBe(true);
    expect(parseFlag('false', 'STAGE')).toBe(false);
    // `inputs.stage_images == 'true'` on a boolean input is always false, so a
    // lookalike must be a refusal, never a silent false.
    for (const bad of [true, false, 'True', 'TRUE', '1', '0', '', undefined, null]) {
      expect(() => parseFlag(bad, 'STAGE'), String(bad)).toThrow(
        /^STAGE must be exactly "true" or "false"/,
      );
    }
  });

  it('reads one platform job outputs: exactly one valid digest per published image', () => {
    const outputs = { app: digest(1), web: digest(2), bootstrap: digest(3) };
    expect(parseLegDigests(JSON.stringify(outputs), 'AMD64')).toEqual(outputs);
    expect(() =>
      parseLegDigests(JSON.stringify({ ...outputs, extra: digest(4) }), 'AMD64'),
    ).toThrow(/AMD64 names app, bootstrap, extra, web, expected app, bootstrap, web/);
    const { bootstrap: _dropped, ...missing } = outputs;
    expect(() => parseLegDigests(JSON.stringify(missing), 'AMD64')).toThrow(
      /expected app, bootstrap, web/,
    );
    expect(() =>
      parseLegDigests(JSON.stringify({ ...outputs, web: 'sha256:abc' }), 'AMD64'),
    ).toThrow(/^AMD64 web is not a sha256 digest/);
    expect(() => parseLegDigests('{not json', 'AMD64')).toThrow(/AMD64 is not JSON/);
    expect(() => parseLegDigests('[]', 'AMD64')).toThrow(/AMD64 is not an object of digests/);
    expect(() => parseLegDigests('', 'AMD64')).toThrow(/AMD64 is not JSON/);
  });
});

describe('when the image jobs build, and when they may publish', () => {
  const MAIN = 'refs/heads/main';
  it.each([
    // [what, facts, expected]
    [
      'a due release on main',
      { shouldRelease: true, createTag: true, stage: false, ref: MAIN },
      { build: true, publish: true },
    ],
    [
      'a re-run on an already-tagged commit',
      { shouldRelease: true, createTag: false, stage: false, ref: MAIN },
      { build: false, publish: false },
    ],
    [
      'a due release dispatched from another branch',
      { shouldRelease: true, createTag: true, stage: false, ref: 'refs/heads/probe' },
      { build: false, publish: false },
    ],
    [
      'a rehearsal on a branch',
      { shouldRelease: false, createTag: false, stage: true, ref: 'refs/heads/probe' },
      { build: true, publish: false },
    ],
    [
      'a rehearsal on main with a release due',
      { shouldRelease: true, createTag: true, stage: true, ref: MAIN },
      { build: true, publish: false },
    ],
    [
      'an ordinary push that bumped nothing',
      { shouldRelease: false, createTag: false, stage: false, ref: MAIN },
      { build: false, publish: false },
    ],
  ])('%s', (_what, facts, expected) => {
    expect(planImages(facts)).toEqual({ stage: facts.stage, ...expected });
  });
});

describe('the per-platform bake', () => {
  const definition = bakeDefinition({ context: '/repo', platform: 'linux/arm64', ...RELEASE });

  it('builds every published image in one group, and nothing else', () => {
    expect(definition.group).toEqual({ default: { targets: ['app', 'web', 'bootstrap'] } });
    expect(Object.keys(definition.target)).toEqual(['app', 'web', 'bootstrap']);
    expect(PUBLISHED_IMAGES.map((image) => definition.target[image.key]?.target)).toEqual([
      'app',
      'web',
      'bootstrap',
    ]);
  });

  it('varies nothing but the stage and its metadata, so the three share one solve and one client build', () => {
    const shared = (key: string) => {
      const { target: _stage, labels: _labels, output: _output, ...rest } = definition.target[key]!;
      return rest;
    };
    expect(shared('web')).toEqual(shared('app'));
    expect(shared('bootstrap')).toEqual(shared('app'));
    expect(shared('app')).toEqual({
      context: '/repo',
      dockerfile: 'docker/Dockerfile',
      platforms: ['linux/arm64'],
    });
  });

  it('pushes each image by digest, untagged and as OCI, to its own repository', () => {
    expect(definition.target['app']!.output).toEqual([
      'type=image,name=ghcr.io/hiprax/hvault-app,oci-mediatypes=true,push-by-digest=true,name-canonical=true,push=true',
    ]);
    for (const image of PUBLISHED_IMAGES) {
      const [output] = definition.target[image.key]!.output;
      // No `:tag` in the name: nothing can pull it by name until the index is tagged.
      expect(output).toContain(`name=ghcr.io/hiprax/${image.name},`);
      expect(output).not.toMatch(/name=[^,]*:[^,]*,/);
      expect(output).not.toContain('registry.insecure');
    }
    const local = bakeDefinition({
      context: '/repo',
      platform: 'linux/amd64',
      ...RELEASE,
      registry: '127.0.0.1:5555/test',
      insecureRegistry: true,
    });
    expect(local.target['web']!.output[0]).toBe(
      'type=image,name=127.0.0.1:5555/test/hvault-web,oci-mediatypes=true,push-by-digest=true,name-canonical=true,push=true,registry.insecure=true',
    );
  });

  it('labels each image with the release it belongs to', () => {
    expect(definition.target['web']!.labels).toEqual({
      'org.opencontainers.image.title': 'hvault-web',
      'org.opencontainers.image.description': WEB!.description,
      'org.opencontainers.image.source': 'https://github.com/Hiprax/h-vault',
      'org.opencontainers.image.url': 'https://github.com/Hiprax/h-vault',
      'org.opencontainers.image.version': '0.20.0',
      'org.opencontainers.image.revision': REVISION,
      'org.opencontainers.image.created': CREATED,
      'org.opencontainers.image.licenses': 'MIT',
    });
    // GHCR shows at most 512 characters of a description.
    for (const image of PUBLISHED_IMAGES) expect(image.description.length).toBeLessThanOrEqual(512);
  });

  it('runs the bake on the named builder with BuildKit attestations off', () => {
    expect(
      bakeArgs({ file: '/tmp/b.json', metadataFile: '/tmp/m.json', builder: 'hvault-release' }),
    ).toEqual([
      'buildx',
      'bake',
      '--builder',
      'hvault-release',
      '--file',
      '/tmp/b.json',
      '--metadata-file',
      '/tmp/m.json',
      '--provenance=false',
      '--sbom=false',
      '--progress=plain',
      'default',
    ]);
  });

  it('reads one digest per image from the bake metadata, and refuses a missing or malformed one', () => {
    const metadata = {
      app: { 'containerimage.digest': digest(1), 'image.name': 'ghcr.io/hiprax/hvault-app' },
      web: { 'containerimage.digest': digest(2) },
      bootstrap: { 'containerimage.digest': digest(3) },
      'buildx.build.warnings': [],
    };
    expect(digestsFromMetadata(metadata)).toEqual({
      app: digest(1),
      web: digest(2),
      bootstrap: digest(3),
    });
    const { web: _web, ...noWeb } = metadata;
    expect(() => digestsFromMetadata(noWeb)).toThrow(
      /^the bake's web digest is not a sha256 digest/,
    );
    expect(() =>
      digestsFromMetadata({ ...metadata, bootstrap: { 'containerimage.digest': 'sha256:bad' } }),
    ).toThrow(/^the bake's bootstrap digest/);
  });

  it('gives the pulled-back images a tag no release uses, per platform', () => {
    expect(smokeTag('0.20.0', 'linux/arm64')).toBe('0.20.0-release-smoke-arm64');
    expect(smokeTag('0.20.0', 'linux/amd64')).toBe('0.20.0-release-smoke-amd64');
    expect(smokeTag('0.20.0', 'linux/amd64')).toMatch(/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/);
  });

  it('finds the content-hashed script the SPA shell names, and nothing else', () => {
    const html =
      '<script nonce="n" type="module" crossorigin src="/assets/index-0000aaaa.js"></script>' +
      '<link rel="stylesheet" href="/assets/index-0000bbbb.css">';
    expect(shellScriptPath(html)).toBe('/assets/index-0000aaaa.js');
    expect(shellScriptPath('<script src="/sandbox-assets/frame-0000.js"></script>')).toBeNull();
    expect(shellScriptPath('<html></html>')).toBeNull();
    expect(shellScriptPath('')).toBeNull();
  });
});

describe('the index each image is published as', () => {
  const digests = { 'linux/amd64': digest(1), 'linux/arm64': digest(2) };

  it('joins both platform digests under the release tag, annotated with the release', () => {
    const args = imagetoolsCreateArgs({ image: APP!, ...RELEASE, digests });
    expect(args.slice(0, 5)).toEqual([
      'buildx',
      'imagetools',
      'create',
      '--tag',
      'ghcr.io/hiprax/hvault-app:0.20.0',
    ]);
    expect(args.slice(-2)).toEqual([
      `ghcr.io/hiprax/hvault-app@${digest(1)}`,
      `ghcr.io/hiprax/hvault-app@${digest(2)}`,
    ]);
    const annotations = args.slice(5, -2);
    expect(annotations).toEqual(
      Object.entries(ociMetadata(APP!, RELEASE)).flatMap(([key, value]) => [
        '--annotation',
        `index:${key}=${value}`,
      ]),
    );
    expect(annotations).toContain(
      'index:org.opencontainers.image.source=https://github.com/Hiprax/h-vault',
    );
  });

  it('refuses to join a platform it has no valid digest for', () => {
    expect(() =>
      imagetoolsCreateArgs({ image: WEB!, ...RELEASE, digests: { 'linux/amd64': digest(1) } }),
    ).toThrow(/^hvault-web linux\/arm64 is not a sha256 digest/);
  });

  const entry = (platform: string, n: number) => {
    const [os, architecture] = platform.split('/');
    return {
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: digest(n),
      size: 1,
      platform: { os, architecture },
    };
  };
  const index = (manifests: object[], annotations: Record<string, string> = {}) =>
    JSON.stringify({ schemaVersion: 2, mediaType: OCI_INDEX, manifests, annotations });

  it('accepts an OCI index of exactly the two platforms, with the expected images and annotations', () => {
    const annotations = ociMetadata(APP!, RELEASE);
    const raw = index([entry('linux/amd64', 1), entry('linux/arm64', 2)], annotations);
    expect(indexProblems(raw, { expected: digests, annotations })).toEqual([]);
  });

  it('refuses a Docker manifest list, which drops the annotations', () => {
    const raw = JSON.stringify({
      mediaType: 'application/vnd.docker.distribution.manifest.list.v2+json',
      manifests: [entry('linux/amd64', 1), entry('linux/arm64', 2)],
    });
    expect(indexProblems(raw)).toEqual([
      'the manifest is application/vnd.docker.distribution.manifest.list.v2+json, not an OCI image index',
    ]);
  });

  it('refuses an index missing a platform, holding one twice, or holding anything else', () => {
    expect(indexProblems(index([entry('linux/amd64', 1)]))).toEqual([
      'the index has no linux/arm64 image',
    ]);
    expect(
      indexProblems(
        index([entry('linux/amd64', 1), entry('linux/amd64', 3), entry('linux/arm64', 2)]),
      ),
    ).toEqual(['the index has 2 linux/amd64 images']);
    // An attestation manifest is what BuildKit's own provenance would add.
    expect(
      indexProblems(
        index([entry('linux/amd64', 1), entry('linux/arm64', 2), entry('unknown/unknown', 4)]),
      ),
    ).toEqual(['the index holds an entry for unknown/unknown, which the release does not build']);
    expect(indexProblems(index([]))).toEqual([
      'the index has no linux/amd64 image',
      'the index has no linux/arm64 image',
    ]);
  });

  it('refuses an index whose platform image is not the one this release built', () => {
    const raw = index([entry('linux/amd64', 1), entry('linux/arm64', 9)]);
    expect(indexProblems(raw, { expected: digests })).toEqual([
      `the linux/arm64 image is ${digest(9)}, not ${digest(2)}, the one this release built`,
    ]);
  });

  it('refuses a missing or different annotation', () => {
    const raw = index([entry('linux/amd64', 1), entry('linux/arm64', 2)], {
      'org.opencontainers.image.version': '0.19.0',
    });
    expect(
      indexProblems(raw, {
        annotations: {
          'org.opencontainers.image.version': '0.20.0',
          'org.opencontainers.image.licenses': 'MIT',
        },
      }),
    ).toEqual([
      'annotation org.opencontainers.image.version is "0.19.0", expected "0.20.0"',
      'annotation org.opencontainers.image.licenses is undefined, expected "MIT"',
    ]);
  });

  it('refuses a manifest that is not JSON', () => {
    expect(indexProblems('<html>')).toEqual(['the manifest is not JSON']);
  });

  it('hashes the exact stored bytes', () => {
    // The empty string's SHA-256, a published constant.
    expect(sha256Digest(Buffer.from(''))).toBe(
      'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(sha256Digest(Buffer.from('a'))).not.toBe(sha256Digest(Buffer.from('a\n')));
  });
});

describe('what an anonymous client can pull', () => {
  const manifest = JSON.stringify({
    schemaVersion: 2,
    mediaType: OCI_INDEX,
    manifests: [
      { digest: digest(1), platform: { os: 'linux', architecture: 'amd64' } },
      { digest: digest(2), platform: { os: 'linux', architecture: 'arm64' } },
    ],
  });
  const manifestDigest = sha256Digest(Buffer.from(manifest));

  interface Call {
    url: string;
    headers: Record<string, string>;
  }
  /** A registry that answers from a table, recording every request it was sent. */
  function registry(
    routes: Record<string, { status: number; body?: string; headers?: Record<string, string> }>,
  ) {
    const calls: Call[] = [];
    const fetchImpl = async (url: string, init: { headers: Record<string, string> }) => {
      calls.push({ url, headers: init.headers });
      const route = Object.entries(routes).find(([prefix]) => url.startsWith(prefix))?.[1];
      if (!route) throw new Error(`unexpected request: ${url}`);
      const body = Buffer.from(route.body ?? '');
      return {
        status: route.status,
        headers: { get: (name: string) => route.headers?.[name.toLowerCase()] ?? null },
        json: () => Promise.resolve(JSON.parse(body.toString('utf8')) as unknown),
        arrayBuffer: () =>
          Promise.resolve(body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)),
      };
    };
    return { calls, fetchImpl };
  }
  const TOKEN = 'https://ghcr.io/token?';
  const MANIFEST = 'https://ghcr.io/v2/hiprax/hvault-app/manifests/0.20.0';
  const publicRoutes = {
    [TOKEN]: { status: 200, body: JSON.stringify({ token: 'anonymous-pull' }) },
    [MANIFEST]: {
      status: 200,
      body: manifest,
      headers: { 'docker-content-digest': manifestDigest },
    },
  };

  it('passes a public tag that resolves to the expected index, asking exactly as docker pull would', async () => {
    const { calls, fetchImpl } = registry(publicRoutes);
    await expect(
      publicImageProblems({
        image: APP!,
        version: '0.20.0',
        expectedIndex: manifestDigest,
        fetchImpl,
      }),
    ).resolves.toEqual([]);
    expect(calls.map((call) => call.url)).toEqual([
      'https://ghcr.io/token?scope=repository%3Ahiprax%2Fhvault-app%3Apull&service=ghcr.io',
      MANIFEST,
    ]);
    expect(calls[0]!.headers).toEqual({});
    expect(calls[1]!.headers).toEqual({
      Accept: OCI_INDEX,
      Authorization: 'Bearer anonymous-pull',
    });
  });

  it('names the package settings page when the package is still private, and asks for nothing more', async () => {
    const { calls, fetchImpl } = registry({ [TOKEN]: { status: 403, body: '{}' } });
    const problems = await publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl });
    expect(problems).toEqual([
      'ghcr.io/hiprax/hvault-app:0.20.0: an anonymous pull is refused (the token endpoint answered 403). ' +
        'If the package is still private, make it public: https://github.com/users/Hiprax/packages/container/hvault-app/settings',
    ]);
    expect(calls).toHaveLength(1);
  });

  it('refuses a token answer without a token, and a manifest refused to the anonymous client', async () => {
    const empty = registry({ [TOKEN]: { status: 200, body: '{}' } });
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl: empty.fetchImpl }),
    ).resolves.toEqual([
      'ghcr.io/hiprax/hvault-app:0.20.0: the token endpoint answered without a token',
    ]);
    const refused = registry({ ...publicRoutes, [MANIFEST]: { status: 401, body: '' } });
    const problems = await publicImageProblems({
      image: APP!,
      version: '0.20.0',
      fetchImpl: refused.fetchImpl,
    });
    expect(problems).toEqual([
      `ghcr.io/hiprax/hvault-app:0.20.0: the manifest is refused to an anonymous client (401); make the package public: ${packageSettingsUrl('hvault-app')}`,
    ]);
  });

  it('reports a missing tag, and any other registry answer, by status', async () => {
    const missing = registry({ ...publicRoutes, [MANIFEST]: { status: 404 } });
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl: missing.fetchImpl }),
    ).resolves.toEqual(['ghcr.io/hiprax/hvault-app:0.20.0: no such tag']);
    const broken = registry({ ...publicRoutes, [MANIFEST]: { status: 502 } });
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl: broken.fetchImpl }),
    ).resolves.toEqual([
      'ghcr.io/hiprax/hvault-app:0.20.0: the registry answered 502 for the manifest',
    ]);
  });

  it('refuses a tag that resolves to another index than the one this run published', async () => {
    const { fetchImpl } = registry(publicRoutes);
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', expectedIndex: digest(7), fetchImpl }),
    ).resolves.toEqual([
      `ghcr.io/hiprax/hvault-app:0.20.0 is ${manifestDigest}, not ${digest(7)}, the index this run published`,
    ]);
  });

  it('refuses bytes that do not hash to the digest the registry announced', async () => {
    const { fetchImpl } = registry({
      ...publicRoutes,
      [MANIFEST]: { status: 200, body: manifest, headers: { 'docker-content-digest': digest(5) } },
    });
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl }),
    ).resolves.toEqual([
      `ghcr.io/hiprax/hvault-app:0.20.0: the registry announced ${digest(5)}, but the bytes hash to ${manifestDigest}`,
    ]);
  });

  it('refuses a public tag that is missing a platform', async () => {
    const amd64Only = JSON.stringify({
      mediaType: OCI_INDEX,
      manifests: [{ digest: digest(1), platform: { os: 'linux', architecture: 'amd64' } }],
    });
    const { fetchImpl } = registry({
      ...publicRoutes,
      [MANIFEST]: { status: 200, body: amd64Only },
    });
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl }),
    ).resolves.toEqual(['ghcr.io/hiprax/hvault-app:0.20.0: the index has no linux/arm64 image']);
  });

  it('turns a request that fails outright into a problem rather than a crash', async () => {
    const fetchImpl = () => Promise.reject(new Error('getaddrinfo ENOTFOUND ghcr.io'));
    await expect(
      publicImageProblems({ image: APP!, version: '0.20.0', fetchImpl }),
    ).resolves.toEqual([
      'ghcr.io/hiprax/hvault-app:0.20.0: could not ask for an anonymous pull token: getaddrinfo ENOTFOUND ghcr.io',
    ]);
  });

  it('asks a plain-HTTP test registry directly, with no token', async () => {
    const { calls, fetchImpl } = registry({
      'http://127.0.0.1:5555/v2/test/hvault-bootstrap/manifests/0.20.0': {
        status: 200,
        body: manifest,
      },
    });
    await expect(
      publicImageProblems({
        image: BOOTSTRAP!,
        version: '0.20.0',
        registry: '127.0.0.1:5555/test',
        insecure: true,
        fetchImpl,
      }),
    ).resolves.toEqual([]);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.headers).toEqual({ Accept: OCI_INDEX });
  });
});

describe('step outputs', () => {
  it('writes one name=value line per output', () => {
    expect(githubOutputLines({ app: digest(1), stage: 'false' })).toBe(
      `app=${digest(1)}\nstage=false\n`,
    );
    expect(githubOutputLines({})).toBe('');
  });

  it('refuses a value that could smuggle in a second output, and a malformed name', () => {
    expect(() => githubOutputLines({ app: `${digest(1)}\npublish=true` })).toThrow(
      /the app output contains a line break/,
    );
    expect(() => githubOutputLines({ app: 'x\r' })).toThrow(/line break/);
    expect(() => githubOutputLines({ 'Bad-Name': 'x' })).toThrow(/not an output name: Bad-Name/);
  });
});

describe('the container scan both the docker gate and the release run', () => {
  it('pins the scanner by digest and never lets it decide the verdict itself', () => {
    expect(TRIVY_IMAGE).toMatch(/^aquasec\/trivy:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
    expect(TRIVY_SCAN_ARGS).toEqual([
      'image',
      '--severity',
      'CRITICAL,HIGH',
      '--ignore-unfixed',
      '--exit-code',
      '0',
      '--scanners',
      'vuln',
      '--format',
      'json',
      '--timeout',
      '15m',
    ]);
  });

  it('reads the baseline, and refuses a file that would accept nothing or everything by accident', () => {
    expect(parseBaseline('{"findings": []}')).toEqual([]);
    expect(() => parseBaseline('{"findings": {}}')).toThrow('`findings` must be an array');
    expect(() => parseBaseline('{}')).toThrow('`findings` must be an array');
    expect(() => parseBaseline('null')).toThrow('`findings` must be an array');
    expect(() => parseBaseline('not json')).toThrow();
  });

  const entry = {
    id: 'CVE-2099-0001',
    image: 'hvault-app',
    package: 'undici',
    pathPrefix: 'usr/local/lib/node_modules/npm/',
  };
  const finding = {
    id: 'CVE-2099-0001',
    pkg: 'undici',
    path: 'usr/local/lib/node_modules/npm/node_modules/undici/package.json',
  };

  it('accepts a finding only when the CVE, image, package and path all match one entry', () => {
    expect(acceptedBy([entry], finding, 'hvault-app')).toBe(entry);
    expect(acceptedBy([entry], { ...finding, id: 'CVE-2099-0002' }, 'hvault-app')).toBeUndefined();
    expect(acceptedBy([entry], finding, 'hvault-web')).toBeUndefined();
    expect(acceptedBy([entry], { ...finding, pkg: 'undici-types' }, 'hvault-app')).toBeUndefined();
    // The same CVE in the application's own tree is never excused by an entry
    // reviewed for npm's bundled copy.
    expect(
      acceptedBy(
        [entry],
        { ...finding, path: 'app/node_modules/undici/package.json' },
        'hvault-app',
      ),
    ).toBeUndefined();
  });

  it('flattens a report, keeping where each package lives', () => {
    const report = {
      Results: [
        {
          Target: 'app/package-lock.json',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2099-0001',
              PkgName: 'undici',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              PkgPath: 'app/node_modules/undici',
              Title: 't',
            },
            {
              VulnerabilityID: 'CVE-2099-0003',
              PkgName: 'zlib',
              InstalledVersion: '2',
              Severity: 'CRITICAL',
            },
          ],
        },
        { Target: 'alpine 3.23' },
      ],
    };
    expect(extractFindings(report)).toEqual([
      {
        id: 'CVE-2099-0001',
        pkg: 'undici',
        installed: '1.0.0',
        fixed: '1.0.1',
        severity: 'HIGH',
        path: 'app/node_modules/undici',
        title: 't',
      },
      // No PkgPath: the scan unit it was found through, never nothing.
      {
        id: 'CVE-2099-0003',
        pkg: 'zlib',
        installed: '2',
        fixed: '',
        severity: 'CRITICAL',
        path: 'app/package-lock.json',
        title: '',
      },
    ]);
    expect(extractFindings({})).toEqual([]);
  });

  it('splits findings into the accepted and the rest', () => {
    const other = {
      ...finding,
      id: 'CVE-2099-0009',
      installed: '',
      fixed: '',
      severity: 'HIGH',
      title: '',
    };
    const full = { ...finding, installed: '', fixed: '', severity: 'HIGH', title: '' };
    expect(judgeFindings([full, other], [entry], 'hvault-app')).toEqual({
      accepted: [{ finding: full, entry }],
      unresolved: [other],
    });
    expect(judgeFindings([full], [], 'hvault-app')).toEqual({ accepted: [], unresolved: [full] });
  });
});

describe('how the release run calls docker', () => {
  it('hands the scanner a read-only tarball and nothing else: no socket, no environment, no privilege', () => {
    const args = trivyRunArgs({
      workspace: '/tmp/w',
      tarball: 'hvault-app.tar',
      cacheVolume: 'cache',
    });
    expect(args).toEqual([
      'run',
      '--rm',
      '-v',
      '/tmp/w:/scan:ro',
      '-v',
      'cache:/root/.cache',
      TRIVY_IMAGE,
      ...TRIVY_SCAN_ARGS,
      '--input',
      '/scan/hvault-app.tar',
    ]);
    const joined = args.join(' ');
    expect(joined).not.toContain('docker.sock');
    expect(joined).not.toMatch(/(?:^|\s)(?:-e|--env|--env-file|--privileged|--network)(?:\s|=|$)/);
    expect(joined).not.toMatch(/\.docker\b/);
  });

  it('refuses a scan target that could reach outside the workspace', () => {
    for (const tarball of ['../etc.tar', 'a/b.tar', 'hvault-app', 'HVAULT.tar', '']) {
      expect(
        () => trivyRunArgs({ workspace: '/tmp/w', tarball, cacheVolume: 'c' }),
        tarball,
      ).toThrow(/not a tarball name/);
    }
    expect(() =>
      trivyRunArgs({ workspace: 'relative', tarball: 'a.tar', cacheVolume: 'c' }),
    ).toThrow(/must be absolute/);
  });

  it('pulls every image-only service before a start that may pull nothing, the storage engine today', () => {
    // `--pull never` applies to EVERY service, so an image the smoke test did not
    // pull back (and cannot build) would be missing on a fresh runner.
    const compose = parse(readFileSync(path.join(repoRoot, 'docker-compose.yml'), 'utf8'), {
      merge: true,
    }) as { services: Record<string, { image?: string; build?: unknown }> };
    expect(pullOnlyServices(compose)).toEqual(['hvault-s3']);
    expect(
      pullOnlyServices({
        services: {
          built: { image: 'x:1', build: { context: '.' } },
          pulled: { image: 'y:1' },
          another: { image: 'z:1' },
          nothing: {},
          gone: null,
        },
      }),
    ).toEqual(['another', 'pulled']);
    expect(pullOnlyServices({})).toEqual([]);
  });

  it('starts the smoke stack neither building nor pulling anything', () => {
    expect(smokeUpArgs(300)).toEqual([
      'up',
      '-d',
      '--wait',
      '--wait-timeout',
      '300',
      '--no-build',
      '--pull',
      'never',
    ]);
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      expect(() => smokeUpArgs(bad), String(bad)).toThrow(/not a wait timeout/);
    }
  });

  it('reads git only as tagged or untagged, and refuses to guess when git itself failed', () => {
    expect(releaseTagState(0)).toBe('tagged');
    expect(releaseTagState(1)).toBe('untagged');
    // 128 is git's own failure (not a repository, a broken ref store): reading it as
    // "untagged" would let a released version's images be replaced.
    expect(() => releaseTagState(128)).toThrow(
      'git could not say whether the release is tagged (exit 128)',
    );
    expect(() => releaseTagState(127)).toThrow(/exit 127/);
  });

  it('refuses a scan that examined nothing, rather than reading it as clean', () => {
    const alpine = { Metadata: { OS: { Family: 'alpine', Name: '3.23.4' } } };
    expect(scanCoverageProblem({ ...alpine, Results: [{ Target: 'alpine 3.23' }] })).toBeNull();
    for (const report of [
      { ...alpine },
      { ...alpine, Results: [] },
      { ...alpine, Results: null },
    ]) {
      expect(scanCoverageProblem(report as never), JSON.stringify(report)).toBe(
        'the scan reported no results at all, so it examined nothing',
      );
    }
    // No operating system identified: whatever was scanned, it was not one of the images.
    for (const report of [
      {},
      null,
      { Results: [{ Target: 'x' }] },
      { Metadata: { OS: {} }, Results: [{}] },
    ]) {
      expect(scanCoverageProblem(report as never), JSON.stringify(report)).toBe(
        'the scan identified no operating system, so it did not examine an image',
      );
    }
  });

  it('attests only an index whose stored bytes hash to the digest buildx reports', () => {
    const raw =
      '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}';
    const digest = sha256Digest(Buffer.from(raw));
    expect(confirmedIndexDigest(raw, { digest })).toBe(digest);
    // One byte more (a newline that is not part of the stored manifest) is another digest.
    expect(() => confirmedIndexDigest(`${raw}\n`, { digest })).toThrow(
      `the stored index hashes to ${sha256Digest(Buffer.from(`${raw}\n`))}, but buildx reports ${digest}`,
    );
    expect(() => confirmedIndexDigest(raw, {})).toThrow(
      /^the index digest buildx reported is not a sha256 digest/,
    );
    expect(() => confirmedIndexDigest(raw, null)).toThrow(/not a sha256 digest/);
  });
});

describe("the release job's own decision against the plan's", () => {
  const plan = { version: '0.20.0', shouldRelease: true, createTag: true };

  it('goes on when nothing changed, and on the retry after an attempt that pushed the tag', () => {
    expect(decisionChangeProblem(plan, plan)).toBeNull();
    // "Re-run failed jobs": the plan still says create, the tag now exists.
    expect(decisionChangeProblem(plan, { ...plan, createTag: false })).toBeNull();
    const healOnTag = { version: '0.20.0', shouldRelease: true, createTag: false };
    expect(decisionChangeProblem(healOnTag, healOnTag)).toBeNull();
    const nothing = { version: '0.20.0', shouldRelease: false, createTag: false };
    expect(decisionChangeProblem(nothing, nothing)).toBeNull();
  });

  it('stops on a changed version, a changed release decision, or a vanished tag', () => {
    expect(decisionChangeProblem(plan, { ...plan, version: '0.20.1' })).toBe(
      'the version changed since the plan: planned 0.20.0, now 0.20.1',
    );
    expect(decisionChangeProblem(plan, { ...plan, shouldRelease: false })).toBe(
      'whether this commit is a release changed since the plan: planned true, now false',
    );
    expect(decisionChangeProblem({ ...plan, createTag: false }, plan)).toBe(
      'the release tag the plan found for 0.20.0 has vanished',
    );
  });
});

describe('a heal run, which publishes nothing itself, still pins the commit', () => {
  const annotated = (annotations: Record<string, string>) =>
    JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [
        { digest: digest(1), platform: { os: 'linux', architecture: 'amd64' } },
        { digest: digest(2), platform: { os: 'linux', architecture: 'arm64' } },
      ],
      annotations,
    });
  const expectedAnnotations = {
    'org.opencontainers.image.version': '0.20.0',
    'org.opencontainers.image.revision': REVISION,
  };
  const registryAnswering = (body: string) => async (url: string) => {
    const bytes = Buffer.from(url.includes('/token?') ? JSON.stringify({ token: 't' }) : body);
    return {
      status: 200,
      headers: { get: () => null },
      json: () => Promise.resolve(JSON.parse(bytes.toString('utf8')) as unknown),
      arrayBuffer: () =>
        Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)),
    };
  };

  it('accepts images annotated with this version and this commit', async () => {
    await expect(
      publicImageProblems({
        image: APP!,
        version: '0.20.0',
        expectedAnnotations,
        fetchImpl: registryAnswering(annotated(expectedAnnotations)),
      }),
    ).resolves.toEqual([]);
  });

  it('refuses images built from another commit, or carrying no provenance annotations', async () => {
    const other = { ...expectedAnnotations, 'org.opencontainers.image.revision': 'f'.repeat(40) };
    await expect(
      publicImageProblems({
        image: APP!,
        version: '0.20.0',
        expectedAnnotations,
        fetchImpl: registryAnswering(annotated(other)),
      }),
    ).resolves.toEqual([
      `ghcr.io/hiprax/hvault-app:0.20.0: annotation org.opencontainers.image.revision is "${'f'.repeat(40)}", expected "${REVISION}"`,
    ]);
    const bare = await publicImageProblems({
      image: APP!,
      version: '0.20.0',
      expectedAnnotations,
      fetchImpl: registryAnswering(annotated({})),
    });
    expect(bare).toHaveLength(2);
  });

  it('names the settings page of the repository owner', () => {
    expect(packageSettingsUrl('hvault-web')).toBe(
      'https://github.com/users/Hiprax/packages/container/hvault-web/settings',
    );
  });
});
