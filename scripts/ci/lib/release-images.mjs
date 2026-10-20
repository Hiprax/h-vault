/**
 * The release images' decisions, separated from the docker commands.
 *
 * `scripts/ci/release-images.mjs` runs the commands, for the release workflow
 * (`.github/workflows/release.yml`); this file decides what they are and judges
 * what came back. Everything here is pure (the one exception, the anonymous
 * registry check, takes its `fetch` as a parameter), which is what lets
 * `packages/server/tests/release-images.test.ts` exercise every refusal without a
 * registry, a runner or a second architecture.
 *
 * The life of a release image, and which function owns each step:
 *
 *   1. each platform's runner builds the three images in ONE bake and pushes
 *      them by digest, untagged (`bakeDefinition`, `bakeArgs`,
 *      `digestsFromMetadata`);
 *   2. after BOTH platforms passed their scan and smoke test, one index per
 *      image is created and tagged with the release version
 *      (`imagetoolsCreateArgs`, then `indexProblems` on what was written);
 *   3. before the release is tagged in git, an ANONYMOUS client must be able to
 *      pull every tag, resolving to exactly the index step 2 wrote
 *      (`publicImageProblems`).
 */
import { createHash } from 'node:crypto';
import path from 'node:path';
import {
  IMAGE_DOCKERFILE,
  IMAGE_REGISTRY,
  PUBLISHED_IMAGES,
  RELEASE_PLATFORMS,
  SOURCE_REPOSITORY,
  imageRepository,
} from './images.mjs';
import { TRIVY_IMAGE, TRIVY_SCAN_ARGS } from './trivy.mjs';

const OCI_INDEX = 'application/vnd.oci.image.index.v1+json';
/** How long one registry request may take before the check gives up on it. */
export const REGISTRY_REQUEST_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Inputs. Every value the workflow hands the CLI is validated before it is used,
// because a malformed one would otherwise surface as a confusing docker error
// halfway through a release, or not at all.
// ---------------------------------------------------------------------------

/** @param {unknown} value */
export function parseVersion(value) {
  const text = String(value ?? '');
  if (!/^\d+\.\d+\.\d+$/.test(text)) throw new Error(`not a release version (X.Y.Z): ${text}`);
  return text;
}

/** @param {unknown} value @param {string} label */
export function parseDigest(value, label) {
  const text = String(value ?? '');
  if (!/^sha256:[0-9a-f]{64}$/.test(text)) {
    throw new Error(`${label} is not a sha256 digest: ${JSON.stringify(text)}`);
  }
  return text;
}

/** @param {unknown} value */
export function parseRevision(value) {
  const text = String(value ?? '');
  if (!/^[0-9a-f]{40}$/.test(text))
    throw new Error(`not a full commit id: ${JSON.stringify(text)}`);
  return text;
}

/** An RFC 3339 UTC timestamp to the second, the form OCI's `created` asks for. */
export function parseCreated(value) {
  const text = String(value ?? '');
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(text)) {
    throw new Error(`not a UTC timestamp (YYYY-MM-DDTHH:MM:SSZ): ${JSON.stringify(text)}`);
  }
  return text;
}

/** @param {unknown} value */
export function parsePlatform(value) {
  const text = String(value ?? '');
  if (!RELEASE_PLATFORMS.includes(text)) {
    throw new Error(`not a release platform (${RELEASE_PLATFORMS.join(', ')}): ${text}`);
  }
  return text;
}

/**
 * Exactly `true` or `false`.
 *
 * A workflow expression that compares a boolean input with the STRING 'true' is
 * always false (GitHub converts both sides to numbers: 1 and NaN), so a mistake
 * there silently turns a rehearsal into a run that builds nothing and still
 * passes. Every flag therefore crosses into a script as one of these two words,
 * and anything else is refused rather than read as false.
 *
 * @param {unknown} value @param {string} label
 */
export function parseFlag(value, label) {
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new Error(`${label} must be exactly "true" or "false", got: ${JSON.stringify(value)}`);
}

/**
 * The digests one platform's job produced, as the workflow hands them over: the
 * job's `outputs` object, serialised with `toJSON`. Exactly one valid digest per
 * published image, and nothing else.
 *
 * @param {string} json @param {string} label
 * @returns {Record<string, string>} digest by image key
 */
export function parseLegDigests(json, label) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`${label} is not JSON: ${String(json).slice(0, 200)}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${label} is not an object of digests`);
  }
  const expected = PUBLISHED_IMAGES.map((image) => image.key).sort();
  const actual = Object.keys(parsed).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `${label} names ${actual.join(', ') || 'nothing'}, expected ${expected.join(', ')}`,
    );
  }
  return Object.fromEntries(
    PUBLISHED_IMAGES.map((image) => [
      image.key,
      parseDigest(parsed[image.key], `${label} ${image.key}`),
    ]),
  );
}

// ---------------------------------------------------------------------------
// 0. Plan: does this run build images, and may it publish them?
// ---------------------------------------------------------------------------

/**
 * What the image jobs do on this run.
 *
 * - `publish`: a release is due, its tag does not exist yet, this is `main`, and
 *   the run is not a staging rehearsal. Only then are images tagged, attested
 *   and checked, and only then may the release job tag git.
 * - `build`: `publish`, or a staging rehearsal (`stage_images`): build, scan and
 *   smoke-test both platforms and push by digest only, from any branch.
 *
 * Three refusals are the point:
 *
 * - a re-run on a commit that is ALREADY tagged builds nothing, because a
 *   rebuild is not byte-identical (`apk upgrade` runs at build time) and the
 *   published tag must never move onto new bytes after the Release is out;
 * - a dispatch from any branch other than `main` never publishes, whatever its
 *   version says;
 * - a rehearsal never publishes, even on `main` with a release due.
 *
 * @param {{ shouldRelease: boolean, createTag: boolean, stage: boolean, ref: string }} facts
 */
export function planImages({ shouldRelease, createTag, stage, ref }) {
  const publish = shouldRelease && createTag && ref === 'refs/heads/main' && !stage;
  return { stage, build: publish || stage, publish };
}

// ---------------------------------------------------------------------------
// 1. Build, per platform
// ---------------------------------------------------------------------------

/**
 * The OCI metadata every published image carries, as image labels and again as
 * index annotations (GHCR reads `source`, `description` and `licenses` off the
 * index to fill in the package page).
 *
 * @param {{ name: string, description: string }} image
 * @param {{ version: string, revision: string, created: string }} release
 */
export function ociMetadata(image, { version, revision, created }) {
  const url = `https://github.com/${SOURCE_REPOSITORY}`;
  return {
    'org.opencontainers.image.title': image.name,
    'org.opencontainers.image.description': image.description,
    'org.opencontainers.image.source': url,
    'org.opencontainers.image.url': url,
    'org.opencontainers.image.version': version,
    'org.opencontainers.image.revision': revision,
    'org.opencontainers.image.created': created,
    'org.opencontainers.image.licenses': 'MIT',
  };
}

/**
 * One bake of all three images for ONE platform, pushed by digest and untagged.
 *
 * One bake rather than three builds is load-bearing. `app` serves the
 * index.html that references the content-hashed assets `web` serves, so the two
 * must come from the SAME client build. In a single bake the three targets are
 * one solve, and BuildKit runs a stage they share once; that holds while they
 * share context, Dockerfile, platform and build arguments, which is why nothing
 * here varies per target except the stage and its metadata. The release smoke
 * test then proves it on the result: an asset the app's page names must be
 * served by the web image.
 *
 * `oci-mediatypes=true` because `imagetools create` writes annotations only into
 * an OCI index and silently drops them otherwise. The images are pushed by
 * digest with no tag: nothing can pull them by name until both platforms have
 * passed and step 2 tags the index.
 *
 * @typedef {{ context: string, dockerfile: string, target: string, platforms: string[],
 *   labels: Record<string, string>, output: string[] }} BakeTarget
 * @param {{ context: string, platform: string, version: string, revision: string,
 *   created: string, registry?: string, insecureRegistry?: boolean }} options
 * @returns {{ group: { default: { targets: string[] } }, target: Record<string, BakeTarget> }}
 */
export function bakeDefinition({
  context,
  platform,
  version,
  revision,
  created,
  registry = IMAGE_REGISTRY,
  insecureRegistry = false,
}) {
  const release = { version, revision, created };
  /** @type {Record<string, BakeTarget>} */
  const target = {};
  for (const image of PUBLISHED_IMAGES) {
    target[image.key] = {
      context,
      dockerfile: IMAGE_DOCKERFILE,
      target: image.target,
      platforms: [platform],
      labels: ociMetadata(image, release),
      output: [
        [
          'type=image',
          `name=${imageRepository(image.name, registry)}`,
          'oci-mediatypes=true',
          'push-by-digest=true',
          'name-canonical=true',
          'push=true',
          ...(insecureRegistry ? ['registry.insecure=true'] : []),
        ].join(','),
      ],
    };
  }
  return {
    group: { default: { targets: PUBLISHED_IMAGES.map((image) => image.key) } },
    target,
  };
}

/**
 * The bake command. BuildKit's own provenance and SBOM attestations are off:
 * the release attaches a signed provenance attestation of its own to each
 * index, and leaving BuildKit's in would put extra manifests in every index
 * beside the two platform images users pull.
 *
 * @param {{ file: string, metadataFile: string, builder: string }} options
 */
export function bakeArgs({ file, metadataFile, builder }) {
  return [
    'buildx',
    'bake',
    '--builder',
    builder,
    '--file',
    file,
    '--metadata-file',
    metadataFile,
    '--provenance=false',
    '--sbom=false',
    '--progress=plain',
    'default',
  ];
}

/**
 * The digest of each image a bake pushed, from its `--metadata-file`.
 *
 * @param {Record<string, unknown>} metadata
 * @returns {Record<string, string>} digest by image key
 */
export function digestsFromMetadata(metadata) {
  return Object.fromEntries(
    PUBLISHED_IMAGES.map((image) => [
      image.key,
      parseDigest(
        metadata?.[image.key]?.['containerimage.digest'],
        `the bake's ${image.key} digest`,
      ),
    ]),
  );
}

/**
 * The tag a pulled-back image is given for the smoke test.
 *
 * Under the compose file's OWN repository name, whatever registry it was pushed
 * to, because the smoke test runs the real docker-compose.yml, which names
 * `ghcr.io/hiprax/...`. A tag no release will ever use, so the smoke test can
 * never be satisfied by an image that happens to be on the runner already.
 */
export function smokeTag(version, platform) {
  return `${version}-release-smoke-${platform.replace('linux/', '')}`;
}

/**
 * The first content-hashed script the SPA shell names.
 *
 * The app serves the shell and the web image serves `/assets/`, so fetching this
 * through the stack's port is what proves the two images came from one build.
 *
 * @param {string} html
 */
export function shellScriptPath(html) {
  return /<script[^>]+src="(\/assets\/[^"]+\.js)"/.exec(String(html ?? ''))?.[1] ?? null;
}

/**
 * The scan of one saved image, as a `docker run` argument list.
 *
 * The scanner is handed the tarball through a READ-ONLY mount and nothing else:
 * no Docker socket (with one, a compromised scanner image could start a container
 * of its choosing on a host holding a registry credential), no environment, no
 * host network and no privilege. Its cache is a named volume, so the vulnerability
 * database is fetched once per job rather than once per image.
 *
 * @param {{ workspace: string, tarball: string, cacheVolume: string }} options
 */
export function trivyRunArgs({ workspace, tarball, cacheVolume }) {
  if (!/^[a-z0-9][a-z0-9.-]*\.tar$/.test(tarball))
    throw new Error(`not a tarball name: ${tarball}`);
  if (!path.isAbsolute(workspace))
    throw new Error(`the scan workspace must be absolute: ${workspace}`);
  return [
    'run',
    '--rm',
    '-v',
    `${workspace}:/scan:ro`,
    '-v',
    `${cacheVolume}:/root/.cache`,
    TRIVY_IMAGE,
    ...TRIVY_SCAN_ARGS,
    '--input',
    `/scan/${tarball}`,
  ];
}

/**
 * The compose services the smoke test must PULL before it starts the stack:
 * those that name an image and have no `build:` (today, the storage engine).
 *
 * The stack starts with `--pull never`, which Compose applies to EVERY service,
 * so that nothing but the images just pulled back can satisfy the published
 * ones. An image-only service would then be missing on a fresh runner and the
 * start would fail, so each is pulled first, by name.
 *
 * @param {{ services?: Record<string, { image?: string, build?: unknown } | null> }} config
 *   `docker compose config --format json`, or the parsed compose file
 */
export function pullOnlyServices(config) {
  return Object.entries(config?.services ?? {})
    .filter(([, service]) => Boolean(service?.image) && service?.build === undefined)
    .map(([name]) => name)
    .sort();
}

/**
 * How the smoke test starts the stack: wait for health, and neither build nor
 * pull anything, so a missing or wrong image is an error instead of a quiet
 * substitute.
 *
 * @param {number} waitTimeoutSeconds
 */
export function smokeUpArgs(waitTimeoutSeconds) {
  if (!Number.isInteger(waitTimeoutSeconds) || waitTimeoutSeconds <= 0) {
    throw new Error(`not a wait timeout: ${String(waitTimeoutSeconds)}`);
  }
  return [
    'up',
    '-d',
    '--wait',
    '--wait-timeout',
    String(waitTimeoutSeconds),
    '--no-build',
    '--pull',
    'never',
  ];
}

/**
 * Whether git already has a release tag, from `git rev-parse --quiet --verify`'s
 * exit status: 0 found, 1 not found. Anything else means git itself failed, which
 * must not be read as "untagged" and let a released version's images be replaced.
 *
 * @param {number} status
 * @returns {'tagged' | 'untagged'}
 */
export function releaseTagState(status) {
  if (status === 0) return 'tagged';
  if (status === 1) return 'untagged';
  throw new Error(`git could not say whether the release is tagged (exit ${String(status)})`);
}

// ---------------------------------------------------------------------------
// 2. Publish: one index per image, tagged with the release
// ---------------------------------------------------------------------------

/**
 * The `imagetools create` call that joins one image's two platform digests into
 * a tagged index, carrying the metadata as index annotations.
 *
 * @param {{ image: { name: string, description: string }, version: string, revision: string,
 *   created: string, digests: Record<string, string>, registry?: string }} options
 *   `digests` is keyed by platform
 */
export function imagetoolsCreateArgs({
  image,
  version,
  revision,
  created,
  digests,
  registry = IMAGE_REGISTRY,
}) {
  const repository = imageRepository(image.name, registry);
  const annotations = Object.entries(ociMetadata(image, { version, revision, created })).flatMap(
    ([key, value]) => ['--annotation', `index:${key}=${value}`],
  );
  return [
    'buildx',
    'imagetools',
    'create',
    '--tag',
    `${repository}:${version}`,
    ...annotations,
    ...RELEASE_PLATFORMS.map(
      (platform) => `${repository}@${parseDigest(digests[platform], `${image.name} ${platform}`)}`,
    ),
  ];
}

/** `sha256:<hex>` of the exact bytes a registry stored. */
export function sha256Digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

/**
 * Everything wrong with an image index, judged from its raw manifest.
 *
 * It must be an OCI index holding exactly one manifest per release platform
 * and nothing else. With `expected` (digest by platform) each platform must be
 * exactly the image the release built; with `annotations`, each named key must
 * carry exactly that value.
 *
 * @param {string} raw the manifest bytes as text
 * @param {{ expected?: Record<string, string>, annotations?: Record<string, string> }} [options]
 * @returns {string[]}
 */
export function indexProblems(raw, { expected, annotations } = {}) {
  let index;
  try {
    index = JSON.parse(raw);
  } catch {
    return ['the manifest is not JSON'];
  }
  const problems = [];
  if (index?.mediaType !== OCI_INDEX) {
    problems.push(`the manifest is ${String(index?.mediaType)}, not an OCI image index`);
  }
  const manifests = Array.isArray(index?.manifests) ? index.manifests : [];
  const platforms = manifests.map((entry) =>
    entry?.platform ? `${entry.platform.os}/${entry.platform.architecture}` : 'no platform',
  );
  for (const platform of RELEASE_PLATFORMS) {
    const count = platforms.filter((candidate) => candidate === platform).length;
    if (count === 0) problems.push(`the index has no ${platform} image`);
    if (count > 1) problems.push(`the index has ${String(count)} ${platform} images`);
  }
  for (const platform of new Set(platforms)) {
    if (!RELEASE_PLATFORMS.includes(platform)) {
      problems.push(`the index holds an entry for ${platform}, which the release does not build`);
    }
  }
  if (expected) {
    for (const platform of RELEASE_PLATFORMS) {
      const entry = manifests.find(
        (candidate) =>
          candidate?.platform &&
          `${candidate.platform.os}/${candidate.platform.architecture}` === platform,
      );
      if (entry && entry.digest !== expected[platform]) {
        problems.push(
          `the ${platform} image is ${String(entry.digest)}, not ${String(expected[platform])}, the one this release built`,
        );
      }
    }
  }
  for (const [key, value] of Object.entries(annotations ?? {})) {
    if (index?.annotations?.[key] !== value) {
      problems.push(
        `annotation ${key} is ${JSON.stringify(index?.annotations?.[key])}, expected ${JSON.stringify(value)}`,
      );
    }
  }
  return problems;
}

/**
 * The digest of the index `publish` just wrote, confirmed two ways: what buildx
 * reports for the tag (`imagetools inspect --format '{{json .Manifest}}'`), held
 * equal to the sha256 of the exact bytes `imagetools inspect --raw` printed
 * (buildx prints the stored bytes verbatim, adding nothing). A disagreement means
 * the bytes judged are not the bytes stored, so nothing is attested.
 *
 * @param {string} raw @param {{ digest?: unknown } | null} manifest
 */
export function confirmedIndexDigest(raw, manifest) {
  const reported = parseDigest(manifest?.digest, 'the index digest buildx reported');
  const computed = sha256Digest(Buffer.from(raw, 'utf8'));
  if (computed !== reported) {
    throw new Error(`the stored index hashes to ${computed}, but buildx reports ${reported}`);
  }
  return reported;
}

// ---------------------------------------------------------------------------
// 3. Verify: what an anonymous user would get
// ---------------------------------------------------------------------------

/**
 * Where a maintainer makes a package public. One the release workflow creates
 * takes the repository's visibility; one pushed any other way starts private.
 */
export function packageSettingsUrl(name) {
  const owner = SOURCE_REPOSITORY.split('/')[0];
  return `https://github.com/users/${owner}/packages/container/${name}/settings`;
}

/**
 * Everything that stops an anonymous client from pulling one release image,
 * judged the way `docker pull` would meet it: an anonymous pull token, then the
 * tag's manifest.
 *
 * A package pushed by hand, or in a private repository, starts private (one this
 * workflow creates takes the repository's visibility), and a private or missing
 * package refuses the anonymous token (measured: 403, against 200 for a public
 * one). So this is the check that stops a Release from being published
 * while its install instructions cannot work. With `expectedIndex`, the tag must
 * also resolve to exactly the index this run published, so a stale tag left by
 * an earlier run cannot pass for this release.
 *
 * `registry` is `ghcr.io/<namespace>`, or a plain-HTTP test registry (`insecure`),
 * which takes no token.
 *
 * @typedef {{ status: number, headers: { get(name: string): string | null },
 *   json(): Promise<any>, arrayBuffer(): Promise<ArrayBuffer> }} RegistryResponse
 * With `expectedAnnotations`, the index must also carry exactly those
 * annotations: how a run that did NOT publish the images itself (the heal of an
 * interrupted release) still proves they were built from the commit it is about
 * to release, under that version.
 *
 * @param {{ image: { name: string }, version: string, expectedIndex?: string,
 *   expectedAnnotations?: Record<string, string>,
 *   registry?: string, insecure?: boolean,
 *   fetchImpl?: (url: string, init: { headers: Record<string, string>, redirect: 'error',
 *     signal: AbortSignal }) => Promise<RegistryResponse>,
 *   timeoutMs?: number }} options
 * @returns {Promise<string[]>}
 */
export async function publicImageProblems({
  image,
  version,
  expectedIndex,
  expectedAnnotations,
  registry = IMAGE_REGISTRY,
  insecure = false,
  fetchImpl = fetch,
  timeoutMs = REGISTRY_REQUEST_TIMEOUT_MS,
}) {
  const [host, ...rest] = registry.split('/');
  const repository = [...rest, image.name].join('/');
  const reference = `${registry}/${image.name}:${version}`;
  const settings = packageSettingsUrl(image.name);
  const base = `${insecure ? 'http' : 'https'}://${host}`;
  const request = (url, headers = {}) =>
    fetchImpl(url, { headers, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });

  const headers = { Accept: OCI_INDEX };
  if (!insecure) {
    let token;
    try {
      const response = await request(
        `${base}/token?scope=${encodeURIComponent(`repository:${repository}:pull`)}&service=${host}`,
      );
      if (response.status !== 200) {
        return [
          `${reference}: an anonymous pull is refused (the token endpoint answered ${String(response.status)}). ` +
            `If the package is still private, make it public: ${settings}`,
        ];
      }
      token = (await response.json())?.token;
    } catch (error) {
      return [`${reference}: could not ask for an anonymous pull token: ${errorText(error)}`];
    }
    if (typeof token !== 'string' || token.length === 0) {
      return [`${reference}: the token endpoint answered without a token`];
    }
    headers.Authorization = `Bearer ${token}`;
  }

  let response;
  let body;
  try {
    response = await request(`${base}/v2/${repository}/manifests/${version}`, headers);
    body = Buffer.from(await response.arrayBuffer());
  } catch (error) {
    return [`${reference}: could not read the manifest: ${errorText(error)}`];
  }
  if (response.status === 401 || response.status === 403) {
    return [
      `${reference}: the manifest is refused to an anonymous client (${String(response.status)}); make the package public: ${settings}`,
    ];
  }
  if (response.status === 404) return [`${reference}: no such tag`];
  if (response.status !== 200) {
    return [`${reference}: the registry answered ${String(response.status)} for the manifest`];
  }

  const problems = [];
  const digest = sha256Digest(body);
  const announced = response.headers.get('docker-content-digest');
  if (announced && announced !== digest) {
    problems.push(
      `${reference}: the registry announced ${announced}, but the bytes hash to ${digest}`,
    );
  }
  if (expectedIndex && digest !== expectedIndex) {
    problems.push(`${reference} is ${digest}, not ${expectedIndex}, the index this run published`);
  }
  for (const problem of indexProblems(body.toString('utf8'), {
    ...(expectedAnnotations ? { annotations: expectedAnnotations } : {}),
  })) {
    problems.push(`${reference}: ${problem}`);
  }
  return problems;
}

/** @param {unknown} error */
function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Why the release job must not go on because its own release decision differs
 * from the one the `plan` job made before the images were built, or null.
 *
 * Runs are serialised, so the two can only differ if a tag appeared or vanished
 * in between, or if this is a RETRY of the release job alone ("Re-run failed
 * jobs"), whose plan outputs are those of the first attempt:
 *
 * - a different version, or a different answer to "is this a release", means the
 *   images were published (or skipped) for a decision that no longer holds;
 * - planned "create the tag", now "it exists" is the retry after an attempt that
 *   pushed the tag and then failed to publish the Release: allowed, and that is
 *   the heal (its images are still pinned to the digests the plan published);
 * - planned "it exists", now "create the tag" means the tag vanished: refused,
 *   or a tag would be minted on images nobody pinned.
 *
 * @param {{ version: string, shouldRelease: boolean, createTag: boolean }} planned
 * @param {{ version: string, shouldRelease: boolean, createTag: boolean }} own
 */
export function decisionChangeProblem(planned, own) {
  if (planned.version !== own.version) {
    return `the version changed since the plan: planned ${planned.version}, now ${own.version}`;
  }
  if (planned.shouldRelease !== own.shouldRelease) {
    return `whether this commit is a release changed since the plan: planned ${String(planned.shouldRelease)}, now ${String(own.shouldRelease)}`;
  }
  if (!planned.createTag && own.createTag) {
    return `the release tag the plan found for ${own.version} has vanished`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Workflow plumbing
// ---------------------------------------------------------------------------

/**
 * `GITHUB_OUTPUT` lines. A value carrying a newline would let it write a second
 * output of its own choosing, so one is refused rather than escaped.
 *
 * @param {Record<string, string>} outputs
 */
export function githubOutputLines(outputs) {
  return Object.entries(outputs)
    .map(([key, value]) => {
      if (!/^[a-z][a-z0-9_]*$/.test(key)) throw new Error(`not an output name: ${key}`);
      if (/[\r\n]/.test(String(value))) throw new Error(`the ${key} output contains a line break`);
      return `${key}=${String(value)}\n`;
    })
    .join('');
}
