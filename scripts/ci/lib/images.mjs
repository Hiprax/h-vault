/**
 * The images this repository publishes, defined once.
 *
 * Every release pushes these three to the GitHub Container Registry, for both
 * platforms below, from the release workflow (`.github/workflows/release.yml`,
 * through `scripts/ci/release-images.mjs`). `docker-compose.yml` names them, so a
 * server can pull a release instead of compiling it, and keeps a `build:` block
 * for each, so `docker compose up --build` still builds the same images from
 * source. `packages/server/tests/docker-hardening.test.ts` holds the compose file
 * to this list, and the docker gate builds and scans exactly these.
 *
 * Only the three images that COMPILE something are published. `hvault-db`
 * (two scripts on top of the pinned `mongo:8.0`) and the optional non-root
 * `hvault-s3` (a `USER` on top of the pinned Garage image) are built locally from
 * their pinned upstream images, which costs a small server nothing, and keeping
 * them local means this repository never redistributes the MongoDB or Garage
 * binaries.
 */

/**
 * Where the images live. GHCR requires the namespace in lower case, so this is
 * `hiprax`, while the repository itself is `Hiprax/h-vault`.
 */
export const IMAGE_REGISTRY = 'ghcr.io/hiprax';

/** The repository the images are built from, linked from each image's metadata. */
export const SOURCE_REPOSITORY = 'Hiprax/h-vault';

/** The one Dockerfile all three are built from (see the comment at its top). */
export const IMAGE_DOCKERFILE = 'docker/Dockerfile';

/**
 * Both release platforms, each built natively on its own runner: 64-bit x86
 * (most servers) and 64-bit ARM (a Raspberry Pi 5, an ARM VPS).
 */
export const RELEASE_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64']);

/**
 * The published images. `key` names the image in workflow job outputs, `target`
 * is its stage in the Dockerfile, `service` the compose service that runs it.
 */
export const PUBLISHED_IMAGES = Object.freeze([
  Object.freeze({
    key: 'app',
    name: 'hvault-app',
    target: 'app',
    service: 'hvault-app',
    description:
      'H-Vault API server: the zero-knowledge vault backend, which also serves the SPA shell.',
  }),
  Object.freeze({
    key: 'web',
    name: 'hvault-web',
    target: 'web',
    service: 'hvault-nginx',
    description:
      "H-Vault's internal Nginx: the stack's single entry point and the SPA's static assets.",
  }),
  Object.freeze({
    key: 'bootstrap',
    name: 'hvault-bootstrap',
    target: 'bootstrap',
    service: 'hvault-bootstrap',
    description: 'H-Vault one-shot: creates the MongoDB indexes, then exits.',
  }),
]);

/** `ghcr.io/hiprax/hvault-app`, or the same name under another registry (tests). */
export function imageRepository(name, registry = IMAGE_REGISTRY) {
  return `${registry}/${name}`;
}
