# syntax=docker/dockerfile:1
# =============================================================================
# H-Vault — single multi-target image definition
# =============================================================================
# One Dockerfile builds every first-party image in the stack:
#
#   target: app          Express API + the SPA fallback (node, non-root)
#   target: web          Nginx serving the SPA bundle + proxying /api -> app
#   target: bootstrap    One-shot: creates the MongoDB indexes, then exits
#   target: development  Hot-reload image used by docker-compose.dev.yml
#
# Keeping `app` and `web` in ONE Dockerfile is load-bearing, not cosmetic. Both
# consume the client bundle, and they MUST consume the *same* bundle: `app`
# serves `index.html` (Express injects the per-request CSP nonce and helmet's
# security headers into it), while `web` serves the content-hashed `/assets/*`
# that this exact `index.html` references. Two independent builds could emit two
# different sets of asset hashes, and the app would 404 every script it asks for.
# Because both targets `COPY --from=build-client`, BuildKit builds that stage
# once and both images share the identical layer — divergence is impossible.
#
# Build context is the repo ROOT (see docker-compose.yml), not this directory.

FROM node:24-alpine AS base
WORKDIR /app
# mongodb-memory-server (a server devDependency) downloads a ~150 MB mongod
# binary in its postinstall. Nothing in any image runs it — the unit tests do,
# and they never run in a container — so skip the download entirely.
ENV MONGOMS_DISABLE_POSTINSTALL=1

# -----------------------------------------------------------------------------
# development — hot-reload image (docker-compose.dev.yml)
# -----------------------------------------------------------------------------
FROM base AS development
ENV NODE_ENV=development
COPY package.json package-lock.json* ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/
COPY packages/client/package.json ./packages/client/
RUN npm ci && npm cache clean --force
COPY . .
RUN npm run build:shared
CMD ["npm", "run", "dev"]

# -----------------------------------------------------------------------------
# deps — every build-time dependency, in one install
# -----------------------------------------------------------------------------
# The install is deliberately NOT scoped with --workspace. `tsc` (which every
# package's build script invokes) and `husky` both live in the ROOT
# devDependencies, and `npm ci --workspace=<pkg>` does not install the root
# workspace unless --include-workspace-root is passed — so a scoped install here
# produces a tree with no `tsc` in it and every build fails on "not found".
#
# --ignore-scripts serves two purposes at once:
#   * it skips the root `"prepare": "husky"` lifecycle script, which cannot work in
#     an image (the .git directory is excluded from the build context);
#   * it skips @hiprax/crypto's optional native `argon2` build, so Alpine needs no
#     python/make/g++ toolchain. Nothing here needs argon2 — the server uses only
#     the sync PBKDF2/AES-GCM path, and the client's Argon2id is WebAssembly via
#     hash-wasm. Optional dependencies are still INSTALLED (they carry the
#     platform binaries for Rolldown, esbuild and Tailwind's oxide, which the
#     client build and `tsx` need); only their install scripts are skipped.
FROM base AS deps
COPY package.json package-lock.json* ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/
COPY packages/client/package.json ./packages/client/
RUN npm ci --ignore-scripts && npm cache clean --force

# -----------------------------------------------------------------------------
# prod-deps — runtime dependencies only (no dev, no optional)
# -----------------------------------------------------------------------------
#
# --ignore-scripts is required, not cosmetic. The root package.json declares
# `"prepare": "husky"`, and npm runs `prepare` on every install — including this
# one. With --omit=dev, husky (a devDependency) is not installed, so the script
# exits 127 and takes the whole build down. Nothing in the RUNTIME dependency tree
# has an install script worth running anyway: the only native module in play is
# @hiprax/crypto's optional `argon2`, which --omit=optional already excludes.
FROM base AS prod-deps
COPY package.json package-lock.json* ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/server/package.json ./packages/server/
RUN npm ci --workspace=packages/shared --workspace=packages/server \
      --omit=dev --omit=optional --ignore-scripts \
 && npm cache clean --force

# -----------------------------------------------------------------------------
# build-shared / build-server / build-client
# -----------------------------------------------------------------------------
FROM deps AS build-shared
COPY tsconfig.base.json ./
COPY packages/shared ./packages/shared
RUN npm run build -w packages/shared

FROM build-shared AS build-server
COPY packages/server ./packages/server
RUN npm run build -w packages/server

FROM build-shared AS build-client
COPY packages/client ./packages/client
RUN npm run build -w packages/client

# -----------------------------------------------------------------------------
# bootstrap — one-shot MongoDB index creation, then exits
# -----------------------------------------------------------------------------
# In production Mongoose runs with `autoIndex: false` (config/database.ts), so
# indexes are NEVER created implicitly. They are not merely a performance
# concern here: the Folder `(userId, searchHash)` UNIQUE partial index is what
# makes duplicate-folder detection return 409, and the AuditLog / RefreshToken
# TTL indexes are what bound their collections' growth. Without this step the
# stack boots and *appears* healthy while silently losing those guarantees — so
# compose gates the app on this container completing successfully.
#
# It reuses the existing, drift-tested `scripts/create-indexes.ts` (whose model
# list, scripts/indexedModels.ts, a unit test asserts covers every model) rather
# than duplicating the registry. That script is TypeScript run through `tsx`, so
# this target derives from `build-server`, which already carries the dev
# dependencies and the sources. The container runs for a second or two and exits;
# its layers are shared with the build stages, so it costs no extra disk.
FROM build-server AS bootstrap
ENV NODE_ENV=production

# The bootstrap runs `npm run create-indexes` (below), so it genuinely needs npm
# at runtime. The Alpine base ships npm bundling a vulnerable undici (Trivy
# fixable HIGH, CVE-2026-12151 — the v6 branch is only patched at 6.27.0, and the
# base's npm 11 bundles 6.26.0). Upgrade npm while still root, before the drop to
# the node user. `npm run <script> -w` is an explicit named-script invocation (not
# an install lifecycle hook), so it keeps the same cwd (/app/packages/server) and
# the log-directory reasoning below stays intact.
#
# The major is PINNED rather than `@latest`, deliberately. This one-shot is
# load-bearing: the app gates on `service_completed_successfully`, so if
# create-indexes ever fails the whole stack stays down. A floating `@latest` could
# pull a future npm MAJOR that changes `npm run -w` behavior, and that would break
# at DEPLOY time — which the build + Trivy gate cannot catch, because it builds and
# scans this image but never runs create-indexes against a live Mongo. Pinning the
# major removes that un-catchable risk. Patches inside 12.x still flow (npm has
# regressed here before, shipping a vulnerable undici transitively via node-gyp),
# and a bundled-undici regression within the line IS caught by the Trivy gate.
RUN npm install -g npm@12 && npm cache clean --force

# The log directory MUST exist and be owned by `node` before the drop to that user.
# This is the difference between a stack that comes up on a fresh clone and one
# that does not:
#   * `npm run <script> -w packages/server` runs with cwd = /app/packages/server
#     (the script is `tsx scripts/create-indexes.ts`, a relative path that only
#     resolves from there);
#   * the script imports src/config, which calls createLogger() at MODULE SCOPE;
#   * @hiprax/logger eagerly mkdirs `<cwd>/logs` and THROWS if it cannot;
#   * /app/packages/server was created by COPY as root (0755), so uid 1000 cannot
#     create anything inside it -> EACCES -> the bootstrap exits non-zero -> the
#     app's `service_completed_successfully` gate never opens -> nginx never starts.
#
# It is easy to miss because a developer's machine usually HAS packages/server/logs
# lying around from a local `npm run dev`; with a bare `logs` in .dockerignore that
# directory was copied in, and mkdir on an existing directory succeeds even without
# write permission. A fresh clone has no such directory, and the stack dies.
RUN mkdir -p /app/packages/server/logs && chown -R node:node /app/packages/server/logs

USER node
CMD ["npm", "run", "create-indexes", "-w", "packages/server"]

# -----------------------------------------------------------------------------
# app — production API server (also serves the SPA when hit directly)
# -----------------------------------------------------------------------------
FROM base AS app
ENV NODE_ENV=production

# The production runtime executes `node` directly (see CMD and HEALTHCHECK) and
# never invokes npm. Remove the global npm CLI: the Alpine base ships it with a
# bundled undici that Trivy flags as a fixable HIGH (CVE-2026-12151), and a
# runtime image has no reason to carry a package manager. Removing it eliminates
# the finding at the source and shrinks the attack surface to Node plus the app.
# The COPY below only touches /app, so it never restores /usr/local npm.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

# The production dependency tree exactly as npm laid it out: the hoisted root
# node_modules, whichever per-package node_modules npm's hoisting decided to
# create (today: none — but that is an npm implementation detail that changes with
# the dependency graph), the workspace symlinks that point node_modules/@hvault/*
# back at packages/*, and the package.json files those symlinks resolve through.
# Copying the tree wholesale instead of cherry-picking directories means the image
# cannot silently lose a path when the graph shifts.
COPY --from=prod-deps /app/ ./

COPY --from=build-shared /app/packages/shared/dist ./packages/shared/dist
COPY --from=build-server /app/packages/server/dist ./packages/server/dist
# The client bundle. Express serves `/` and `/index.html` from here (through
# helmet, so the document keeps its CSP and its other security headers) and falls
# back to index.html for deep-linked SPA routes. Nginx serves `/assets/*` from its
# own copy of this identical build; this one is both the SPA-shell source and a
# complete standalone fallback if the app is ever run without Nginx in front.
COPY --from=build-client /app/packages/client/dist ./packages/server/public

EXPOSE 5000

# Exits explicitly on success rather than waiting for the event loop to drain: an
# unconsumed fetch body keeps undici's pooled socket ref'd, so the process would
# linger for as long as the keep-alive timer says, and a probe that overruns
# --timeout is recorded as a FAILURE. (Compose overrides this healthcheck with its
# own; this one is what `docker run` of the image alone gets, so it must agree.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:5000/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

USER node

CMD ["node", "packages/server/dist/server.js"]

# -----------------------------------------------------------------------------
# web-root — the SPA bundle, minus index.html
# -----------------------------------------------------------------------------
# The HTML document is ALWAYS served by Express, never by Nginx, because helmet
# (inside Express) is what attaches the Content-Security-Policy with its
# per-request nonce, X-Frame-Options, Referrer-Policy and COOP to it. A copy of
# index.html sitting in Nginx's document root would be a header-free version of
# the app one URL away, so the file is removed here: Nginx cannot serve what it
# does not have, no matter how a future `try_files` edit is worded.
FROM build-client AS web-root
RUN rm -f /app/packages/client/dist/index.html

# -----------------------------------------------------------------------------
# web — Nginx: the stack's single serving surface
# -----------------------------------------------------------------------------
# nginx-unprivileged runs as uid 101 and listens on 8080, so the container needs
# neither root nor NET_BIND_SERVICE. The routing config is BAKED IN rather than
# bind-mounted, which keeps the image self-contained and portable across host OSes
# (no Windows/WSL bind-mount permission or line-ending surprises).
FROM nginxinc/nginx-unprivileged:1.29-alpine AS web

# Patch the base image's OS packages before serving anything from it. The
# nginx-unprivileged:1.29-alpine base trails a full Alpine minor behind
# node:24-alpine (3.23 vs 3.24) and ships fixable HIGH CVEs in c-ares, openssl
# (libcrypto3 / libssl3), libexpat and libxml2 — exactly the kind the Trivy gate
# refuses to let through. Upgrading pulls the patched packages from the pinned
# Alpine release. The base runs as the unprivileged uid 101, so switch to root
# ONLY for the apk transaction and drop straight back; the final runtime user is
# unchanged, and --no-cache leaves no apk index behind in the layer.
USER root
RUN apk upgrade --no-cache
USER 101

# The bundle is served from /srv/hvault, NOT from the base image's
# /usr/share/nginx/html. That directory already contains nginx's own stock
# index.html (the "Welcome to nginx!" page), and COPY overlays rather than
# replaces — so serving from there means a request for /index.html is answered
# with the stock page instead of falling through to Express, and it comes back
# with none of helmet's security headers. Owning the document root outright means
# nothing can be served from it that this repo did not put there.
COPY --from=web-root /app/packages/client/dist /srv/hvault
COPY docker/nginx/internal.conf  /etc/nginx/conf.d/default.conf
# Deliberately NOT under conf.d/: the stock nginx.conf globs conf.d/*.conf into
# the http{} context, which would apply this fragment's proxy headers globally.
COPY docker/nginx/proxy_app.conf /etc/nginx/hvault/proxy_app.conf

EXPOSE 8080
