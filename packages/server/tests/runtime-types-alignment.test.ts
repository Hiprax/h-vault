/**
 * `@types/node` describes ONE Node release line, and it has to be the one this
 * project runs on.
 *
 * The runtime is pinned in three places (`.nvmrc`, the root `engines.node`
 * floor, and the `FROM node:<major>-…` of every image stage), and the `engines`
 * gate refuses a lower runtime. Nothing refused TYPES from a later line, and
 * types from a later line are not a harmless superset: they declare functions
 * and options that the pinned runtime does not have. A call to one compiles and
 * then throws, which a covered test would catch; an unknown OPTION compiles and
 * is silently ignored by Node, which nothing catches (an option passed to
 * `http.createServer` in `utils/httpTimeouts.ts` that Node 24 does not know
 * would simply never take effect). So the types major is held to the runtime
 * major, and this file is what holds it: moving to a new Node line means moving
 * all of these together.
 *
 * Coverage boundary, stated so nobody assumes more: it reads `docker/Dockerfile`
 * and `docker/<name>.Dockerfile` (a `FROM` naming `node` with no tag, a digest,
 * or an unpinned or variable tag is reported, not skipped), the root and
 * workspace manifests, and the lockfile. It does not
 * read Dockerfiles elsewhere or compose `image:` lines; today every Node image
 * is built from `docker/Dockerfile`.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { REPO_ROOT } from './tempDir.js';

/** Everything the check reads, as text, so a planted tree can be handed in. */
interface RuntimeSources {
  nvmrc: string;
  /** Root `package.json`. */
  rootManifest: string;
  /** `docker/*Dockerfile*`, by repo-relative path. */
  dockerfiles: Record<string, string>;
  /** Every workspace `package.json`, by repo-relative path (root included). */
  manifests: Record<string, string>;
  /** `package-lock.json`. */
  lockfile: string;
}

/** The major a declared `@types/node` range admits, or `null` if it admits more than one. */
function singleMajor(range: string): number | null {
  // `^N`, `^N.x.y`, `~N.x.y`, `N.x` and an exact `N.x.y` each stay inside major
  // N. Anything else (`>=24`, `*`, `24 || 26`, a tag) can resolve to another line.
  const match = /^[\^~]?(\d+)(?:\.(?:\d+|x|\*)){0,2}$/.exec(range.trim());
  return match ? Number(match[1]) : null;
}

/**
 * A `FROM` naming the `node` image, past `--platform=…` flags and a registry
 * prefix, in any case (Dockerfile instructions are case-insensitive), with its
 * tag or digest when it has one. `nodered:1` and `mongo:8.0` do not match.
 */
const NODE_FROM = /^FROM\s+(?:--\S+\s+)*(?:\S+\/)?node(?:([:@])(\S+))?(?=\s|$)/gim;

/** Every disagreement between the runtime pin and the Node types, each naming its file. */
function runtimeTypesMismatches(sources: RuntimeSources): string[] {
  const problems: string[] = [];
  const runtime = Number(/^\s*v?(\d+)/.exec(sources.nvmrc)?.[1] ?? Number.NaN);
  if (!Number.isInteger(runtime)) return ['.nvmrc does not name a Node major'];

  const engines = (JSON.parse(sources.rootManifest) as { engines?: { node?: string } }).engines
    ?.node;
  // The FLOOR is what the runtime pin means, wherever it sits in the range.
  const floor = />=\s*v?(\d+)/.exec(engines ?? '') ?? /^\s*[\^~]?v?(\d+)/.exec(engines ?? '');
  const enginesMajor = Number(floor?.[1] ?? Number.NaN);
  if (enginesMajor !== runtime) {
    problems.push(`package.json engines.node "${String(engines)}" is not major ${runtime}`);
  }

  for (const [file, text] of Object.entries(sources.dockerfiles)) {
    // `--platform=…` flags and a registry prefix do not hide a stage.
    for (const [, separator = '', tag = ''] of text.matchAll(NODE_FROM)) {
      // A bare `node` is `latest`, and a digest names no line: neither pins one.
      const major = separator === ':' ? /^(\d+)\b/.exec(tag)?.[1] : undefined;
      if (major === undefined) {
        problems.push(`${file} builds FROM node${separator}${tag}, which pins no major`);
      } else if (Number(major) !== runtime) problems.push(`${file} builds FROM node:${major}`);
    }
  }

  for (const [file, text] of Object.entries(sources.manifests)) {
    const manifest = JSON.parse(text) as Record<string, Record<string, string> | undefined>;
    for (const field of [
      'dependencies',
      'devDependencies',
      'optionalDependencies',
      'peerDependencies',
    ]) {
      const range = manifest[field]?.['@types/node'];
      if (range === undefined) continue;
      const major = singleMajor(range);
      if (major !== runtime) {
        problems.push(`${file} ${field} @types/node "${range}" is not confined to ${runtime}.x`);
      }
    }
  }

  const lock = JSON.parse(sources.lockfile) as {
    packages?: Record<string, { version?: string }>;
  };
  for (const [location, entry] of Object.entries(lock.packages ?? {})) {
    if (!location.endsWith('node_modules/@types/node')) continue;
    const major = Number(/^(\d+)\./.exec(entry.version ?? '')?.[1] ?? Number.NaN);
    if (major !== runtime) {
      problems.push(`package-lock.json ${location} resolves ${String(entry.version)}`);
    }
  }
  return problems;
}

/** The sources as they are on disk right now. */
function readRepository(): RuntimeSources {
  const read = (relative: string) => readFileSync(path.join(REPO_ROOT, relative), 'utf-8');
  const dockerfiles = Object.fromEntries(
    readdirSync(path.join(REPO_ROOT, 'docker'))
      // `Dockerfile` and `<name>.Dockerfile`, never a `Dockerfile.tmp` backup.
      .filter((name) => /(^|\.)Dockerfile$/.test(name))
      .map((name) => [`docker/${name}`, read(`docker/${name}`)]),
  );
  const { workspaces = [] } = JSON.parse(read('package.json')) as { workspaces?: string[] };
  const workspaceManifests = workspaces.map((dir) => `${dir}/package.json`);
  const manifests = Object.fromEntries(
    ['package.json', ...workspaceManifests].map((file) => [file, read(file)]),
  );
  return {
    nvmrc: read('.nvmrc'),
    rootManifest: read('package.json'),
    dockerfiles,
    manifests,
    lockfile: read('package-lock.json'),
  };
}

/** A minimal tree that agrees with itself on Node 24, for planting one fault at a time. */
function agreeingTree(): RuntimeSources {
  const root = JSON.stringify({ engines: { node: '>=24.0.0' } });
  return {
    nvmrc: '24\n',
    rootManifest: root,
    dockerfiles: { 'docker/Dockerfile': 'FROM node:24-alpine3.23 AS base\nFROM base AS web\n' },
    manifests: {
      'package.json': root,
      'packages/server/package.json': JSON.stringify({
        devDependencies: { '@types/node': '^24.13.6' },
      }),
    },
    lockfile: JSON.stringify({
      packages: { 'node_modules/@types/node': { version: '24.13.6' } },
    }),
  };
}

describe('@types/node follows the pinned Node runtime', () => {
  it('agrees on one major across .nvmrc, engines, every image and every @types/node', () => {
    const sources = readRepository();

    expect(runtimeTypesMismatches(sources)).toEqual([]);
    // The check read something real: a lock with no @types/node entry, or no
    // workspace declaring it, would make the empty list above vacuous.
    expect(sources.lockfile).toContain('"node_modules/@types/node"');
    expect(Object.values(sources.manifests).some((m) => m.includes('"@types/node"'))).toBe(true);
    expect(Object.keys(sources.manifests).length).toBeGreaterThan(1);
    expect(
      Object.values(sources.dockerfiles).some((text) => [...text.matchAll(NODE_FROM)].length > 0),
      'no FROM node: line was examined',
    ).toBe(true);
  });

  it('reports nothing for a tree that agrees with itself', () => {
    expect(runtimeTypesMismatches(agreeingTree())).toEqual([]);
  });

  it.each(['lts/*', 'node', 'lts/krypton', ''])(
    'refuses an .nvmrc that names no fixed major (%j), which would roll over on its own',
    (nvmrc) => {
      const sources = agreeingTree();
      sources.nvmrc = nvmrc;

      expect(runtimeTypesMismatches(sources)).toEqual(['.nvmrc does not name a Node major']);
    },
  );

  it.each(['^24', '24.x', '~24.13.6', '24.13.6'])(
    'accepts a range confined to the runtime major: %s',
    (range) => {
      const sources = agreeingTree();
      sources.manifests['packages/server/package.json'] = JSON.stringify({
        devDependencies: { '@types/node': range },
      });

      expect(runtimeTypesMismatches(sources)).toEqual([]);
    },
  );

  it('names the manifest that declares types from a later Node line', () => {
    const sources = agreeingTree();
    sources.manifests['packages/shared/package.json'] = JSON.stringify({
      devDependencies: { '@types/node': '^26.6.2' },
    });

    expect(runtimeTypesMismatches(sources)).toEqual([
      'packages/shared/package.json devDependencies @types/node "^26.6.2" is not confined to 24.x',
    ]);
  });

  it('checks a peerDependencies range as well as the install-time fields', () => {
    const sources = agreeingTree();
    sources.manifests['packages/shared/package.json'] = JSON.stringify({
      peerDependencies: { '@types/node': '^26.0.0' },
    });

    expect(runtimeTypesMismatches(sources)).toEqual([
      'packages/shared/package.json peerDependencies @types/node "^26.0.0" is not confined to 24.x',
    ]);
  });

  it.each(['>=24.0.0', '*', '24 || 26', 'latest'])(
    'refuses a range that could resolve outside the runtime major: %s',
    (range) => {
      const sources = agreeingTree();
      sources.manifests['packages/server/package.json'] = JSON.stringify({
        devDependencies: { '@types/node': range },
      });

      expect(runtimeTypesMismatches(sources)).toEqual([
        `packages/server/package.json devDependencies @types/node "${range}" is not confined to 24.x`,
      ]);
    },
  );

  it('names a nested lockfile copy from another line, not only the hoisted one', () => {
    const sources = agreeingTree();
    sources.lockfile = JSON.stringify({
      packages: {
        'node_modules/@types/node': { version: '24.13.6' },
        'node_modules/some-tool/node_modules/@types/node': { version: '26.6.2' },
      },
    });

    expect(runtimeTypesMismatches(sources)).toEqual([
      'package-lock.json node_modules/some-tool/node_modules/@types/node resolves 26.6.2',
    ]);
  });

  it('finds a stage behind --platform or a registry prefix, and refuses an unpinned tag', () => {
    const sources = agreeingTree();
    sources.dockerfiles['docker/Dockerfile'] = [
      'FROM --platform=$BUILDPLATFORM docker.io/library/node:26-alpine AS build',
      'FROM node:${NODE_VERSION}-alpine AS base',
      'FROM mongo:8.0 AS db',
      '',
    ].join('\n');

    expect(runtimeTypesMismatches(sources)).toEqual([
      'docker/Dockerfile builds FROM node:26',
      'docker/Dockerfile builds FROM node:${NODE_VERSION}-alpine, which pins no major',
    ]);
  });

  it('refuses a bare, digest-only or lowercase node base rather than skipping it', () => {
    const sources = agreeingTree();
    sources.dockerfiles['docker/Dockerfile'] = [
      'FROM node AS latest',
      'FROM node@sha256:0123abcd AS pinned-by-digest',
      'from node:26-alpine as lower',
      'FROM nodered:1 AS not-node',
      '',
    ].join('\n');

    expect(runtimeTypesMismatches(sources)).toEqual([
      'docker/Dockerfile builds FROM node, which pins no major',
      'docker/Dockerfile builds FROM node@sha256:0123abcd, which pins no major',
      'docker/Dockerfile builds FROM node:26',
    ]);
  });

  it('reads the engines floor wherever it sits in the range', () => {
    const sources = agreeingTree();
    sources.rootManifest = JSON.stringify({ engines: { node: '<25.0.0 >=24.0.0' } });

    expect(runtimeTypesMismatches(sources)).toEqual([]);
  });

  it('names an image stage or an engines floor that has moved without the rest', () => {
    const sources = agreeingTree();
    sources.dockerfiles['docker/Dockerfile'] = 'FROM node:26-alpine3.23 AS base\n';
    sources.rootManifest = JSON.stringify({ engines: { node: '>=26.0.0' } });

    expect(runtimeTypesMismatches(sources)).toEqual([
      'package.json engines.node ">=26.0.0" is not major 24',
      'docker/Dockerfile builds FROM node:26',
    ]);
  });
});
