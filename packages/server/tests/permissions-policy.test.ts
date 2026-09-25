import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import app from '../src/app.js';
import {
  APPLICATION_PERMISSIONS_POLICY,
  SANDBOX_PERMISSIONS_POLICY,
} from '../src/config/permissionsPolicy.js';

/**
 * The `Permissions-Policy` this server sends, held against the golden nginx floor
 * it has to replace.
 *
 * Both nginx layers in front of Express add the golden curated policy to any
 * response whose upstream sent none, and that policy denies the camera, which
 * made the authenticator import's camera scan impossible behind either of them.
 * So the application sends its own, and these tests pin three things: what it
 * sends, that it sends it on the responses a browser renders, and that it stays
 * the golden list feature for feature (a golden refresh that adds a feature must
 * fail here, not leave this server one feature looser than the policy it
 * replaces).
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/** The fallback value a `map $upstream_http_permissions_policy …` yields, read off disk. */
function floorValue(relativeFile: string, variable: string): string {
  const text = readFileSync(path.join(repoRoot, relativeFile), 'utf-8');
  const block = new RegExp(
    `map \\$upstream_http_permissions_policy\\s+\\$${variable}\\s*\\{\\s*''\\s+"([^"]+)"`,
  ).exec(text);
  if (block?.[1] === undefined) {
    throw new Error(`${relativeFile} no longer maps $${variable} from the upstream header`);
  }
  return block[1];
}

/** `"a=(), b=(self)"` -> `{ a: '()', b: '(self)' }`, refusing a feature named twice. */
function parsePolicy(policy: string): Record<string, string> {
  const features: Record<string, string> = {};
  for (const entry of policy.split(',')) {
    const [name, allowlist] = entry.trim().split('=');
    if (name === undefined || allowlist === undefined) throw new Error(`malformed: ${entry}`);
    if (Object.hasOwn(features, name)) throw new Error(`${name} is named twice`);
    features[name] = allowlist;
  }
  return features;
}

describe('the Permissions-Policy values', () => {
  const innerFloor = floorValue('docker/nginx/nginx.conf', 'fb_permissions_policy');
  const hostFloor = floorValue('docker/nginx/00-newapp-http.conf', 'newapp_permissions_policy');

  it('reads the same golden floor from both nginx layers', () => {
    expect(hostFloor).toBe(innerFloor);
    // The floor this whole module exists to replace: it denies the camera.
    expect(parsePolicy(innerFloor)['camera']).toBe('()');
  });

  it('sends the golden list unchanged to the isolated document, camera denied', () => {
    expect(SANDBOX_PERMISSIONS_POLICY).toBe(innerFloor);
  });

  it('sends the golden list to everything else with exactly one change: the camera, for this origin', () => {
    const application = parsePolicy(APPLICATION_PERMISSIONS_POLICY);
    const golden = parsePolicy(innerFloor);

    expect(application['camera']).toBe('(self)');
    // Every other feature exactly as the floor has it, and no feature added or
    // dropped: the same names, in the same order.
    expect(Object.keys(application)).toEqual(Object.keys(golden));
    const { camera: _appCamera, ...applicationRest } = application;
    const { camera: _goldenCamera, ...goldenRest } = golden;
    expect(applicationRest).toEqual(goldenRest);
    expect(Object.values(applicationRest).every((allowlist) => allowlist === '()')).toBe(true);
  });
});

describe('the responses the application sends', () => {
  it('carries the application policy, once, on an ordinary response', async () => {
    const res = await request(app).get('/api/v1/health');

    // One header, not two: nginx's floor yields only to a value that is there,
    // and a second copy on one response would be two policies for the browser to
    // combine.
    expect(res.headers['permissions-policy']).toBe(APPLICATION_PERMISSIONS_POLICY);
    expect(Array.isArray(res.headers['permissions-policy'])).toBe(false);
  });

  it('carries it on a refusal as well, which is still a response a browser may render', async () => {
    const res = await request(app).get('/api/v1/no-such-route');

    expect(res.status).toBe(404);
    expect(res.headers['permissions-policy']).toBe(APPLICATION_PERMISSIONS_POLICY);
  });
});
