/**
 * `config/clientArtifacts.ts` — where the production block finds the client
 * build and the isolated render document.
 *
 * Two constants and no behaviour, which is exactly why they get their own file:
 * the SEPARATION between them is a security control, and a control expressed as
 * a path is a control one "tidy-up" away from being deleted for looking
 * pointless.
 *
 * The control: the isolated document is read from a directory `express.static`
 * does not serve. Its whole containment is the per-response
 * Content-Security-Policy `config/sandboxCsp.ts` attaches, and a copy answered
 * off the static root carries helmet's application policy instead. Registering
 * the Express route before the static mount does not close that, because Express
 * 5 matches the RAW pathname while `send` decodes and normalises it, so
 * `/sandbox%2Ehtml`, `//sandbox.html`, `/sandbox.htm%6C` and `/%73andbox.html`
 * all miss the route and reach static. Absence is the control; ordering is not.
 * `tests/app-production-client.test.ts` drives those four spellings through the
 * real app over a real filesystem; this file pins the layout they depend on.
 */
import { beforeEach, describe, it, expect, vi } from 'vitest';
import path from 'node:path';

/**
 * `readFileSync` is replaced so the two readers can be driven WITHOUT a client
 * build on disk, and so the path each one asks for is recorded rather than
 * inferred.
 *
 * The alternative — letting the real read fail and reading the path off the
 * `ENOENT` — would make these assertions depend on `packages/server/public` and
 * `packages/server/sandbox-document` being absent, which is true in a checkout
 * but is a property of the environment rather than of the code. The argument is
 * the assertion here.
 */
const readFileSync = vi.hoisted(() =>
  // Parameters declared, unused: `mock.calls` is typed from the implementation's
  // signature, so a zero-argument stub makes every recorded call an empty tuple
  // and `calls[0][0]` a type error rather than the path under assertion.
  vi.fn((_file: string, _encoding: string) => '<!doctype html><title>stub</title>'),
);
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return { ...actual, readFileSync };
});

import {
  APPLICATION_SHELL_PATH,
  CLIENT_PUBLIC_DIR,
  SANDBOX_DOCUMENT_DIR,
  SANDBOX_DOCUMENT_PATH,
  readApplicationShell,
  readSandboxDocument,
} from '../src/config/clientArtifacts.js';

beforeEach(() => {
  readFileSync.mockClear();
});

describe('the isolated render document lives outside the static root', () => {
  it('resolves the sandbox document outside the express.static root', () => {
    // `path.relative` from the static root to the document has to LEAVE it. A
    // containment check rather than a string comparison, because the failure
    // that matters is any path under `public/`, not one particular spelling of
    // it — and `startsWith` on the raw strings would also call
    // `<pkg>/public-sandbox` "inside", which it is not.
    const fromStaticRoot = path.relative(CLIENT_PUBLIC_DIR, SANDBOX_DOCUMENT_PATH);

    expect(fromStaticRoot.startsWith(`..${path.sep}`)).toBe(true);
    expect(path.isAbsolute(fromStaticRoot)).toBe(false);
  });

  it('keeps the document in its own directory, not merely under a different name', () => {
    // The near miss this forbids: `<pkg>/public/../public/sandbox-doc.html`, or
    // anything else that leaves the file where static can stream it while the
    // assertion above still passes on a renamed file. The document's DIRECTORY
    // must be the thing that is outside.
    const dirFromStaticRoot = path.relative(CLIENT_PUBLIC_DIR, SANDBOX_DOCUMENT_DIR);

    expect(dirFromStaticRoot.startsWith(`..${path.sep}`)).toBe(true);
    expect(path.dirname(SANDBOX_DOCUMENT_PATH)).toBe(SANDBOX_DOCUMENT_DIR);
  });

  it('places both beside each other under the server package root', () => {
    // Both are resolved from this module's own URL rather than from
    // `process.cwd()`, and the expression has to hold in BOTH trees:
    // `packages/server/src/config/` in a checkout and
    // `packages/server/dist/config/` in the production image. Asserting the
    // shared parent is what catches a `..` being added or dropped.
    expect(path.dirname(CLIENT_PUBLIC_DIR)).toBe(path.dirname(SANDBOX_DOCUMENT_DIR));
    expect(path.basename(path.dirname(CLIENT_PUBLIC_DIR))).toBe('server');
    expect(path.isAbsolute(CLIENT_PUBLIC_DIR)).toBe(true);
    expect(path.isAbsolute(SANDBOX_DOCUMENT_DIR)).toBe(true);
  });

  it('reads the document from the directory its own constant names', () => {
    // The reader and the constant travel together or the control is a comment.
    // `app.ts` calls this function and never joins a path itself, so a reader
    // pointed at `CLIENT_PUBLIC_DIR` would put the document back inside the
    // static root while every path assertion above stayed green.
    expect(readSandboxDocument()).toBe('<!doctype html><title>stub</title>');
    expect(readFileSync).toHaveBeenCalledTimes(1);
    expect(readFileSync).toHaveBeenCalledWith(SANDBOX_DOCUMENT_PATH, 'utf-8');
    // The negative: not out of the static root, under any name.
    expect(String(readFileSync.mock.calls[0]?.[0]).startsWith(CLIENT_PUBLIC_DIR)).toBe(false);
  });

  it('reads the application shell from the static root, which is where it belongs', () => {
    // The shell is the one document that SHOULD sit in the static root: it is
    // served with helmet's application policy either way, and Nginx deletes its
    // own copy for the nonce rather than for isolation. Asserted so the two
    // readers cannot be swapped.
    expect(readApplicationShell()).toBe('<!doctype html><title>stub</title>');
    expect(readFileSync).toHaveBeenCalledWith(APPLICATION_SHELL_PATH, 'utf-8');
    expect(APPLICATION_SHELL_PATH).toBe(path.join(CLIENT_PUBLIC_DIR, 'index.html'));
  });

  it('names the document sandbox.html, which is the URL the app frames', () => {
    // The file name is not free: `DocumentSandbox.tsx` frames `/sandbox.html`,
    // the service worker's navigation denylist exempts that exact path, and the
    // Express route claims that exact string. Renaming the emitted file without
    // the other three is a blank frame in production only.
    expect(path.basename(SANDBOX_DOCUMENT_PATH)).toBe('sandbox.html');
    expect(path.basename(CLIENT_PUBLIC_DIR)).toBe('public');
  });
});
