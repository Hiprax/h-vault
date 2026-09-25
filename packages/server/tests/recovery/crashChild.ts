/**
 * The crash probe's CHILD: a real server process that dies mid-write.
 *
 *   node --import tsx tests/recovery/crashChild.ts '<json request>'
 *
 * It connects to the mongod the parent names, drives one real request through
 * the real Express application, and — at a point the parent chose — sends itself
 * SIGKILL.
 *
 * ---------------------------------------------------------------------------
 * WHY A CHILD PROCESS, AND WHY SIGKILL
 * ---------------------------------------------------------------------------
 *
 * "What does the database look like after the process died?" cannot be answered
 * from inside the process that has to keep running to ask it, and it cannot be
 * simulated by throwing: a thrown error runs `catch`, runs `finally`, releases
 * the job lock, clears the rotation fence and answers the request. Every one of
 * those is exactly what a crash does NOT do, and every one of them is what the
 * recovery paths under test exist to compensate for. An in-process simulation
 * would therefore be testing the ORDERLY abort — which four other suites already
 * cover — while claiming to test the crash.
 *
 * SIGKILL cannot be caught, blocked or ignored, even when a process sends it to
 * itself. No `finally` runs, no lock is released, no fence is lowered, no
 * response is written, and the kernel closes the sockets — which is precisely
 * the state a `kill -9`, an OOM kill, a container eviction or a power loss
 * leaves behind.
 *
 * ---------------------------------------------------------------------------
 * WHY THE KILL POINT IS A PATCHED MODEL METHOD
 * ---------------------------------------------------------------------------
 *
 * The alternative — let the request run and have the PARENT kill the child when
 * it notices the fence in the database — is a race: the window between the fence
 * commit and the vault-key update is milliseconds wide, so the probe would
 * sometimes kill too late and the suite would be reporting the weather.
 *
 * So each scenario patches ONE persistence-layer method and dies there. That is
 * fault INJECTION, not mocking: nothing is stubbed out, every write before the
 * injection point is real and committed by real code, and the patched call
 * either performs its real work and then the process ceases to exist, or the
 * process ceases to exist first — which is what "the machine died at this
 * instant" means. The unit under test is what the database holds afterwards.
 *
 * Each patch is described where it is registered, and each one is the instant a
 * particular invariant claims to be safe at.
 */
import mongoose from 'mongoose';
import request from 'supertest';
import app from '../../src/app.js';
import { AuditLog } from '../../src/models/AuditLog.js';
import { Document } from '../../src/models/Document.js';
import { DocumentUpload } from '../../src/models/DocumentUpload.js';
import { User } from '../../src/models/User.js';
import { VaultItem } from '../../src/models/VaultItem.js';
import { getStorage } from '../../src/services/storage/index.js';
import { CRASH_MARKERS, type CrashRequest, type CrashScenario } from './crashContract.js';
import { createIpcStorageClient } from './storageBridge.js';

/**
 * Ends this process the way a machine failure does.
 *
 * `process.kill(process.pid, 'SIGKILL')` rather than `process.exit()`: exit runs
 * `beforeExit`/`exit` listeners and flushes streams, so a mongoose connection
 * could still tidy up after itself — the very thing being denied here.
 */
function die(): never {
  process.kill(process.pid, 'SIGKILL');
  // Unreachable: SIGKILL is delivered before the next statement. Present so the
  // function's `never` return type is honest to the type checker rather than
  // asserted, and so a platform that somehow survived the signal still stops.
  throw new Error('SIGKILL did not terminate the crash probe');
}

/**
 * Replaces a static model method for the lifetime of this doomed process.
 *
 * Typed through `unknown` rather than `any` (which the integrity scan forbids
 * and which would disable checking of everything downstream): the two casts are
 * confined to this one function, and every call site below stays typed.
 */
function patchStatic(
  model: object,
  method: string,
  replace: (original: (...args: unknown[]) => unknown) => (...args: unknown[]) => unknown,
): void {
  const target = model as unknown as Record<string, (...args: unknown[]) => unknown>;
  const original = target[method]!.bind(model);
  target[method] = replace(original);
}

function arm(scenario: CrashScenario): void {
  switch (scenario) {
    case 'rotation-before-first-item-write':
      // The instant AFTER the write fence is committed and BEFORE the first row
      // is re-encrypted. What must hold: the fence is already up (it is written
      // before this call, not after it), the vault key is untouched, and every
      // item still opens under the OLD key.
      patchStatic(VaultItem, 'updateOne', () => () => die());
      return;

    case 'rotation-before-vault-key-update':
      // The instant the new vault key is about to be written — the transactional
      // path's last statement, with every re-encrypted row still uncommitted
      // inside the transaction. This is the exact window the invariant names:
      // between the fence commit and the vault-key update.
      patchStatic(User, 'updateOne', (original) => (...args: unknown[]) => {
        const update = JSON.stringify(args[1] ?? {});
        if (update.includes('encryptedVaultKey')) die();
        return original(...args);
      });
      return;

    case 'reseal-after-first-item-write':
      // A same-key RE-SEAL, killed once its first row is rewritten and before its
      // second. What must hold is what makes a re-seal crash-benign rather than
      // merely recoverable: every row, rewritten or not, is still under the key
      // the account stores, no pending wrapper was written (there is no new key
      // to lose), and the fence is up until login's recovery lowers it.
      patchStatic(VaultItem, 'updateOne', (original) => {
        let calls = 0;
        return (...args: unknown[]) => {
          calls += 1;
          if (calls === 2) die();
          return original(...args);
        };
      });
      return;

    case 'import-before-insert':
      // After the lock is held and the per-user cap has been checked, before any
      // row exists. What must hold: nothing was written, and the lock the dead
      // process still owns blocks the next import until its TTL expires.
      patchStatic(VaultItem, 'insertMany', () => () => die());
      return;

    case 'import-after-insert-before-commit':
      // The rows are inserted INSIDE the transaction and the process dies before
      // the commit. What must hold: not one of them is visible afterwards.
      patchStatic(VaultItem, 'insertMany', (original) => async (...args: unknown[]) => {
        const created = await original(...args);
        // Deliberately after the await: the insert really happened, in the
        // session, and only the commit is missing.
        void created;
        return die();
      });
      return;

    case 'document-part-before-ledger-write':
      // A part upload, killed between the engine write and the ledger write.
      // `uploadPart` stores the bytes FIRST and records them second, deliberately —
      // a ledger naming bytes that were never stored would be counted at completion
      // and produce a document with a hole in it. This is the instant that ordering
      // is a claim about: the engine holds the part, the staging row does not know,
      // and nothing has been committed. `DocumentUpload.findOneAndUpdate` has
      // exactly one call site in this codebase, so the injection cannot fire early.
      patchStatic(DocumentUpload, 'findOneAndUpdate', () => () => die());
      return;

    case 'document-complete-before-row-insert':
      // A completion, killed at the one statement that creates the `documents`
      // row. On the single-segment path the staging row has ALREADY been deleted by
      // then, and the object has already been written to its final key at part
      // time, so the crash leaves an object that NEITHER collection names — the
      // window `ORPHAN_MIN_AGE_MS` exists to make safe. The handler's own
      // compensating `deleteObject` sits in the `catch` around this call, which is
      // exactly what SIGKILL denies it.
      patchStatic(Document, 'create', () => () => die());
      return;

    case 'document-purge-after-object-delete':
      // A permanent delete, killed between the object delete and the row delete.
      // `purgeDocument` marks `purgePending` first, deletes the object second and
      // the row third; a crash here is the state that marker exists for. Three
      // other call sites of `Document.deleteOne` exist (bulk trash-empty and two
      // crons) and none of them is reachable from this route.
      patchStatic(Document, 'deleteOne', () => () => die());
      return;

    case 'import-after-commit':
      // The write has committed — on a replica set that means the transaction,
      // on the standalone path (where this scenario is used) it means the insert
      // itself, since that topology has no transaction to commit — and the lock
      // has been released in its `finally`. The audit row and the response have
      // not been written. What must hold: the import is COMPLETE rather than
      // partial, and nothing is left locked.
      patchStatic(AuditLog, 'create', () => () => die());
      return;
  }
}

async function main(): Promise<void> {
  const raw = process.argv[2];
  if (!raw) throw new Error('crashChild: no request was passed');
  const req = JSON.parse(raw) as CrashRequest;

  await mongoose.connect(req.uri);

  if (req.storageBridge === true) {
    // THE INJECTION SEAM, and it is one line because of two properties of the
    // production code rather than a trick played on it: `createS3Provider` returns
    // a plain object literal, and `getStorage()` MEMOISES it. So the first call
    // here builds the real provider (over the four `S3_*` values the parent passed
    // in the environment, pointing at nothing), and overwriting its methods in
    // place redirects every later caller in this process. There is no earlier
    // caller to miss: the one boot-time probe, `runStoragePreflight`, is fired from
    // `server.ts` inside the `app.listen` callback, and this child imports
    // `app.js`.
    //
    // Off unless the request asked for it: the five vault scenarios run with the
    // `S3_*` variables empty, where `getStorage()` throws 503.
    const provider = getStorage();
    Object.assign(provider, createIpcStorageClient());
    // One round trip BEFORE the marker below, so a bridge that never came up is a
    // named startup failure rather than a request that completes and reports
    // `SURVIVED` — which would send the parent looking at the injection point.
    await provider.headBucket();
  }

  arm(req.scenario);

  // The parent reads this to know the child got as far as its request; a probe
  // that died during startup would otherwise be indistinguishable from one that
  // died at its injection point.
  process.stdout.write(`${CRASH_MARKERS.ready}\n`);

  const agent = request.agent(app);
  const csrf = await agent.get('/api/v1/csrf-token');
  const csrfToken = (csrf.body as { data: { csrfToken: string } }).data.csrfToken;
  const setCookie = csrf.headers['set-cookie'];
  const cookies = Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [];
  const csrfCookie = cookies.find((value) => value.startsWith('__csrf='))?.split(';')[0] ?? '';

  const method = req.method ?? 'POST';
  const pending = agent[method === 'POST' ? 'post' : method === 'PUT' ? 'put' : 'delete'](req.path)
    .set('Authorization', `Bearer ${req.token}`)
    .set('Cookie', csrfCookie)
    .set('x-csrf-token', csrfToken);
  for (const [name, value] of Object.entries(req.headers ?? {})) pending.set(name, value);

  // A raw body is sent as `application/octet-stream`, which is the only type the
  // part route's parser accepts; superagent computes `Content-Length` from the
  // buffer, which the 411 guard ahead of that parser requires.
  const res =
    req.bodyBase64 === undefined
      ? await pending.send(req.body)
      : await pending.type('application/octet-stream').send(Buffer.from(req.bodyBase64, 'base64'));

  // Reaching here means the injection point was never hit — the request
  // completed, or failed before it. Either way this probe proved nothing, and
  // the parent must fail rather than assert against a state no crash produced.
  process.stdout.write(
    `${CRASH_MARKERS.survived}${String(res.status)} ${JSON.stringify(res.body)}\n`,
  );
  await mongoose.disconnect();
}

await main();
