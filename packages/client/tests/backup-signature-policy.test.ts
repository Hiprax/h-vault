import { describe, it, expect, vi } from 'vitest';
import {
  classifyBackupSignature,
  resolveBackupSignature,
  type BackupHmacKey,
  type BackupHmacKeySource,
  type BackupSignatureFacts,
  type BackupSignatureVerdict,
} from '../src/lib/backupSignature';

/**
 * The structural half of the restore-signature policy.
 *
 * `BackupSettingsPage` is a 1,600-line component whose restore handler has a
 * dozen exits, and the question "may this file be restored without the user
 * saying so?" used to be answered inline, by an `else` branch that raised a
 * warning toast and then fell through into the restore. A UI test can only
 * sample the combinations the UI happens to produce today; this file enumerates
 * the decision's WHOLE input domain — six combinations, generated rather than
 * hand-listed — so a future refactor cannot quietly re-open the fall-through by
 * adding a path the sampled cases do not cover.
 *
 * The invariant it exists to pin, stated once: **`verified` is reachable from
 * exactly one of the six inputs**, the one where a signature was present and it
 * verified under key material the file did not supply. Everything else must ask
 * the user or refuse.
 */

const KEY_SOURCES: readonly BackupHmacKeySource[] = ['account', 'file'];
const VERIFIED_UNDER: readonly (BackupHmacKeySource | null)[] = ['account', 'file', null];

/** Every point in the decision's input domain, generated, never listed by hand. */
function everyInput(): BackupSignatureFacts[] {
  const all: BackupSignatureFacts[] = [];
  for (const signaturePresent of [false, true]) {
    for (const verifiedUnder of VERIFIED_UNDER) {
      all.push({ signaturePresent, verifiedUnder });
    }
  }
  return all;
}

function describeInput(facts: BackupSignatureFacts): string {
  return `present=${String(facts.signaturePresent)} verifiedUnder=${String(facts.verifiedUnder)}`;
}

/** A distinguishable stand-in for an unwrapped BWK — the bytes are never read here. */
function key(source: BackupHmacKeySource): BackupHmacKey {
  return { source, bwk: new Uint8Array([source === 'account' ? 1 : 2]).buffer };
}

describe('classifyBackupSignature — the whole input domain', () => {
  it('covers all six combinations, so the sweeps below are exhaustive and not a sample', () => {
    const inputs = everyInput();
    expect(inputs).toHaveLength(6);
    expect(new Set(inputs.map(describeInput)).size).toBe(6);
  });

  it('lets exactly one input through as `verified`: signed, and verified under the ACCOUNT key', () => {
    const verified = everyInput().filter(
      (facts) => classifyBackupSignature(facts).kind === 'verified',
    );

    expect(verified).toEqual([{ signaturePresent: true, verifiedUnder: 'account' }]);
  });

  it('never returns `verified` for a signature only the FILE’s own key could check', () => {
    const fileKeyed = everyInput().filter((facts) => facts.verifiedUnder === 'file');
    expect(fileKeyed).toHaveLength(2);

    for (const facts of fileKeyed) {
      expect(classifyBackupSignature(facts).kind, describeInput(facts)).not.toBe('verified');
    }
  });

  it('never returns `verified` for a file carrying no signature, whatever else is set', () => {
    // Including the incoherent `verifiedUnder: 'account'`, which is the shape a
    // caller that forgot to reset a stale verdict would hand in. The absence of
    // the signature is answered BEFORE that field is read, so it cannot buy a pass.
    const unsigned = everyInput().filter((facts) => !facts.signaturePresent);
    expect(unsigned).toHaveLength(3);

    for (const facts of unsigned) {
      expect(classifyBackupSignature(facts), describeInput(facts)).toEqual({
        kind: 'unconfirmed',
        reason: 'unsigned',
      });
    }
  });

  it('refuses a present signature that no available key agrees with', () => {
    expect(classifyBackupSignature({ signaturePresent: true, verifiedUnder: null })).toEqual({
      kind: 'refused',
      reason: 'signature_mismatch',
    });
  });

  it('asks the user about a signature that verified only under the file’s own key', () => {
    expect(classifyBackupSignature({ signaturePresent: true, verifiedUnder: 'file' })).toEqual({
      kind: 'unconfirmed',
      reason: 'self_signed',
    });
  });

  it('is total: every input yields one of the three kinds, and no verdict is reasonless', () => {
    const kinds = new Set<BackupSignatureVerdict['kind']>();
    for (const facts of everyInput()) {
      const verdict = classifyBackupSignature(facts);
      kinds.add(verdict.kind);
      // Each non-`verified` verdict carries a machine-readable reason, so the
      // call site keys its copy on the discriminant instead of on a sentence.
      if (verdict.kind !== 'verified') {
        expect(verdict.reason, describeInput(facts)).toBeTruthy();
      }
    }
    expect([...kinds].sort()).toEqual(['refused', 'unconfirmed', 'verified']);
  });

  it('reads no property of its argument other than the two it declares', () => {
    // A smuggled field must not widen the verdict: the page builds these facts
    // from a parsed JSON file, and a hostile file is why the policy exists.
    const smuggled = {
      signaturePresent: false,
      verifiedUnder: null,
      trusted: true,
      kind: 'verified',
      confirmed: true,
    } as unknown as BackupSignatureFacts;

    expect(classifyBackupSignature(smuggled)).toEqual({ kind: 'unconfirmed', reason: 'unsigned' });
  });
});

describe('resolveBackupSignature — which key gets to answer, and in what order', () => {
  it('verifies under the account key and never consults the file key once it agrees', async () => {
    const verify = vi.fn().mockResolvedValue(true);
    const accountKey = key('account');
    const fileKey = key('file');

    const verdict = await resolveBackupSignature(
      'sig',
      '{"items":[]}',
      [accountKey, fileKey],
      verify,
    );

    expect(verdict).toEqual({ kind: 'verified' });
    // The ordering IS the control: a file key reached first would verify a
    // hostile file and report `verified`, so the short-circuit is asserted.
    expect(verify).toHaveBeenCalledTimes(1);
    // IDENTITY on the key, never `toHaveBeenCalledWith`. Vitest's structural
    // equality gives `ArrayBuffer`s no own enumerable keys, so ANY two of them
    // compare equal and the key slot of a `toHaveBeenCalledWith` asserts
    // nothing whatsoever about which key was used.
    const [data, hmac, keyUsed] = verify.mock.calls[0]!;
    expect(data).toBe('{"items":[]}');
    expect(hmac).toBe('sig');
    expect(keyUsed).toBe(accountKey.bwk);
    expect(keyUsed).not.toBe(fileKey.bwk);
  });

  it('falls through to the file key and reports the restore as self-signed', async () => {
    const accountBwk = key('account').bwk;
    const verify = vi.fn(async (_data: string, _hmac: string, bwk: ArrayBuffer) =>
      Promise.resolve(bwk !== accountBwk),
    );

    const verdict = await resolveBackupSignature(
      'sig',
      'payload',
      [{ source: 'account', bwk: accountBwk }, key('file')],
      verify,
    );

    expect(verdict).toEqual({ kind: 'unconfirmed', reason: 'self_signed' });
    expect(verify).toHaveBeenCalledTimes(2);
  });

  it('refuses when every available key disagrees, having tried all of them', async () => {
    const verify = vi.fn().mockResolvedValue(false);

    const verdict = await resolveBackupSignature(
      'sig',
      'payload',
      [key('account'), key('file')],
      verify,
    );

    expect(verdict).toEqual({ kind: 'refused', reason: 'signature_mismatch' });
    expect(verify).toHaveBeenCalledTimes(2);
  });

  it('treats a verifier that rejects as a disagreement and still tries the next key', async () => {
    // A malformed wrapper must not turn a refusal into an unhandled failure the
    // caller reports as "Failed to restore backup" — the verdict still decides.
    const accountBwk = key('account').bwk;
    const verify = vi.fn(async (_data: string, _hmac: string, bwk: ArrayBuffer) => {
      if (bwk === accountBwk) throw new Error('unusable key material');
      return Promise.resolve(true);
    });

    const verdict = await resolveBackupSignature(
      'sig',
      'payload',
      [{ source: 'account', bwk: accountBwk }, key('file')],
      verify,
    );

    expect(verdict).toEqual({ kind: 'unconfirmed', reason: 'self_signed' });
    expect(verify).toHaveBeenCalledTimes(2);
  });

  it('refuses a signed file when every key throws, rather than letting the rejection escape', async () => {
    const verify = vi.fn().mockRejectedValue(new Error('unusable key material'));

    await expect(
      resolveBackupSignature('sig', 'payload', [key('account')], verify),
    ).resolves.toEqual({ kind: 'refused', reason: 'signature_mismatch' });
  });

  it('asks for confirmation on an unsigned file WITHOUT verifying anything', async () => {
    const verify = vi.fn().mockResolvedValue(true);

    const verdict = await resolveBackupSignature(null, 'payload', [key('account')], verify);

    expect(verdict).toEqual({ kind: 'unconfirmed', reason: 'unsigned' });
    expect(verify).not.toHaveBeenCalled();
  });

  it('refuses a signed file when no key could be unwrapped at all', async () => {
    const verify = vi.fn().mockResolvedValue(true);

    const verdict = await resolveBackupSignature('sig', 'payload', [], verify);

    expect(verdict).toEqual({ kind: 'refused', reason: 'signature_mismatch' });
    expect(verify).not.toHaveBeenCalled();
  });

  it('reaches `verified` for no ordering that puts a file key ahead of the account key', async () => {
    // The caller owns the order, so the property worth pinning is the one that
    // survives a caller mistake: a file key first can never produce `verified`.
    for (const keys of [[key('file')], [key('file'), key('account')]]) {
      const verify = vi.fn().mockResolvedValue(true);
      const verdict = await resolveBackupSignature('sig', 'payload', keys, verify);
      expect(verdict, `keys=${keys.map((k) => k.source).join(',')}`).toEqual({
        kind: 'unconfirmed',
        reason: 'self_signed',
      });
    }
  });

  it('spans every key source the union declares, checked by the type system', () => {
    // A TYPE-LEVEL guard, because a runtime one cannot do this job: comparing
    // the hand-written `KEY_SOURCES` against the literal `['account','file']`
    // would still pass after a third member was added to the union, since the
    // literal goes on equalling itself. This `Record` does not compile when the
    // union gains a member (missing property) or loses one (excess property),
    // so `type-check` is what fails, before any test runs.
    const everySource: Record<BackupHmacKeySource, true> = { account: true, file: true };

    expect(Object.keys(everySource).sort()).toEqual([...KEY_SOURCES].sort());
    expect(VERIFIED_UNDER).toEqual([...KEY_SOURCES, null]);
  });
});
