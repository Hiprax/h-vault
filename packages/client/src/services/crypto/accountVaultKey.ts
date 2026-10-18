/**
 * accountVaultKey: is the vault key this session holds the account's current one?
 *
 * Two callers ask it, for opposite reasons. A re-seal must prove it before sealing
 * every row under the key it holds (a re-seal under a key that is not the
 * account's would be a vault nothing can open). A session that finds rows it
 * cannot open asks it to tell a superseded key — the account rotated from another
 * session — from a row that is genuinely damaged (`stores/heldVaultKey.ts`).
 */
import { cryptoService } from './cryptoService';

/** The account's stored wrapper: the vault key sealed under the master key. */
export interface WrappedVaultKey {
  readonly encrypted: string;
  readonly iv: string;
  readonly tag: string;
}

/**
 * Opens `wrapper` with `mek` and compares the key inside, in constant time, with
 * `heldKey`.
 *
 * THROWS when the wrapper will not open under `mek` rather than answering either
 * way, because the callers need different answers: the re-seal aborts, and the
 * held-key check reads it as "this session's master key no longer opens the
 * account". The opened key bytes are cleared on every path.
 */
export async function holdsAccountVaultKey(
  heldKey: CryptoKey,
  wrapper: WrappedVaultKey,
  mek: CryptoKey,
): Promise<boolean> {
  const raw = await cryptoService.decryptVaultKey(wrapper.encrypted, wrapper.iv, wrapper.tag, mek);
  try {
    return await cryptoService.vaultKeyEqualsRaw(heldKey, raw);
  } finally {
    cryptoService.clearKey(raw);
  }
}
