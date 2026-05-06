/**
 * IETF X-Wing KEM — encapsulate / decapsulate built on ML-KEM-768 +
 * X25519 with the SHA3-256 combiner. Wire bytes match the Go and Rust
 * implementations.
 */

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";

import {
  combineXWing,
  MLKEM768_CIPHERTEXT_SIZE,
  X25519_POINT_SIZE,
  XWING_CIPHERTEXT_SIZE,
  XWING_SHARED_SIZE,
} from "./zwing.js";
import type { Identity, IdentityPublic } from "./identity.js";

/**
 * Encapsulate a fresh X-Wing shared secret to a recipient. Returns the
 * combined wire ciphertext (ML-KEM-768 ct || X25519 ephemeral pk) and
 * the 32-byte shared secret.
 */
export function xwingEncapsulate(recipient: IdentityPublic): {
  ciphertext: Uint8Array;
  shared: Uint8Array;
} {
  const { sharedSecret: ssM, cipherText: ctM } = ml_kem768.encapsulate(
    recipient.xwingMlkemPk,
  );

  const ephSk = crypto.getRandomValues(new Uint8Array(32));
  const ephPk = x25519.getPublicKey(ephSk);
  const ssX = x25519.getSharedSecret(ephSk, recipient.xwingX25519Pk);

  const ssM32: Uint8Array = ssM.slice(0, 32);
  const ssX32: Uint8Array = ssX.slice(0, 32);
  const shared = combineXWing(ssM32, ssX32, ephPk, recipient.xwingX25519Pk);

  const wire = new Uint8Array(XWING_CIPHERTEXT_SIZE);
  wire.set(ctM, 0);
  wire.set(ephPk, MLKEM768_CIPHERTEXT_SIZE);

  // Best-effort wipe of intermediate secrets.
  ephSk.fill(0);
  ssM.fill(0);
  ssX.fill(0);

  return { ciphertext: wire, shared };
}

/**
 * Decapsulate an X-Wing wire ciphertext using `id`'s static keypair.
 * Throws on size mismatch or low-order ephemeral.
 */
export function xwingDecapsulate(id: Identity, ciphertext: Uint8Array): Uint8Array {
  if (ciphertext.length !== XWING_CIPHERTEXT_SIZE) {
    throw new Error(
      `zwing: invalid X-Wing ciphertext size (got ${ciphertext.length})`,
    );
  }
  const ctM = ciphertext.slice(0, MLKEM768_CIPHERTEXT_SIZE);
  const ephPk = ciphertext.slice(MLKEM768_CIPHERTEXT_SIZE);

  const ssM = ml_kem768.decapsulate(ctM, id.xwingMlkemSk);
  const ssX = x25519.getSharedSecret(id.xwingX25519Sk, ephPk);

  const shared = combineXWing(
    ssM.slice(0, 32),
    ssX.slice(0, 32),
    ephPk,
    id.xwingX25519Pk,
  );

  ssM.fill(0);
  ssX.fill(0);
  return shared;
}

export { XWING_CIPHERTEXT_SIZE, XWING_SHARED_SIZE, X25519_POINT_SIZE };
