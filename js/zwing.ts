/**
 * Z-Wing — Lux post-quantum secure channel (TypeScript port).
 *
 * Z-Wing is a composition: IETF X-Wing KEM at the bottom (X25519 +
 * ML-KEM-768 with the SHA3-256 combiner from
 * draft-connolly-cfrg-xwing-kem) plus Lux Ed25519 + ML-DSA-65 hybrid
 * identity signatures plus ChaCha20-Poly1305 channel records. The KEM
 * combiner is byte-for-byte the IETF spec for full interop with the Go
 * implementation in this same repo (luxfi/zwing) and any third-party
 * X-Wing peer.
 *
 * X-Wing combiner (IETF spec, exact):
 *
 *   shared_secret = SHA3-256( "\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )
 *
 * The label is `"X-Wing"`, not `"Z-Wing"`. Z-Wing's domain separation
 * lives one layer up in the HKDF info string `"lux.zwing.v1/{i2r,r2i}"`
 * that derives the channel keys, and in the ML-DSA context
 * `"lux.zwing.v1"` used for hybrid identity signatures.
 *
 * @module
 */

import { sha3_256 } from "@noble/hashes/sha3.js";

/** ML-KEM-768 public key size in bytes. */
export const MLKEM768_PUBLIC_KEY_SIZE = 1184;
/** ML-KEM-768 ciphertext size in bytes. */
export const MLKEM768_CIPHERTEXT_SIZE = 1088;
/** X25519 public key (and ciphertext) size in bytes. */
export const X25519_POINT_SIZE = 32;

/** X-Wing public key wire size: ML-KEM-768 pk || X25519 pk. */
export const XWING_PUBLIC_KEY_SIZE =
  MLKEM768_PUBLIC_KEY_SIZE + X25519_POINT_SIZE;
/** X-Wing ciphertext wire size: ML-KEM-768 ct || X25519 ephemeral pk. */
export const XWING_CIPHERTEXT_SIZE =
  MLKEM768_CIPHERTEXT_SIZE + X25519_POINT_SIZE;
/** Z-Wing / X-Wing shared-secret size in bytes. */
export const XWING_SHARED_SIZE = 32;

// IETF X-Wing combiner labels (exact bytes from draft-connolly-cfrg-xwing-kem).
// Three-byte prefix `\./` plus the six-byte ASCII protocol name `X-Wing`.
const XWING_LABEL_PREFIX = new Uint8Array([0x5c, 0x2e, 0x2f]); // "\./"
const XWING_LABEL_NAME = new TextEncoder().encode("X-Wing");

/**
 * Combine the X-Wing KEM ingredients into a single 32-byte shared
 * secret. Inputs are all 32 bytes: ss_m = ML-KEM-768 shared secret,
 * ss_x = X25519 shared secret, ct_x = X25519 ephemeral public key from
 * encapsulator, pk_x = X25519 static public key of recipient.
 */
export function combineXWing(
  ss_m: Uint8Array,
  ss_x: Uint8Array,
  ct_x: Uint8Array,
  pk_x: Uint8Array,
): Uint8Array {
  if (ss_m.length !== XWING_SHARED_SIZE) {
    throw new Error(`ss_m must be ${XWING_SHARED_SIZE} bytes`);
  }
  if (ss_x.length !== X25519_POINT_SIZE) {
    throw new Error(`ss_x must be ${X25519_POINT_SIZE} bytes`);
  }
  if (ct_x.length !== X25519_POINT_SIZE) {
    throw new Error(`ct_x must be ${X25519_POINT_SIZE} bytes`);
  }
  if (pk_x.length !== X25519_POINT_SIZE) {
    throw new Error(`pk_x must be ${X25519_POINT_SIZE} bytes`);
  }

  const h = sha3_256.create();
  h.update(XWING_LABEL_PREFIX);
  h.update(XWING_LABEL_NAME);
  h.update(ss_m);
  h.update(ss_x);
  h.update(ct_x);
  h.update(pk_x);
  return h.digest();
}
