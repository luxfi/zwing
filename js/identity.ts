/**
 * Hybrid Z-Wing identity: Ed25519 + ML-DSA-65 + X-Wing static keypair.
 *
 * Wire format mirrors the Go and Rust implementations:
 *
 *   [Ed25519 pk: 32][ML-DSA-65 pk: 1952][X-Wing pk: 1216] = 3200 bytes
 *
 * Signature wire = [Ed25519 sig: 64][ML-DSA-65 sig: 3309] = 3373 bytes.
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { XWING_PUBLIC_KEY_SIZE, X25519_POINT_SIZE } from "./zwing.js";

/** Ed25519 public key length. */
export const ED25519_PUBLIC_KEY_SIZE = 32;
/** Ed25519 signature length. */
export const ED25519_SIGNATURE_SIZE = 64;
/** ML-DSA-65 public key length (FIPS 204). */
export const MLDSA65_PUBLIC_KEY_SIZE = 1952;
/** ML-DSA-65 signature length (FIPS 204). */
export const MLDSA65_SIGNATURE_SIZE = 3309;
/** ML-KEM-768 public key length. */
export const MLKEM768_PUBLIC_KEY_SIZE = 1184;

/** Total wire size of an `IdentityPublic`. */
export const IDENTITY_PUBLIC_SIZE =
  ED25519_PUBLIC_KEY_SIZE + MLDSA65_PUBLIC_KEY_SIZE + XWING_PUBLIC_KEY_SIZE;

/** Total wire size of an identity signature. */
export const SIGNATURE_SIZE =
  ED25519_SIGNATURE_SIZE + MLDSA65_SIGNATURE_SIZE;

/** Z-Wing protocol context bound into every identity signature. */
export const ZWING_DOMAIN = new TextEncoder().encode("lux.zwing.v1");

/** Long-term Z-Wing identity. */
export interface Identity {
  edSk: Uint8Array; // 32-byte Ed25519 seed
  edPk: Uint8Array; // 32-byte Ed25519 public key
  mlSk: Uint8Array; // ML-DSA-65 secret
  mlPk: Uint8Array; // ML-DSA-65 public
  xwingMlkemSk: Uint8Array; // ML-KEM-768 secret
  xwingMlkemPk: Uint8Array; // ML-KEM-768 public
  xwingX25519Sk: Uint8Array; // X25519 32-byte secret
  xwingX25519Pk: Uint8Array; // X25519 32-byte public
}

/** Public half of an Identity. */
export interface IdentityPublic {
  edPk: Uint8Array;
  mlPk: Uint8Array;
  xwingMlkemPk: Uint8Array;
  xwingX25519Pk: Uint8Array;
}

/** Generate a fresh identity using a CSPRNG. */
export function generateIdentity(): Identity {
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPk = ed25519.getPublicKey(edSeed);

  const mlKp = ml_dsa65.keygen();
  const mlSk = mlKp.secretKey;
  const mlPk = mlKp.publicKey;

  const mlkemKp = ml_kem768.keygen();
  const xwingMlkemSk = mlkemKp.secretKey;
  const xwingMlkemPk = mlkemKp.publicKey;

  const xwingX25519Sk = crypto.getRandomValues(new Uint8Array(32));
  const xwingX25519Pk = x25519.getPublicKey(xwingX25519Sk);

  return {
    edSk: edSeed,
    edPk,
    mlSk,
    mlPk,
    xwingMlkemSk,
    xwingMlkemPk,
    xwingX25519Sk,
    xwingX25519Pk,
  };
}

/** Public half of `id`. */
export function publicOf(id: Identity): IdentityPublic {
  return {
    edPk: id.edPk,
    mlPk: id.mlPk,
    xwingMlkemPk: id.xwingMlkemPk,
    xwingX25519Pk: id.xwingX25519Pk,
  };
}

/** Marshal a public identity to wire bytes. */
export function marshalIdentityPublic(pub: IdentityPublic): Uint8Array {
  const out = new Uint8Array(IDENTITY_PUBLIC_SIZE);
  let off = 0;
  out.set(pub.edPk, off);
  off += ED25519_PUBLIC_KEY_SIZE;
  out.set(pub.mlPk, off);
  off += MLDSA65_PUBLIC_KEY_SIZE;
  out.set(pub.xwingMlkemPk, off);
  off += MLKEM768_PUBLIC_KEY_SIZE;
  out.set(pub.xwingX25519Pk, off);
  return out;
}

/** Parse a public identity from wire bytes. Throws on size mismatch. */
export function parseIdentityPublic(data: Uint8Array): IdentityPublic {
  if (data.length !== IDENTITY_PUBLIC_SIZE) {
    throw new Error(
      `zwing: invalid identity public size (got ${data.length}, want ${IDENTITY_PUBLIC_SIZE})`,
    );
  }
  let off = 0;
  const edPk = data.slice(off, off + ED25519_PUBLIC_KEY_SIZE);
  off += ED25519_PUBLIC_KEY_SIZE;
  const mlPk = data.slice(off, off + MLDSA65_PUBLIC_KEY_SIZE);
  off += MLDSA65_PUBLIC_KEY_SIZE;
  const xwingMlkemPk = data.slice(off, off + MLKEM768_PUBLIC_KEY_SIZE);
  off += MLKEM768_PUBLIC_KEY_SIZE;
  const xwingX25519Pk = data.slice(off, off + X25519_POINT_SIZE);
  return { edPk, mlPk, xwingMlkemPk, xwingX25519Pk };
}

/** Bind (ZWING_DOMAIN || len(ctx) || ctx || message) into a SHA-256 digest. */
export function identityDigest(ctx: Uint8Array, message: Uint8Array): Uint8Array {
  const h = sha256.create();
  h.update(ZWING_DOMAIN);
  h.update(new Uint8Array([ctx.length & 0xff]));
  h.update(ctx);
  h.update(message);
  return h.digest();
}

/** Sign `(ctx, message)` with both Ed25519 and ML-DSA-65. */
export function signIdentity(
  id: Identity,
  ctx: Uint8Array,
  message: Uint8Array,
): Uint8Array {
  const digest = identityDigest(ctx, message);
  const edSig = ed25519.sign(digest, id.edSk);
  // Noble ml-dsa API: sign(msg, secretKey).
  const mlSig = ml_dsa65.sign(digest, id.mlSk);
  const out = new Uint8Array(SIGNATURE_SIZE);
  out.set(edSig, 0);
  out.set(mlSig, ED25519_SIGNATURE_SIZE);
  return out;
}

/** Verify a hybrid Z-Wing signature. Throws on any failure. */
export function verifyIdentity(
  pub: IdentityPublic,
  ctx: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void {
  if (signature.length !== SIGNATURE_SIZE) {
    throw new Error("zwing: signature size mismatch");
  }
  const digest = identityDigest(ctx, message);
  const edSig = signature.slice(0, ED25519_SIGNATURE_SIZE);
  const mlSig = signature.slice(ED25519_SIGNATURE_SIZE);
  if (!ed25519.verify(edSig, digest, pub.edPk)) {
    throw new Error("zwing: ed25519 verify failed");
  }
  // Noble ml-dsa API: verify(sig, msg, pubKey).
  if (!ml_dsa65.verify(mlSig, digest, pub.mlPk)) {
    throw new Error("zwing: ml-dsa-65 verify failed");
  }
}

/** Constant-time equality of two public identities. */
export function identityEquals(a: IdentityPublic, b: IdentityPublic): boolean {
  return (
    constantTimeEq(a.edPk, b.edPk) &&
    constantTimeEq(a.mlPk, b.mlPk) &&
    constantTimeEq(a.xwingMlkemPk, b.xwingMlkemPk) &&
    constantTimeEq(a.xwingX25519Pk, b.xwingX25519Pk)
  );
}

function constantTimeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
