/**
 * Z-Wing 1-RTT mutual-auth handshake (TypeScript).
 *
 * Bit-for-bit compatible with the Go and Rust implementations. All
 * HKDF / transcript / AEAD labels are identical.
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

import {
  Identity,
  IdentityPublic,
  identityEquals,
  marshalIdentityPublic,
  parseIdentityPublic,
  signIdentity,
  verifyIdentity,
} from "./identity.js";
import { xwingDecapsulate, xwingEncapsulate } from "./kem.js";
import { XWING_CIPHERTEXT_SIZE } from "./zwing.js";

export const MAX_FRAME_SIZE = 1 << 20; // 1 MiB
export const HS_LABEL_INIT = new TextEncoder().encode(
  "lux.zwing.v1/handshake-init",
);
export const HS_LABEL_RESPONSE = new TextEncoder().encode(
  "lux.zwing.v1/handshake-response",
);
export const CHANNEL_KEY_LABEL_I2R = new TextEncoder().encode(
  "lux.zwing.v1/i2r",
);
export const CHANNEL_KEY_LABEL_R2I = new TextEncoder().encode(
  "lux.zwing.v1/r2i",
);
export const RESP_ID_HKDF_LABEL = new TextEncoder().encode(
  "lux.zwing.v1/resp-id",
);
export const RESP_ID_NONCE_LABEL = new TextEncoder().encode("zwing-resp-id");
export const TRANSCRIPT_LABEL = new TextEncoder().encode(
  "lux.zwing.v1/transcript",
);

/** Outcome of a successful handshake. */
export interface HandshakeOutput {
  shared: Uint8Array;
  remote: IdentityPublic;
  keyI2R: Uint8Array;
  keyR2I: Uint8Array;
}

/**
 * Asynchronous full-duplex byte stream interface — abstracts away
 * network/socket specifics so the handshake works over any duplex
 * medium (TCP, in-memory pipe, Web socket, RNS link).
 */
export interface DuplexStream {
  read(n: number): Promise<Uint8Array>;
  write(data: Uint8Array): Promise<void>;
}

/** Drive the initiator side of the handshake. */
export async function runInitiator(
  conn: DuplexStream,
  local: Identity,
  expectedRemote?: IdentityPublic,
): Promise<HandshakeOutput> {
  // 1. Send HandshakeInit.
  const idPub = marshalIdentityPublic({
    edPk: local.edPk,
    mlPk: local.mlPk,
    xwingMlkemPk: local.xwingMlkemPk,
    xwingX25519Pk: local.xwingX25519Pk,
  });
  const sig = signIdentity(local, HS_LABEL_INIT, idPub);
  await writeFrame(conn, encodeHandshakeInit(idPub, sig));

  // 2. Receive HandshakeResponse.
  const respFrame = await readFrame(conn);
  const { ct, encrypted } = decodeHandshakeResponse(respFrame);

  // 3. Decapsulate.
  const shared = xwingDecapsulate(local, ct);

  // 4. AEAD-open responder identity payload.
  const idKey = deriveKey(shared, RESP_ID_HKDF_LABEL);
  const plaintext = aeadOpen(idKey, RESP_ID_NONCE_LABEL, ct, encrypted);

  const { id: remoteIdBytes, sig: remoteSig } = splitRespIDPayload(plaintext);
  const remote = parseIdentityPublic(remoteIdBytes);

  // 5. Verify responder sig over transcript.
  const transcript = transcriptHash(idPub, ct);
  verifyIdentity(remote, HS_LABEL_RESPONSE, transcript, remoteSig);

  // 6. Optional pinning.
  if (expectedRemote && !identityEquals(remote, expectedRemote)) {
    throw new Error("zwing: remote identity does not match expected");
  }

  return {
    shared,
    remote,
    keyI2R: deriveKey(shared, CHANNEL_KEY_LABEL_I2R),
    keyR2I: deriveKey(shared, CHANNEL_KEY_LABEL_R2I),
  };
}

/** Drive the responder side of the handshake. */
export async function runResponder(
  conn: DuplexStream,
  local: Identity,
  expectedRemote?: IdentityPublic,
): Promise<HandshakeOutput> {
  // 1. Read HandshakeInit.
  const initFrame = await readFrame(conn);
  const { idPub, sig: initSig } = decodeHandshakeInit(initFrame);
  const remote = parseIdentityPublic(idPub);
  verifyIdentity(remote, HS_LABEL_INIT, idPub, initSig);

  if (expectedRemote && !identityEquals(remote, expectedRemote)) {
    throw new Error("zwing: remote identity does not match expected");
  }

  // 2. Encapsulate to initiator's static X-Wing.
  const { ciphertext: ct, shared } = xwingEncapsulate(remote);

  // 3. Sign transcript and seal.
  const localIdPub = marshalIdentityPublic({
    edPk: local.edPk,
    mlPk: local.mlPk,
    xwingMlkemPk: local.xwingMlkemPk,
    xwingX25519Pk: local.xwingX25519Pk,
  });
  const transcript = transcriptHash(idPub, ct);
  const sig = signIdentity(local, HS_LABEL_RESPONSE, transcript);
  const plaintext = buildRespIDPayload(localIdPub, sig);
  const idKey = deriveKey(shared, RESP_ID_HKDF_LABEL);
  const encrypted = aeadSeal(idKey, RESP_ID_NONCE_LABEL, ct, plaintext);

  await writeFrame(conn, encodeHandshakeResponse(ct, encrypted));

  return {
    shared,
    remote,
    keyI2R: deriveKey(shared, CHANNEL_KEY_LABEL_I2R),
    keyR2I: deriveKey(shared, CHANNEL_KEY_LABEL_R2I),
  };
}

// ─── wire helpers ──────────────────────────────────────────────────

export async function writeFrame(
  conn: DuplexStream,
  payload: Uint8Array,
): Promise<void> {
  if (payload.length > MAX_FRAME_SIZE) {
    throw new Error("zwing: message exceeds maximum size");
  }
  const hdr = new Uint8Array(4);
  const dv = new DataView(hdr.buffer);
  dv.setUint32(0, payload.length, false);
  await conn.write(hdr);
  await conn.write(payload);
}

export async function readFrame(conn: DuplexStream): Promise<Uint8Array> {
  const hdr = await conn.read(4);
  const dv = new DataView(hdr.buffer, hdr.byteOffset, 4);
  const n = dv.getUint32(0, false);
  if (n > MAX_FRAME_SIZE) {
    throw new Error("zwing: message exceeds maximum size");
  }
  if (n === 0) {
    throw new Error("zwing: invalid wire format");
  }
  return await conn.read(n);
}

function encodeHandshakeInit(idPub: Uint8Array, sig: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + idPub.length + sig.length);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, idPub.length, false);
  out.set(idPub, 2);
  dv.setUint16(2 + idPub.length, sig.length, false);
  out.set(sig, 4 + idPub.length);
  return out;
}

function decodeHandshakeInit(data: Uint8Array): {
  idPub: Uint8Array;
  sig: Uint8Array;
} {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < 2) throw new Error("zwing: short read");
  const idLen = dv.getUint16(0, false);
  if (data.length < 2 + idLen + 2) throw new Error("zwing: short read");
  const idPub = data.slice(2, 2 + idLen);
  const sigLen = dv.getUint16(2 + idLen, false);
  const sigStart = 4 + idLen;
  if (data.length < sigStart + sigLen) throw new Error("zwing: short read");
  const sig = data.slice(sigStart, sigStart + sigLen);
  if (data.length !== sigStart + sigLen) {
    throw new Error("zwing: invalid wire format");
  }
  return { idPub, sig };
}

function encodeHandshakeResponse(ct: Uint8Array, encrypted: Uint8Array): Uint8Array {
  const out = new Uint8Array(ct.length + 2 + encrypted.length);
  out.set(ct, 0);
  const dv = new DataView(out.buffer);
  dv.setUint16(ct.length, encrypted.length, false);
  out.set(encrypted, ct.length + 2);
  return out;
}

function decodeHandshakeResponse(data: Uint8Array): {
  ct: Uint8Array;
  encrypted: Uint8Array;
} {
  if (data.length < XWING_CIPHERTEXT_SIZE + 2) {
    throw new Error("zwing: invalid wire format");
  }
  const ct = data.slice(0, XWING_CIPHERTEXT_SIZE);
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const encLen = dv.getUint16(XWING_CIPHERTEXT_SIZE, false);
  const encStart = XWING_CIPHERTEXT_SIZE + 2;
  if (data.length < encStart + encLen) {
    throw new Error("zwing: short read");
  }
  const encrypted = data.slice(encStart, encStart + encLen);
  if (data.length !== encStart + encLen) {
    throw new Error("zwing: invalid wire format");
  }
  return { ct, encrypted };
}

function buildRespIDPayload(id: Uint8Array, sig: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + id.length + sig.length);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, id.length, false);
  out.set(id, 2);
  dv.setUint16(2 + id.length, sig.length, false);
  out.set(sig, 4 + id.length);
  return out;
}

function splitRespIDPayload(data: Uint8Array): {
  id: Uint8Array;
  sig: Uint8Array;
} {
  if (data.length < 2) throw new Error("zwing: short read");
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const idLen = dv.getUint16(0, false);
  if (data.length < 2 + idLen + 2) throw new Error("zwing: short read");
  const id = data.slice(2, 2 + idLen);
  const sigLen = dv.getUint16(2 + idLen, false);
  const sigStart = 4 + idLen;
  if (data.length < sigStart + sigLen) throw new Error("zwing: short read");
  const sig = data.slice(sigStart, sigStart + sigLen);
  if (data.length !== sigStart + sigLen) {
    throw new Error("zwing: invalid wire format");
  }
  return { id, sig };
}

// Internal helpers exported only for branch-coverage tests. Not part
// of the public API.
export const __internal = {
  encodeHandshakeInit,
  decodeHandshakeInit,
  encodeHandshakeResponse,
  decodeHandshakeResponse,
  buildRespIDPayload,
  splitRespIDPayload,
};

// ─── KDF / transcript / AEAD ──────────────────────────────────────

export function deriveKey(secret: Uint8Array, label: Uint8Array): Uint8Array {
  return hkdf(sha256, secret, undefined, label, 32);
}

function transcriptHash(initPub: Uint8Array, ct: Uint8Array): Uint8Array {
  const h = sha256.create();
  h.update(TRANSCRIPT_LABEL);
  const lenBuf = new Uint8Array(4);
  const dv = new DataView(lenBuf.buffer);
  dv.setUint32(0, initPub.length, false);
  h.update(lenBuf);
  h.update(initPub);
  dv.setUint32(0, ct.length, false);
  h.update(lenBuf);
  h.update(ct);
  return h.digest();
}

function aeadSeal(
  key: Uint8Array,
  nonceLabel: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const nonce = handshakeNonce(nonceLabel);
  return chacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

function aeadOpen(
  key: Uint8Array,
  nonceLabel: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const nonce = handshakeNonce(nonceLabel);
  return chacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

function handshakeNonce(label: Uint8Array): Uint8Array {
  const n = new Uint8Array(12);
  const copy = Math.min(label.length, 12);
  n.set(label.slice(0, copy));
  return n;
}
