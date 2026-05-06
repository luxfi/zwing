/**
 * Z-Wing post-handshake encrypted channel for TypeScript.
 *
 * Wraps a `DuplexStream` with ChaCha20-Poly1305 records using
 * sequence-numbered nonces. Wire format matches the Go and Rust
 * implementations byte-for-byte.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha.js";

import {
  DuplexStream,
  HandshakeOutput,
  MAX_FRAME_SIZE,
  readFrame,
  writeFrame,
} from "./handshake.js";
import type { IdentityPublic } from "./identity.js";

const CHACHA_OVERHEAD = 16;
const NONCE_LEN = 12;

/** Build the 12-byte nonce from a 64-bit BE counter. */
export function nonceFor(seq: bigint): Uint8Array {
  const n = new Uint8Array(NONCE_LEN);
  for (let i = 0; i < 8; i++) {
    n[NONCE_LEN - 1 - i] = Number((seq >> BigInt(i * 8)) & 0xffn);
  }
  return n;
}

export class Channel {
  private inner: DuplexStream;
  public readonly remote: IdentityPublic;
  private rxKey: Uint8Array;
  private txKey: Uint8Array;
  private rxSeq = 0n;
  private txSeq = 0n;
  private rxOverflow: Uint8Array | null = null;

  constructor(inner: DuplexStream, out: HandshakeOutput, initiator: boolean) {
    this.inner = inner;
    this.remote = out.remote;
    if (initiator) {
      this.txKey = out.keyI2R;
      this.rxKey = out.keyR2I;
    } else {
      this.txKey = out.keyR2I;
      this.rxKey = out.keyI2R;
    }
    // Best-effort wipe of the handshake-side keys.
    out.shared.fill(0);
    // Note: keyI2R / keyR2I have been copied into rxKey / txKey above
    // by reference — wiping them is the responsibility of the caller
    // since we don't own the original buffers exclusively.
  }

  /** Encrypt and send a single record. Splits if larger than MAX. */
  async send(plaintext: Uint8Array): Promise<void> {
    const maxPlain = MAX_FRAME_SIZE - CHACHA_OVERHEAD;
    let written = 0;
    while (written < plaintext.length) {
      const end = Math.min(written + maxPlain, plaintext.length);
      const chunk = plaintext.slice(written, end);
      if (this.txSeq === 0xffffffffffffffffn) {
        throw new Error("zwing: AEAD sequence number exhausted");
      }
      const nonce = nonceFor(this.txSeq);
      const ct = chacha20poly1305(this.txKey, nonce).encrypt(chunk);
      this.txSeq += 1n;
      await writeFrame(this.inner, ct);
      written = end;
    }
  }

  /** Receive one full record. */
  async recv(): Promise<Uint8Array> {
    if (this.rxOverflow) {
      const buf = this.rxOverflow;
      this.rxOverflow = null;
      return buf;
    }
    const frame = await readFrame(this.inner);
    if (this.rxSeq === 0xffffffffffffffffn) {
      throw new Error("zwing: AEAD sequence number exhausted");
    }
    const nonce = nonceFor(this.rxSeq);
    const pt = chacha20poly1305(this.rxKey, nonce).decrypt(frame);
    this.rxSeq += 1n;
    return pt;
  }
}
