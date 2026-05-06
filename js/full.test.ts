import { describe, expect, it } from "vitest";

import { Channel, nonceFor } from "./channel.js";
import {
  HandshakeOutput,
  MAX_FRAME_SIZE,
  readFrame,
  runInitiator,
  runResponder,
  writeFrame,
} from "./handshake.js";
import type { DuplexStream } from "./handshake.js";
import {
  generateIdentity,
  identityEquals,
  marshalIdentityPublic,
  parseIdentityPublic,
  publicOf,
  signIdentity,
  verifyIdentity,
} from "./identity.js";
import { xwingDecapsulate, xwingEncapsulate } from "./kem.js";

/**
 * Async in-memory pipe pair so two sides of a handshake can run in
 * parallel via `Promise.all`.
 */
function pipe(): [DuplexStream, DuplexStream] {
  type Buf = { data: Uint8Array; resolve: (b: Uint8Array) => void };
  const queueAB: Uint8Array[] = [];
  const queueBA: Uint8Array[] = [];
  const waitersAB: ((b: Uint8Array) => void)[] = [];
  const waitersBA: ((b: Uint8Array) => void)[] = [];

  function makeReader(queue: Uint8Array[], waiters: ((b: Uint8Array) => void)[]) {
    let buf = new Uint8Array(0);
    return async function read(n: number): Promise<Uint8Array> {
      while (buf.length < n) {
        let chunk: Uint8Array;
        if (queue.length > 0) {
          chunk = queue.shift()!;
        } else {
          chunk = await new Promise<Uint8Array>((resolve) => {
            waiters.push(resolve);
          });
        }
        const merged = new Uint8Array(buf.length + chunk.length);
        merged.set(buf);
        merged.set(chunk, buf.length);
        buf = merged;
      }
      const out = buf.slice(0, n);
      buf = buf.slice(n);
      return out;
    };
  }

  function makeWriter(queue: Uint8Array[], waiters: ((b: Uint8Array) => void)[]) {
    return async function write(data: Uint8Array): Promise<void> {
      const copy = new Uint8Array(data);
      if (waiters.length > 0) {
        const resolve = waiters.shift()!;
        resolve(copy);
      } else {
        queue.push(copy);
      }
    };
  }

  const a: DuplexStream = {
    read: makeReader(queueBA, waitersBA),
    write: makeWriter(queueAB, waitersAB),
  };
  const b: DuplexStream = {
    read: makeReader(queueAB, waitersAB),
    write: makeWriter(queueBA, waitersBA),
  };
  return [a, b];
}

describe("Z-Wing full e2e (TS)", () => {
  it("identity sign + verify round trip", () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    const sig = signIdentity(id, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"));
    expect(() =>
      verifyIdentity(pub, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"), sig),
    ).not.toThrow();
  });

  it("verify rejects wrong message", () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    const sig = signIdentity(id, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"));
    expect(() =>
      verifyIdentity(pub, new TextEncoder().encode("ctx"), new TextEncoder().encode("bye"), sig),
    ).toThrow();
  });

  it("verify rejects wrong context", () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    const sig = signIdentity(id, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"));
    expect(() =>
      verifyIdentity(pub, new TextEncoder().encode("other"), new TextEncoder().encode("hi"), sig),
    ).toThrow();
  });

  it("verify rejects wrong-size signature", () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    expect(() =>
      verifyIdentity(
        pub,
        new TextEncoder().encode("ctx"),
        new TextEncoder().encode("hi"),
        new Uint8Array([1, 2, 3]),
      ),
    ).toThrow();
  });

  it("identity public marshal round trip", () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    const wire = marshalIdentityPublic(pub);
    const parsed = parseIdentityPublic(wire);
    expect(identityEquals(parsed, pub)).toBe(true);
  });

  it("rejects wrong-size identity public", () => {
    expect(() => parseIdentityPublic(new Uint8Array(10))).toThrow();
  });

  it("two distinct identities differ", () => {
    const a = publicOf(generateIdentity());
    const b = publicOf(generateIdentity());
    expect(identityEquals(a, b)).toBe(false);
  });

  it("xwing encap/decap round trip", () => {
    const recipient = generateIdentity();
    const { ciphertext, shared } = xwingEncapsulate(publicOf(recipient));
    const out = xwingDecapsulate(recipient, ciphertext);
    expect(out).toEqual(shared);
  });

  it("xwing decap rejects wrong size", () => {
    const id = generateIdentity();
    expect(() => xwingDecapsulate(id, new Uint8Array(10))).toThrow();
  });

  it("full handshake round trip via in-memory pipe", async () => {
    const client = generateIdentity();
    const server = generateIdentity();
    const [a, b] = pipe();
    const [cOut, sOut] = await Promise.all([
      runInitiator(a, client, publicOf(server)),
      runResponder(b, server, publicOf(client)),
    ]);
    expect(cOut.keyI2R).toEqual(sOut.keyI2R);
    expect(cOut.keyR2I).toEqual(sOut.keyR2I);
    expect(identityEquals(cOut.remote, publicOf(server))).toBe(true);
    expect(identityEquals(sOut.remote, publicOf(client))).toBe(true);
  });

  it("pinned remote mismatch rejected", async () => {
    const client = generateIdentity();
    const server = generateIdentity();
    const other = generateIdentity();
    const [a, b] = pipe();
    await expect(
      Promise.all([runInitiator(a, client, publicOf(other)), runResponder(b, server)]),
    ).rejects.toThrow();
  });

  it("e2e channel echo", async () => {
    const client = generateIdentity();
    const server = generateIdentity();
    const [a, b] = pipe();
    const [cOut, sOut] = await Promise.all([
      runInitiator(a, client, publicOf(server)),
      runResponder(b, server, publicOf(client)),
    ]);
    const cChan = new Channel(a, cOut, true);
    const sChan = new Channel(b, sOut, false);

    await cChan.send(new TextEncoder().encode("z-wing ts e2e"));
    const got = await sChan.recv();
    expect(new TextDecoder().decode(got)).toBe("z-wing ts e2e");

    await sChan.send(new TextEncoder().encode("ack"));
    const back = await cChan.recv();
    expect(new TextDecoder().decode(back)).toBe("ack");
  });

  it("write frame oversize rejected", async () => {
    const sink: DuplexStream = {
      read: async () => new Uint8Array(0),
      write: async () => {},
    };
    await expect(writeFrame(sink, new Uint8Array(MAX_FRAME_SIZE + 1))).rejects.toThrow();
  });

  it("read frame zero length rejected", async () => {
    let i = 0;
    const conn: DuplexStream = {
      read: async (n: number) => {
        if (i++ === 0) return new Uint8Array([0, 0, 0, 0]);
        return new Uint8Array(n);
      },
      write: async () => {},
    };
    await expect(readFrame(conn)).rejects.toThrow();
  });

  it("read frame oversize rejected", async () => {
    const conn: DuplexStream = {
      read: async () => new Uint8Array([0xff, 0xff, 0xff, 0xff]),
      write: async () => {},
    };
    await expect(readFrame(conn)).rejects.toThrow();
  });

  it("nonce_for has BE counter in low bytes", () => {
    expect(nonceFor(0n)).toEqual(new Uint8Array(12));
    const n1 = nonceFor(1n);
    expect(n1[11]).toBe(1);
    const nMax = nonceFor(0xffffffffffffffffn);
    for (let i = 4; i < 12; i++) expect(nMax[i]).toBe(0xff);
  });

  it("identityEquals length mismatch returns false", async () => {
    const { identityEquals } = await import("./identity.js");
    const a = {
      edPk: new Uint8Array(32),
      mlPk: new Uint8Array(1952),
      xwingMlkemPk: new Uint8Array(1184),
      xwingX25519Pk: new Uint8Array(32),
    };
    const b = {
      edPk: new Uint8Array(16), // wrong length
      mlPk: new Uint8Array(1952),
      xwingMlkemPk: new Uint8Array(1184),
      xwingX25519Pk: new Uint8Array(32),
    };
    expect(identityEquals(a, b)).toBe(false);
  });

  it("Channel rx overflow path", async () => {
    const sink: DuplexStream = {
      read: async () => new Uint8Array(0),
      write: async () => {},
    };
    const id = generateIdentity();
    const out: HandshakeOutput = {
      shared: new Uint8Array(32),
      remote: publicOf(id),
      keyI2R: new Uint8Array(32),
      keyR2I: new Uint8Array(32),
    };
    const chan = new Channel(sink, out, true);
    // Inject overflow buffer; recv must return it without touching the wire.
    (chan as any).rxOverflow = new TextEncoder().encode("hello-overflow");
    const got = await chan.recv();
    expect(new TextDecoder().decode(got)).toBe("hello-overflow");
  });

  it("Channel tx seq exhausted", async () => {
    const sink: DuplexStream = {
      read: async () => new Uint8Array(0),
      write: async () => {},
    };
    const id = generateIdentity();
    const out: HandshakeOutput = {
      shared: new Uint8Array(32),
      remote: publicOf(id),
      keyI2R: new Uint8Array(32),
      keyR2I: new Uint8Array(32),
    };
    const chan = new Channel(sink, out, true);
    (chan as any).txSeq = 0xffffffffffffffffn;
    await expect(chan.send(new Uint8Array([1]))).rejects.toThrow();
  });

  it("Channel rx seq exhausted", async () => {
    let frameRead = false;
    const stream: DuplexStream = {
      read: async (n) => {
        if (!frameRead) {
          frameRead = true;
          // Return a valid header for a 1-byte frame...
          if (n === 4) return new Uint8Array([0, 0, 0, 1]);
        }
        if (n === 1) return new Uint8Array([0]);
        return new Uint8Array(n);
      },
      write: async () => {},
    };
    const id = generateIdentity();
    const out: HandshakeOutput = {
      shared: new Uint8Array(32),
      remote: publicOf(id),
      keyI2R: new Uint8Array(32),
      keyR2I: new Uint8Array(32),
    };
    const chan = new Channel(stream, out, true);
    (chan as any).rxSeq = 0xffffffffffffffffn;
    await expect(chan.recv()).rejects.toThrow();
  });

  it("zwing combineXWing rejects every wrong-size input", async () => {
    const { combineXWing } = await import("./zwing.js");
    const ok = new Uint8Array(32);
    const short = new Uint8Array(31);
    expect(() => combineXWing(short, ok, ok, ok)).toThrow();
    expect(() => combineXWing(ok, short, ok, ok)).toThrow();
    expect(() => combineXWing(ok, ok, short, ok)).toThrow();
    expect(() => combineXWing(ok, ok, ok, short)).toThrow();
  });

  it("xwing wire decode errors", async () => {
    // Full wire round-trip already tested. Here we drive the few pure
    // decode error branches.
    const conn: DuplexStream = {
      read: async (n) => {
        // Fast-fail header read with an oversize length.
        if (n === 4) return new Uint8Array([0xff, 0xff, 0xff, 0xff]);
        return new Uint8Array(n);
      },
      write: async () => {},
    };
    await expect(readFrame(conn)).rejects.toThrow();
  });

  it("identity sign verify rejects corrupt mldsa half", async () => {
    const id = generateIdentity();
    const pub = publicOf(id);
    const sig = signIdentity(id, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"));
    sig[200] ^= 0xff; // mutate inside the ML-DSA portion
    expect(() =>
      verifyIdentity(pub, new TextEncoder().encode("ctx"), new TextEncoder().encode("hi"), sig),
    ).toThrow();
  });

  it("decodeHandshakeResponse short enc body rejected", async () => {
    const { __internal } = await import("./handshake.js");
    const { XWING_CIPHERTEXT_SIZE } = await import("./zwing.js");
    // Right-size ct, encLen=0xFFFF, no body.
    const buf = new Uint8Array(XWING_CIPHERTEXT_SIZE + 2);
    buf[XWING_CIPHERTEXT_SIZE] = 0xff;
    buf[XWING_CIPHERTEXT_SIZE + 1] = 0xff;
    expect(() => __internal.decodeHandshakeResponse(buf)).toThrow();
  });

  it("decodeHandshakeResponse trailing garbage rejected", async () => {
    const { __internal } = await import("./handshake.js");
    const { XWING_CIPHERTEXT_SIZE } = await import("./zwing.js");
    // Right-size ct, encLen=0, plus trailing byte.
    const buf = new Uint8Array(XWING_CIPHERTEXT_SIZE + 3);
    expect(() => __internal.decodeHandshakeResponse(buf)).toThrow();
  });

  it("splitRespIDPayload short sig rejected", async () => {
    const { __internal } = await import("./handshake.js");
    // idLen=0, sigLen=0xFFFF, no body.
    expect(() => __internal.splitRespIDPayload(new Uint8Array([0, 0, 0xff, 0xff]))).toThrow();
  });

  it("splitRespIDPayload trailing garbage rejected", async () => {
    const { __internal } = await import("./handshake.js");
    // idLen=0, sigLen=0, then extra byte.
    expect(() =>
      __internal.splitRespIDPayload(new Uint8Array([0, 0, 0, 0, 0x99])),
    ).toThrow();
  });

  it("responder pinned remote mismatch rejected", async () => {
    const client = generateIdentity();
    const server = generateIdentity();
    const other = generateIdentity();
    const [a, b] = pipe();
    await expect(
      Promise.all([runInitiator(a, client), runResponder(b, server, publicOf(other))]),
    ).rejects.toThrow();
  });

  it("splitRespIDPayload short pre-idLen rejected", async () => {
    const { __internal } = await import("./handshake.js");
    expect(() => __internal.splitRespIDPayload(new Uint8Array(0))).toThrow();
    expect(() => __internal.splitRespIDPayload(new Uint8Array([0]))).toThrow();
  });

  it("splitRespIDPayload short id rejected", async () => {
    const { __internal } = await import("./handshake.js");
    // idLen=10 but buffer only 2 bytes long.
    expect(() =>
      __internal.splitRespIDPayload(new Uint8Array([0, 10])),
    ).toThrow();
  });

  it("decodeHandshakeResponse rejects pre-XWING-CT-length buffer", async () => {
    const { __internal } = await import("./handshake.js");
    expect(() => __internal.decodeHandshakeResponse(new Uint8Array(50))).toThrow();
  });

  it("decodeHandshakeInit short reads at every boundary", async () => {
    const { __internal } = await import("./handshake.js");
    expect(() => __internal.decodeHandshakeInit(new Uint8Array(0))).toThrow();
    expect(() => __internal.decodeHandshakeInit(new Uint8Array([0]))).toThrow();
    // idLen=1, no id body.
    expect(() => __internal.decodeHandshakeInit(new Uint8Array([0, 1]))).toThrow();
    // idLen=1, id="A", no sigLen.
    expect(() =>
      __internal.decodeHandshakeInit(new Uint8Array([0, 1, 0x41])),
    ).toThrow();
    // idLen=0, sigLen=0xFFFF, no body.
    expect(() =>
      __internal.decodeHandshakeInit(new Uint8Array([0, 0, 0xff, 0xff])),
    ).toThrow();
    // idLen=0, sigLen=0, trailing garbage.
    expect(() =>
      __internal.decodeHandshakeInit(new Uint8Array([0, 0, 0, 0, 0x99])),
    ).toThrow();
  });
});
