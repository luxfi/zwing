/**
 * End-to-end interop test: TypeScript Z-Wing client ↔ Go Z-Wing server.
 *
 * Spawns the Go test server (built from cmd/zwing-test-server), reads
 * the listen address and server identity hex from its stdout, opens a
 * TCP socket, and runs a full Z-Wing handshake + AEAD echo round trip
 * against it. If this test passes, every wire byte from
 * HandshakeInit/HandshakeResponse and every record on the post-handshake
 * channel is bit-identical between the Go and TypeScript implementations.
 */

import { spawn } from "node:child_process";
import { Socket, connect } from "node:net";
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { Channel } from "./channel.js";
import { runInitiator, type DuplexStream } from "./handshake.js";
import {
  generateIdentity,
  parseIdentityPublic,
  publicOf,
} from "./identity.js";

const SERVER_BIN = "/tmp/zwing-test-server";

class SocketStream implements DuplexStream {
  private buf = new Uint8Array(0);
  // Single waiter at a time: each pending read knows how many bytes it
  // needs. When new data arrives we either satisfy it or wait again.
  private pending:
    | { n: number; resolve: (b: Uint8Array) => void; reject: (e: Error) => void }
    | null = null;
  private closed = false;
  private closeErr: Error | null = null;

  constructor(private sock: Socket) {
    sock.on("data", (chunk) => {
      const merged = new Uint8Array(this.buf.length + chunk.length);
      merged.set(this.buf);
      merged.set(chunk, this.buf.length);
      this.buf = merged;
      this.tryDeliver();
    });
    sock.on("close", () => {
      this.closed = true;
      this.closeErr = this.closeErr ?? new Error("socket closed");
      if (this.pending) {
        this.pending.reject(this.closeErr);
        this.pending = null;
      }
    });
    sock.on("error", (err) => {
      this.closed = true;
      this.closeErr = err;
      if (this.pending) {
        this.pending.reject(err);
        this.pending = null;
      }
    });
  }

  private tryDeliver() {
    if (!this.pending) return;
    if (this.buf.length < this.pending.n) return;
    const out = this.buf.slice(0, this.pending.n);
    this.buf = this.buf.slice(this.pending.n);
    const p = this.pending;
    this.pending = null;
    p.resolve(out);
  }

  async read(n: number): Promise<Uint8Array> {
    if (this.buf.length >= n) {
      const out = this.buf.slice(0, n);
      this.buf = this.buf.slice(n);
      return out;
    }
    if (this.closed) {
      throw this.closeErr ?? new Error("socket closed");
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending = { n, resolve, reject };
      this.tryDeliver();
    });
  }

  async write(data: Uint8Array): Promise<void> {
    return new Promise((resolve, reject) => {
      this.sock.write(Buffer.from(data), (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }
}

describe("Z-Wing TS ↔ Go interop", () => {
  it.skipIf(!existsSync(SERVER_BIN))(
    "TS client connects to Go server, completes handshake, echoes payload",
    async () => {
      // Spawn Go server.
      const proc = spawn(SERVER_BIN, ["-addr", "127.0.0.1:0"], {
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdoutBuf = "";
      const lines: string[] = [];
      const lineWaiters: Array<() => void> = [];

      proc.stdout.on("data", (chunk: Buffer) => {
        stdoutBuf += chunk.toString();
        let nl: number;
        while ((nl = stdoutBuf.indexOf("\n")) !== -1) {
          lines.push(stdoutBuf.slice(0, nl));
          stdoutBuf = stdoutBuf.slice(nl + 1);
          const w = lineWaiters.shift();
          if (w) w();
        }
      });

      const stderrChunks: Buffer[] = [];
      proc.stderr.on("data", (c: Buffer) => stderrChunks.push(c));

      async function readLine(): Promise<string> {
        if (lines.length > 0) return lines.shift()!;
        await new Promise<void>((resolve) => lineWaiters.push(resolve));
        return lines.shift()!;
      }

      try {
        const addr = await readLine();
        const pubHex = await readLine();
        expect(addr).toMatch(/^127\.0\.0\.1:\d+$/);
        expect(pubHex.length).toBeGreaterThan(0);

        const [host, portStr] = addr.split(":");
        const port = Number(portStr);
        const serverPub = parseIdentityPublic(Buffer.from(pubHex, "hex"));

        const sock = connect({ host, port });
        await new Promise<void>((resolve, reject) => {
          sock.once("connect", () => resolve());
          sock.once("error", reject);
        });

        try {
          const stream = new SocketStream(sock);
          const client = generateIdentity();
          const out = await runInitiator(stream, client, serverPub);
          const chan = new Channel(stream, out, true);

          const payload = new TextEncoder().encode("hello from TS initiator");
          await chan.send(payload);
          const got = await chan.recv();
          expect(new TextDecoder().decode(got)).toBe("hello from TS initiator");
        } finally {
          sock.end();
        }

        const exit = await new Promise<number | null>((resolve) => {
          proc.on("exit", (code) => resolve(code));
          setTimeout(() => resolve(-1), 5000);
        });
        if (exit !== 0) {
          const stderr = Buffer.concat(stderrChunks).toString();
          throw new Error(`go server exit=${exit}\nstderr:\n${stderr}`);
        }
      } finally {
        if (proc.exitCode === null) proc.kill();
      }
    },
    20_000,
  );
});
