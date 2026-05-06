"""End-to-end interop test: Python Z-Wing client ↔ Go Z-Wing server.

Spawns the Go test server (built from cmd/zwing-test-server), reads the
listen address and the server's public-identity hex from its stdout, then
connects with a Python initiator pinning that identity. If the handshake
completes and the encrypted echo round-trips, full Go↔Python wire-byte
interop is proven for X-Wing KEM + ML-DSA-65 hybrid identity +
ChaCha20-Poly1305 channel records.

Usage:

    cd py && python3 test_interop_go.py

Requires the test server binary at /tmp/zwing-test-server (built by
``cd .. && go build -o /tmp/zwing-test-server ./cmd/zwing-test-server``).
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import unittest

# Make sure py/ is on sys.path when executed from anywhere.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from channel import Channel
from handshake import run_initiator
from identity import (
    generate_identity,
    parse_identity_public,
    public_of,
)


SERVER_BIN = "/tmp/zwing-test-server"


class _SocketStream:
    """Adapter: socket.socket → DuplexStream-shaped read/write."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise ConnectionError("zwing: remote closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def write(self, data: bytes) -> None:
        self._sock.sendall(data)


class GoPythonInterop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.exists(SERVER_BIN):
            raise unittest.SkipTest(f"server binary missing at {SERVER_BIN}")

    def test_python_client_to_go_server_handshake_and_echo(self):
        # Spawn the Go server. It prints the listen addr on the first
        # stdout line and the server public-identity hex on the second.
        proc = subprocess.Popen(
            [SERVER_BIN, "-addr", "127.0.0.1:0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            addr_line = proc.stdout.readline().strip()
            pub_hex = proc.stdout.readline().strip()
            self.assertNotEqual(addr_line, "", "no addr from go server")
            self.assertNotEqual(pub_hex, "", "no pubkey from go server")

            host, port_s = addr_line.rsplit(":", 1)
            port = int(port_s)
            server_pub = parse_identity_public(bytes.fromhex(pub_hex))

            client = generate_identity()
            sock = socket.create_connection((host, port), timeout=10.0)
            try:
                stream = _SocketStream(sock)
                out = run_initiator(stream, client, server_pub)
                chan = Channel(stream, out, initiator=True)

                payload = b"hello from Python initiator"
                chan.send(payload)
                got = chan.recv()
                self.assertEqual(got, payload)
            finally:
                sock.close()

            # Server should exit cleanly within a few seconds.
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=2)

            stderr_out = proc.stderr.read()
            self.assertEqual(
                proc.returncode,
                0,
                msg=f"go server exit={proc.returncode}\nstderr=\n{stderr_out}",
            )
        finally:
            if proc.poll() is None:
                # Drain stderr to surface what the server saw.
                try:
                    err = proc.stderr.read()
                    print(f"go server stderr:\n{err}", file=sys.stderr)
                except Exception:
                    pass
                proc.kill()
                proc.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
