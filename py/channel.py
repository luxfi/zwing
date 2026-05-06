"""Z-Wing post-handshake encrypted channel (Python).

ChaCha20-Poly1305 over length-prefixed frames with sequence-numbered
nonces. Wire format identical to Go and Rust.
"""

from __future__ import annotations

import struct
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from handshake import DuplexStream, HandshakeOutput, MAX_FRAME_SIZE, read_frame, write_frame
from identity import IdentityPublic

CHACHA_OVERHEAD = 16
NONCE_LEN = 12


def nonce_for(seq: int) -> bytes:
    """12-byte nonce: high 4 bytes zero, low 8 bytes BE counter."""
    n = bytearray(NONCE_LEN)
    n[NONCE_LEN - 8 :] = struct.pack(">Q", seq)
    return bytes(n)


class Channel:
    """Post-handshake Z-Wing secure channel."""

    def __init__(
        self, inner: DuplexStream, out: HandshakeOutput, initiator: bool
    ) -> None:
        self._inner = inner
        self.remote: IdentityPublic = out.remote
        if initiator:
            tx_key = out.key_i2r
            rx_key = out.key_r2i
        else:
            tx_key = out.key_r2i
            rx_key = out.key_i2r
        self._tx = ChaCha20Poly1305(tx_key)
        self._rx = ChaCha20Poly1305(rx_key)
        self._tx_seq = 0
        self._rx_seq = 0
        self._rx_overflow: Optional[bytes] = None

    def send(self, plaintext: bytes) -> None:
        max_plain = MAX_FRAME_SIZE - CHACHA_OVERHEAD
        written = 0
        while written < len(plaintext):
            end = min(written + max_plain, len(plaintext))
            chunk = plaintext[written:end]
            if self._tx_seq >= (1 << 64) - 1:
                raise ValueError("zwing: AEAD sequence number exhausted")
            nonce = nonce_for(self._tx_seq)
            ct = self._tx.encrypt(nonce, chunk, None)
            self._tx_seq += 1
            write_frame(self._inner, ct)
            written = end

    def recv(self) -> bytes:
        if self._rx_overflow is not None:
            buf = self._rx_overflow
            self._rx_overflow = None
            return buf
        frame = read_frame(self._inner)
        if self._rx_seq >= (1 << 64) - 1:
            raise ValueError("zwing: AEAD sequence number exhausted")
        nonce = nonce_for(self._rx_seq)
        pt = self._rx.decrypt(nonce, frame, None)
        self._rx_seq += 1
        return pt
