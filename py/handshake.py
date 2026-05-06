"""Z-Wing 1-RTT mutual-auth handshake (Python).

Bit-for-bit compatible with the Go and Rust ports. Uses sync I/O over
any object with ``read(n)`` / ``write(data)`` methods.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Optional, Protocol

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from zwing import XWING_CIPHERTEXT_SIZE
from identity import (
    Identity,
    IdentityPublic,
    identity_equals,
    marshal_identity_public,
    parse_identity_public,
    sign_identity,
    verify_identity,
)
from kem import xwing_decapsulate, xwing_encapsulate

MAX_FRAME_SIZE = 1 << 20  # 1 MiB

HS_LABEL_INIT = b"lux.zwing.v1/handshake-init"
HS_LABEL_RESPONSE = b"lux.zwing.v1/handshake-response"
CHANNEL_KEY_LABEL_I2R = b"lux.zwing.v1/i2r"
CHANNEL_KEY_LABEL_R2I = b"lux.zwing.v1/r2i"
RESP_ID_HKDF_LABEL = b"lux.zwing.v1/resp-id"
RESP_ID_NONCE_LABEL = b"zwing-resp-id"
TRANSCRIPT_LABEL = b"lux.zwing.v1/transcript"


class DuplexStream(Protocol):
    def read(self, n: int) -> bytes: ...
    def write(self, data: bytes) -> None: ...


class HandshakeOutput:
    """Both peers' shared post-handshake state."""

    def __init__(
        self,
        shared: bytes,
        remote: IdentityPublic,
        key_i2r: bytes,
        key_r2i: bytes,
    ) -> None:
        self.shared = shared
        self.remote = remote
        self.key_i2r = key_i2r
        self.key_r2i = key_r2i


def run_initiator(
    conn: DuplexStream,
    local: Identity,
    expected_remote: Optional[IdentityPublic] = None,
) -> HandshakeOutput:
    # 1. Send HandshakeInit.
    from identity import public_of  # avoid cycle at import time

    id_pub = marshal_identity_public(public_of(local))
    sig = sign_identity(local, HS_LABEL_INIT, id_pub)
    write_frame(conn, _encode_handshake_init(id_pub, sig))

    # 2. Receive HandshakeResponse.
    resp_frame = read_frame(conn)
    ct, encrypted = _decode_handshake_response(resp_frame)

    # 3. Decapsulate.
    shared = xwing_decapsulate(local, ct)

    # 4. AEAD-open responder identity payload.
    id_key = derive_key(shared, RESP_ID_HKDF_LABEL)
    plaintext = _aead_open(id_key, RESP_ID_NONCE_LABEL, ct, encrypted)

    remote_id_bytes, remote_sig = _split_resp_id_payload(plaintext)
    remote = parse_identity_public(remote_id_bytes)

    # 5. Verify responder sig over transcript.
    transcript = _transcript_hash(id_pub, ct)
    verify_identity(remote, HS_LABEL_RESPONSE, transcript, remote_sig)

    # 6. Optional pinning.
    if expected_remote is not None and not identity_equals(remote, expected_remote):
        raise ValueError("zwing: remote identity does not match expected")

    return HandshakeOutput(
        shared=shared,
        remote=remote,
        key_i2r=derive_key(shared, CHANNEL_KEY_LABEL_I2R),
        key_r2i=derive_key(shared, CHANNEL_KEY_LABEL_R2I),
    )


def run_responder(
    conn: DuplexStream,
    local: Identity,
    expected_remote: Optional[IdentityPublic] = None,
) -> HandshakeOutput:
    # 1. Read HandshakeInit.
    init_frame = read_frame(conn)
    id_pub, init_sig = _decode_handshake_init(init_frame)
    remote = parse_identity_public(id_pub)
    verify_identity(remote, HS_LABEL_INIT, id_pub, init_sig)

    if expected_remote is not None and not identity_equals(remote, expected_remote):
        raise ValueError("zwing: remote identity does not match expected")

    # 2. Encapsulate to initiator's static X-Wing.
    ct, shared = xwing_encapsulate(remote)

    # 3. Sign transcript and seal.
    from identity import public_of

    local_id_pub = marshal_identity_public(public_of(local))
    transcript = _transcript_hash(id_pub, ct)
    sig = sign_identity(local, HS_LABEL_RESPONSE, transcript)
    plaintext = _build_resp_id_payload(local_id_pub, sig)
    id_key = derive_key(shared, RESP_ID_HKDF_LABEL)
    encrypted = _aead_seal(id_key, RESP_ID_NONCE_LABEL, ct, plaintext)

    write_frame(conn, _encode_handshake_response(ct, encrypted))

    return HandshakeOutput(
        shared=shared,
        remote=remote,
        key_i2r=derive_key(shared, CHANNEL_KEY_LABEL_I2R),
        key_r2i=derive_key(shared, CHANNEL_KEY_LABEL_R2I),
    )


# ─── wire helpers ──────────────────────────────────────────────────


def write_frame(conn: DuplexStream, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError("zwing: message exceeds maximum size")
    hdr = struct.pack(">I", len(payload))
    conn.write(hdr)
    conn.write(payload)


def read_frame(conn: DuplexStream) -> bytes:
    hdr = _read_exact(conn, 4)
    (n,) = struct.unpack(">I", hdr)
    if n > MAX_FRAME_SIZE:
        raise ValueError("zwing: message exceeds maximum size")
    if n == 0:
        raise ValueError("zwing: invalid wire format")
    return _read_exact(conn, n)


def _read_exact(conn: DuplexStream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.read(n - len(buf))
        if not chunk:
            raise ValueError("zwing: short read")
        buf += chunk
    return buf


def _encode_handshake_init(id_pub: bytes, sig: bytes) -> bytes:
    return (
        struct.pack(">H", len(id_pub))
        + id_pub
        + struct.pack(">H", len(sig))
        + sig
    )


def _decode_handshake_init(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < 2:
        raise ValueError("zwing: short read")
    (id_len,) = struct.unpack(">H", data[:2])
    if len(data) < 2 + id_len + 2:
        raise ValueError("zwing: short read")
    id_pub = data[2 : 2 + id_len]
    (sig_len,) = struct.unpack(">H", data[2 + id_len : 4 + id_len])
    sig_start = 4 + id_len
    if len(data) < sig_start + sig_len:
        raise ValueError("zwing: short read")
    sig = data[sig_start : sig_start + sig_len]
    if len(data) != sig_start + sig_len:
        raise ValueError("zwing: invalid wire format")
    return id_pub, sig


def _encode_handshake_response(ct: bytes, encrypted: bytes) -> bytes:
    return ct + struct.pack(">H", len(encrypted)) + encrypted


def _decode_handshake_response(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < XWING_CIPHERTEXT_SIZE + 2:
        raise ValueError("zwing: invalid wire format")
    ct = data[:XWING_CIPHERTEXT_SIZE]
    (enc_len,) = struct.unpack(">H", data[XWING_CIPHERTEXT_SIZE : XWING_CIPHERTEXT_SIZE + 2])
    enc_start = XWING_CIPHERTEXT_SIZE + 2
    if len(data) < enc_start + enc_len:
        raise ValueError("zwing: short read")
    encrypted = data[enc_start : enc_start + enc_len]
    if len(data) != enc_start + enc_len:
        raise ValueError("zwing: invalid wire format")
    return ct, encrypted


def _build_resp_id_payload(id_bytes: bytes, sig: bytes) -> bytes:
    return (
        struct.pack(">H", len(id_bytes))
        + id_bytes
        + struct.pack(">H", len(sig))
        + sig
    )


def _split_resp_id_payload(data: bytes) -> tuple[bytes, bytes]:
    if len(data) < 2:
        raise ValueError("zwing: short read")
    (id_len,) = struct.unpack(">H", data[:2])
    if len(data) < 2 + id_len + 2:
        raise ValueError("zwing: short read")
    id_bytes = data[2 : 2 + id_len]
    (sig_len,) = struct.unpack(">H", data[2 + id_len : 4 + id_len])
    sig_start = 4 + id_len
    if len(data) < sig_start + sig_len:
        raise ValueError("zwing: short read")
    sig = data[sig_start : sig_start + sig_len]
    if len(data) != sig_start + sig_len:
        raise ValueError("zwing: invalid wire format")
    return id_bytes, sig


# ─── KDF / transcript / AEAD ──────────────────────────────────────


def derive_key(secret: bytes, label: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256(secret, salt='', info=label) → 32 bytes."""
    # Extract.
    prk = hmac.new(b"", secret, hashlib.sha256).digest()
    # Expand.
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + label + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _transcript_hash(init_pub: bytes, ct: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(TRANSCRIPT_LABEL)
    h.update(struct.pack(">I", len(init_pub)))
    h.update(init_pub)
    h.update(struct.pack(">I", len(ct)))
    h.update(ct)
    return h.digest()


def _aead_seal(key: bytes, nonce_label: bytes, aad: bytes, plaintext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = _handshake_nonce(nonce_label)
    return aead.encrypt(nonce, plaintext, aad)


def _aead_open(key: bytes, nonce_label: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    aead = ChaCha20Poly1305(key)
    nonce = _handshake_nonce(nonce_label)
    return aead.decrypt(nonce, ciphertext, aad)


def _handshake_nonce(label: bytes) -> bytes:
    n = bytearray(12)
    copy = min(len(label), 12)
    n[:copy] = label[:copy]
    return bytes(n)
