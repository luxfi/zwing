"""IETF X-Wing KEM (Python) — encap/decap matching the Go and Rust ports."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_768

from zwing import (
    MLKEM768_CIPHERTEXT_SIZE,
    XWING_CIPHERTEXT_SIZE,
    XWING_SHARED_SIZE,
    X25519_POINT_SIZE,
    combine_xwing,
)
from identity import Identity, IdentityPublic


def xwing_encapsulate(recipient: IdentityPublic) -> tuple[bytes, bytes]:
    """Encapsulate to a recipient. Returns (wire ciphertext, 32-byte shared)."""
    ss_m, ct_m = ML_KEM_768.encaps(recipient.xwing_mlkem_pk)

    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    recipient_x25519 = x25519.X25519PublicKey.from_public_bytes(
        recipient.xwing_x25519_pk
    )
    ss_x = eph_sk.exchange(recipient_x25519)

    shared = combine_xwing(ss_m, ss_x, eph_pk, recipient.xwing_x25519_pk)

    wire = bytearray(XWING_CIPHERTEXT_SIZE)
    wire[:MLKEM768_CIPHERTEXT_SIZE] = ct_m
    wire[MLKEM768_CIPHERTEXT_SIZE:] = eph_pk

    return bytes(wire), shared


def xwing_decapsulate(identity: Identity, ciphertext: bytes) -> bytes:
    """Decapsulate using the identity's static X-Wing key."""
    if len(ciphertext) != XWING_CIPHERTEXT_SIZE:
        raise ValueError(
            f"zwing: invalid X-Wing ciphertext size (got {len(ciphertext)})"
        )
    ct_m = ciphertext[:MLKEM768_CIPHERTEXT_SIZE]
    eph_pk = ciphertext[MLKEM768_CIPHERTEXT_SIZE:]

    ss_m = ML_KEM_768.decaps(identity.xwing_mlkem_sk, ct_m)
    eph_pub = x25519.X25519PublicKey.from_public_bytes(eph_pk)
    ss_x = identity.xwing_x25519_sk.exchange(eph_pub)

    return combine_xwing(ss_m, ss_x, eph_pk, identity.xwing_x25519_pk_bytes)
