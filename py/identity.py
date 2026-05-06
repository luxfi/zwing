"""Hybrid Z-Wing identity (Python) — Ed25519 + ML-DSA-65 + X-Wing.

Wire format mirrors the Go and Rust ports byte-for-byte.

  IdentityPublic = [Ed25519 pk: 32][ML-DSA-65 pk: 1952][X-Wing pk: 1216]
  Signature      = [Ed25519 sig: 64][ML-DSA-65 sig: 3309]

Pure-Python crypto via ``kyber_py``, ``dilithium_py`` and the standard
``cryptography`` library. No native deps.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

from zwing import (
    XWING_PUBLIC_KEY_SIZE,
    X25519_POINT_SIZE,
)

ED25519_PUBLIC_KEY_SIZE = 32
ED25519_SIGNATURE_SIZE = 64
MLDSA65_PUBLIC_KEY_SIZE = 1952
MLDSA65_SIGNATURE_SIZE = 3309
MLKEM768_PUBLIC_KEY_SIZE = 1184

IDENTITY_PUBLIC_SIZE = (
    ED25519_PUBLIC_KEY_SIZE + MLDSA65_PUBLIC_KEY_SIZE + XWING_PUBLIC_KEY_SIZE
)
SIGNATURE_SIZE = ED25519_SIGNATURE_SIZE + MLDSA65_SIGNATURE_SIZE

ZWING_DOMAIN = b"lux.zwing.v1"


@dataclass
class Identity:
    """Long-term Z-Wing identity (private)."""

    ed_sk: ed25519.Ed25519PrivateKey
    ed_pk_bytes: bytes
    ml_sk: bytes
    ml_pk: bytes
    xwing_mlkem_sk: bytes
    xwing_mlkem_pk: bytes
    xwing_x25519_sk: x25519.X25519PrivateKey
    xwing_x25519_pk_bytes: bytes


@dataclass
class IdentityPublic:
    """Wire-serialisable public half of an Identity."""

    ed_pk: bytes  # 32
    ml_pk: bytes  # 1952
    xwing_mlkem_pk: bytes  # 1184
    xwing_x25519_pk: bytes  # 32


def generate_identity() -> Identity:
    """Generate a fresh identity using ``os.urandom`` and per-primitive RNG."""
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    ed_pk_bytes = ed_sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )

    ml_pk, ml_sk = ML_DSA_65.keygen()
    mlkem_pk, mlkem_sk = ML_KEM_768.keygen()

    xwing_x25519_sk = x25519.X25519PrivateKey.generate()
    xwing_x25519_pk_bytes = xwing_x25519_sk.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )

    return Identity(
        ed_sk=ed_sk,
        ed_pk_bytes=ed_pk_bytes,
        ml_sk=ml_sk,
        ml_pk=ml_pk,
        xwing_mlkem_sk=mlkem_sk,
        xwing_mlkem_pk=mlkem_pk,
        xwing_x25519_sk=xwing_x25519_sk,
        xwing_x25519_pk_bytes=xwing_x25519_pk_bytes,
    )


def public_of(identity: Identity) -> IdentityPublic:
    return IdentityPublic(
        ed_pk=identity.ed_pk_bytes,
        ml_pk=identity.ml_pk,
        xwing_mlkem_pk=identity.xwing_mlkem_pk,
        xwing_x25519_pk=identity.xwing_x25519_pk_bytes,
    )


def marshal_identity_public(pub: IdentityPublic) -> bytes:
    return pub.ed_pk + pub.ml_pk + pub.xwing_mlkem_pk + pub.xwing_x25519_pk


def parse_identity_public(data: bytes) -> IdentityPublic:
    if len(data) != IDENTITY_PUBLIC_SIZE:
        raise ValueError(
            f"zwing: invalid identity public size (got {len(data)}, want {IDENTITY_PUBLIC_SIZE})"
        )
    off = 0
    ed_pk = data[off : off + ED25519_PUBLIC_KEY_SIZE]
    off += ED25519_PUBLIC_KEY_SIZE
    ml_pk = data[off : off + MLDSA65_PUBLIC_KEY_SIZE]
    off += MLDSA65_PUBLIC_KEY_SIZE
    xwing_mlkem_pk = data[off : off + MLKEM768_PUBLIC_KEY_SIZE]
    off += MLKEM768_PUBLIC_KEY_SIZE
    xwing_x25519_pk = data[off : off + X25519_POINT_SIZE]
    return IdentityPublic(
        ed_pk=ed_pk,
        ml_pk=ml_pk,
        xwing_mlkem_pk=xwing_mlkem_pk,
        xwing_x25519_pk=xwing_x25519_pk,
    )


def identity_digest(ctx: bytes, message: bytes) -> bytes:
    """Bind ``ZWING_DOMAIN || len(ctx) || ctx || message`` into SHA-256."""
    h = hashlib.sha256()
    h.update(ZWING_DOMAIN)
    h.update(bytes([len(ctx) & 0xFF]))
    h.update(ctx)
    h.update(message)
    return h.digest()


def sign_identity(identity: Identity, ctx: bytes, message: bytes) -> bytes:
    """Concatenate Ed25519 and ML-DSA-65 detached signatures over the digest."""
    digest = identity_digest(ctx, message)
    ed_sig = identity.ed_sk.sign(digest)
    ml_sig = ML_DSA_65.sign(identity.ml_sk, digest)
    return ed_sig + ml_sig


def verify_identity(
    pub: IdentityPublic, ctx: bytes, message: bytes, signature: bytes
) -> None:
    """Verify a hybrid Z-Wing signature. Raises on any failure."""
    if len(signature) != SIGNATURE_SIZE:
        raise ValueError("zwing: signature size mismatch")
    digest = identity_digest(ctx, message)
    ed_sig = signature[:ED25519_SIGNATURE_SIZE]
    ml_sig = signature[ED25519_SIGNATURE_SIZE:]

    ed_pub = ed25519.Ed25519PublicKey.from_public_bytes(pub.ed_pk)
    try:
        ed_pub.verify(ed_sig, digest)
    except Exception as e:  # cryptography raises InvalidSignature
        raise ValueError("zwing: ed25519 verify failed") from e

    if not ML_DSA_65.verify(pub.ml_pk, digest, ml_sig):
        raise ValueError("zwing: ml-dsa-65 verify failed")


def identity_equals(a: IdentityPublic, b: IdentityPublic) -> bool:
    """Constant-time equality."""
    fields = [
        (a.ed_pk, b.ed_pk),
        (a.ml_pk, b.ml_pk),
        (a.xwing_mlkem_pk, b.xwing_mlkem_pk),
        (a.xwing_x25519_pk, b.xwing_x25519_pk),
    ]
    diff = 0
    for x, y in fields:
        if len(x) != len(y):
            return False
        for bx, by in zip(x, y):
            diff |= bx ^ by
    return diff == 0
