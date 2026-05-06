"""Z-Wing — Lux post-quantum secure channel (Python port).

Z-Wing is a composition: IETF X-Wing KEM at the bottom (X25519 + ML-KEM-768
with the SHA3-256 combiner from draft-connolly-cfrg-xwing-kem) plus Lux
Ed25519 + ML-DSA-65 hybrid identity signatures plus ChaCha20-Poly1305
channel records. The KEM combiner is byte-for-byte the IETF spec for full
interop with the Go implementation in this same repo (luxfi/zwing).

X-Wing combiner (IETF spec, exact)::

    shared_secret = SHA3-256( "\\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )

The label is ``"X-Wing"``, not ``"Z-Wing"``. Z-Wing's domain separation
lives one layer up in the HKDF info string ``"lux.zwing.v1/{i2r,r2i}"``
that derives the channel keys, and in the ML-DSA context
``"lux.zwing.v1"`` used for hybrid identity signatures.
"""

from __future__ import annotations

import hashlib

# ML-KEM-768 public key size in bytes.
MLKEM768_PUBLIC_KEY_SIZE = 1184
# ML-KEM-768 ciphertext size in bytes.
MLKEM768_CIPHERTEXT_SIZE = 1088
# X25519 public key (and ciphertext) size in bytes.
X25519_POINT_SIZE = 32

# X-Wing public key wire size: ML-KEM-768 pk || X25519 pk.
XWING_PUBLIC_KEY_SIZE = MLKEM768_PUBLIC_KEY_SIZE + X25519_POINT_SIZE
# X-Wing ciphertext wire size: ML-KEM-768 ct || X25519 ephemeral pk.
XWING_CIPHERTEXT_SIZE = MLKEM768_CIPHERTEXT_SIZE + X25519_POINT_SIZE
# Z-Wing / X-Wing shared-secret size in bytes.
XWING_SHARED_SIZE = 32

# IETF X-Wing combiner labels (exact bytes from draft-connolly-cfrg-xwing-kem).
# Three-byte prefix `\./` plus the six-byte ASCII protocol name `X-Wing`.
_XWING_LABEL_PREFIX = b"\\./"
_XWING_LABEL_NAME = b"X-Wing"


def combine_xwing(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    """Combine the X-Wing KEM ingredients into a single 32-byte shared secret.

    All inputs are 32 bytes:
      ss_m: ML-KEM-768 shared secret
      ss_x: X25519 shared secret
      ct_x: X25519 ephemeral public key from encapsulator
      pk_x: X25519 static public key of recipient
    """
    if len(ss_m) != XWING_SHARED_SIZE:
        raise ValueError(f"ss_m must be {XWING_SHARED_SIZE} bytes")
    if len(ss_x) != X25519_POINT_SIZE:
        raise ValueError(f"ss_x must be {X25519_POINT_SIZE} bytes")
    if len(ct_x) != X25519_POINT_SIZE:
        raise ValueError(f"ct_x must be {X25519_POINT_SIZE} bytes")
    if len(pk_x) != X25519_POINT_SIZE:
        raise ValueError(f"pk_x must be {X25519_POINT_SIZE} bytes")

    h = hashlib.sha3_256()
    h.update(_XWING_LABEL_PREFIX)
    h.update(_XWING_LABEL_NAME)
    h.update(ss_m)
    h.update(ss_x)
    h.update(ct_x)
    h.update(pk_x)
    return h.digest()
