"""End-to-end Python Z-Wing tests.

Run with::

    cd py && python3 test_full.py -v
"""

from __future__ import annotations

import threading
import unittest
from queue import Queue

from channel import Channel, nonce_for
from handshake import (
    HandshakeOutput,
    MAX_FRAME_SIZE,
    read_frame,
    run_initiator,
    run_responder,
    write_frame,
)
from identity import (
    SIGNATURE_SIZE,
    Identity,
    IDENTITY_PUBLIC_SIZE,
    generate_identity,
    identity_equals,
    marshal_identity_public,
    parse_identity_public,
    public_of,
    sign_identity,
    verify_identity,
)
from kem import xwing_decapsulate, xwing_encapsulate


class _Pipe:
    """Tiny in-memory full-duplex pipe."""

    def __init__(self) -> None:
        self.q1: "Queue[bytes]" = Queue()
        self.q2: "Queue[bytes]" = Queue()
        self.buf1 = bytearray()
        self.buf2 = bytearray()


class _End:
    def __init__(self, pipe: _Pipe, side: int) -> None:
        self._pipe = pipe
        self._side = side

    def read(self, n: int) -> bytes:
        if self._side == 0:
            buf = self._pipe.buf1
            q = self._pipe.q1
        else:
            buf = self._pipe.buf2
            q = self._pipe.q2
        while len(buf) < n:
            buf += q.get()
        out = bytes(buf[:n])
        del buf[:n]
        return out

    def write(self, data: bytes) -> None:
        if self._side == 0:
            self._pipe.q2.put(data)
        else:
            self._pipe.q1.put(data)


def _make_pipe():
    p = _Pipe()
    return _End(p, 0), _End(p, 1)


class IdentityTests(unittest.TestCase):
    def test_sign_verify_round_trip(self):
        id_ = generate_identity()
        pub = public_of(id_)
        sig = sign_identity(id_, b"ctx", b"hello")
        self.assertEqual(len(sig), SIGNATURE_SIZE)
        verify_identity(pub, b"ctx", b"hello", sig)

    def test_verify_rejects_wrong_message(self):
        id_ = generate_identity()
        sig = sign_identity(id_, b"ctx", b"hello")
        with self.assertRaises(ValueError):
            verify_identity(public_of(id_), b"ctx", b"goodbye", sig)

    def test_verify_rejects_wrong_ctx(self):
        id_ = generate_identity()
        sig = sign_identity(id_, b"ctx", b"hello")
        with self.assertRaises(ValueError):
            verify_identity(public_of(id_), b"other", b"hello", sig)

    def test_verify_rejects_short_sig(self):
        id_ = generate_identity()
        with self.assertRaises(ValueError):
            verify_identity(public_of(id_), b"ctx", b"hello", b"short")

    def test_marshal_round_trip(self):
        id_ = generate_identity()
        pub = public_of(id_)
        wire = marshal_identity_public(pub)
        self.assertEqual(len(wire), IDENTITY_PUBLIC_SIZE)
        parsed = parse_identity_public(wire)
        self.assertTrue(identity_equals(parsed, pub))

    def test_parse_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            parse_identity_public(b"\x00" * 10)

    def test_distinct_identities_differ(self):
        a = public_of(generate_identity())
        b = public_of(generate_identity())
        self.assertFalse(identity_equals(a, b))


class KEMTests(unittest.TestCase):
    def test_xwing_round_trip(self):
        id_ = generate_identity()
        ct, ss_a = xwing_encapsulate(public_of(id_))
        ss_b = xwing_decapsulate(id_, ct)
        self.assertEqual(ss_a, ss_b)

    def test_xwing_decap_rejects_wrong_size(self):
        id_ = generate_identity()
        with self.assertRaises(ValueError):
            xwing_decapsulate(id_, b"\x00" * 10)


class WireTests(unittest.TestCase):
    def test_write_frame_oversize_rejected(self):
        class Sink:
            def read(self, n):
                return b""

            def write(self, b):
                pass

        with self.assertRaises(ValueError):
            write_frame(Sink(), b"x" * (MAX_FRAME_SIZE + 1))

    def test_read_frame_zero_length_rejected(self):
        class Src:
            def __init__(self):
                self.b = bytearray(b"\x00\x00\x00\x00")

            def read(self, n):
                out = bytes(self.b[:n])
                del self.b[:n]
                return out

            def write(self, b):
                pass

        with self.assertRaises(ValueError):
            read_frame(Src())

    def test_read_frame_oversize_rejected(self):
        class Src:
            def __init__(self):
                self.b = bytearray(b"\xff\xff\xff\xff")

            def read(self, n):
                out = bytes(self.b[:n])
                del self.b[:n]
                return out

            def write(self, b):
                pass

        with self.assertRaises(ValueError):
            read_frame(Src())


class HandshakeTests(unittest.TestCase):
    def test_full_handshake_round_trip(self):
        client = generate_identity()
        server = generate_identity()
        a, b = _make_pipe()

        results: dict[str, HandshakeOutput] = {}
        err: dict[str, Exception] = {}

        def server_thread():
            try:
                results["s"] = run_responder(b, server, public_of(client))
            except Exception as e:
                err["s"] = e

        t = threading.Thread(target=server_thread)
        t.start()
        try:
            results["c"] = run_initiator(a, client, public_of(server))
            t.join(timeout=10)
        finally:
            if t.is_alive():
                t.join(timeout=1)

        if err:
            raise AssertionError(f"server: {err['s']}")

        c_out = results["c"]
        s_out = results["s"]
        self.assertEqual(c_out.key_i2r, s_out.key_i2r)
        self.assertEqual(c_out.key_r2i, s_out.key_r2i)
        self.assertTrue(identity_equals(c_out.remote, public_of(server)))
        self.assertTrue(identity_equals(s_out.remote, public_of(client)))

    def test_pinned_remote_mismatch_rejected(self):
        client = generate_identity()
        server = generate_identity()
        other = generate_identity()
        a, b = _make_pipe()

        err = {}

        def server_thread():
            try:
                run_responder(b, server)
            except Exception as e:
                err["s"] = e

        t = threading.Thread(target=server_thread)
        t.start()
        try:
            with self.assertRaises(ValueError):
                run_initiator(a, client, public_of(other))
        finally:
            t.join(timeout=2)


class CombinerSizeValidationTests(unittest.TestCase):
    """zwing.py combine_xwing rejects wrong-size inputs (3 separate branches)."""

    def test_rejects_wrong_ss_m(self):
        from zwing import combine_xwing
        with self.assertRaises(ValueError):
            combine_xwing(b"\x00" * 31, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)

    def test_rejects_wrong_ss_x(self):
        from zwing import combine_xwing
        with self.assertRaises(ValueError):
            combine_xwing(b"\x00" * 32, b"\x00" * 31, b"\x00" * 32, b"\x00" * 32)

    def test_rejects_wrong_ct_x(self):
        from zwing import combine_xwing
        with self.assertRaises(ValueError):
            combine_xwing(b"\x00" * 32, b"\x00" * 32, b"\x00" * 31, b"\x00" * 32)

    def test_rejects_wrong_pk_x(self):
        from zwing import combine_xwing
        with self.assertRaises(ValueError):
            combine_xwing(b"\x00" * 32, b"\x00" * 32, b"\x00" * 32, b"\x00" * 31)


class IdentityEqualLengthTests(unittest.TestCase):
    """Force identity_equals to compare differently-shaped pubkeys."""

    def test_identity_equals_short_field_returns_false(self):
        from identity import IdentityPublic, identity_equals
        a = IdentityPublic(
            ed_pk=b"\x00" * 32,
            ml_pk=b"\x00" * 1952,
            xwing_mlkem_pk=b"\x00" * 1184,
            xwing_x25519_pk=b"\x00" * 32,
        )
        # Build b with a shorter ed_pk; identity_equals must short-circuit
        # to False on the length mismatch path.
        b = IdentityPublic(
            ed_pk=b"\x00" * 16,  # wrong length
            ml_pk=b"\x00" * 1952,
            xwing_mlkem_pk=b"\x00" * 1184,
            xwing_x25519_pk=b"\x00" * 32,
        )
        self.assertFalse(identity_equals(a, b))


class HandshakeWireDecodeTests(unittest.TestCase):
    """Drive every wire-decode error branch in handshake.py."""

    def test_decode_handshake_init_short_idlen(self):
        from handshake import _decode_handshake_init
        with self.assertRaises(ValueError):
            _decode_handshake_init(b"\x00")  # missing idLen byte

    def test_decode_handshake_init_short_id(self):
        from handshake import _decode_handshake_init
        with self.assertRaises(ValueError):
            _decode_handshake_init(b"\x00\xff")  # idLen=0x00FF, no body

    def test_decode_handshake_init_short_siglen(self):
        from handshake import _decode_handshake_init
        # idLen=1, id="A", then no bytes for sigLen.
        with self.assertRaises(ValueError):
            _decode_handshake_init(b"\x00\x01A")

    def test_decode_handshake_init_short_sig(self):
        from handshake import _decode_handshake_init
        # idLen=0, sigLen=0xFFFF, no body.
        with self.assertRaises(ValueError):
            _decode_handshake_init(b"\x00\x00\xff\xff")

    def test_decode_handshake_init_trailing_garbage(self):
        from handshake import _decode_handshake_init
        # Valid idLen=0, sigLen=0, then extra byte.
        with self.assertRaises(ValueError):
            _decode_handshake_init(b"\x00\x00\x00\x00\x99")

    def test_decode_handshake_response_too_short(self):
        from handshake import _decode_handshake_response
        with self.assertRaises(ValueError):
            _decode_handshake_response(b"\x00" * 100)

    def test_decode_handshake_response_short_enc_body(self):
        from handshake import _decode_handshake_response
        from zwing import XWING_CIPHERTEXT_SIZE
        # Right-size ct, encLen=0xFFFF, no body.
        buf = b"\x00" * XWING_CIPHERTEXT_SIZE + b"\xff\xff"
        with self.assertRaises(ValueError):
            _decode_handshake_response(buf)

    def test_decode_handshake_response_trailing_garbage(self):
        from handshake import _decode_handshake_response
        from zwing import XWING_CIPHERTEXT_SIZE
        # Right-size ct, encLen=0, plus trailing byte.
        buf = b"\x00" * XWING_CIPHERTEXT_SIZE + b"\x00\x00\x99"
        with self.assertRaises(ValueError):
            _decode_handshake_response(buf)

    def test_split_resp_id_short_idlen(self):
        from handshake import _split_resp_id_payload
        with self.assertRaises(ValueError):
            _split_resp_id_payload(b"\x00")

    def test_split_resp_id_short_id(self):
        from handshake import _split_resp_id_payload
        with self.assertRaises(ValueError):
            _split_resp_id_payload(b"\x00\xff")

    def test_split_resp_id_short_sig(self):
        from handshake import _split_resp_id_payload
        # idLen=0, sigLen=0xFFFF, no body.
        with self.assertRaises(ValueError):
            _split_resp_id_payload(b"\x00\x00\xff\xff")

    def test_split_resp_id_trailing_garbage(self):
        from handshake import _split_resp_id_payload
        with self.assertRaises(ValueError):
            _split_resp_id_payload(b"\x00\x00\x00\x00\x99")

    def test_read_exact_short_read(self):
        """_read_exact must raise if conn returns empty."""
        from handshake import _read_exact

        class Empty:
            def read(self, n):
                return b""

            def write(self, b):
                pass

        with self.assertRaises(ValueError):
            _read_exact(Empty(), 4)


class ChannelExhaustionTests(unittest.TestCase):
    """Drive sequence-exhaustion error branches via direct field manipulation."""

    def _make_pair(self):
        client = generate_identity()
        server = generate_identity()
        a, b = _make_pipe()

        results = {}
        err = {}

        def server_thread():
            try:
                results["s"] = run_responder(b, server, public_of(client))
            except Exception as e:
                err["s"] = e

        t = threading.Thread(target=server_thread)
        t.start()
        try:
            results["c"] = run_initiator(a, client, public_of(server))
        finally:
            t.join(timeout=5)
        return Channel(a, results["c"], True), Channel(b, results["s"], False)

    def test_tx_seq_exhausted(self):
        c, _ = self._make_pair()
        c._tx_seq = (1 << 64) - 1
        with self.assertRaises(ValueError):
            c.send(b"x")

    def test_rx_seq_exhausted(self):
        c, s = self._make_pair()
        # Server pushes one record so receiver can read; force seq=MAX so the
        # check trips before decrypt.
        s.send(b"x")
        c._rx_seq = (1 << 64) - 1
        with self.assertRaises(ValueError):
            c.recv()


class FinalCoverageTests(unittest.TestCase):
    """Targeted tests to drive the last few error/edge branches."""

    def test_channel_rx_overflow_path(self):
        """Channel.recv must serve _rx_overflow before reading the next frame."""
        from channel import Channel
        from handshake import HandshakeOutput

        # Build a Channel with a preset overflow buffer; recv() must return it.
        out = HandshakeOutput(
            shared=b"\x00" * 32,
            remote=parse_identity_public(
                marshal_identity_public(public_of(generate_identity()))
            ),
            key_i2r=b"\x00" * 32,
            key_r2i=b"\x00" * 32,
        )

        class Sink:
            def read(self, n):
                return b""

            def write(self, b):
                pass

        chan = Channel(Sink(), out, initiator=True)
        chan._rx_overflow = b"hello-overflow"
        got = chan.recv()
        self.assertEqual(got, b"hello-overflow")
        self.assertIsNone(chan._rx_overflow)

    def test_responder_pinned_remote_mismatch(self):
        """Server-side pinning rejection — handshake.py:114."""
        client = generate_identity()
        server = generate_identity()
        other = generate_identity()
        a, b = _make_pipe()

        err = {}

        def initiator_thread():
            try:
                run_initiator(a, client)
            except Exception as e:
                err["c"] = e

        t = threading.Thread(target=initiator_thread)
        t.start()
        try:
            with self.assertRaises(ValueError):
                # Responder pins a different identity than what client sends.
                run_responder(b, server, public_of(other))
        finally:
            t.join(timeout=2)

    def test_verify_rejects_corrupt_mldsa_sig(self):
        """Drive identity.py:167 — ML-DSA-65 verify failure."""
        from identity import (
            ED25519_SIGNATURE_SIZE,
            sign_identity,
            verify_identity,
        )

        id_ = generate_identity()
        pub = public_of(id_)
        sig = sign_identity(id_, b"ctx", b"hi")
        # Flip a byte in the ML-DSA portion (after first 64 ed25519 bytes).
        bad = bytearray(sig)
        bad[ED25519_SIGNATURE_SIZE + 200] ^= 0xFF
        with self.assertRaises(ValueError):
            verify_identity(pub, b"ctx", b"hi", bytes(bad))


class ChannelTests(unittest.TestCase):
    def test_e2e_channel_echo(self):
        client = generate_identity()
        server = generate_identity()
        a, b = _make_pipe()

        results = {}
        err = {}

        def server_thread():
            try:
                s_out = run_responder(b, server, public_of(client))
                s_chan = Channel(b, s_out, initiator=False)
                msg = s_chan.recv()
                s_chan.send(msg)
                results["s_chan"] = s_chan
            except Exception as e:
                err["s"] = e

        t = threading.Thread(target=server_thread)
        t.start()
        try:
            c_out = run_initiator(a, client, public_of(server))
            c_chan = Channel(a, c_out, initiator=True)
            payload = b"z-wing python e2e"
            c_chan.send(payload)
            got = c_chan.recv()
            self.assertEqual(got, payload)
        finally:
            t.join(timeout=5)
        if err:
            raise AssertionError(f"server: {err['s']}")

    def test_nonce_for_low_byte_carries_counter(self):
        self.assertEqual(nonce_for(0), b"\x00" * 12)
        self.assertEqual(nonce_for(1)[-1], 1)
        n_max = nonce_for((1 << 64) - 1)
        for i in range(4, 12):
            self.assertEqual(n_max[i], 0xFF)


if __name__ == "__main__":
    unittest.main()
