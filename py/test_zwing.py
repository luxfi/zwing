"""Z-Wing X-Wing combiner KAT — must match Go/Rust/JS impls byte-for-byte.

Run with:

    cd py && python3 test_zwing.py -v
"""

import unittest

from zwing import (
    XWING_SHARED_SIZE,
    combine_xwing,
)


# Cross-language KAT shared with Go (../kat_test.go), Rust
# (~/work/zap/zap/src/zwing.rs), and JS (../js/zwing.test.ts). If
# this hex changes, Z-Wing has diverged across implementations.
KAT_HEX = "72df2088314a73de80c21d9593f13fcd5629c800c70b1507f0dd918fde5fe4ed"


class XWingCombinerKAT(unittest.TestCase):
    def test_xwing_combiner_kat_constant_inputs(self):
        ss_m = b"\x01" * 32
        ss_x = b"\x02" * 32
        ct_x = b"\x03" * 32
        pk_x = b"\x04" * 32
        got = combine_xwing(ss_m, ss_x, ct_x, pk_x)
        self.assertEqual(len(got), XWING_SHARED_SIZE)
        self.assertEqual(got.hex(), KAT_HEX)

    def test_xwing_combiner_is_deterministic(self):
        a = combine_xwing(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        b = combine_xwing(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        self.assertEqual(a, b)

    def test_xwing_combiner_changes_on_any_input_change(self):
        base = combine_xwing(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        flipped = bytes([0x01 ^ 0x01]) + b"\x01" * 31
        mutated = combine_xwing(flipped, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        self.assertNotEqual(base, mutated)

    def test_xwing_combiner_rejects_wrong_size(self):
        with self.assertRaises(ValueError):
            combine_xwing(b"\x00" * 31, b"\x00" * 32, b"\x00" * 32, b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
