// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestXWingCombinerKAT pins the IETF X-Wing combiner output for a
// fixed set of inputs. This same KAT is reproduced in every language
// port of Z-Wing (Rust, Python, JS) so that any divergence on the KEM
// label, hash, or input ordering is caught immediately.
//
// Inputs: 32-byte arrays of repeated 0x01, 0x02, 0x03, 0x04.
// Expected: SHA3-256("\./X-Wing" || ssM || ssX || ctX || pkX).
//
// The canonical hex must match the Rust constant in
// `~/work/zap/zap/src/zwing.rs::xwing_combiner_kat_constant_inputs`
// and the equivalent Python and JS test fixtures.
func TestXWingCombinerKAT(t *testing.T) {
	ssM := bytes.Repeat([]byte{0x01}, 32)
	ssX := bytes.Repeat([]byte{0x02}, 32)
	ctX := bytes.Repeat([]byte{0x03}, 32)
	pkX := bytes.Repeat([]byte{0x04}, 32)

	got := combineXWing(ssM, ssX, ctX, pkX)
	const wantHex = "72df2088314a73de80c21d9593f13fcd5629c800c70b1507f0dd918fde5fe4ed"
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHex {
		t.Fatalf("X-Wing combiner KAT diverged:\n  got  %s\n  want %s", gotHex, wantHex)
	}
}
