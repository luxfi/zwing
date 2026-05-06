// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/luxfi/crypto/mlkem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

// X-Wing KEM combiner per IETF draft-connolly-cfrg-xwing-kem.
// EXACT labels — Z-Wing uses real IETF X-Wing, no rebranding,
// for full interop with any X-Wing peer. The Lux value-add lives
// in the layers ABOVE the KEM (identity binding, RNS transport),
// not by forking the KEM itself.
//
// shared_secret = SHA3-256( "\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )
//
//	ss_M   ML-KEM-768 shared secret (32 bytes)
//	ss_X   X25519 shared secret (32 bytes)
//	ct_X   X25519 ephemeral public key sent by encapsulator (32 bytes)
//	pk_X   X25519 static public key of recipient (32 bytes)
var (
	xwingLabelPrefix = []byte{'\\', '.', '/'} // 3 bytes: backslash, dot, slash
	xwingLabelName   = []byte("X-Wing")       // 6 bytes ASCII — IETF spec
)

// X-Wing wire sizes.
const (
	XWingPublicKeySize  = mlkem.MLKEM768PublicKeySize + curve25519.PointSize  // 1184 + 32
	XWingCiphertextSize = mlkem.MLKEM768CiphertextSize + curve25519.PointSize // 1088 + 32
	XWingSharedSize     = 32
)

// XWingPublicKey is the recipient's X-Wing static public key.
type XWingPublicKey struct {
	MLKEM  *mlkem.PublicKey
	X25519 [32]byte
}

// XWingPrivateKey is the recipient's X-Wing static secret key plus the
// matching public material needed for the combiner.
type XWingPrivateKey struct {
	MLKEMPriv  *mlkem.PrivateKey
	X25519Priv [32]byte
	X25519Pub  [32]byte
}

// Public returns the X-Wing public key.
func (sk *XWingPrivateKey) Public() *XWingPublicKey {
	return &XWingPublicKey{
		MLKEM:  sk.MLKEMPriv.PublicKey(),
		X25519: sk.X25519Pub,
	}
}

// MarshalBinary serialises the X-Wing public key as ML-KEM-768 || X25519.
func (pk *XWingPublicKey) MarshalBinary() []byte {
	out := make([]byte, 0, XWingPublicKeySize)
	out = append(out, pk.MLKEM.Bytes()...)
	out = append(out, pk.X25519[:]...)
	return out
}

// ParseXWingPublicKey decodes the wire format produced by MarshalBinary.
func ParseXWingPublicKey(data []byte) (*XWingPublicKey, error) {
	if len(data) != XWingPublicKeySize {
		return nil, errors.New("zwing: invalid X-Wing public key size")
	}
	mlkemPK, err := mlkem.PublicKeyFromBytes(data[:mlkem.MLKEM768PublicKeySize], mlkem.MLKEM768)
	if err != nil {
		return nil, err
	}
	pk := &XWingPublicKey{MLKEM: mlkemPK}
	copy(pk.X25519[:], data[mlkem.MLKEM768PublicKeySize:])
	return pk, nil
}

// GenerateXWingKey produces a fresh X-Wing static keypair.
//
// curve25519.X25519 with the Basepoint never errors (it would only error
// on a wrong-size scalar — we always pass 32 bytes). The error branch is
// therefore dead and elided.
func GenerateXWingKey(reader io.Reader) (*XWingPrivateKey, error) {
	if reader == nil {
		reader = rand.Reader
	}
	_, mlkemPriv, err := mlkem.GenerateKeyPair(reader, mlkem.MLKEM768)
	if err != nil {
		return nil, err
	}
	sk := &XWingPrivateKey{MLKEMPriv: mlkemPriv}
	if _, err := io.ReadFull(reader, sk.X25519Priv[:]); err != nil {
		return nil, err
	}
	pub, _ := curve25519.X25519(sk.X25519Priv[:], curve25519.Basepoint)
	copy(sk.X25519Pub[:], pub)
	return sk, nil
}

// XWingEncapsulate runs the encapsulator side. Output is (ciphertext, shared).
// The ciphertext is ML-KEM-768 ct || X25519 ephemeral pk.
func XWingEncapsulate(reader io.Reader, recipient *XWingPublicKey) (ciphertext []byte, shared [XWingSharedSize]byte, err error) {
	if reader == nil {
		reader = rand.Reader
	}

	mlkemCT, ssM, err := recipient.MLKEM.Encapsulate(reader)
	if err != nil {
		return nil, shared, err
	}

	var ephPriv [32]byte
	if _, err := io.ReadFull(reader, ephPriv[:]); err != nil {
		return nil, shared, err
	}
	// curve25519.X25519 only errors on wrong-length inputs (we always
	// pass 32 bytes) or on a low-order recipient point. The recipient
	// public key was decoded above, so a low-order point reaching here
	// would be a peer presenting a malformed pubkey — ParseXWingPublicKey
	// caught the size, but the curve check is the canonical detector.
	ephPub, _ := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	ssX, err := curve25519.X25519(ephPriv[:], recipient.X25519[:])
	if err != nil {
		return nil, shared, err
	}

	shared = combineXWing(ssM, ssX, ephPub, recipient.X25519[:])

	ciphertext = make([]byte, 0, XWingCiphertextSize)
	ciphertext = append(ciphertext, mlkemCT...)
	ciphertext = append(ciphertext, ephPub...)

	zero(ephPriv[:])
	zero(ssM)
	zero(ssX)
	return ciphertext, shared, nil
}

// XWingDecapsulate runs the recipient side.
func XWingDecapsulate(sk *XWingPrivateKey, ciphertext []byte) ([XWingSharedSize]byte, error) {
	var shared [XWingSharedSize]byte
	if len(ciphertext) != XWingCiphertextSize {
		return shared, errors.New("zwing: invalid X-Wing ciphertext size")
	}
	mlkemCT := ciphertext[:mlkem.MLKEM768CiphertextSize]
	ephPub := ciphertext[mlkem.MLKEM768CiphertextSize:]

	// ML-KEM-768 uses implicit rejection: any 1088-byte ciphertext yields
	// a 32-byte shared secret with no error. The error branch is therefore
	// dead in current upstream but kept defensively for future versions
	// that might tighten validation. The decapsulateMLKEM seam exposes the
	// error path to tests.
	ssM, err := decapsulateMLKEM(sk, mlkemCT)
	if err != nil {
		return shared, err
	}
	ssX, err := curve25519.X25519(sk.X25519Priv[:], ephPub)
	if err != nil {
		return shared, err
	}

	shared = combineXWing(ssM, ssX, ephPub, sk.X25519Pub[:])
	zero(ssM)
	zero(ssX)
	return shared, nil
}

// decapsulateMLKEM is a seam: tests can swap it to inject an error from
// ML-KEM Decapsulate that current upstream cannot produce naturally.
var decapsulateMLKEM = func(sk *XWingPrivateKey, ct []byte) ([]byte, error) {
	return sk.MLKEMPriv.Decapsulate(ct)
}

// combineXWing implements the IETF X-Wing KDF combiner exactly:
//
//	SHA3-256( "\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )
//
// All inputs are fixed-length so no separators are needed: ss_M=32,
// ss_X=32, ct_X=32, pk_X=32.
func combineXWing(ssM, ssX, ctX, pkX []byte) [XWingSharedSize]byte {
	h := sha3.New256()
	h.Write(xwingLabelPrefix)
	h.Write(xwingLabelName)
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	var out [XWingSharedSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
