// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"

	"github.com/luxfi/crypto/ed25519"
	"github.com/luxfi/crypto/mldsa"
)

// Identity binds a peer to long-term Ed25519 + ML-DSA-65 keys plus an
// X-Wing static keypair used as the KEM recipient material.
type Identity struct {
	EdPub  ed25519.PublicKey
	EdPriv ed25519.PrivateKey

	DSAPriv *mldsa.PrivateKey

	XWing *XWingPrivateKey
}

// IdentityPublic is the wire-serialisable, secrets-stripped half of an
// Identity. It is what peers exchange and verify against.
type IdentityPublic struct {
	EdPub    ed25519.PublicKey
	DSAPub   *mldsa.PublicKey
	XWingPub *XWingPublicKey
}

// GenerateIdentity creates a fresh Z-Wing identity using crypto/rand.
func GenerateIdentity() (*Identity, error) {
	return GenerateIdentityFrom(rand.Reader)
}

// GenerateIdentityFrom creates an identity from a custom entropy source.
// Useful for deterministic key generation in tests.
func GenerateIdentityFrom(r io.Reader) (*Identity, error) {
	edPub, edPriv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	dsaPriv, err := mldsa.GenerateKey(r, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}
	xwing, err := GenerateXWingKey(r)
	if err != nil {
		return nil, err
	}
	return &Identity{
		EdPub:   edPub,
		EdPriv:  edPriv,
		DSAPriv: dsaPriv,
		XWing:   xwing,
	}, nil
}

// Public returns the public half of the identity.
func (id *Identity) Public() *IdentityPublic {
	return &IdentityPublic{
		EdPub:    id.EdPub,
		DSAPub:   id.DSAPriv.PublicKey,
		XWingPub: id.XWing.Public(),
	}
}

// Sign produces the Z-Wing identity signature: an Ed25519 signature over
// SHA-256(ctx || message) concatenated with an ML-DSA-65 signature over
// the same digest. ctx is a hard-coded protocol label so signatures are
// not portable across protocols.
func (id *Identity) Sign(ctx, message []byte) ([]byte, error) {
	digest := identityDigest(ctx, message)
	edSig := ed25519.Sign(id.EdPriv, digest)
	dsaSig, err := id.DSAPriv.SignCtx(rand.Reader, digest, []byte(zwingDomain))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, ed25519.SignatureSize+mldsa.MLDSA65SignatureSize)
	out = append(out, edSig...)
	out = append(out, dsaSig...)
	return out, nil
}

// Verify checks an identity signature produced by Sign.
func (pub *IdentityPublic) Verify(ctx, message, signature []byte) error {
	if len(signature) != ed25519.SignatureSize+mldsa.MLDSA65SignatureSize {
		return ErrSignatureInvalid
	}
	digest := identityDigest(ctx, message)
	edSig := signature[:ed25519.SignatureSize]
	dsaSig := signature[ed25519.SignatureSize:]
	if !ed25519.Verify(pub.EdPub, digest, edSig) {
		return ErrSignatureInvalid
	}
	if !pub.DSAPub.VerifySignatureCtx(digest, dsaSig, []byte(zwingDomain)) {
		return ErrSignatureInvalid
	}
	return nil
}

// MarshalBinary serialises the public identity:
//
//	[Ed25519 pk: 32][ML-DSA-65 pk: 1952][X-Wing pk: 1216]
func (pub *IdentityPublic) MarshalBinary() []byte {
	out := make([]byte, 0, IdentityPublicSize)
	out = append(out, pub.EdPub...)
	out = append(out, pub.DSAPub.Bytes()...)
	out = append(out, pub.XWingPub.MarshalBinary()...)
	return out
}

// ParseIdentityPublic decodes the wire format produced by MarshalBinary.
func ParseIdentityPublic(data []byte) (*IdentityPublic, error) {
	if len(data) != IdentityPublicSize {
		return nil, errors.New("zwing: invalid public identity size")
	}
	off := 0
	edPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(edPub, data[off:off+ed25519.PublicKeySize])
	off += ed25519.PublicKeySize

	dsaPubBytes := data[off : off+mldsa.MLDSA65PublicKeySize]
	off += mldsa.MLDSA65PublicKeySize
	dsaPub, err := mldsa.PublicKeyFromBytes(dsaPubBytes, mldsa.MLDSA65)
	if err != nil {
		return nil, err
	}

	xwingPub, err := ParseXWingPublicKey(data[off : off+XWingPublicKeySize])
	if err != nil {
		return nil, err
	}
	return &IdentityPublic{EdPub: edPub, DSAPub: dsaPub, XWingPub: xwingPub}, nil
}

// Equal reports whether two public identities have byte-identical key material.
func (pub *IdentityPublic) Equal(other *IdentityPublic) bool {
	if pub == nil || other == nil {
		return false
	}
	if subtle.ConstantTimeCompare(pub.EdPub, other.EdPub) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare(pub.DSAPub.Bytes(), other.DSAPub.Bytes()) != 1 {
		return false
	}
	if subtle.ConstantTimeCompare(pub.XWingPub.MarshalBinary(), other.XWingPub.MarshalBinary()) != 1 {
		return false
	}
	return true
}

// IdentityPublicSize is the fixed-size wire encoding of an IdentityPublic.
const IdentityPublicSize = ed25519.PublicKeySize +
	mldsa.MLDSA65PublicKeySize +
	XWingPublicKeySize

// zwingDomain is the protocol domain separator. It is bound into every
// identity signature so Z-Wing signatures cannot be replayed onto another
// Lux protocol that signs with the same identity keys.
const zwingDomain = "lux.zwing.v1"

func identityDigest(ctx, message []byte) []byte {
	h := sha256.New()
	h.Write([]byte(zwingDomain))
	h.Write([]byte{byte(len(ctx))})
	h.Write(ctx)
	h.Write(message)
	return h.Sum(nil)
}
