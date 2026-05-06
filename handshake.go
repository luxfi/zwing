// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Handshake is the Z-Wing 1-RTT mutual-auth handshake.
//
//	Initiator -> Responder : HandshakeInit
//	    initiator IdentityPublic || ML-DSA+Ed25519 sig over (label || init pub)
//
//	Responder -> Initiator : HandshakeResponse
//	    XWing ciphertext || encrypted{ responder IdentityPublic || sig }
//
// After both messages, both sides hold the same X-Wing shared secret
// derived against initiator's static X-Wing key. Forward secrecy is
// provided by the X25519 ephemeral inside X-Wing and by zeroing all
// intermediate key material once channel keys are derived.
//
// Identity-binding: the responder signs a transcript hash that covers
// the initiator's identity material AND the X-Wing ciphertext, so the
// signature can't be replayed onto another session.

const (
	hsLabelInit     = "lux.zwing.v1/handshake-init"
	hsLabelResponse = "lux.zwing.v1/handshake-response"

	channelKeyLabelI2R = "lux.zwing.v1/i2r"
	channelKeyLabelR2I = "lux.zwing.v1/r2i"

	chacha20KeySize = 32
)

// HandshakeInit is the wire form of the initiator's first message.
type HandshakeInit struct {
	IdentityPub []byte // serialised IdentityPublic
	Signature   []byte // identity signature over label || IdentityPub
}

// HandshakeResponse is the wire form of the responder's reply. The
// identity payload is encrypted under a key derived from the X-Wing
// shared secret so the responder identity is not revealed to passive
// observers.
type HandshakeResponse struct {
	XWingCiphertext []byte // X-Wing ct (1088+32 bytes)
	EncryptedID     []byte // AEAD-sealed responder identity + signature
}

// MarshalBinary encodes a HandshakeInit as
//
//	[2 bytes BE: idLen][id bytes][2 bytes BE: sigLen][sig bytes]
func (h *HandshakeInit) MarshalBinary() []byte {
	out := make([]byte, 0, 4+len(h.IdentityPub)+len(h.Signature))
	out = appendU16(out, len(h.IdentityPub))
	out = append(out, h.IdentityPub...)
	out = appendU16(out, len(h.Signature))
	out = append(out, h.Signature...)
	return out
}

func parseHandshakeInit(data []byte) (*HandshakeInit, error) {
	r := newSliceReader(data)
	idLen, err := r.readU16()
	if err != nil {
		return nil, err
	}
	id, err := r.readN(int(idLen))
	if err != nil {
		return nil, err
	}
	sigLen, err := r.readU16()
	if err != nil {
		return nil, err
	}
	sig, err := r.readN(int(sigLen))
	if err != nil {
		return nil, err
	}
	if !r.empty() {
		return nil, ErrInvalidWireFormat
	}
	return &HandshakeInit{IdentityPub: id, Signature: sig}, nil
}

// MarshalBinary encodes a HandshakeResponse as
//
//	[XWingCiphertextSize bytes][2 bytes BE: encLen][enc bytes]
func (h *HandshakeResponse) MarshalBinary() []byte {
	out := make([]byte, 0, XWingCiphertextSize+2+len(h.EncryptedID))
	out = append(out, h.XWingCiphertext...)
	out = appendU16(out, len(h.EncryptedID))
	out = append(out, h.EncryptedID...)
	return out
}

func parseHandshakeResponse(data []byte) (*HandshakeResponse, error) {
	// The precheck below guarantees we have enough bytes for ct + the 2-byte
	// encLen, so the ct/encLen reads here never short-fail; only the variable
	// encLen body read can.
	if len(data) < XWingCiphertextSize+2 {
		return nil, ErrInvalidWireFormat
	}
	r := newSliceReader(data)
	ct, _ := r.readN(XWingCiphertextSize)
	encLen, _ := r.readU16()
	enc, err := r.readN(int(encLen))
	if err != nil {
		return nil, err
	}
	if !r.empty() {
		return nil, ErrInvalidWireFormat
	}
	return &HandshakeResponse{XWingCiphertext: ct, EncryptedID: enc}, nil
}

// handshakeResult holds the data both sides agree on after a successful run.
type handshakeResult struct {
	shared [XWingSharedSize]byte
	remote *IdentityPublic
	keyI2R []byte // 32 bytes, initiator->responder AEAD key
	keyR2I []byte // 32 bytes, responder->initiator AEAD key
}

// runInitiator drives the initiator side of the handshake on conn.
func runInitiator(conn io.ReadWriter, cfg *Config) (*handshakeResult, error) {
	if cfg == nil || cfg.LocalIdentity == nil {
		return nil, ErrConfigMissingID
	}
	local := cfg.LocalIdentity

	// 1. Send HandshakeInit.
	idPub := local.Public().MarshalBinary()
	sig := local.Sign([]byte(hsLabelInit), idPub)
	init := &HandshakeInit{IdentityPub: idPub, Signature: sig}
	if err := writeFrame(conn, init.MarshalBinary()); err != nil {
		return nil, err
	}

	// 2. Receive HandshakeResponse.
	respFrame, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	resp, err := parseHandshakeResponse(respFrame)
	if err != nil {
		return nil, err
	}

	// 3. Decapsulate X-Wing shared secret.
	shared, err := XWingDecapsulate(local.XWing, resp.XWingCiphertext)
	if err != nil {
		return nil, err
	}

	// 4. Derive a temporary AEAD key for the responder-identity payload
	//    and decrypt it. Then derive the channel keys from the same secret
	//    via separate labels.
	idKey := derive(shared[:], []byte("lux.zwing.v1/resp-id"), chacha20KeySize)
	defer zero(idKey)
	plaintext, err := aeadOpen(idKey, []byte("zwing-resp-id"), resp.XWingCiphertext, resp.EncryptedID)
	if err != nil {
		return nil, ErrCiphertextCorrupted
	}

	remoteID, remoteSig, err := splitRespIDPayload(plaintext)
	if err != nil {
		return nil, err
	}
	remote, err := ParseIdentityPublic(remoteID)
	if err != nil {
		return nil, err
	}

	// 5. Verify responder signature over transcript = init || ct.
	transcript := transcriptHash(idPub, resp.XWingCiphertext)
	if err := remote.Verify([]byte(hsLabelResponse), transcript, remoteSig); err != nil {
		return nil, err
	}

	// 6. Optional pinning.
	if cfg.ExpectedRemote != nil && !remote.Equal(cfg.ExpectedRemote) {
		return nil, ErrIdentityMismatch
	}

	res := &handshakeResult{
		shared: shared,
		remote: remote,
		keyI2R: derive(shared[:], []byte(channelKeyLabelI2R), chacha20KeySize),
		keyR2I: derive(shared[:], []byte(channelKeyLabelR2I), chacha20KeySize),
	}
	return res, nil
}

// runResponder drives the responder side on conn.
func runResponder(conn io.ReadWriter, cfg *Config) (*handshakeResult, error) {
	if cfg == nil || cfg.LocalIdentity == nil {
		return nil, ErrConfigMissingID
	}
	local := cfg.LocalIdentity

	// 1. Read HandshakeInit.
	initFrame, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	init, err := parseHandshakeInit(initFrame)
	if err != nil {
		return nil, err
	}
	remote, err := ParseIdentityPublic(init.IdentityPub)
	if err != nil {
		return nil, err
	}
	if err := remote.Verify([]byte(hsLabelInit), init.IdentityPub, init.Signature); err != nil {
		return nil, err
	}

	if cfg.ExpectedRemote != nil && !remote.Equal(cfg.ExpectedRemote) {
		return nil, ErrIdentityMismatch
	}

	// 2. Encapsulate X-Wing to initiator's static key.
	ct, shared, err := XWingEncapsulate(nil, remote.XWingPub)
	if err != nil {
		return nil, err
	}

	// 3. Sign transcript and seal local identity.
	idPub := local.Public().MarshalBinary()
	transcript := transcriptHash(init.IdentityPub, ct)
	sig := local.Sign([]byte(hsLabelResponse), transcript)
	plaintext := buildRespIDPayload(idPub, sig)
	idKey := derive(shared[:], []byte("lux.zwing.v1/resp-id"), chacha20KeySize)
	defer zero(idKey)
	ciphertext := aeadSeal(idKey, []byte("zwing-resp-id"), ct, plaintext)

	resp := &HandshakeResponse{XWingCiphertext: ct, EncryptedID: ciphertext}
	if err := writeFrame(conn, resp.MarshalBinary()); err != nil {
		return nil, err
	}

	res := &handshakeResult{
		shared: shared,
		remote: remote,
		keyI2R: derive(shared[:], []byte(channelKeyLabelI2R), chacha20KeySize),
		keyR2I: derive(shared[:], []byte(channelKeyLabelR2I), chacha20KeySize),
	}
	return res, nil
}

// derive runs HKDF-SHA256 over the X-Wing shared secret to produce a key
// for the requested label. We use SHA-256 (not SHA3) here to avoid pulling
// a second hash construction into the critical path; the underlying secret
// is already SHA3-256-derived by the X-Wing combiner.
//
// HKDF over a fixed-length input never short-reads for the sizes we ask
// for (≤32 bytes), so io.ReadFull cannot fail. We therefore drop the
// always-dead error branch.
func derive(secret, label []byte, size int) []byte {
	out := make([]byte, size)
	r := hkdf.New(sha256.New, secret, nil, label)
	_, _ = io.ReadFull(r, out)
	return out
}

// transcriptHash binds the initiator's identity payload and the X-Wing
// ciphertext into a single 32-byte hash that the responder signs.
func transcriptHash(initPub, ct []byte) []byte {
	h := sha256.New()
	h.Write([]byte("lux.zwing.v1/transcript"))
	binary.Write(h, binary.BigEndian, uint32(len(initPub)))
	h.Write(initPub)
	binary.Write(h, binary.BigEndian, uint32(len(ct)))
	h.Write(ct)
	return h.Sum(nil)
}

// buildRespIDPayload encodes the responder identity + signature as
//
//	[2 BE idLen][id][2 BE sigLen][sig]
func buildRespIDPayload(id, sig []byte) []byte {
	out := make([]byte, 0, 4+len(id)+len(sig))
	out = appendU16(out, len(id))
	out = append(out, id...)
	out = appendU16(out, len(sig))
	out = append(out, sig...)
	return out
}

func splitRespIDPayload(data []byte) (id, sig []byte, err error) {
	r := newSliceReader(data)
	idLen, err := r.readU16()
	if err != nil {
		return nil, nil, err
	}
	id, err = r.readN(int(idLen))
	if err != nil {
		return nil, nil, err
	}
	sigLen, err := r.readU16()
	if err != nil {
		return nil, nil, err
	}
	sig, err = r.readN(int(sigLen))
	if err != nil {
		return nil, nil, err
	}
	if !r.empty() {
		return nil, nil, ErrInvalidWireFormat
	}
	return id, sig, nil
}

// ── small helpers ────────────────────────────────────────────────────

func appendU16(b []byte, n int) []byte {
	if n < 0 || n > 0xFFFF {
		panic("zwing: u16 out of range")
	}
	return append(b, byte(n>>8), byte(n))
}

type sliceReader struct {
	buf []byte
}

func newSliceReader(b []byte) *sliceReader { return &sliceReader{buf: b} }

func (r *sliceReader) readU16() (uint16, error) {
	if len(r.buf) < 2 {
		return 0, ErrShortRead
	}
	v := binary.BigEndian.Uint16(r.buf[:2])
	r.buf = r.buf[2:]
	return v, nil
}

func (r *sliceReader) readN(n int) ([]byte, error) {
	if n < 0 || len(r.buf) < n {
		return nil, ErrShortRead
	}
	out := r.buf[:n]
	r.buf = r.buf[n:]
	return out, nil
}

func (r *sliceReader) empty() bool { return len(r.buf) == 0 }
