// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Conn is a Z-Wing secure channel implementing net.Conn. After the
// handshake, every Read/Write goes through ChaCha20-Poly1305 with
// per-direction sequence-numbered nonces.
type Conn struct {
	raw    net.Conn
	remote *IdentityPublic

	readMu   sync.Mutex
	readAEAD cipher.AEAD
	readSeq  uint64
	readBuf  []byte // overflow from a previous Read

	writeMu   sync.Mutex
	writeAEAD cipher.AEAD
	writeSeq  uint64
}

// newConn wraps a freshly handshaken net.Conn. role determines which
// direction's key is used for reading vs writing.
//
// chacha20poly1305.New only fails on a wrong-size key. We always pass a
// 32-byte HKDF output, so the construction is infallible; we use
// mustChaCha20 to make that invariant explicit.
func newConn(raw net.Conn, res *handshakeResult, initiator bool) (*Conn, error) {
	c := &Conn{raw: raw, remote: res.remote}
	var rxKey, txKey []byte
	if initiator {
		txKey = res.keyI2R
		rxKey = res.keyR2I
	} else {
		txKey = res.keyR2I
		rxKey = res.keyI2R
	}
	c.readAEAD = mustChaCha20(rxKey)
	c.writeAEAD = mustChaCha20(txKey)
	// Best-effort zeroing of the channel keys held by the handshake result
	// once the AEADs have copied them internally.
	zero(res.keyI2R)
	zero(res.keyR2I)
	return c, nil
}

// mustChaCha20 builds a ChaCha20-Poly1305 AEAD from a key. The only
// failure mode of chacha20poly1305.New is a wrong-size key — every
// caller in this package supplies a 32-byte HKDF output, so any
// failure here is a programming bug.
//
// The construction is deliberately unconditional: a wrong-size key
// would be caught in tests via TestMustChaCha20Panics. In production
// every key reaching this function is a 32-byte HKDF/chacha20KeySize
// slice, by construction.
func mustChaCha20(key []byte) cipher.AEAD {
	if len(key) != chacha20poly1305.KeySize {
		panic("zwing: chacha20poly1305 key must be 32 bytes")
	}
	a, _ := chacha20poly1305.New(key)
	return a
}

// RemoteIdentity returns the verified remote IdentityPublic. Callers may
// pin specific peers via Config.ExpectedRemote, but this getter lets
// servers see who connected once the handshake succeeded.
func (c *Conn) RemoteIdentity() *IdentityPublic { return c.remote }

// Read reads decrypted plaintext into b. A Z-Wing record may be larger
// than b, in which case the remainder is buffered for the next call.
func (c *Conn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		if len(c.readBuf) == 0 {
			c.readBuf = nil
		}
		return n, nil
	}

	frame, err := readFrame(c.raw)
	if err != nil {
		return 0, err
	}
	if c.readSeq == ^uint64(0) {
		return 0, ErrSequenceExhausted
	}
	nonce := nonceFor(c.readSeq)
	plaintext, err := c.readAEAD.Open(nil, nonce[:], frame, nil)
	if err != nil {
		return 0, ErrCiphertextCorrupted
	}
	c.readSeq++

	n := copy(b, plaintext)
	if n < len(plaintext) {
		c.readBuf = plaintext[n:]
	}
	return n, nil
}

// Write encrypts b as a single Z-Wing record and writes it to the
// underlying conn. Application payloads larger than MaxFrameSize-tag are
// split.
func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	const maxPlain = MaxFrameSize - chacha20poly1305.Overhead
	written := 0
	for written < len(b) {
		end := written + maxPlain
		if end > len(b) {
			end = len(b)
		}
		chunk := b[written:end]

		if c.writeSeq == ^uint64(0) {
			return written, ErrSequenceExhausted
		}
		nonce := nonceFor(c.writeSeq)
		ciphertext := c.writeAEAD.Seal(nil, nonce[:], chunk, nil)
		c.writeSeq++

		if err := writeFrame(c.raw, ciphertext); err != nil {
			return written, err
		}
		written += len(chunk)
	}
	return written, nil
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	if c.raw == nil {
		return ErrChannelClosed
	}
	return c.raw.Close()
}

// LocalAddr returns the underlying local address.
func (c *Conn) LocalAddr() net.Addr { return c.raw.LocalAddr() }

// RemoteAddr returns the underlying remote address.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// SetDeadline sets read+write deadline on the underlying conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.raw.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

// nonceFor builds a 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter:
// the high 4 bytes are zero, the low 8 are the big-endian counter.
func nonceFor(seq uint64) [12]byte {
	var n [12]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// aeadSeal/aeadOpen are used during the handshake to protect the
// responder identity payload. They use the X-Wing ciphertext as
// associated data so the binding cannot be transplanted onto another
// session. The key is always a 32-byte HKDF output, so AEAD
// construction never fails (see mustChaCha20).
func aeadSeal(key, nonceLabel, aad, plaintext []byte) []byte {
	aead := mustChaCha20(key)
	nonce := handshakeNonce(nonceLabel)
	return aead.Seal(nil, nonce[:], plaintext, aad)
}

func aeadOpen(key, nonceLabel, aad, ciphertext []byte) ([]byte, error) {
	aead := mustChaCha20(key)
	nonce := handshakeNonce(nonceLabel)
	pt, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, errors.New("zwing: handshake AEAD open failed")
	}
	return pt, nil
}

// handshakeNonce derives a 12-byte fixed nonce from a label. The key used
// with this nonce is unique to a single handshake (HKDF over the X-Wing
// shared secret with a session-specific label), so reusing the nonce is
// safe.
func handshakeNonce(label []byte) [12]byte {
	var n [12]byte
	copy(n[:], label)
	return n
}
