// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"encoding/binary"
	"io"
)

// MaxFrameSize is the largest single transport frame Z-Wing will read or
// write. Application bytes larger than this are split by the channel.
const MaxFrameSize = 1 << 20 // 1 MiB

// frame layout:
//
//	[4 bytes BE length][payload]
//
// length covers the payload only. payload is either a handshake message
// (raw bytes) or an AEAD-sealed transport record.

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return ErrMessageTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameSize {
		return nil, ErrMessageTooLarge
	}
	if n == 0 {
		return nil, ErrInvalidWireFormat
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
