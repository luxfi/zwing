// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import "errors"

var (
	ErrHandshakeFailed     = errors.New("zwing: handshake failed")
	ErrIdentityMismatch    = errors.New("zwing: remote identity does not match expected")
	ErrSignatureInvalid    = errors.New("zwing: signature verification failed")
	ErrMessageTooLarge     = errors.New("zwing: message exceeds maximum size")
	ErrShortRead           = errors.New("zwing: short read")
	ErrInvalidWireFormat   = errors.New("zwing: invalid wire format")
	ErrChannelClosed       = errors.New("zwing: channel closed")
	ErrSequenceExhausted   = errors.New("zwing: AEAD sequence number exhausted")
	ErrConfigMissingID     = errors.New("zwing: config missing LocalIdentity")
	ErrCiphertextCorrupted = errors.New("zwing: AEAD authentication failed")
)
