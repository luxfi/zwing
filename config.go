// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import "time"

// DefaultPort is the canonical Z-Wing TCP port.
const DefaultPort = 9999

// Config configures a Z-Wing dialer or listener.
type Config struct {
	// LocalIdentity is this endpoint's long-term identity. Required.
	LocalIdentity *Identity

	// ExpectedRemote pins the peer's expected public identity. If set, the
	// handshake fails with ErrIdentityMismatch when the remote presents a
	// different identity. Leave nil for "any peer with a valid identity".
	ExpectedRemote *IdentityPublic

	// HandshakeTimeout bounds the handshake itself. Zero means no timeout.
	HandshakeTimeout time.Duration
}
