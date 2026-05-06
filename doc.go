// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package zwing implements Z-Wing, the canonical Lux post-quantum secure
// channel. It provides an authenticated, forward-secret, hybrid PQ tunnel
// that exposes a net.Conn so application protocols (e.g. luxfi/api/zap)
// run unchanged on top.
//
// Layering:
//
//	Application: ZAP RPC (luxfi/api/zap)            <- unchanged
//	Channel:     Z-Wing (this package)
//	  KEM:       X-Wing  (X25519 + ML-KEM-768, IETF draft-connolly-cfrg-xwing-kem)
//	  Identity:  Ed25519 + ML-DSA-65 hybrid signatures
//	  AEAD:      ChaCha20-Poly1305, sequence-numbered nonces
//	Routing:     Plain TCP (this version) or RNS (follow-up package)
//
// Z-Wing is one construction. There are no alternates, no build tags, no
// cipher negotiation. The point of standardising is that two endpoints
// either speak Z-Wing v1 or they don't talk.
//
// Public API:
//
//	id, _ := zwing.GenerateIdentity()
//	ln, _ := zwing.Listen(":9999", &zwing.Config{LocalIdentity: id})
//	conn, _ := zwing.Dial(ctx, "host:9999", &zwing.Config{LocalIdentity: clientID})
//
// `conn` and the result of `ln.Accept()` both implement net.Conn and can be
// passed to zap.NewConn, http.Serve, or anything else that wants a stream.
package zwing
