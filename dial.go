// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"context"
	"net"
	"time"
)

// Dial connects to a Z-Wing listener at addr and runs the handshake.
// The returned net.Conn is the post-handshake encrypted channel.
func Dial(ctx context.Context, addr string, cfg *Config) (net.Conn, error) {
	if cfg == nil || cfg.LocalIdentity == nil {
		return nil, ErrConfigMissingID
	}
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return clientHandshake(raw, cfg)
}

// Client wraps an existing net.Conn (e.g. a TLS conn, a Unix socket, a
// pipe) and runs the Z-Wing handshake on top as the initiator.
func Client(raw net.Conn, cfg *Config) (net.Conn, error) {
	return clientHandshake(raw, cfg)
}

// Server wraps an existing net.Conn and runs the handshake as the responder.
func Server(raw net.Conn, cfg *Config) (net.Conn, error) {
	return serverHandshake(raw, cfg)
}

func clientHandshake(raw net.Conn, cfg *Config) (net.Conn, error) {
	if cfg.HandshakeTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
		defer raw.SetDeadline(time.Time{})
	}
	res, err := runInitiator(raw, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return newConn(raw, res, true)
}

func serverHandshake(raw net.Conn, cfg *Config) (net.Conn, error) {
	if cfg.HandshakeTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
		defer raw.SetDeadline(time.Time{})
	}
	res, err := runResponder(raw, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return newConn(raw, res, false)
}
