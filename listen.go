// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import "net"

// Listener is a Z-Wing listener. Accepted connections are post-handshake
// net.Conns ready for application traffic.
type Listener struct {
	raw net.Listener
	cfg *Config
}

// Listen binds a TCP listener at addr that performs Z-Wing handshakes
// before yielding connections.
func Listen(addr string, cfg *Config) (*Listener, error) {
	if cfg == nil || cfg.LocalIdentity == nil {
		return nil, ErrConfigMissingID
	}
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Listener{raw: raw, cfg: cfg}, nil
}

// Accept returns the next handshaken connection. If a handshake fails
// the underlying conn is closed and Accept returns the error; callers
// that want to keep listening should call Accept again.
func (l *Listener) Accept() (net.Conn, error) {
	raw, err := l.raw.Accept()
	if err != nil {
		return nil, err
	}
	return serverHandshake(raw, l.cfg)
}

// Close closes the underlying TCP listener.
func (l *Listener) Close() error { return l.raw.Close() }

// Addr returns the listener's TCP address.
func (l *Listener) Addr() net.Addr { return l.raw.Addr() }
