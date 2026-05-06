// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"context"

	"github.com/luxfi/api/zap"
)

// DialZAP opens a Z-Wing channel to addr and wraps it as a ZAP client
// connection. This is the canonical way to speak ZAP RPC over a PQ
// transport: one call, one composition, no chance of misuse.
//
//	conn, err := zwing.DialZAP(ctx, "host:9999", &zwing.Config{
//	    LocalIdentity:  myID,
//	    ExpectedRemote: pinnedServerPub, // optional
//	})
//	defer conn.Close()
//	resp, payload, err := conn.Call(ctx, zap.MsgFoo, body)
func DialZAP(ctx context.Context, addr string, cfg *Config) (*zap.Conn, error) {
	raw, err := Dial(ctx, addr, cfg)
	if err != nil {
		return nil, err
	}
	return zap.NewConn(raw, nil), nil
}

// ListenZAP binds a Z-Wing listener at addr and returns a ZAP listener
// that accepts post-handshake encrypted ZAP connections. Pair with
// zap.NewServer to host an RPC service.
//
//	ln, _ := zwing.ListenZAP(":9999", &zwing.Config{LocalIdentity: id})
//	srv  := zap.NewServer(ln, zap.HandlerFunc(handle))
//	srv.Serve(ctx)
func ListenZAP(addr string, cfg *Config) (*zap.Listener, error) {
	zln, err := Listen(addr, cfg)
	if err != nil {
		return nil, err
	}
	return zap.NewListener(zln, nil), nil
}
