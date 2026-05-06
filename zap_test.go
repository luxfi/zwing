// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/luxfi/api/zap"
	"github.com/luxfi/zwing"
)

// TestZAPOverZWing wires a luxfi/api/zap client through a Z-Wing channel,
// runs one request/response, and verifies the application bytes survive
// the encrypted transport unchanged.
func TestZAPOverZWing(t *testing.T) {
	clientID, err := zwing.GenerateIdentity()
	if err != nil {
		t.Fatalf("client id: %v", err)
	}
	serverID, err := zwing.GenerateIdentity()
	if err != nil {
		t.Fatalf("server id: %v", err)
	}

	ln, err := zwing.Listen("127.0.0.1:0", &zwing.Config{LocalIdentity: serverID})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvDone := make(chan error, 1)
	go func() {
		srvDone <- runZAPEchoServer(ln)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cConn, err := zwing.Dial(ctx, ln.Addr().String(), &zwing.Config{LocalIdentity: clientID})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cConn.Close()

	zapConn := zap.NewConn(cConn, nil)
	defer zapConn.Close()

	payload := []byte("zap-over-zwing")
	respType, respPayload, err := zapConn.Call(ctx, zap.MsgBuildBlock, payload)
	if err != nil {
		t.Fatalf("zap call: %v", err)
	}
	if respType&zap.MsgResponseFlag == 0 {
		t.Fatalf("response missing MsgResponseFlag")
	}
	if !bytes.Equal(respPayload, payload) {
		t.Fatalf("payload mismatch: got %q want %q", respPayload, payload)
	}

	// Close the client side first so the server's blocking ReadMessage
	// returns EOF promptly, then close the listener.
	zapConn.Close()
	cConn.Close()
	ln.Close()
	select {
	case err := <-srvDone:
		if err != nil && err != net.ErrClosed {
			t.Logf("server exited: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after closing client and listener")
	}
}

// runZAPEchoServer accepts one Z-Wing conn and runs a tiny ZAP echo loop
// using the zap wire helpers directly so we don't need to construct a
// full zap.Server (which would need a Listener built from a net.Listener,
// not from zwing.Listener).
func runZAPEchoServer(ln *zwing.Listener) error {
	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Read one request frame, echo it back with the response flag set.
	for {
		msgType, payload, err := zap.ReadMessage(readerOf(conn))
		if err != nil {
			return err
		}
		if len(payload) < 4 {
			return nil
		}
		// payload is [reqID:uint32][body...]; echo body back with reqID.
		body := payload[4:]
		respPayload := make([]byte, 4+len(body))
		copy(respPayload[:4], payload[:4])
		copy(respPayload[4:], body)
		if err := zap.WriteMessage(writerOf(conn), msgType|zap.MsgResponseFlag, respPayload); err != nil {
			return err
		}
	}
}

// readerOf / writerOf wrap a net.Conn so the zap wire helpers see plain
// io.Reader / io.Writer (which they require).
type readerOnly struct{ net.Conn }
type writerOnly struct{ net.Conn }

func readerOf(c net.Conn) readerOnly { return readerOnly{c} }
func writerOf(c net.Conn) writerOnly { return writerOnly{c} }
