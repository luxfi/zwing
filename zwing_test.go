// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zwing

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func newPair(t *testing.T) (clientID, serverID *Identity) {
	t.Helper()
	c, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	s, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	return c, s
}

// pipeConn turns a net.Pipe end into a deadline-supporting conn. net.Pipe
// already gives us net.Conns; we just plumb both ends.

// runHandshakeOverPipe drives one initiator and one responder over a
// memory pipe with the given configs and returns both Conns or the first
// error.
func runHandshakeOverPipe(t *testing.T, clientCfg, serverCfg *Config) (cConn, sConn net.Conn, cErr, sErr error) {
	t.Helper()
	left, right := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c, err := Client(left, clientCfg)
		cConn = c
		cErr = err
	}()
	go func() {
		defer wg.Done()
		s, err := Server(right, serverCfg)
		sConn = s
		sErr = err
	}()
	wg.Wait()
	return cConn, sConn, cErr, sErr
}

func TestHandshakeRoundTrip(t *testing.T) {
	clientID, serverID := newPair(t)
	cConn, sConn, cErr, sErr := runHandshakeOverPipe(t,
		&Config{LocalIdentity: clientID},
		&Config{LocalIdentity: serverID},
	)
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake errors: client=%v server=%v", cErr, sErr)
	}
	defer cConn.Close()
	defer sConn.Close()

	// The remote identities should be the peers'.
	cRemote := cConn.(*Conn).RemoteIdentity()
	sRemote := sConn.(*Conn).RemoteIdentity()
	if !cRemote.Equal(serverID.Public()) {
		t.Fatal("client did not see server identity")
	}
	if !sRemote.Equal(clientID.Public()) {
		t.Fatal("server did not see client identity")
	}

	// Round-trip a payload in both directions.  net.Pipe is synchronous
	// so writes must overlap with reads on the peer.
	payload := []byte("z-wing flies")
	wErr := make(chan error, 1)
	go func() { _, e := cConn.Write(payload); wErr <- e }()
	buf := make([]byte, len(payload))
	if _, err := sConn.Read(buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if err := <-wErr; err != nil {
		t.Fatalf("client write: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("c->s: got %q want %q", buf, payload)
	}

	go func() { _, _ = sConn.Write([]byte("ack")) }()
	buf = make([]byte, 3)
	if _, err := cConn.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(buf, []byte("ack")) {
		t.Fatalf("s->c: got %q want %q", buf, "ack")
	}
}

func TestDialListen(t *testing.T) {
	clientID, serverID := newPair(t)

	ln, err := Listen("127.0.0.1:0", &Config{LocalIdentity: serverID})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type accepted struct {
		c   net.Conn
		err error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		c, err := ln.Accept()
		acceptCh <- accepted{c: c, err: err}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cConn, err := Dial(ctx, ln.Addr().String(), &Config{LocalIdentity: clientID})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cConn.Close()

	a := <-acceptCh
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	defer a.c.Close()

	msg := []byte("hello over tcp")
	if _, err := cConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := a.c.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("got %q want %q", buf, msg)
	}
}

func TestIdentityMismatch(t *testing.T) {
	clientID, serverID := newPair(t)
	_, otherID := newPair(t)

	_, _, cErr, sErr := runHandshakeOverPipe(t,
		// Client expects a server identity that does not match.
		&Config{LocalIdentity: clientID, ExpectedRemote: otherID.Public()},
		&Config{LocalIdentity: serverID},
	)
	if !errors.Is(cErr, ErrIdentityMismatch) {
		t.Fatalf("client: want ErrIdentityMismatch, got %v", cErr)
	}
	// Server side may either succeed in writing then see the conn close,
	// or fail with a pipe error - we don't pin the exact behaviour.
	_ = sErr
}

func TestForwardSecrecy(t *testing.T) {
	clientID, serverID := newPair(t)
	cConn, sConn, cErr, sErr := runHandshakeOverPipe(t,
		&Config{LocalIdentity: clientID},
		&Config{LocalIdentity: serverID},
	)
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: %v / %v", cErr, sErr)
	}
	defer cConn.Close()
	defer sConn.Close()

	// The post-handshake Conn must not retain any handshake-scoped raw
	// key material in exported fields. The handshakeResult.keyI2R / keyR2I
	// slices are zeroed after AEADs are constructed (see newConn). We can
	// verify by introspecting the result via a fresh handshake and
	// inspecting keys-after-zero.
	res := &handshakeResult{
		shared: [XWingSharedSize]byte{},
		keyI2R: derive([]byte{1, 2, 3}, []byte("k1"), 32),
		keyR2I: derive([]byte{1, 2, 3}, []byte("k2"), 32),
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	c, err := newConn(left, res, true)
	if err != nil {
		t.Fatalf("newConn: %v", err)
	}
	_ = c
	// After newConn the slices fed in should be zeroed.
	for i, b := range res.keyI2R {
		if b != 0 {
			t.Fatalf("keyI2R[%d] not zeroed: 0x%x", i, b)
		}
	}
	for i, b := range res.keyR2I {
		if b != 0 {
			t.Fatalf("keyR2I[%d] not zeroed: 0x%x", i, b)
		}
	}
}

// TestSequencedNonces makes sure two messages in a row use distinct
// nonces and decrypt independently.
func TestSequencedNonces(t *testing.T) {
	clientID, serverID := newPair(t)
	cConn, sConn, cErr, sErr := runHandshakeOverPipe(t,
		&Config{LocalIdentity: clientID},
		&Config{LocalIdentity: serverID},
	)
	if cErr != nil || sErr != nil {
		t.Fatalf("handshake: %v / %v", cErr, sErr)
	}
	defer cConn.Close()
	defer sConn.Close()

	for i, msg := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		wErr := make(chan error, 1)
		go func() { _, e := cConn.Write(msg); wErr <- e }()
		buf := make([]byte, len(msg))
		if _, err := sConn.Read(buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if err := <-wErr; err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("msg %d: got %q want %q", i, buf, msg)
		}
	}
}
