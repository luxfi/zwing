// Tiny Z-Wing test server used for cross-language interop tests.
// Listens on the address given by the first arg (or 127.0.0.1:0),
// prints the listening address + the public-identity hex on stdout
// (one per line), then accepts ONE Z-Wing connection, echoes one
// payload, and exits.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/luxfi/zwing"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen addr")
	flag.Parse()

	id, err := zwing.GenerateIdentity()
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	ln, err := zwing.Listen(*addr, &zwing.Config{LocalIdentity: id})
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	pubBytes := id.Public().MarshalBinary()
	fmt.Println(ln.Addr().String())
	fmt.Println(hex.EncodeToString(pubBytes))

	// Force stdout flush so the harness can read both lines before we
	// block on Accept.
	os.Stdout.Sync()

	conn, err := ln.Accept()
	if err != nil {
		log.Fatalf("accept: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		if err == io.EOF {
			return
		}
		log.Fatalf("read: %v", err)
	}
	if _, err := conn.Write(buf[:n]); err != nil {
		log.Fatalf("write: %v", err)
	}
}
