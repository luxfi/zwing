# Z-Wing — Lux Post-Quantum Secure Channel

## Overview

Z-Wing is the canonical Lux PQ secure channel. One construction, one wire
format, no negotiation. If two endpoints don't both speak Z-Wing v1, they
don't talk.

Layering:

```
Application:  ZAP RPC (luxfi/api/zap)            <- unchanged
Channel:      Z-Wing                              <- this package
  KEM:        X-Wing  (X25519 + ML-KEM-768, IETF draft-connolly-cfrg-xwing-kem)
  Identity:   Ed25519 + ML-DSA-65 hybrid signatures
  AEAD:       ChaCha20-Poly1305 with sequence-numbered nonces
Routing:      Plain TCP (this version) or RNS (follow-up)
```

The `Conn` returned by `Dial` / `Listener.Accept()` implements `net.Conn`,
so any Lux service that already speaks ZAP gets PQ on the wire by simply
swapping its dialer:

```go
raw, _ := zwing.Dial(ctx, "host:9999", &zwing.Config{LocalIdentity: id})
zapConn := zap.NewConn(raw, nil)   // ZAP unchanged
```

## Default port

Z-Wing inherits the canonical Lux ZAP port: **TCP 9999**. Override only
when running multiple Z-Wing servers on the same host.

## Wire format

### Frame

Every transport frame on a Z-Wing channel:

```
[4 bytes BE: payload length][payload bytes]
```

`MaxFrameSize` = 1 MiB. The `payload` is either a handshake message
(during the handshake) or an AEAD-sealed application record (after).

### Handshake (1-RTT)

```
Initiator -> Responder : HandshakeInit
    [2 BE idLen][IdentityPublic bytes][2 BE sigLen][hybrid signature]

Responder -> Initiator : HandshakeResponse
    [XWingCiphertextSize bytes: ML-KEM ct || X25519 ephemeral pk]
    [2 BE encLen][AEAD-sealed responder identity + signature]
```

* The initiator signs `(label || IdentityPublic)` so a passive observer
  cannot lift the public identity onto another protocol.
* The responder signs the **transcript hash** that covers the initiator's
  public identity AND the X-Wing ciphertext, binding the signature to
  the session.
* The responder identity is encrypted under an HKDF-derived key from the
  X-Wing shared secret, so passive observers do not learn the responder's
  long-term identity.

### IdentityPublic

```
[Ed25519 pk: 32][ML-DSA-65 pk: 1952][X-Wing pk: 1216]
              total: 3200 bytes
```

`X-Wing pk = ML-KEM-768 pk (1184) || X25519 pk (32)`.

## X-Wing combiner (IETF spec, exact)

```
shared_secret = SHA3-256( "\./" || "X-Wing" || ss_M || ss_X || ct_X || pk_X )
```

| Input | Bytes | Source |
|---|---|---|
| `"\./"`   | 3   | label prefix (backslash, dot, slash) |
| `"X-Wing"` | 6   | ASCII protocol name |
| `ss_M`    | 32  | ML-KEM-768 shared secret |
| `ss_X`    | 32  | X25519 shared secret |
| `ct_X`    | 32  | X25519 ephemeral public key from encapsulator |
| `pk_X`    | 32  | X25519 static public key of recipient |

Hash construction: SHA3-256, no HKDF. Inputs are fixed-length so no
length separators are required.

In the Z-Wing handshake the **responder is the encapsulator** (it sends
ct_X) and the **initiator is the recipient** (its X-Wing static is the
target of the encapsulation).

## Channel keys

After the handshake:

```
keyI2R = HKDF-SHA256(shared, "lux.zwing.v1/i2r", 32)
keyR2I = HKDF-SHA256(shared, "lux.zwing.v1/r2i", 32)
```

Each direction has its own ChaCha20-Poly1305 key. Nonce = 12 bytes,
high 4 bytes zero, low 8 bytes are the big-endian sequence counter.
A 64-bit counter would last 5.8e11 years at one record per nanosecond;
exhausting it returns `ErrSequenceExhausted`.

Forward secrecy comes from the X25519 ephemeral inside X-Wing. The
ephemeral private key and intermediate `ss_M` / `ss_X` values are zeroed
once the shared secret is derived. Channel keys are zeroed after the
AEADs have been constructed.

## Identity signatures

The `Identity` type holds three keypairs: Ed25519, ML-DSA-65, and X-Wing.
Signature wire format:

```
[Ed25519 sig: 64][ML-DSA-65 sig: 3309]   total: 3373 bytes
```

Both must verify or `ErrSignatureInvalid` is returned. ML-DSA is signed
with the `lux.zwing.v1` context per FIPS 204 §5.2 so signatures are not
portable across protocols that share identity keys.

## Public API

```go
// Identity
id, _ := zwing.GenerateIdentity()
pub  := id.Public()                   // serialise + hand to a peer

// Server
ln, _ := zwing.Listen(":9999", &zwing.Config{LocalIdentity: id})
for {
    conn, err := ln.Accept()          // post-handshake net.Conn
    if err != nil { break }
    go handle(conn)
}

// Client
conn, _ := zwing.Dial(ctx, "host:9999", &zwing.Config{
    LocalIdentity:  clientID,
    ExpectedRemote: pinnedServerPub,  // optional; nil = any valid peer
})
```

`Client(net.Conn, *Config)` and `Server(net.Conn, *Config)` wrap an
existing connection (Unix socket, TLS conn, in-memory pipe, RNS link)
without TCP `Dial`/`Listen`.

## What's NOT in this version

* RNS routing. Z-Wing-over-RNS is a follow-up package (LP-9702 deployment
  path); v0.1.0 ships Z-Wing-over-TCP only.
* AES-256-GCM AEAD. Single ciphersuite; ChaCha20-Poly1305 only.
* Cipher / KEM negotiation. There is one Z-Wing v1.

## Testing

```
GOWORK=off go test ./... -count=1
```

Six tests cover the spec:

| Test | What it proves |
|---|---|
| `TestHandshakeRoundTrip`   | end-to-end handshake; both peers see correct remote identity; bidirectional traffic works |
| `TestDialListen`           | TCP `Dial` + `Listener.Accept`, payload round-trip |
| `TestIdentityMismatch`     | `Config.ExpectedRemote = wrong` returns `ErrIdentityMismatch` |
| `TestForwardSecrecy`       | channel keys are zeroed after the AEAD is constructed |
| `TestSequencedNonces`      | three sequential records each decrypt cleanly under increasing nonces |
| `TestZAPOverZWing`         | `zap.NewConn` over a Z-Wing client; one ZAP RPC round-trip succeeds |

## Files

| File | Purpose |
|---|---|
| `doc.go`        | package documentation |
| `errors.go`     | typed errors |
| `kem.go`        | X-Wing KEM (X25519 + ML-KEM-768 + SHA3-256 combiner) |
| `identity.go`   | hybrid Ed25519 + ML-DSA-65 identity with X-Wing static key |
| `wire.go`       | length-prefixed framing |
| `handshake.go`  | initiator/responder state machines |
| `channel.go`    | post-handshake `net.Conn` with ChaCha20-Poly1305 |
| `config.go`     | `Config` and `DefaultPort` |
| `dial.go`       | `Dial` / `Client` |
| `listen.go`     | `Listen` / `Listener` |
| `zwing_test.go` | core protocol tests |
| `zap_test.go`   | ZAP-over-Z-Wing integration |

## See also

* `~/work/lux/api/zap/LLM.md` — the application protocol that runs on top
* `~/work/zap/zap/src/crypto.rs` — Rust hybrid handshake reference
* `~/work/lux/crypto` — ML-KEM, ML-DSA, Ed25519 primitives used here
* `draft-connolly-cfrg-xwing-kem` — IETF X-Wing combiner spec
