# ctunnel (working name)

ctunnel is a small, auditable, zero-trust secure transport implemented in Rust.

It provides:
- Mutual authentication (Ed25519)
- Forward secrecy (X25519)
- Transcript-bound handshakes (MITM & replay resistant)
- Authenticated encryption (XChaCha20-Poly1305)
- Replay-protected record layer
- Clean separation between protocol logic and I/O

This project is intentionally not TLS and not a wrapper around an existing protocol.
It is a ground-up implementation designed to be:

- Easy to reason about
- Easy to audit
- Easy to reuse in other systems

## Why ctunnel exists

Most secure transports fall into one of two extremes:
- **Very complex (TLS)**: powerful, but hard to reason about or adapt
- **Very simple (DIY crypto)**: easy to write, easy to break

ctunnel demonstrates a third option:

> A small, composable, cryptographically sound transport with explicit guarantees.

This makes it useful for:
- service-to-service control planes
- secure agents / collectors
- sidecar tunnels
- custom RPC protocols
- security research and education

## Security properties

ctunnel provides the following guarantees:

**Handshake layer**
- Mutual authentication (pinned identities / allowlists)
- Fresh ephemeral keys per session
- Transcript-bound signatures (replay & tamper resistant)
- Strict state machines (no message reordering)

**Record layer**
- AEAD encryption (XChaCha20-Poly1305)
- Directional keys (client→server / server→client)
- Monotonic counters with replay detection
- Authenticated headers (AAD binding)

**Failure semantics**
- Fail-closed on any integrity violation
- No partial state
- No downgrade paths
-- No silent corruption

All of these properties are empirically tested using on-path attacker scripts.

## Threat Model Assumptions
ctunnel assumes:
- An active on-path attacker capable of replay and tampering
- No compromise of long-term private keys
- Both peers are provisioned out-of-band

ctunnel does not attmept to defend against:
- Endpoint compromise
- Traffic analysis
- Denial of service at the transport layer

See `THREAT_MODEL.md` for concrete attack demonstrations.

### Repository Layout
```Nix
ctunnel/
├── crates/
│   ├── ctunnel-core           # Protocol, crypto traits, handshake, channel
│   ├── ctunnel-crypto-sodium  # libsodium-backed crypto provider
│   └── ctunnel-net-tokio      # Tokio TCP adapter
│
├── apps/
│   └── ctunnel                # CLI demo (server / client / keygen)
│
├── tools/                     # Attacker & MITM scripts (Python)
│
├── ARCHITECTURE.md
├── THREAT_MODEL.md
└── README.md
```

**Each layer is intentionally isolated**
- `ctunnel-core` contains no networking
- Crypto backends are pluggable via traits
- Networkin integration lives outside the protocol

## Quick Start
**1. Build**
```bash
cargo buid
```

**2. Generate Keys**
```bash
cargo run -p ctunnel -- keygen --out-dir keys --name server
cargo run -p ctunnel -- keygen --out-dir keys --name client
```

Thid produces:
```bash
keys/server.key
keys/server.pub
keys/client.key
keys/client.pub
```

Private keys are written with `0600` permissions on nix.

**3. Start the Server**
```
cargo run -p ctunnel -- server \
  --bind 127.0.0.1:9000 \
  --server-key keys/server.key \
  --allow-client keys/client.pub
```

**4. Run the Client**
```
cargo run -p ctunnel -- client \
  --connect 127.0.0.1:9000 \
  --client-key keys/client.key \
  --expect-server keys/server.pub \
  --msg "hello, encrypted world"
```

You should see the echoed message. All traffic on the wire is encrypted, authenticated, and replay-protected.

## Threat modeling & attacker validation

This repository includes **active attacker tooling** under `tools/`:

### MITM replay attacks
- Handshake tampering
- Identity spoofing attempts
- Record-layer replay
- Ciphertext / AAD tampering
- Framing abuse

These scripts were used to validate that:
- Replayed handshakes fail
- Tampered handshakes fail
- Replayed encrypted frames fail
- Modified ciphertext is rejected

See `THREAT_MODEL.md` for:
- Attacker capabilities
- Exact attack steps
- Observed failures
- Mitigation mapping to code

### What ctunnel is not
ctunnel is not intended to replace TLS. It intentionally does not provide:
- Browser compatibility
- PKI / certificates
- Algorithm negotiation
- Backward compatibility
- HTTP integration

Instead, ctunnel is designed for environments where:
- Identities are pinned or provisioned
- Both sides are under your control
- Simplicity and auditability matter

### Reuse in other projects
ctunnel is designed to be reused at different layers:
- Use ctunnel-core if you want just the protocol
- Use ctunnel-net-tokio for a ready-made TCP transport
- Swap in a different crypto backend if needed

Future work includes:
- Extracting the tunnel into a standalone repository
- Docker-based demos
- Optional persistent connections & UX polish

### License
MIT / Apache-2.0 (dual licensed)