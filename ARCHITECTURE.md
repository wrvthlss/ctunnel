# Architecture
### Overview
`ctunnel` is a layered secure transport designed around explicit trust boundaries, auditable cryptography, and protocol correctness.

The system is intentionally decomposed into small, orthogonal layers so that:

- Security properties are localized and testable
- Cryptographic assumptions are explicit
- Failures are isolated and fail-closed
- Components can be reused independently

This document describes how the system is structured, why each layer exists, and how they compose into a complete secure connection.

## High Level Architecture
```
┌─────────────────────────────────────────────┐
│                Application                  │
│        (CLI demo / future consumers)        │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│          Network Adapter (Tokio)            │
│         ctunnel-net-tokio                   │
│                                             │
│  - TCP sockets                              │
│  - Length-prefixed framing                  │
│  - Handshake orchestration                  │
│  - SecureConn abstraction                   │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│              Protocol Core                  │
│               ctunnel-core                  │
│                                             │
│  ┌─────────────┐   ┌─────────────────────┐  │
│  │ Handshake   │   │ Secure Channel      │  │
│  │ State Mach. │   │ (AEAD record layer) │  │
│  └─────────────┘   └─────────────────────┘  │
│                                             │
│  - Transcript binding                       │
│  - Policy enforcement                       │
│  - Replay detection                         │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│           Crypto Provider (Trait)           │
│                                             │
│  - Ed25519                                  │
│  - X25519                                   │
│  - XChaCha20-Poly1305                       │
│  - BLAKE2b                                  │
└──────────────────────┬──────────────────────┘
                       │
┌──────────────────────▼──────────────────────┐
│     libsodium-backed implementation         │
│        ctunnel-crypto-sodium                │
│                                             │
│  - Single unsafe boundary                   │
│  - Auditable FFI                            │
└─────────────────────────────────────────────┘
```
### Design goals
The architecture is driven by the following goals:
1. **Zero implicit trust**
    - Every identity is explicit
    - Every message is authenticated
    - No “best effort” parsing or recovery

2. **Explicit threat boundaries**
    - Network is assumed hostile
    - On-path attackers are expected
    - Replay and tampering are first-class concerns
3. **Auditability over abstraction**
    - Prefer simple, explicit code to opaque frameworks
    - Cryptographic operations are visible and testable
    - Unsafe code is isolated
4. **Composable layers**
    - Handshake can exist without networking
    - Secure channel can exist without TCP
    - Crypto backend can be swapped

## Layer 1: Framing
**Responsibility**
- Convert a byte stream into discrete messages

**Implementation**
- Length-prefixed framing: `[u32 length][payload]`

**Why it exists**
- Prevents message boundary ambiguity
- Enables strict size validation
- Separates transport concerns from protocol logic

**Security properties**
- Oversized frames rejected
- Truncated frames rejected
- `EOF` handled explicitly

**Out of scope**
- Encryption
- Authentication
- Message semantics

## Layer 2: Handshake protocol
**Responsibility**
- Establish a mutually authenticated, forward-secret session
- Derive shared session keys
- Enforce identity policy

**Handshake Flow**
```
ClientHello  ─────────▶
               ServerHello (signed)
             ◀─────────
ClientFinish (signed) ─▶
```
**Key properties**
- Mutual authentication (Ed25519)
- Forward secrecy (ephemeral X25519)
- Transcript-bound signatures
- Strict state machines

**Why transcript binding matters**

All handshake signatures are computed over:
```
H(ClientHello || ServerHello)
```
This ensures
- Replayed messages fail
- Reordered messages fail
- Tampered messages fail
- Mismatched randomness fails

**Failure Semants**
- Any verification failures abort immediately
- No partial session state is retained
- No fallback paths exist

## Layer 3: Secure channel (record layer)

**Responsibility**
- Confidentiality and integrity of application data
- Replay protection for encrypted frames

**Implementation**
- AEAD: XChaCha20-Poly1305
- Directional keys (client→server / server→client)
- Nonce = `prefix || counter`
- AAD = `(frame_type || counter)`

**Replay defense**
- Monotonic counters per direction
- Any `counter <= last_seen` is rejected

**Why this design**
- Simple and auditable
- Strong nonce-misuse resistance
- Clear separation between framing and cryptography

## Layer 4: Crypto provider abstraction

**Responsibility**
- Provide cryptographic primitives without embedding policy

**Why a trait**
- Decouples protocol logic from implementation
- Enables mocking and deterministic testing
- Allows alternative backends (HSM, RustCrypto, etc.)

**Provided primitives**
- Ed25519 sign/verify
- X25519 key exchange
- AEAD encrypt/decrypt
- BLAKE2b hashing
- Secure randomness

### libsodium integration

The libsodium backend is intentionally isolated in its own crate.

**Properties**
- Single unsafe boundary
- Thin, explicit FFI
- No protocol logic
- No networking logic

**Why libsodium**
- Well-audited
- Conservative defaults
- Widely deployed

### Network adapter (Tokio)

**Responsibility**
- Bind protocol to real TCP sockets
- Orchestrate handshake message exchange
- Switch to secure channel post-handshake

**Key abstraction**
```
SecureConn
```
This represents an established secure connection with encrypted `send()`/`recv()`. The adapter contains no cryptographic decisions; it only wires layers together.

### Failure philosophy

ctunnel follows a fail-closed model:
- Any malformed input aborts
- Any authentication failure aborts
- Any replay aborts
- Any decryption failure aborts

This is intentional. Recovering from cryptographic or protocol errors is a security risk, not a feature.

## What is explicitly out of scope currently

ctunnel does not attempt to solve:
- Public PKI / certificates
- Browser compatibility
- Algorithm negotiation
- Transport-layer DoS
- Traffic analysis resistance
- Endpoint compromise

Some of these features are planned for implementation.

## Reuse and extensibility

Because layers are isolated, ctunnel-core can be embedded into other transports.The secure channel can be reused independently and the handshake can be extended with:
- Additional authentication steps
- Role assertions
- Key rotation

Future work can add features without weakening existing guarantees.

## Summary

ctunnel is intentionally small, explicit, and defensive.

Every layer:
- Has a single responsibility
- Enforces its own invariants
- Exposes failures early and clearly

The result is a secure transport that is, understandable, auditable, reusable, and resilient under active attack