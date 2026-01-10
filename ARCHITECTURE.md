# Architecture
### Purpose
ctunnel is a control-plane tunneling library designed to establish authenticated, encrypted, replay-resistant channels between mutually distrustful peers over untrusted networks.

**The Project is Intentionally**
- library-first
- low-level
- explicit trust boundaries

Binaries, demos and deployment artifacts are adapters layered on top of the core.

## Architectural Principles
This project follows these non-negotiable principles:

**Separation of concerns**

Framing, protocol, crypto, handshake, and channel logic are isolated.

**Dependency Inversion**

Core logic depends on traits, not implementation.

**Explicit State Machines**

Protocol phases are encoded in types and transitions.

**Minimal Unsafe Surface**

Unsafe code is confined to crypto backend implementations.

**Extensibility without Refactor**

New features must be addable via composition, not rewrites.

*If a change violates these principles, the design must change before the code.*

### High-Level System View
The core has no knowledge of:

- CLI arguments
- Filesystem layouts
- Docker
- Environment variables
- Deployment topology

### Core Subsystems
**Framing**

Responsibility:

- Convert an ordered byte stream into discrete, bounded frames.

Non-responsibilities:
- No encryption
- No protocol semantics
- No handshake logic

Design notes:
- Length-prefixed binary framing
- Enforced size limits
- Transport-agnostic (operates over async I/O traits)

---

**Protocol Types**

Responsibility:

- Define exact byte-level layouts for protocol messages.

Non-responsibilities:
- No network I/O
- No cryptography
- No state tracking

Design notes:
- Strict validation on decode
- Deterministic encoding
- No serde / text formats

---

**Crypto Provider (Inversion Boundary)**

Responsibility:

- Provide cryptographic primitives via a trait interface.

Non-responsibilities:
- No protocol logic
- No key storage policy
- No network interaction

Design notes:
- Core depends on `CryptoProvider` trait only
- `libsodium` implementation lives outside core logic
- Unsafe code is restricted to backend crates/modules

---

**Handshake State Machine**

Responsibility:
- Drive authentication and session establishment.

Non-responsibilities:
- No socket management
- No framing
- No persistent storage

Design notes:
- Deterministic state transitions
- **Input:** protocol messages
- **Output:** actions (send message, establish session, fail)

---

**Secure Channel**

Responsibility:
- Provide an authenticated, encrypted record layer once a session is established.

Non-responsibilities:
- No handshake
- No framing
- No transport concerns

Design notes:
- Counter-based replay protection
- Directional keys
- Explicit close semantics

---

**Error Model**

Errors are typed, layered, and explicit.

Each subsystem defines its own error type:
- `FramingError`
- `ProtocolError`
- `CryptoError`
- `HandshakeError`
- `ChannelError`

A top-level `CtunnelError` aggregates them without erasing meaning. Errors represent security-relevant failure modes, not generic strings.

---

**Extensibility Strategy**

The system is designed to allow:
- New crypto backends (RustCrypto, HSMs, PQ)
- Alternative transports (QUIC, Unix sockets)
- Additional protocol versions
- Policy engines (authorization, rate limits)
- Multiplexed channels

All extensions must:
- Implement existing traits
- Avoid modifying core invariants
- Preserve backward compatibility where possible

---

**Unsafe Code Policy**

- Unsafe code is forbidden in core protocol logic.
- Unsafe code is permitted only in crypto backend implementations.

All unsafe blocks must be:
- Minimal
- Documented
- Justified
