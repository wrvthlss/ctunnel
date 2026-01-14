# Threat Models
The `tools` directory contains a number of attack scripts that may be ran against the protocol for security proof and testing. This document contains information pertaining to each attack script.

## Threat: Handshake Replay

**Script(s)**
- `mitm_proxy_record.py`
- `replay_handshake.py`

**Outputs**
- `handshake_capture.json`

### Attacker Capability
- Observe and record full handshake messages
- Replay messages byte-for-byte in a new TCP connection

**Attack Steps**
1. Capture `ClientHello`, `ServerHello`, `ClientFinish`
2. Establish new TCP connection
3. Replay old `ClientHello`
4. Receive fresh `ServerHello`
5. Replay old `ClientFinish`

**Expected Outcome**
- Server rejects the handshake

**Observed Outcome**
- Signature verification fails
- Server closes connection immediately
- No secure channel is established

**Mitigation**
- Transcript-bound signatures
- Fresh server randomness and ephemeral keys per handshake
- Strict state machine validation

## Threat: Handshake Tampering

**Script(s)**
- `mitm_proxy_tamper.py`

### Attacker Capability
- Observe and modify handshake messages in transit
- Preserve framing and message structure
- Flip individual bits in handshake payloads

**Attack**
- Modify one byte in `ServerHello.server_sig` while forwarding traffic

**Expected Outcome**
- Client must reject the handshake
- No secure session established
- No application data exchanged

**Observed Outcome**
- Client aborts handshake  with `signature_verification` failed
- Server receives `EOF` and terminates connection
- No channel keys derived

**Mitigation**
- Transcript bound Ed25519 signature
- Strict verification before key derivation
- Explicit state machine enforcing authentication-first design

## Threat: On-path tampering with ClientHello ID

**Script(s)**
- `mitm_proxy_tamper.py`

### Attacker capability
- Observe and modify `ClientHello` messages in transit
- Preserve framing and message structure
- Flip bits within the client identity public key

**Attack**
- Modify `ClientHello.client_id_pk` before forwarding to server

**Expected**
- Server rejects immediately, due to allowlist (`PeerNotAllowed`)
- No handshake progress
- No secure channel established

**Observed outcome**
- Server returns `PeerNotAllowed`
- Connection is closed
- Client receives `EOF`

**Mitigation**
- Explicit server-side allowlist
- Identity treated as authorization input
- Strict state machine preventing handshake continuation