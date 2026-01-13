# Threat Models
The `tools` directory contains a number of attacks scripts that may be ran against the protocol for security proof and testing. This document contains information pertaining to each attack script.

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
- Siganture verification fails
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
