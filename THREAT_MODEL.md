# Threat Models
The `tools` directory contains a number of attacks scripts that may be ran against the protocol for security proof and testing. This document contains information pertaining to each attack script.

## Threat: Handshake Replay
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