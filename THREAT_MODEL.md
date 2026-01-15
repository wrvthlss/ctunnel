# Threat Models
The `tools/` directory contains a number of attack scripts that may be ran against the protocol for security proof and testing. This document contains information pertaining to each attack script.

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

## Threat: Record-layer replay within an established session

**Script(s)**
- `mitm_proxy_recordlayer_attack.py`

### Attacker capability
- Observe encrypted application frames
- Replay captured frames byte-for-byte

**Attack**
- Duplicate an encrypted DATA frame with the same counter

**Expected outcome**
- Receiver must reject the replayed frame

**Observed outcome**
- First frame accepted
- Replayed frame rejected with ReplayDetected
- Connection terminated

**Mitigation**
- Strict monotonic counter tracking per direction
- Replay detection enforced before decryption

## Threat: Record-layer ciphertext tampering

**Attack**
- Duplicate an encrypted DATA frame with the same counter

### Attacker capability
- Observe and modify encrypted application frames
- Preserve framing, counters, and structure
- Flip individual bits in ciphertext or AAD fields

**Attack**
- Modify a single ciphertext byte in an encrypted DATA frame

**Expected outcome**
- Receiver must reject the frame
- No plaintext delivered

**Observed outcome**
- AEAD verification failed
- Channel aborted with DecryptFailed
- Connection closed

**Mitigation**
- AEAD (XChaCha20-Poly1305)
- AAD binding of (frame_type, counter)
- Fail-closed behavior on authentication fail

## Reproducing Attacks and Validating Defenses
This section describes how to actively reproduce the attacks discussed above using the provided tooling. All attacks assume an on-path attacker capable of observing, replaying, and modifying traffic, but without access to private keys.

All attack scripts live under the `tools/` directory and operate as TCP MITM proxies.

### Prerequisites
- Linux or macOS
- Python 3.9+
- Rust toolchain
- libsodium installed (already required)

Build the project
```
cargo build
```

Generate demo keys if not already present
```
cargo run -p ctunnel -- keygen --out-dir keys --name server
cargo run -p ctunnel -- keygen --out-dir keys --name client
```
### Handshake-Level Attacks

Handshake attacks target authentication, integrity, and replay resistance during session establishment.

**Handshake Replay Goal**

Replay previously valid handshake messages to establish a new session.

**Expected Result**

Handshake must fail with signature verification error.

**Step 1: Start the server**
```
cargo run -p ctunnel -- server \
  --bind 127.0.0.1:9000 \
  --server-key keys/server.key \
  --allow-client keys/client.pub

```

**Step 2: Record a valid handshake**

Start the MITM recording proxy:
```
python3 tools/mitm_proxy_record.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --out tools/handshake_capture.json
```
Run a normal client through the proxy:
```
cargo run -p ctunnel -- client \
  --connect 127.0.0.1:9001 \
  --client-key keys/client.key \
  --expect-server keys/server.pub \
  --msg "capture handshake"

```
This records `ClientHello`, `ServerHello` and `ClientFinish`.

**Step 3: Replay the handshake**

Restart the server, then run:
```
python3 tools/mitm_proxy_record.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --out tools/handshake_capture.json
```

**Observed Outcome**
- Server responds with a fresh `ServerHello`
- Replayed `ClientFinish` fails signature verification
- Connection is closed
- No secure session is established

## Handshake Tampering
Handshake tampering demonstrates that any bit-level modification of handshake messages results in immediate failure.

**Tampering ServerHello (sig corruption)**
```
python3 tools/mitm_proxy_tamper.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_serverhello_sig
```

Run the client through the proxy:
```
cargo run -p ctunnel -- client \
  --connect 127.0.0.1:9001 \
  --client-key keys/client.key \
  --expect-server keys/server.pub \
  --msg "should fail"
```
**Observed Outcome**
- Client fails handshake with signature verification error
- No secure channel established

**Tampering ClientHello Identity**
```
python3 tools/mitm_proxy_tamper.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_clienthello_clientpk

```
**Oberved Outcome**
- Server rejects handshake with `PeerNotAllowed`
- No handshake progress occurs

**Tampering ClientHello Randomness or Ephemeral Key**
```
python3 tools/mitm_proxy_tamper.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_clienthello_random
```
--or--
```
python3 tools/mitm_proxy_tamper.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_clienthello_eph
```

**Observed Outcome**
- Server sends `ServerHello`
- Client fials signature verification
- Connection is aborted

## Record Layer Attacks
Record-layer attacks target confidentiality, integrity, and replay protection after a session is established.

### Encrypted Frame Replay
The goal is to replay an encrypted DATA frame with the same session.
```
python3 tools/mitm_proxy_recordlayer_attack.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode duplicate_first_data
```
**Oberved Outcome**
- First frame decrypts
- Replayed frame is rejected
- Channel aborts with replay detection

## Encrypted Frame Tampering
The goal is to modify ciphertext or authenticated header fields.
```
python3 tools/mitm_proxy_recordlayer_attack.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_ciphertext
```
-- or --
```
python3 tools/mitm_proxy_recordlayer_attack.py \
  --listen-port 9001 \
  --upstream-port 9000 \
  --mode tamper_header
```
**Observed Outcome**
- AEAD verification fails
- No plaintext delivered
- Connection is aborted immediately

## Interpreting Errors
Some expected error messages include:
- `signature verification failed`
- `peer identity not allowed`
- `replay detected`
- `decrypt failed`
- `unexpected EOF while reading a frame`

EOF-related messages indicate intentional defensive connection termination, not protocol failure.

## Summary
All attacks described in this document are:
- Executable
- Reproducible
- Observed to fail safely

This validates that ctunnel:
- Resists replay
- Detects tampering
- Enforces identity policy
- Fails closed under active attack