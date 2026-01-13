use std::sync::Arc;
use std::mem;
use async_trait::async_trait;


use crate::{
    crypto::{CryptoProvider, Ed25519Keypair, X25519Keypair},
    handshake::{HandshakeAction, HandshakeError, HandshakeMachine, ServerPolicy, transcript, proto_sig_to_crypto, crypto_sig_to_proto},
    protocol::{
        ClientHello, Ed25519PublicKey, HandshakeMessage, Random32, ServerHello, Signature64, X25519PublicKey,
        PROTOCOL_VERSION_V1,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerState {
    AwaitClientHello,
    AwaitClientFinish {
        client_id_pk: Ed25519PublicKey,
        client_eph_pk: X25519PublicKey,
        client_random: Random32,
        server_eph: X25519Keypair,
        server_random: Random32,
        client_hello_bytes: Vec<u8>,
        server_hello_full_bytes: Vec<u8>,
    },
    Complete,
}

/// Server-side handshake machine (Phase 3).
#[derive(Debug)]
pub struct ServerHandshake {
    state: ServerState,
    policy: ServerPolicy,
    crypto: Arc<dyn CryptoProvider>,
    server_id: Ed25519Keypair,
    flags: u8,
}

impl ServerHandshake {
    pub fn new(policy: ServerPolicy, crypto: Arc<dyn CryptoProvider>, server_id: Ed25519Keypair) -> Self {
        Self {
            state: ServerState::AwaitClientHello,
            policy,
            crypto,
            server_id,
            flags: 0,
        }
    }

    pub fn state(&self) -> &ServerState {
        &self.state
    }

    pub fn policy(&self) -> &ServerPolicy {
        &self.policy
    }
}

#[async_trait]
impl HandshakeMachine for ServerHandshake {
    async fn start(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError> {
        // Server does not initiate
        Ok(None)
    }

    async fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError> {
        use std::mem;
    
        let state = mem::replace(&mut self.state, ServerState::Complete);
    
        match state {
            ServerState::AwaitClientHello => match msg {
                HandshakeMessage::ClientHello(ch) => {
                    // Delegate; on_client_hello will set the next state explicitly
                    self.on_client_hello(ch).await
                }
                other => Err(HandshakeError::UnexpectedMessage {
                    expected: 0x01,
                    got: msg_type(&other),
                }),
            },
    
            ServerState::AwaitClientFinish {
                client_eph_pk,
                client_random,
                server_eph,
                server_random,
                client_id_pk,
                client_hello_bytes,
                server_hello_full_bytes,
            } => match msg {
                HandshakeMessage::ClientFinish(cf) => {
                    // --- verify client signature ---
                    let t2 = transcript::client_signing_transcript(
                        &client_hello_bytes,
                        &server_hello_full_bytes,
                    );
    
                    let h2 = self
                        .crypto
                        .blake2b_32(None, &t2)
                        .await
                        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
    
                    self.crypto
                        .ed25519_verify(
                            &client_id_pk.0,
                            &h2.0,
                            &proto_sig_to_crypto(cf.client_sig),
                        )
                        .await
                        .map_err(|_| HandshakeError::BadSignature)?;
    
                    // --- derive session keys ---
                    let shared = self
                        .crypto
                        .x25519_shared_secret(&server_eph.secret, &client_eph_pk.0)
                        .await
                        .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
    
                    let keys = crate::handshake::kdf::derive_session_keys(
                        self.crypto.as_ref(),
                        &shared,
                        &client_random,
                        &server_random,
                    )
                    .await?;
    
                    // --- now we can safely set final state ---
                    self.state = ServerState::Complete;
    
                    Ok(HandshakeAction::Established(crate::handshake::EstablishedSession {
                        peer_identity: client_id_pk,
                        keys,
                    }))
                }
    
                other => {
                    // Restore state before returning error
                    self.state = ServerState::AwaitClientFinish {
                        client_eph_pk,
                        client_random,
                        server_eph,
                        server_random,
                        client_id_pk,
                        client_hello_bytes,
                        server_hello_full_bytes,
                    };
    
                    Err(HandshakeError::UnexpectedMessage {
                        expected: 0x03,
                        got: msg_type(&other),
                    })
                }
            },
    
            ServerState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }
}

impl ServerHandshake {
    async fn on_client_hello(&mut self, ch: ClientHello) -> Result<HandshakeAction, HandshakeError> {
        // Enforce allowlist policy
        if !self.policy.is_allowed(&ch.client_id_pk) {
            return Ok(HandshakeAction::Fail(HandshakeError::PeerNotAllowed));
        }

        // Generate server ephemeral
        let server_eph = self
            .crypto
            .x25519_generate()
            .await
            .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

        // Generate server_random
        let mut rnd = [0u8; 32];
        self.crypto
            .random_bytes(&mut rnd)
            .await
            .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
        let server_random = Random32(rnd);

        // Step 2: signature not implemented yet -> placeholder zeros.
        let server_sig = Signature64([0u8; 64]);

        let mut sh = ServerHello {
            version: PROTOCOL_VERSION_V1,
            flags: self.flags,
            server_id_pk: Ed25519PublicKey(self.server_id.public),
            server_eph_pk: X25519PublicKey(server_eph.public),
            server_random,
            server_sig: Signature64([0u8; 64]),
        };
        
        // Canonical bytes
        let client_hello_bytes = transcript::client_hello_bytes(&ch);
        let sh_wo_sig_bytes = transcript::server_hello_wo_sig_bytes(&sh);

        // Hash transcript and sign
        let t1 = transcript::server_signing_transcript(&client_hello_bytes, &sh_wo_sig_bytes);
        let h = self
            .crypto
            .blake2b_32(None, &t1)
            .await
            .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

        let sig = self
            .crypto
            .ed25519_sign(&self.server_id, &h.0)
            .await
            .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

        sh.server_sig = crypto_sig_to_proto(sig);
        
        // Compute full ServerHello bytes for client transcript + server verification later
        let server_hello_full_bytes = transcript::server_hello_full_bytes(&sh);

        self.state = ServerState::AwaitClientFinish {
            client_id_pk: ch.client_id_pk,
            client_hello_bytes,
            server_hello_full_bytes,
            client_eph_pk: ch.client_eph_pk,
            client_random: ch.client_random,
            server_eph,
            server_random,
        };
        
        Ok(HandshakeAction::Send(HandshakeMessage::ServerHello(sh)))
        
    }
}

fn msg_type(msg: &HandshakeMessage) -> u8 {
    match msg {
        HandshakeMessage::ClientHello(_) => 0x01,
        HandshakeMessage::ServerHello(_) => 0x02,
        HandshakeMessage::ClientFinish(_) => 0x03,
    }
}
