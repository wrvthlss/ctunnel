use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    crypto::{CryptoProvider, Ed25519Keypair, X25519Keypair},
    handshake::{ClientPolicy, HandshakeAction, HandshakeError, HandshakeMachine},
    protocol::{ClientHello, Ed25519PublicKey, HandshakeMessage, Random32, X25519PublicKey, PROTOCOL_VERSION_V1},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Init,
    AwaitServerHello {
        client_eph: X25519Keypair,
        client_random: Random32,
        client_id_pk: Ed25519PublicKey,
    },
    Complete,
}

/// Client handshake machine.
#[derive(Debug)]
pub struct ClientHandshake {
    state: ClientState,
    policy: ClientPolicy,
    crypto: Arc<dyn CryptoProvider>,
    client_id: Ed25519Keypair,
    flags: u8,
}

impl ClientHandshake {
    pub fn new(policy: ClientPolicy, crypto: Arc<dyn CryptoProvider>, client_id: Ed25519Keypair) -> Self {
        Self {
            state: ClientState::Init,
            policy,
            crypto,
            client_id,
            flags: 0,
        }
    }

    pub fn state(&self) -> &ClientState {
        &self.state
    }

    pub fn policy(&self) -> &ClientPolicy {
        &self.policy
    }
}

#[async_trait]
impl HandshakeMachine for ClientHandshake {
    async fn start(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError> {
        match self.state {
            ClientState::Init => {
                // Generate ephemeral X25519 keypair
                let client_eph = self
                    .crypto
                    .x25519_generate()
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;

                // Generate client_random (32 bytes)
                let mut rnd = [0u8; 32];
                self.crypto
                    .random_bytes(&mut rnd)
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
                let client_random = Random32(rnd);

                let client_id_pk = Ed25519PublicKey(self.client_id.public);

                // Build ClientHello
                let hello = ClientHello {
                    version: PROTOCOL_VERSION_V1,
                    flags: self.flags,
                    client_id_pk,
                    client_eph_pk: X25519PublicKey(client_eph.public),
                    client_random,
                };

                // Transition state
                self.state = ClientState::AwaitServerHello {
                    client_eph,
                    client_random,
                    client_id_pk,
                };

                Ok(Some(HandshakeMessage::ClientHello(hello)))
            }
            ClientState::AwaitServerHello { .. } | ClientState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }

    async fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError> {
        match &self.state {
            ClientState::AwaitServerHello { .. } => {
                // Keep state shape stable and enforce message ordering.
                match msg {
                    HandshakeMessage::ServerHello(_) => Err(HandshakeError::Failed),
                    other => Err(HandshakeError::UnexpectedMessage {
                        expected: 0x02,
                        got: msg_type(&other),
                    }),
                }
            }
            ClientState::Init => Err(HandshakeError::Protocol("client not started".into())),
            ClientState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }
}

fn msg_type(msg: &HandshakeMessage) -> u8 {
    match msg {
        HandshakeMessage::ClientHello(_) => 0x01,
        HandshakeMessage::ServerHello(_) => 0x02,
        HandshakeMessage::ClientFinish(_) => 0x03,
    }
}