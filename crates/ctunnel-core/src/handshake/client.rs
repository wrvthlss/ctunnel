use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    crypto::{CryptoProvider, Ed25519Keypair, X25519Keypair},
    handshake::{ClientPolicy, HandshakeAction, HandshakeError, HandshakeMachine, transcript, proto_sig_to_crypto, crypto_sig_to_proto, kdf, EstablishedSession},
    protocol::{ClientHello, Ed25519PublicKey, HandshakeMessage, Random32, X25519PublicKey, PROTOCOL_VERSION_V1, ClientFinish, Signature64},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Init,
    AwaitServerHello {
        client_eph: X25519Keypair,
        client_random: Random32,
        client_id_pk: Ed25519PublicKey,
        client_hello_bytes: Vec<u8>,
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

                let client_hello_bytes = transcript::client_hello_bytes(&hello);

                self.state = ClientState::AwaitServerHello {
                    client_eph,
                    client_random,
                    client_id_pk,
                    client_hello_bytes,
                };

                Ok(Some(HandshakeMessage::ClientHello(hello)))
            }
            ClientState::AwaitServerHello { .. } | ClientState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }

    async fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError> {
        match (&self.state, msg) {
            (ClientState::AwaitServerHello { client_eph, client_random, client_hello_bytes, .. }, HandshakeMessage::ServerHello(sh)) => {
                // Verify server identity pin
                if sh.server_id_pk != self.policy.expected_server {
                    return Err(HandshakeError::BadServerIdentity);
                }
        
                // Verify server signature over t1 = H(ch || sh_wo_sig)
                let sh_wo_sig_bytes = transcript::server_hello_wo_sig_bytes(&sh);
                let t1 = transcript::server_signing_transcript(client_hello_bytes, &sh_wo_sig_bytes);
        
                let h1 = self
                    .crypto
                    .blake2b_32(None, &t1)
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;


                self.crypto
                    .ed25519_verify(&sh.server_id_pk.0, &h1.0, &proto_sig_to_crypto(sh.server_sig))
                    .await
                    .map_err(|_| HandshakeError::BadSignature)?;
                    
                // Client signs t2 = H(ch || sh_full)
                let sh_full_bytes = transcript::server_hello_full_bytes(&sh);
                let t2 = transcript::client_signing_transcript(client_hello_bytes, &sh_full_bytes);
        
                let h2 = self
                    .crypto
                    .blake2b_32(None, &t2)
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
        
                let sig = self
                    .crypto
                    .ed25519_sign(&self.client_id, &h2.0)
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
        
                let finish = ClientFinish { client_sig: crypto_sig_to_proto(sig) };

                let shared = self
                    .crypto
                    .x25519_shared_secret(&client_eph.secret, &sh.server_eph_pk.0)
                    .await
                    .map_err(|e| HandshakeError::Crypto(format!("{e}")))?;
            
                let keys = kdf::derive_session_keys(self.crypto.as_ref(), &shared, client_random, &sh.server_random).await?;
                
                let session = EstablishedSession {
                    peer_identity: sh.server_id_pk,
                    keys,
                }; 

                // Transition to complete (client is done after sending finish)
                self.state = ClientState::Complete;

                Ok(HandshakeAction::SendAndEstablished {
                    msg: HandshakeMessage::ClientFinish(finish),
                    session,
                })
            }
            (ClientState::AwaitServerHello { .. }, other) => Err(HandshakeError::UnexpectedMessage {
                expected: 0x02,
                got: msg_type(&other),
            }),
            (ClientState::Init, _) => Err(HandshakeError::Protocol("client not started".into())),
            (ClientState::Complete, _) => Err(HandshakeError::AlreadyComplete),
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