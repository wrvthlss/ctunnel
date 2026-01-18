use std::sync::Arc;

use crate::{AnchorError, Identity, PublicKey, TrustPolicy};
use ctunnel_core::protocol::Ed25519PublicKey;

pub struct AnchorConn {
    inner: ctunnel_net_tokio::SecureConn,
    peer: PublicKey,
}

impl AnchorConn {
    pub(crate) fn new(inner: ctunnel_net_tokio::SecureConn, peer: PublicKey) -> Self {
        Self { inner, peer }
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), AnchorError> {
        self.inner
            .send_data(data)
            .await
            .map_err(|e| AnchorError::Protocol(e.to_string()))
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, AnchorError> {
        self.inner
            .recv_data()
            .await
            .map_err(|e| AnchorError::Protocol(e.to_string()))
    }

    pub fn peer_identity(&self) -> PublicKey {
        self.peer
    }
}

// Client connect (TCP) using a pinned server identity.
pub async fn connect(
    addr: &str,
    identity: Identity,
    trust: TrustPolicy,
) -> Result<AnchorConn, AnchorError> {
    let expected_server = match trust {
        TrustPolicy::Pinned(pk) => pk,
        _ => return Err(AnchorError::Trust("client requires TrustPolicy::Pinned(server_pk)".into())),
    };

    let crypto = Arc::new(ctunnel_crypto_sodium::SodiumCryptoProvider::new());

    let client_id = ctunnel_core::crypto::Ed25519Keypair {
        public: identity.public_key.0,
        secret: identity.secret_key,
    };

    let conn = ctunnel_net_tokio::connect_tcp(
        addr,
        crypto,
        client_id,
        Ed25519PublicKey(expected_server.0),
    )
    .await
    .map_err(|e| AnchorError::Protocol(e.to_string()))?;

    Ok(AnchorConn::new(conn, expected_server))
}
