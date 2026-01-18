use std::{collections::HashSet, sync::Arc};

use tokio::net::TcpListener;

use crate::{AnchorConn, AnchorError, Identity, PublicKey, TrustPolicy};
use ctunnel_core::protocol::Ed25519PublicKey;

pub struct AnchorListener {
    listener: TcpListener,
    crypto: Arc<dyn ctunnel_core::crypto::CryptoProvider>,
    server_id: ctunnel_core::crypto::Ed25519Keypair,
    policy: ctunnel_core::handshake::ServerPolicy,
}

pub async fn listen( bind: &str, identity: Identity, trust: TrustPolicy,) -> Result<AnchorListener, AnchorError> {
    let allowed: HashSet<PublicKey> = match trust {
        TrustPolicy::AllowList(s) => s,
        _ => return Err(AnchorError::Trust("server requires TrustPolicy::AllowList(client_pks)".into())),
    };

    let mut allow = HashSet::new();
    for pk in allowed {
        allow.insert(Ed25519PublicKey(pk.0));
    }

    let policy = ctunnel_core::handshake::ServerPolicy::new(allow);

    let listener = TcpListener::bind(bind).await.map_err(AnchorError::Io)?;

    let crypto = Arc::new(ctunnel_crypto_sodium::SodiumCryptoProvider::new());

    let server_id = ctunnel_core::crypto::Ed25519Keypair {
        public: identity.public_key.0,
        secret: identity.secret_key,
    };

    Ok(AnchorListener {
        listener,
        crypto,
        server_id,
        policy,
    })
}

impl AnchorListener {
    pub async fn accept(&self) -> Result<AnchorConn, AnchorError> {
        let (conn, peer) = ctunnel_net_tokio::accept_tcp(
            &self.listener,
            self.crypto.clone(),
            self.server_id,
            self.policy.clone(),
        )
        .await
        .map_err(|e| AnchorError::Protocol(e.to_string()))?;

        Ok(AnchorConn::new(conn, PublicKey(peer.0)))
    }

    pub fn local_addr(&self) -> Result<std::net::SocketAddr, AnchorError> {
        self.listener.local_addr().map_err(AnchorError::Io)
    }
}