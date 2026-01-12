use std::{collections::HashSet, sync::Arc};

use tokio::net::TcpListener;

use ctunnel_core::crypto::CryptoProvider;
use ctunnel_core::protocol::Ed25519PublicKey;
use ctunnel_crypto_sodium::SodiumCryptoProvider;
use ctunnel_net_tokio::{accept_tcp, connect_tcp};

#[tokio::test]
async fn tcp_handshake_and_encrypted_round_trip() {
    let crypto = Arc::new(SodiumCryptoProvider::new());

    // Generate identities
    let server_id = crypto.ed25519_generate().await.unwrap();
    let client_id = crypto.ed25519_generate().await.unwrap();

    let server_pk = Ed25519PublicKey(server_id.public);
    let client_pk = Ed25519PublicKey(client_id.public);

    // Server allowlist
    let mut allowed = HashSet::new();
    allowed.insert(client_pk);
    let server_policy = ctunnel_core::handshake::ServerPolicy::new(allowed);

    // Bind ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Spawn server
    let server_crypto = crypto.clone();
    let server_task = tokio::spawn(async move {
        let (mut conn, peer) = accept_tcp(&listener, server_crypto, server_id, server_policy)
            .await
            .unwrap();

        // Ensure peer identity matches client
        assert_eq!(peer, client_pk);

        // Receive and echo
        let msg = conn.recv_data().await.unwrap();
        conn.send_data(&msg).await.unwrap();
    });

    // Client connects
    let mut client_conn = connect_tcp(&addr, crypto.clone(), client_id, server_pk)
        .await
        .unwrap();

    // Send and expect echo
    let payload = b"hello over tcp secure conn";
    client_conn.send_data(payload).await.unwrap();
    let echo = client_conn.recv_data().await.unwrap();
    assert_eq!(echo, payload);

    server_task.await.unwrap();
}