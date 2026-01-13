use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    crypto::{AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair},
    handshake::{ClientHandshake, ClientPolicy, HandshakeMachine, ServerHandshake, ServerPolicy, MockCrypto},
    protocol::{Ed25519PublicKey, HandshakeMessage},
};


fn derive_mock_secret_from_public(public: &[u8; 32]) -> [u8; 64] {
    // Matches test_keypair() below: secret bytes are (public_byte + 1)
    let b = public[0].wrapping_add(1);
    let mut sk = [0u8; 64];
    sk.fill(b);
    sk
}

fn weak_hash32(key: Option<&[u8]>, data: &[u8]) -> [u8; 32] {
    // Deterministic toy hash for tests:
    // folds key and data into 32 bytes via XOR + index mixing.
    let mut out = [0u8; 32];

    if let Some(k) = key {
        for (i, b) in k.iter().enumerate() {
            out[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(31));
        }
    }

    for (i, b) in data.iter().enumerate() {
        out[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
    }

    out
}

fn sig64_from_hash32(h: [u8; 32]) -> Signature64 {
    let mut s = [0u8; 64];
    s[..32].copy_from_slice(&h);
    s[32..].copy_from_slice(&h);
    Signature64(s)
}

fn test_keypair(tag: u8) -> Ed25519Keypair {
    let mut pk = [0u8; 32];
    pk.fill(tag);
    let mut sk = [0u8; 64];
    sk.fill(tag.wrapping_add(1));
    Ed25519Keypair { public: pk, secret: sk }
}

#[tokio::test]
async fn happy_path_signatures_verify() {
    let crypto = Arc::new(MockCrypto::default());

    let server_id = test_keypair(0x22);
    let client_id = test_keypair(0x11);

    let mut allowed = HashSet::new();
    allowed.insert(Ed25519PublicKey(client_id.public));

    let server_policy = ServerPolicy::new(allowed);
    let client_policy = ClientPolicy { expected_server: Ed25519PublicKey(server_id.public) };

    let mut client = ClientHandshake::new(client_policy, crypto.clone(), client_id);
    let mut server = ServerHandshake::new(server_policy, crypto.clone(), server_id);

    // client -> server: ClientHello
    let ch = client.start().await.unwrap().unwrap();

    // server -> client: ServerHello
    let sh_action = server.on_message(ch).await.unwrap();
    let sh_msg = match sh_action {
        crate::handshake::HandshakeAction::Send(m) => m,
        other => panic!("expected Send(ServerHello), got {other:?}"),
    };

    // client verifies server + derives keys + sends ClientFinish
    let cf_action = client.on_message(sh_msg).await.unwrap();

    // client side must now be established
    let (cf_msg, client_session) = match cf_action {
        crate::handshake::HandshakeAction::SendAndEstablished { msg, session } => (msg, session),
        other => panic!("expected SendAndEstablished(ClientFinish), got {other:?}"),
    };

    // server verifies client + derives keys
    let server_action = server.on_message(cf_msg).await.unwrap();
    let server_session = match server_action {
        crate::handshake::HandshakeAction::Established(s) => s,
        other => panic!("expected Established, got {other:?}"),
    };

    // Prove both sides derived the same material
    assert_eq!(client_session.keys.key_c2s.0, server_session.keys.key_c2s.0);
    assert_eq!(client_session.keys.key_s2c.0, server_session.keys.key_s2c.0);
    assert_eq!(client_session.keys.np_c2s.0, server_session.keys.np_c2s.0);
    assert_eq!(client_session.keys.np_s2c.0, server_session.keys.np_s2c.0);

    // Directionality sanity check
    assert_ne!(
        client_session.keys.key_c2s.0,
        client_session.keys.key_s2c.0,
        "directional keys must not be identical"
    );

    
}

#[tokio::test]
async fn client_rejects_tampered_server_signature() {
    let crypto = Arc::new(MockCrypto::default());

    let server_id = test_keypair(0x22);
    let client_id = test_keypair(0x11);

    let mut allowed = HashSet::new();
    allowed.insert(Ed25519PublicKey(client_id.public));

    let server_policy = ServerPolicy::new(allowed);
    let client_policy = ClientPolicy { expected_server: Ed25519PublicKey(server_id.public) };

    let mut client = ClientHandshake::new(client_policy, crypto.clone(), client_id);
    let mut server = ServerHandshake::new(server_policy, crypto.clone(), server_id);

    let ch = client.start().await.unwrap().unwrap();
    let sh_action = server.on_message(ch).await.unwrap();
    let mut sh_msg = match sh_action {
        crate::handshake::HandshakeAction::Send(m) => m,
        _ => panic!("expected ServerHello"),
    };

    // Tamper signature inside ServerHello
    if let HandshakeMessage::ServerHello(ref mut sh) = sh_msg {
        sh.server_sig.0[0] ^= 0x01;
    } else {
        panic!("expected ServerHello");
    }

    let err = client.on_message(sh_msg).await.unwrap_err();
    assert!(matches!(err, crate::handshake::HandshakeError::BadSignature));
}

#[tokio::test]
async fn client_rejects_wrong_pinned_server_identity() {
    let crypto = Arc::new(MockCrypto::default());

    let server_id = test_keypair(0x22);
    let client_id = test_keypair(0x11);

    let mut allowed = HashSet::new();
    allowed.insert(Ed25519PublicKey(client_id.public));

    let server_policy = ServerPolicy::new(allowed);

    // Wrong expected server pin
    let client_policy = ClientPolicy { expected_server: Ed25519PublicKey([0x99; 32]) };

    let mut client = ClientHandshake::new(client_policy, crypto.clone(), client_id);
    let mut server = ServerHandshake::new(server_policy, crypto.clone(), server_id);

    let ch = client.start().await.unwrap().unwrap();
    let sh_action = server.on_message(ch).await.unwrap();
    let sh_msg = match sh_action {
        crate::handshake::HandshakeAction::Send(m) => m,
        _ => panic!("expected ServerHello"),
    };

    let err = client.on_message(sh_msg).await.unwrap_err();
    assert!(matches!(err, crate::handshake::HandshakeError::BadServerIdentity));
}