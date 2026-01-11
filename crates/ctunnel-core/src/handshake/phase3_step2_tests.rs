use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    crypto::{
        AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
    },
    handshake::{ClientHandshake, ClientPolicy, HandshakeAction, HandshakeMachine, ServerHandshake, ServerPolicy, MockCrypto},
    protocol::{Ed25519PublicKey, HandshakeMessage, PROTOCOL_VERSION_V1},
};

fn test_keypair(tag: u8) -> Ed25519Keypair {
    let mut pk = [0u8; 32];
    pk.fill(tag);
    let mut sk = [0u8; 64];
    sk.fill(tag.wrapping_add(1));
    Ed25519Keypair { public: pk, secret: sk }
}

#[tokio::test]
async fn client_start_emits_client_hello() {
    let crypto = Arc::new(MockCrypto::default());
    let client_id = test_keypair(0x11);

    let policy = ClientPolicy {
        expected_server: Ed25519PublicKey([0x22; 32]),
    };

    let mut client = ClientHandshake::new(policy, crypto, client_id);

    let msg = client.start().await.unwrap().unwrap();
    match msg {
        HandshakeMessage::ClientHello(ch) => {
            assert_eq!(ch.version, PROTOCOL_VERSION_V1);
            assert_eq!(ch.client_id_pk.0, [0x11; 32]);
            assert_eq!(ch.client_eph_pk.0, [9u8; 32]);
            assert_eq!(ch.client_random.0[0], 1);
        }
        _ => panic!("expected ClientHello"),
    }
}

#[tokio::test]
async fn server_receives_client_hello_and_emits_server_hello_when_allowed() {
    let crypto = Arc::new(MockCrypto::default());

    let client_pk = Ed25519PublicKey([0x33; 32]);
    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let server_policy = ServerPolicy::new(allowed);
    let server_id = test_keypair(0x44);

    let mut server = ServerHandshake::new(server_policy, crypto, server_id);

    let client_hello = crate::protocol::ClientHello {
        version: PROTOCOL_VERSION_V1,
        flags: 0,
        client_id_pk: client_pk,
        client_eph_pk: crate::protocol::X25519PublicKey([8u8; 32]),
        client_random: crate::protocol::Random32([1u8; 32]),
    };

    let action = server
        .on_message(HandshakeMessage::ClientHello(client_hello))
        .await
        .unwrap();

    match action {
        HandshakeAction::Send(HandshakeMessage::ServerHello(sh)) => {
            assert_eq!(sh.version, PROTOCOL_VERSION_V1);
            assert_eq!(sh.server_id_pk.0, [0x44; 32]);
            assert_eq!(sh.server_eph_pk.0, [9u8; 32]);
            assert_eq!(sh.server_random.0[0], 1);
            assert_ne!(sh.server_sig.0, [0u8; 64]);
        }
        other => panic!("expected Send(ServerHello), got {other:?}"),
    }
}

#[tokio::test]
async fn server_rejects_client_not_in_allowlist() {
    let crypto = Arc::new(MockCrypto::default());

    let allowed = HashSet::new();
    let server_policy = ServerPolicy::new(allowed);
    let server_id = test_keypair(0x44);

    let mut server = ServerHandshake::new(server_policy, crypto, server_id);

    let client_hello = crate::protocol::ClientHello {
        version: PROTOCOL_VERSION_V1,
        flags: 0,
        client_id_pk: Ed25519PublicKey([0x33; 32]),
        client_eph_pk: crate::protocol::X25519PublicKey([8u8; 32]),
        client_random: crate::protocol::Random32([1u8; 32]),
    };

    let action = server
        .on_message(HandshakeMessage::ClientHello(client_hello))
        .await
        .unwrap();

    assert!(matches!(action, HandshakeAction::Fail(_)));
}