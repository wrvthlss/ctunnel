use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::crypto::{
    AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair
};
use crate::handshake::{ClientHandshake, ClientPolicy, ServerHandshake, ServerPolicy, MockCrypto};
use crate::protocol::Ed25519PublicKey;

fn test_keypair(tag: u8) -> Ed25519Keypair {
    let mut pk = [0u8; 32];
    pk.fill(tag);
    let mut sk = [0u8; 64];
    sk.fill(tag.wrapping_add(1));
    Ed25519Keypair { public: pk, secret: sk }
}

#[test]
fn policies_are_constructible_and_comparable() {
    let server_pk = Ed25519PublicKey([1u8; 32]);
    let client_pk = Ed25519PublicKey([2u8; 32]);

    let cp = ClientPolicy {
        expected_server: server_pk,
    };

    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let sp = ServerPolicy::new(allowed);

    assert_eq!(cp.expected_server, server_pk);
    assert!(sp.is_allowed(&client_pk));
}

#[test]
fn handshake_state_machines_construct() {
    let crypto = Arc::new(MockCrypto::default());

    let server_pk = Ed25519PublicKey([3u8; 32]);
    let client_pk = Ed25519PublicKey([4u8; 32]);

    let client_id = test_keypair(0x10);
    let server_id = test_keypair(0x20);

    let client = ClientHandshake::new(
        ClientPolicy {
            expected_server: server_pk,
        },
        crypto.clone(),
        client_id,
    );

    let mut allowed = HashSet::new();
    allowed.insert(client_pk);

    let server = ServerHandshake::new(ServerPolicy::new(allowed), crypto, server_id);

    // Just proving the types exist and can be constructed.
    assert_eq!(*client.policy(), ClientPolicy { expected_server: server_pk });
    assert!(server.policy().allowed_clients.contains(&client_pk));
}