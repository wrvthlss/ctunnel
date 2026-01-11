use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    crypto::{
        AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
    },
    handshake::{ClientHandshake, ClientPolicy, HandshakeAction, HandshakeMachine, ServerHandshake, ServerPolicy},
    protocol::{Ed25519PublicKey, HandshakeMessage, PROTOCOL_VERSION_V1},
};

#[derive(Debug, Default)]
struct MockCrypto;

#[async_trait]
impl CryptoProvider for MockCrypto {
    async fn random_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        // deterministic pattern for tests
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        Ok(())
    }

    async fn ed25519_generate(&self) -> Result<Ed25519Keypair, CryptoError> {
        Err(CryptoError::InvalidKey)
    }

    async fn ed25519_sign(&self, _keypair: &Ed25519Keypair, _msg: &[u8]) -> Result<Signature64, CryptoError> {
        Err(CryptoError::EncryptFailure)
    }

    async fn ed25519_verify(&self, _public: &[u8; 32], _msg: &[u8], _sig: &Signature64) -> Result<(), CryptoError> {
        Err(CryptoError::BadSignature)
    }

    async fn x25519_generate(&self) -> Result<X25519Keypair, CryptoError> {
        Ok(X25519Keypair {
            public: [9u8; 32],
            secret: [7u8; 32],
        })
    }

    async fn x25519_shared_secret(
        &self,
        _my_secret: &[u8; 32],
        _peer_public: &[u8; 32],
    ) -> Result<SharedSecret32, CryptoError> {
        Ok(SharedSecret32([3u8; 32]))
    }

    async fn blake2b_32(&self, _key: Option<&[u8]>, _data: &[u8]) -> Result<Hash32, CryptoError> {
        Ok(Hash32([5u8; 32]))
    }

    async fn aead_encrypt(
        &self,
        _key: &AeadKey,
        _nonce: &Nonce24,
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(plaintext.to_vec())
    }

    async fn aead_decrypt(
        &self,
        _key: &AeadKey,
        _nonce: &Nonce24,
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(ciphertext.to_vec())
    }
}

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
            assert_eq!(sh.server_sig.0, [0u8; 64]); // placeholder until Step 3
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