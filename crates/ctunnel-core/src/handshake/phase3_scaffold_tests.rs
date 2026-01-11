use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;

use crate::crypto::{
    AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
};
use crate::handshake::{ClientHandshake, ClientPolicy, ServerHandshake, ServerPolicy};
use crate::protocol::Ed25519PublicKey;

#[derive(Debug, Default)]
struct MockCrypto;

#[async_trait]
impl CryptoProvider for MockCrypto {
    async fn random_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
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