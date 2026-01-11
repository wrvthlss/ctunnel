use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    channel::{AeadSecureChannel, Side, SecureChannel, ChannelError, FRAME_DATA},
    crypto::{AeadKey, CryptoError, CryptoProvider, Hash32, Nonce24, Signature64, SharedSecret32, X25519Keypair},
    handshake::SessionKeys,
    crypto::NoncePrefix16,
};

#[derive(Debug, Default)]
struct TestAeadCrypto;

fn weak_hash32(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in data.iter().enumerate() {
        out[i % 32] ^= b.wrapping_add((i as u8).wrapping_mul(17));
    }
    out
}

fn tag16(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut buf = Vec::new();
    buf.extend_from_slice(key);
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(aad);
    buf.extend_from_slice(ciphertext);
    let h = weak_hash32(&buf);
    let mut t = [0u8; 16];
    t.copy_from_slice(&h[..16]);
    t
}

#[async_trait]
impl CryptoProvider for TestAeadCrypto {
    async fn random_bytes(&self, _out: &mut [u8]) -> Result<(), CryptoError> { Err(CryptoError::RngFailure) }
    async fn ed25519_generate(&self) -> Result<crate::crypto::Ed25519Keypair, CryptoError> { Err(CryptoError::InvalidKey) }
    async fn ed25519_sign(&self, _k: &crate::crypto::Ed25519Keypair, _m: &[u8]) -> Result<Signature64, CryptoError> { Err(CryptoError::EncryptFailure) }
    async fn ed25519_verify(&self, _p: &[u8; 32], _m: &[u8], _s: &Signature64) -> Result<(), CryptoError> { Err(CryptoError::BadSignature) }
    async fn x25519_generate(&self) -> Result<X25519Keypair, CryptoError> { Err(CryptoError::InvalidKey) }
    async fn x25519_shared_secret(&self, _s: &[u8; 32], _p: &[u8; 32]) -> Result<SharedSecret32, CryptoError> { Err(CryptoError::KeyAgreementFailure) }

    async fn blake2b_32(&self, _key: Option<&[u8]>, data: &[u8]) -> Result<Hash32, CryptoError> {
        Ok(Hash32(weak_hash32(data)))
    }

    async fn aead_encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut c = plaintext.to_vec();
        for b in &mut c {
            *b ^= 0xAA;
        }
        let tag = tag16(&key.0, &nonce.0, aad, &c);
        c.extend_from_slice(&tag);
        Ok(c)
    }

    async fn aead_decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::DecryptFailure);
        }
        let (c, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let expected = tag16(&key.0, &nonce.0, aad, c);
        if tag != expected {
            return Err(CryptoError::DecryptFailure);
        }
        let mut p = c.to_vec();
        for b in &mut p {
            *b ^= 0xAA;
        }
        Ok(p)
    }
}

fn test_keys() -> SessionKeys {
    SessionKeys {
        key_c2s: AeadKey([1u8; 32]),
        key_s2c: AeadKey([2u8; 32]),
        np_c2s: NoncePrefix16([3u8; 16]),
        np_s2c: NoncePrefix16([4u8; 16]),
    }
}

#[tokio::test]
async fn client_to_server_round_trip() {
    let crypto = Arc::new(TestAeadCrypto::default());
    let keys = test_keys();

    let mut client = AeadSecureChannel::new(keys, Side::Client, crypto.clone());
    let mut server = AeadSecureChannel::new(keys, Side::Server, crypto.clone());

    let msg = b"hello over secure channel";
    let frame = client.seal(FRAME_DATA, msg).await.unwrap();
    let got = server.open(&frame).await.unwrap();

    assert_eq!(got, msg);
}

#[tokio::test]
async fn server_to_client_round_trip() {
    let crypto = Arc::new(TestAeadCrypto::default());
    let keys = test_keys();

    let mut client = AeadSecureChannel::new(keys, Side::Client, crypto.clone());
    let mut server = AeadSecureChannel::new(keys, Side::Server, crypto.clone());

    let msg = b"reply payload";
    let frame = server.seal(FRAME_DATA, msg).await.unwrap();
    let got = client.open(&frame).await.unwrap();

    assert_eq!(got, msg);
}

#[tokio::test]
async fn tamper_ciphertext_is_detected() {
    let crypto = Arc::new(TestAeadCrypto::default());
    let keys = test_keys();

    let mut client = AeadSecureChannel::new(keys, Side::Client, crypto.clone());
    let mut server = AeadSecureChannel::new(keys, Side::Server, crypto.clone());

    let msg = b"secret";
    let mut frame = client.seal(FRAME_DATA, msg).await.unwrap();

    frame.ciphertext[0] ^= 0x01;

    let err = server.open(&frame).await.unwrap_err();
    assert!(matches!(err, ChannelError::DecryptFailed));
}

#[tokio::test]
async fn replay_is_detected() {
    let crypto = Arc::new(TestAeadCrypto::default());
    let keys = test_keys();

    let mut client = AeadSecureChannel::new(keys, Side::Client, crypto.clone());
    let mut server = AeadSecureChannel::new(keys, Side::Server, crypto.clone());

    let msg = b"once";
    let frame = client.seal(FRAME_DATA, msg).await.unwrap();

    let _ = server.open(&frame).await.unwrap();
    let err = server.open(&frame).await.unwrap_err();

    assert!(matches!(err, ChannelError::ReplayDetected));
}