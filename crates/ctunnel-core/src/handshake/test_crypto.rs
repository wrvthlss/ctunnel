use async_trait::async_trait;

use crate::crypto::{
    AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32,
    Signature64, X25519Keypair,
};

#[derive(Debug, Default)]
pub(crate) struct MockCrypto;

fn derive_mock_secret_from_public(public: &[u8; 32]) -> [u8; 64] {
    let b = public[0].wrapping_add(1);
    let mut sk = [0u8; 64];
    sk.fill(b);
    sk
}

fn weak_hash32(key: Option<&[u8]>, data: &[u8]) -> [u8; 32] {
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

    async fn ed25519_sign(
        &self,
        keypair: &Ed25519Keypair,
        msg: &[u8],
    ) -> Result<Signature64, CryptoError> {
        let h = weak_hash32(Some(&keypair.secret), msg);
        Ok(sig64_from_hash32(h))
    }

    async fn ed25519_verify(
        &self,
        public: &[u8; 32],
        msg: &[u8],
        sig: &Signature64,
    ) -> Result<(), CryptoError> {
        let sk = derive_mock_secret_from_public(public);
        let expected = sig64_from_hash32(weak_hash32(Some(&sk), msg));
        if sig.0 == expected.0 {
            Ok(())
        } else {
            Err(CryptoError::BadSignature)
        }
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

    async fn blake2b_32(&self, key: Option<&[u8]>, data: &[u8]) -> Result<Hash32, CryptoError> {
        Ok(Hash32(weak_hash32(key, data)))
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