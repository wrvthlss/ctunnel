/*
    ctunnel-crypto-sodium
      - libsodium-based implementation of ctunnel-core's CryptoProvider.
      - All `unsafe` is confined to `sodium::ffi`.
*/
mod sodium;

use async_trait::async_trait;
use ctunnel_core::crypto::{
    AeadKey, CryptoError, CryptoProvider, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
};

/// Crypto provider backed by libsodium.
#[derive(Debug, Default, Clone)]
pub struct SodiumCryptoProvider;

impl SodiumCryptoProvider {
    pub fn new() -> Self {
        sodium::init();
        Self
    }
}

#[async_trait]
impl CryptoProvider for SodiumCryptoProvider {
    async fn random_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError> {
        sodium::safe::random_bytes(out)
    }

    async fn ed25519_generate(&self) -> Result<Ed25519Keypair, CryptoError> {
        sodium::safe::ed25519_generate()
    }

    async fn ed25519_sign(&self, keypair: &Ed25519Keypair, msg: &[u8]) -> Result<Signature64, CryptoError> {
        sodium::safe::ed25519_sign(keypair, msg)
    }

    async fn ed25519_verify(&self, public: &[u8; 32], msg: &[u8], sig: &Signature64) -> Result<(), CryptoError> {
        sodium::safe::ed25519_verify(public, msg, sig)
    }

    async fn x25519_generate(&self) -> Result<X25519Keypair, CryptoError> {
        sodium::safe::x25519_generate()
    }

    async fn x25519_shared_secret(
        &self,
        my_secret: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret32, CryptoError> {
        sodium::safe::x25519_shared_secret(my_secret, peer_public)
    }

    async fn blake2b_32(&self, key: Option<&[u8]>, data: &[u8]) -> Result<Hash32, CryptoError> {
        sodium::safe::blake2b_32(key, data)
    }

    async fn aead_encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sodium::safe::aead_encrypt(key, nonce, aad, plaintext)
    }

    async fn aead_decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sodium::safe::aead_decrypt(key, nonce, aad, ciphertext)
    }
}

#[cfg(test)]
mod tests;