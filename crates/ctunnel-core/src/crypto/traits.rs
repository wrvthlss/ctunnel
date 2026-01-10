use async_trait::async_trait;

use crate::crypto::{
    AeadKey, CryptoError, Ed25519Keypair, Hash32, Nonce24, SharedSecret32, Signature64, X25519Keypair,
};

// Trait boundary for cryptographic primitives.
// Core protocol logic must depend on this trait, never on concrete crypto backends.
// NOTE: async methods are used for maximal backend flexibility (HSMs, remote KMS, etc.).
#[async_trait]
pub trait CryptoProvider: Send + Sync + 'static {
    async fn random_bytes(&self, out: &mut [u8]) -> Result<(), CryptoError>;

    async fn ed25519_generate(&self) -> Result<Ed25519Keypair, CryptoError>;
    async fn ed25519_sign(&self, keypair: &Ed25519Keypair, msg: &[u8]) -> Result<Signature64, CryptoError>;
    async fn ed25519_verify(&self, public: &[u8; 32], msg: &[u8], sig: &Signature64) -> Result<(), CryptoError>;

    async fn x25519_generate(&self) -> Result<X25519Keypair, CryptoError>;
    async fn x25519_shared_secret(
        &self,
        my_secret: &[u8; 32],
        peer_public: &[u8; 32],
    ) -> Result<SharedSecret32, CryptoError>;

    async fn blake2b_32(&self, key: Option<&[u8]>, data: &[u8]) -> Result<Hash32, CryptoError>;

    async fn aead_encrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    async fn aead_decrypt(
        &self,
        key: &AeadKey,
        nonce: &Nonce24,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}