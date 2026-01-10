pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("randomness generation failed")]
    RngFailure,

    #[error("signature verification failed")]
    BadSignature,

    #[error("key agreement failed")]
    KeyAgreementFailure,

    #[error("encryption failed")]
    EncryptFailure,

    #[error("decryption failed")]
    DecryptFailure,

    #[error("hash/kdf failed")]
    HashFailure,

    #[error("invalid key material")]
    InvalidKey,
}
