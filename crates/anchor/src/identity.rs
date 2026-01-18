use std::{fs, path::Path};

use crate::AnchorError;
use ctunnel_core::crypto::CryptoProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug, Clone)]
pub struct Identity {
    pub public_key: PublicKey,
    // Ed25519 secret key is 64 bytes (libsodium format)
    pub secret_key: [u8; 64],
}

impl Identity {
    /// Generate a new Ed25519 identity using the libsodium-backed provider.
    pub async fn generate() -> Result<Self, AnchorError> {
        let crypto = ctunnel_crypto_sodium::SodiumCryptoProvider::new();
        let kp = crypto
            .ed25519_generate()
            .await
            .map_err(|e| AnchorError::Internal(format!("keygen failed: {e}")))?;

        Ok(Self {
            public_key: PublicKey(kp.public),
            secret_key: kp.secret,
        })
    }

    /// Load identity from `{name}.key` (64 bytes hex) and `{name}.pub` (32 bytes hex).
    pub fn from_files(secret_path: impl AsRef<Path>, public_path: impl AsRef<Path>) -> Result<Self, AnchorError> {
        let secret = read_hex_exact(secret_path.as_ref(), 64)?;
        let public = read_hex_exact(public_path.as_ref(), 32)?;

        let mut sk = [0u8; 64];
        sk.copy_from_slice(&secret);

        let mut pk = [0u8; 32];
        pk.copy_from_slice(&public);

        Ok(Self {
            public_key: PublicKey(pk),
            secret_key: sk,
        })
    }
}

fn read_hex_exact(path: &Path, expected_len: usize) -> Result<Vec<u8>, AnchorError> {
    let s = fs::read_to_string(path).map_err(AnchorError::Io)?;
    let s = s.trim();
    let bytes = hex::decode(s).map_err(|e| AnchorError::Key(format!("invalid hex in {}: {e}", path.display())))?;
    if bytes.len() != expected_len {
        return Err(AnchorError::Key(format!(
            "wrong length in {}: got {} bytes, expected {}",
            path.display(),
            bytes.len(),
            expected_len
        )));
    }
    Ok(bytes)
}