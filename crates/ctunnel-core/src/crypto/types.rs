#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Keypair {
    pub public: [u8; 32],
    // Private key format is backend-defined.
    // For libsodium, Ed25519 secret keys are 64 bytes.
    pub secret: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519Keypair {
    pub public: [u8; 32],
    pub secret: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoncePrefix16(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nonce24(pub [u8; 24]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hash32(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret32(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter(pub u64);

impl Nonce24 {
    pub fn from_prefix_and_counter(prefix: NoncePrefix16, counter: Counter) -> Self {
        let mut out = [0u8; 24];
        out[..16].copy_from_slice(&prefix.0);
        out[16..].copy_from_slice(&counter.0.to_be_bytes());
        Nonce24(out)
    }
}