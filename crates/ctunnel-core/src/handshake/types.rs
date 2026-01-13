use crate::crypto::{AeadKey, NoncePrefix16};
use crate::protocol::Ed25519PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub key_c2s: AeadKey,
    pub key_s2c: AeadKey,
    pub np_c2s: NoncePrefix16,
    pub np_s2c: NoncePrefix16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishedSession {
    pub peer_identity: Ed25519PublicKey,
    pub keys: SessionKeys,
}