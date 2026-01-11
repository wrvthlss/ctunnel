pub mod traits;
pub mod types;

pub mod policy;
pub mod client;
pub mod server;
pub mod kdf;
pub mod transcript;

pub use traits::*;
pub use types::*;

pub use policy::*;
pub use client::*;
pub use server::*;

#[derive(Debug, Clone, PartialEq, thiserror::Error, Eq)]
pub enum HandshakeError {
    #[error("peer identity not allowed")]
    PeerNotAllowed,

    #[error("server identity does not match expected pin")]
    BadServerIdentity,

    #[error("signature verification failed")]
    BadSignature,

    #[error("unexpected message type: expected={expected:#x}, got={got:#x}")]
    UnexpectedMessage { expected: u8, got: u8 },

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("handshake already complete")]
    AlreadyComplete,

    #[error("handshake failed")]
    Failed,
}

#[cfg(test)]
mod phase3_scaffold_tests;
