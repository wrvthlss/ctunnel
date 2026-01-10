pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;

#[derive(Debug, Clone, PartialEq, thiserror::Error, Eq)]
pub enum HandshakeError {
    #[error("peer identity not allowed")]
    PeerNotAllowed,

    #[error("signature verification failed")]
    BadSignature,

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("handshake already complete")]
    AlreadyComplete,

    #[error("handshake failed")]
    Failed,
}