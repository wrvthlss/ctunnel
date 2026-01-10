pub mod types;

pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),

    #[error("malformed message")]
    Malformed,

    #[error("unexpected message type: {0:#x}")]
    UnexpectedType(u8),

    #[error("invalid field length")]
    InvalidLength,

    #[error("size limit exceeded")]
    SizeLimit,
}
