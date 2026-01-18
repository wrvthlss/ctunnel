use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid key material: {0}")]
    Key(String),

    #[error("trust policy violation: {0}")]
    Trust(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("internal error: {0}")]
    Internal(String),
}