pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("not established")]
    NotEstablished,

    #[error("decrypt failed")]
    DecryptFailed,

    #[error("replay detected")]
    ReplayDetected,

    #[error("invalid frame")]
    InvalidFrame,
}