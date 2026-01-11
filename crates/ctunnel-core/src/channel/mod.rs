pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;

pub mod aead;
pub use aead::*;


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

#[cfg(test)]
mod phase4_tests;
