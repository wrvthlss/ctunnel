use thiserror::Error;

use crate::{
    channel::ChannelError,
    crypto::CryptoError,
    framing::FramingError,
    handshake::HandshakeError,
    protocol::ProtocolError
};

#[derive(Debug, Error)]
pub enum CtunnelError {
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),
}

