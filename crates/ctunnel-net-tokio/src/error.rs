use thiserror::Error;

use ctunnel_core::{
    channel::ChannelError,
    framing::FramingError,
    handshake::HandshakeError,
    protocol::ProtocolError,
};

#[derive(Debug, Error)]
pub enum NetError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("framing error: {0}")]
    Framing(#[from] FramingError),

    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("handshake error: {0}")]
    Handshake(#[from] HandshakeError),

    #[error("channel error: {0}")]
    Channel(#[from] ChannelError),

    #[error("handshake produced no establishment")]
    NotEstablished,
}