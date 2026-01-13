use async_trait::async_trait;

use crate::framing::Frame;

/*
    Low-evel interface for reading and writing framed payloads.
      - Implementations define how frames are encoded on underlying transport.
      - ctunnel uses a length-prefixed binary frame format by default.
*/
#[async_trait]
pub trait FrameIo: Send {
    async fn read_frame(&mut self) -> Result<Frame, FramingError>;
    async fn write_frame(&mut self, frame: &Frame) -> Result<(), FramingError>;
}

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("unexpected EOF while reading a frame")]
    UnexpectedEof,

    #[error("invalid frame length: zero-length frame")]
    ZeroLengthFrame,

    #[error("frame too large: len={len}, max={max}")]
    FrameTooLarge { len: u32, max: u32 },

    #[error("malformed length prefix")]
    MalformedLength,

    #[error("I/O error: {0}")]
    Io(String),
}
