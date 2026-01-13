use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::framing::{Frame, FrameIo, FrameLimits, FramingError};

/// Length-prefixed framing over an async byte stream.
///
/// Frame format:
///   [u32 big-endian length][payload bytes...]
pub struct LengthPrefixedFrameIo<RW> {
    io: RW,
    limits: FrameLimits,
}

impl<RW> LengthPrefixedFrameIo<RW> {
    pub fn new(io: RW, limits: FrameLimits) -> Self {
        Self { io, limits }
    }

    pub fn into_inner(self) -> RW {
        self.io
    }
}

/// Map std::io errors into the framing error taxonomy.
fn map_io_err(e: std::io::Error) -> FramingError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        FramingError::UnexpectedEof
    } else {
        FramingError::Io(e.to_string())
    }
}

#[async_trait]
impl<RW> FrameIo for LengthPrefixedFrameIo<RW> where RW: AsyncRead + AsyncWrite + Unpin + Send, {

    async fn read_frame(&mut self) -> Result<Frame, FramingError> {
        let mut len_buf = [0u8; 4];
        self.io.read_exact(&mut len_buf).await.map_err(map_io_err)?;

        let len = u32::from_be_bytes(len_buf);
        self.limits.validate_len(len)?;

        let mut payload = vec![0u8; len as usize];
        self.io.read_exact(&mut payload).await.map_err(map_io_err)?;

        Ok(Frame(payload))
    }

    async fn write_frame(&mut self, frame: &Frame) -> Result<(), FramingError> {
        let len_u32: u32 = frame
            .0
            .len()
            .try_into()
            .map_err(|_| FramingError::FrameTooLarge {
                len: u32::MAX,
                max: self.limits.max_frame_len,
            })?;

        self.limits.validate_len(len_u32)?;

        self.io
            .write_all(&len_u32.to_be_bytes())
            .await
            .map_err(map_io_err)?;

        self.io.write_all(&frame.0).await.map_err(map_io_err)?;
        self.io.flush().await.map_err(map_io_err)?;

        Ok(())
    }
}