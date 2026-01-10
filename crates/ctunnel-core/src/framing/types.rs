use crate::framing::FramingError;

// A single frame payload, deframed from the byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame(pub Vec<u8>);

#[derive(Debug, Clone, Copy)]
pub struct FrameLimits {
    pub max_fame_len: u32
}

impl FrameLimits {
    pub const DEFAULT: FrameLimits = FrameLimits {
        max_fame_len: 65_536, // 64 KB
    };

    pub fn validate_len(&self, len: u32) -> Result<(), FramingError> {
        if len == 0 {
            return Err(FramingError::ZeroLengthFrame);
        }

        if len > self.max_fame_len {
            return Err(FramingError::FrameTooLarge {
                len,
                max: self.max_fame_len
            });
        }
        Ok(())
    }
}
