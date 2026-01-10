use crate::channel::{ChannelError, SecureFrame};

// Record-layer interface.
// Seal/open are pure transformations once constructed with keys.
pub trait SecureChannel {
    fn seal(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<SecureFrame, ChannelError>;
    fn open(&mut self, frame: &SecureFrame) -> Result<Vec<u8>, ChannelError>;
}
