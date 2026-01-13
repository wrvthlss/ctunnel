use async_trait::async_trait;

use crate::channel::{ChannelError, SecureFrame};

// Record layer interface.
// Seal/open are pure transformations once constructed with keys,
// they may require async crypto providers.
#[async_trait]
pub trait SecureChannel: Send {
    async fn seal(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<SecureFrame, ChannelError>;
    async fn open(&mut self, frame: &SecureFrame) -> Result<Vec<u8>, ChannelError>;
}
