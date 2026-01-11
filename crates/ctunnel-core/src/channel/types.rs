use crate::crypto::Counter;
use crate::channel::ChannelError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureFrame {
    pub frame_type: u8,
    pub counter: Counter,
    pub ciphertext: Vec<u8>,
}

pub const FRAME_DATA: u8 = 0x10;
pub const FRAME_CLOSE: u8 = 0x11;

impl SecureFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + self.ciphertext.len());
        out.push(self.frame_type);
        out.extend_from_slice(&self.counter.0.to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChannelError> {
        if bytes.len() < 9 {
            return Err(ChannelError::InvalidFrame);
        }
        let frame_type = bytes[0];
        let mut cbuf = [0u8; 8];
        cbuf.copy_from_slice(&bytes[1..9]);
        let counter = u64::from_be_bytes(cbuf);

        Ok(SecureFrame {
            frame_type,
            counter: crate::crypto::Counter(counter),
            ciphertext: bytes[9..].to_vec(),
        })
    }
}