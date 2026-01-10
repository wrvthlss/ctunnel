use crate::crypto::Counter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureFrame {
    pub frame_type: u8,
    pub counter: Counter,
    pub ciphertext: Vec<u8>,
}

pub const FRAME_DATA: u8 = 0x10;
pub const FRAME_CLOSE: u8 = 0x11;