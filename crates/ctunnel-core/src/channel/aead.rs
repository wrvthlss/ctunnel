use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    channel::{ChannelError, SecureChannel, SecureFrame},
    crypto::{Counter, CryptoProvider, Nonce24},
    handshake::SessionKeys,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug)]
pub struct AeadSecureChannel {
    crypto: Arc<dyn CryptoProvider>,

    // Outbound
    out_key: crate::crypto::AeadKey,
    out_nonce_prefix: crate::crypto::NoncePrefix16,
    send_counter: u64,

    // Inbound
    in_key: crate::crypto::AeadKey,
    in_nonce_prefix: crate::crypto::NoncePrefix16,
    last_recv_counter: Option<u64>,
}

impl AeadSecureChannel {
    pub fn new(keys: SessionKeys, side: Side, crypto: Arc<dyn CryptoProvider>) -> Self {
        let (out_key, out_np, in_key, in_np) = match side {
            Side::Client => (keys.key_c2s, keys.np_c2s, keys.key_s2c, keys.np_s2c),
            Side::Server => (keys.key_s2c, keys.np_s2c, keys.key_c2s, keys.np_c2s),
        };

        Self {
            crypto,
            out_key,
            out_nonce_prefix: out_np,
            send_counter: 0,
            in_key,
            in_nonce_prefix: in_np,
            last_recv_counter: None,
        }
    }
}

fn aad_bytes(frame_type: u8, counter: u64) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[0] = frame_type;
    aad[1..].copy_from_slice(&counter.to_be_bytes());
    aad
}

#[async_trait]
impl SecureChannel for AeadSecureChannel {
    async fn seal(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<SecureFrame, ChannelError> {
        let counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        let nonce = Nonce24::from_prefix_and_counter(self.out_nonce_prefix, Counter(counter));
        let aad = aad_bytes(frame_type, counter);

        let ciphertext = self
            .crypto
            .aead_encrypt(&self.out_key, &nonce, &aad, plaintext)
            .await
            .map_err(|_| ChannelError::InvalidFrame)?;

        Ok(SecureFrame {
            frame_type,
            counter: Counter(counter),
            ciphertext,
        })
    }

    async fn open(&mut self, frame: &SecureFrame) -> Result<Vec<u8>, ChannelError> {
        let c = frame.counter.0;

        if let Some(last) = self.last_recv_counter {
            if c <= last {
                return Err(ChannelError::ReplayDetected);
            }
        }

        let nonce = Nonce24::from_prefix_and_counter(self.in_nonce_prefix, frame.counter);
        let aad = aad_bytes(frame.frame_type, c);

        let plaintext = self
            .crypto
            .aead_decrypt(&self.in_key, &nonce, &aad, &frame.ciphertext)
            .await
            .map_err(|_| ChannelError::DecryptFailed)?;

        self.last_recv_counter = Some(c);
        Ok(plaintext)
    }
}