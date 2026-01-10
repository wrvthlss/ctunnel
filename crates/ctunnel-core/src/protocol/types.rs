use crate::protocol::ProtocolError;

pub const PROTOCOL_VERSION_V1: u16 = 0x0001;

pub const MSG_CLIENT_HELLO: u8 = 0x01;
pub const MSG_SERVER_HELLO: u8 = 0x02;
pub const MSG_CLIENT_FINISH: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Random32(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    pub flags: u8,
    pub client_id_pk: Ed25519PublicKey,
    pub client_eph_pk: X25519PublicKey,
    pub client_random: Random32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub flags: u8,
    pub server_id_pk: Ed25519PublicKey,
    pub server_eph_pk: X25519PublicKey,
    pub server_random: Random32,
    pub server_sig: Signature64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFinish {
    pub client_sig: Signature64,
}

// Minimal message envelope for handshake parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    ClientFinish(ClientFinish),
}

impl HandshakeMessage {
    // Encode the message into deterministic bytes.
    pub fn encode(&self) -> Vec<u8> {
        todo!("Protocol encoding implemented in a later phase");
    }

    // Decode deterministic bytes into a HandshakeMessage.
    pub fn decode(_bytes: &[u8]) -> Result<Self, ProtocolError> {
        todo!("Protocol decoding implemented in a later phase");
    }
}