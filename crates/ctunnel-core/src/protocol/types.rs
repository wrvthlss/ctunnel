use crate::protocol::ProtocolError;

pub const PROTOCOL_VERSION_V1: u16 = 0x0001;

pub const MSG_CLIENT_HELLO: u8 = 0x01;
pub const MSG_SERVER_HELLO: u8 = 0x02;
pub const MSG_CLIENT_FINISH: u8 = 0x03;

pub const LEN_CLIENT_HELLO: usize = 100;
pub const LEN_SERVER_HELLO: usize = 164;
pub const LEN_CLIENT_FINISH: usize = 65;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub fn encode(&self) -> Vec<u8> {
        match self {
            HandshakeMessage::ClientHello(ch) => {
                let mut out = Vec::with_capacity(LEN_CLIENT_HELLO);
                out.push(MSG_CLIENT_HELLO);
                out.extend_from_slice(&ch.version.to_be_bytes());
                out.push(ch.flags);
                out.extend_from_slice(&ch.client_id_pk.0);
                out.extend_from_slice(&ch.client_eph_pk.0);
                out.extend_from_slice(&ch.client_random.0);
                out
            }
            HandshakeMessage::ServerHello(sh) => {
                let mut out = Vec::with_capacity(LEN_SERVER_HELLO);
                out.push(MSG_SERVER_HELLO);
                out.extend_from_slice(&sh.version.to_be_bytes());
                out.push(sh.flags);
                out.extend_from_slice(&sh.server_id_pk.0);
                out.extend_from_slice(&sh.server_eph_pk.0);
                out.extend_from_slice(&sh.server_random.0);
                out.extend_from_slice(&sh.server_sig.0);
                out
            }
            HandshakeMessage::ClientFinish(cf) => {
                let mut out = Vec::with_capacity(LEN_CLIENT_FINISH);
                out.push(MSG_CLIENT_FINISH);
                out.extend_from_slice(&cf.client_sig.0);
                out
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        let msg_type = bytes[0];

        match msg_type {
            MSG_CLIENT_HELLO => {
                if bytes.len() != LEN_CLIENT_HELLO {
                    return Err(ProtocolError::InvalidLength);
                }
                let version = u16::from_be_bytes([bytes[1], bytes[2]]);
                if version != PROTOCOL_VERSION_V1 {
                    return Err(ProtocolError::UnsupportedVersion(version));
                }
                let flags = bytes[3];

                let mut off = 4;
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes[off..off + 32]);
                off += 32;

                let mut eph = [0u8; 32];
                eph.copy_from_slice(&bytes[off..off + 32]);
                off += 32;

                let mut rnd = [0u8; 32];
                rnd.copy_from_slice(&bytes[off..off + 32]);

                Ok(HandshakeMessage::ClientHello(ClientHello {
                    version,
                    flags,
                    client_id_pk: Ed25519PublicKey(pk),
                    client_eph_pk: X25519PublicKey(eph),
                    client_random: Random32(rnd),
                }))
            }

            MSG_SERVER_HELLO => {
                if bytes.len() != LEN_SERVER_HELLO {
                    return Err(ProtocolError::InvalidLength);
                }
                let version = u16::from_be_bytes([bytes[1], bytes[2]]);
                if version != PROTOCOL_VERSION_V1 {
                    return Err(ProtocolError::UnsupportedVersion(version));
                }
                let flags = bytes[3];

                let mut off = 4;
                let mut pk = [0u8; 32];
                pk.copy_from_slice(&bytes[off..off + 32]);
                off += 32;

                let mut eph = [0u8; 32];
                eph.copy_from_slice(&bytes[off..off + 32]);
                off += 32;

                let mut rnd = [0u8; 32];
                rnd.copy_from_slice(&bytes[off..off + 32]);
                off += 32;

                let mut sig = [0u8; 64];
                sig.copy_from_slice(&bytes[off..off + 64]);

                Ok(HandshakeMessage::ServerHello(ServerHello {
                    version,
                    flags,
                    server_id_pk: Ed25519PublicKey(pk),
                    server_eph_pk: X25519PublicKey(eph),
                    server_random: Random32(rnd),
                    server_sig: Signature64(sig),
                }))
            }

            MSG_CLIENT_FINISH => {
                if bytes.len() != LEN_CLIENT_FINISH {
                    return Err(ProtocolError::InvalidLength);
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&bytes[1..1 + 64]);
                Ok(HandshakeMessage::ClientFinish(ClientFinish {
                    client_sig: Signature64(sig),
                }))
            }

            other => Err(ProtocolError::UnexpectedType(other)),
        }
    }
}