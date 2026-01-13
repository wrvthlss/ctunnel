use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};

use ctunnel_core::{
    channel::{AeadSecureChannel, ChannelError, SecureChannel, Side, FRAME_DATA},
    crypto::CryptoProvider,
    framing::{Frame, FrameIo, FrameLimits, LengthPrefixedFrameIo},
    handshake::{ClientHandshake, ClientPolicy, HandshakeAction, HandshakeMachine, ServerHandshake, ServerPolicy},
    protocol::{Ed25519PublicKey, HandshakeMessage},
};

use crate::error::NetError;

// A secure, encrypted connection over TCP.
// Internally uses:
//   - Length-prefixed framing on the TCP stream
//   - Handshake state machine to establish SessionKeys
//   - AEAD record layer (SecureChannel) for message confidentiality + integrity + replay defense
pub struct SecureConn {
    framer: LengthPrefixedFrameIo<TcpStream>,
    channel: AeadSecureChannel,
}

impl SecureConn {
    // Send an encrypted application frame.
    pub async fn send(&mut self, frame_type: u8, plaintext: &[u8]) -> Result<(), NetError> {
        let secure_frame = self.channel.seal(frame_type, plaintext).await?;
        let payload = secure_frame.encode();
        self.framer.write_frame(&Frame(payload)).await?;
        Ok(())
    }

    // Receive and decrypt the next application frame.
    pub async fn recv(&mut self) -> Result<(u8, Vec<u8>), NetError> {
        let Frame(payload) = self.framer.read_frame().await?;
        let secure_frame = ctunnel_core::channel::SecureFrame::decode(&payload)?;
        let plaintext = self.channel.open(&secure_frame).await?;
        Ok((secure_frame.frame_type, plaintext))
    }

    // Convenience for normal data frames.
    pub async fn send_data(&mut self, bytes: &[u8]) -> Result<(), NetError> {
        self.send(FRAME_DATA, bytes).await
    }

    // Convenience for normal data frames.
    pub async fn recv_data(&mut self) -> Result<Vec<u8>, NetError> {
        let (ty, bytes) = self.recv().await?;
        if ty != FRAME_DATA {
            return Err(NetError::Channel(ChannelError::InvalidFrame));
        }
        Ok(bytes)
    }
}

// Client-side connect + handshake over TCP.
pub async fn connect_tcp(
    addr: &str,
    crypto: Arc<dyn CryptoProvider>,
    client_id: ctunnel_core::crypto::Ed25519Keypair,
    expected_server: Ed25519PublicKey,
) -> Result<SecureConn, NetError> {
    let stream = TcpStream::connect(addr).await?;
    let framer = LengthPrefixedFrameIo::new(stream, FrameLimits::DEFAULT);

    let policy = ClientPolicy {
        expected_server,
    };

    run_client_handshake(framer, crypto, client_id, policy).await
}

// Server-side accept + handshake over TCP.

// Returns the established SecureConn plus the peer identity.
pub async fn accept_tcp(
    listener: &TcpListener,
    crypto: Arc<dyn CryptoProvider>,
    server_id: ctunnel_core::crypto::Ed25519Keypair,
    policy: ServerPolicy,
) -> Result<(SecureConn, Ed25519PublicKey), NetError> {
    let (stream, _) = listener.accept().await?;
    let framer = LengthPrefixedFrameIo::new(stream, FrameLimits::DEFAULT);

    run_server_handshake(framer, crypto, server_id, policy).await
}

async fn run_client_handshake(
    mut framer: LengthPrefixedFrameIo<TcpStream>,
    crypto: Arc<dyn CryptoProvider>,
    client_id: ctunnel_core::crypto::Ed25519Keypair,
    policy: ClientPolicy,
) -> Result<SecureConn, NetError> {
    let mut hs = ClientHandshake::new(policy, crypto.clone(), client_id);

    // client.start -> ClientHello
    if let Some(msg) = hs.start().await? {
        write_handshake(&mut framer, &msg).await?;
    } else {
        return Err(NetError::NotEstablished);
    }

    // loop until established
    loop {
        let inbound = read_handshake(&mut framer).await?;
        let action = hs.on_message(inbound).await?;

        match action {
            HandshakeAction::Send(msg) => {
                write_handshake(&mut framer, &msg).await?;
            }
            HandshakeAction::SendAndEstablished { msg, session } => {
                // send ClientFinish then switch to AEAD channel
                write_handshake(&mut framer, &msg).await?;
                let channel = AeadSecureChannel::new(session.keys, Side::Client, crypto.clone());
                return Ok(SecureConn { framer, channel });
            }
            HandshakeAction::Established(session) => {
                let channel = AeadSecureChannel::new(session.keys, Side::Client, crypto.clone());
                return Ok(SecureConn { framer, channel });
            }
            HandshakeAction::Fail(e) => return Err(NetError::Handshake(e)),
        }
    }
}

async fn run_server_handshake(
    mut framer: LengthPrefixedFrameIo<TcpStream>,
    crypto: Arc<dyn CryptoProvider>,
    server_id: ctunnel_core::crypto::Ed25519Keypair,
    policy: ServerPolicy,
) -> Result<(SecureConn, Ed25519PublicKey), NetError> {
    let mut hs = ServerHandshake::new(policy, crypto.clone(), server_id);

    // server.start()
    let _ = hs.start().await?;

    loop {
        let inbound = read_handshake(&mut framer).await?;
        let action = hs.on_message(inbound).await?;

        match action {
            HandshakeAction::Send(msg) => {
                write_handshake(&mut framer, &msg).await?;
            }
            HandshakeAction::Established(session) => {
                let peer = session.peer_identity;
                let channel = AeadSecureChannel::new(session.keys, Side::Server, crypto.clone());
                return Ok((SecureConn { framer, channel }, peer));
            }
            HandshakeAction::SendAndEstablished { msg, session } => {
                // (shouldn't happen for server in our protocol, but handle it cleanly)
                write_handshake(&mut framer, &msg).await?;
                let peer = session.peer_identity;
                let channel = AeadSecureChannel::new(session.keys, Side::Server, crypto.clone());
                return Ok((SecureConn { framer, channel }, peer));
            }
            HandshakeAction::Fail(e) => return Err(NetError::Handshake(e)),
        }
    }
}

async fn write_handshake(framer: &mut impl FrameIo, msg: &HandshakeMessage) -> Result<(), NetError> {
    let payload = msg.encode();
    framer.write_frame(&Frame(payload)).await?;
    Ok(())
}

async fn read_handshake(framer: &mut impl FrameIo) -> Result<HandshakeMessage, NetError> {
    let Frame(payload) = framer.read_frame().await?;
    Ok(HandshakeMessage::decode(&payload)?)
}