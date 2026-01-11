use async_trait::async_trait;

use crate::{
    handshake::{EstablishedSession, HandshakeError},
    protocol::HandshakeMessage,
};

// Output actions a handshake machine can request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeAction {
    // Send this handshake message to the peer.
    Send(HandshakeMessage),

    // Handshake complete; session established.
    Established(EstablishedSession),

    // Send a message and also consider the handshake established.
    SendAndEstablished { msg: HandshakeMessage, session: EstablishedSession },

    // Fatal handshake failure.
    Fail(HandshakeError),
}

// Low-level handshake state machine.
// This is transport-agnostic: it consumes decoded handshake messages and emits actions.
#[async_trait]
pub trait HandshakeMachine: Send {
    // Called once at the beginning to produce an initial message (client sends hello).
    async fn start(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError>;

    // Feed the next inbound handshake message.
    async fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError>;
}
