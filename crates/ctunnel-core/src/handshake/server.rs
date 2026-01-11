use crate::{
    handshake::{HandshakeAction, HandshakeError, HandshakeMachine, ServerPolicy},
    protocol::{HandshakeMessage, MSG_CLIENT_HELLO, MSG_CLIENT_FINISH},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerState {
    AwaitClientHello,
    AwaitClientFinish,
    Complete,
}

// Server handshake machine.
#[derive(Debug)]
pub struct ServerHandshake {
    state: ServerState,
    policy: ServerPolicy,
}

impl ServerHandshake {
    pub fn new(policy: ServerPolicy) -> Self {
        Self {
            state: ServerState::AwaitClientHello,
            policy,
        }
    }

    pub fn state(&self) -> &ServerState {
        &self.state
    }

    pub fn policy(&self) -> &ServerPolicy {
        &self.policy
    }
}

impl HandshakeMachine for ServerHandshake {
    fn start(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError> {
        // Servers don't initiate handshakes in this protocol.
        Ok(None)
    }

    fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError> {
        match self.state {
            ServerState::AwaitClientHello => match msg {
                HandshakeMessage::ClientHello(_) => {
                    // Behavior comes later. For now, lock the transition.
                    self.state = ServerState::AwaitClientFinish;
                    Err(HandshakeError::Failed)
                }
                _ => Err(HandshakeError::UnexpectedMessage {
                    expected: MSG_CLIENT_HELLO,
                    got: msg_type(&msg),
                }),
            },
            ServerState::AwaitClientFinish => match msg {
                HandshakeMessage::ClientFinish(_) => Err(HandshakeError::Failed), // implement later
                _ => Err(HandshakeError::UnexpectedMessage {
                    expected: MSG_CLIENT_FINISH,
                    got: msg_type(&msg),
                }),
            },
            ServerState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }
}

fn msg_type(msg: &HandshakeMessage) -> u8 {
    match msg {
        HandshakeMessage::ClientHello(_) => 0x01,
        HandshakeMessage::ServerHello(_) => 0x02,
        HandshakeMessage::ClientFinish(_) => 0x03,
    }
}
