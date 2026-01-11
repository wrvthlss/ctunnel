use crate::{
    handshake::{ClientPolicy, HandshakeAction, HandshakeError, HandshakeMachine},
    protocol::{HandshakeMessage, MSG_SERVER_HELLO},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Init, 
    AwaitServerHello,
    Complete,
}

// Client handshake machine.
#[derive(Debug)]
pub struct ClientHandshake {
    state: ClientState,
    policy: ClientPolicy,
}

impl ClientHandshake {
    pub fn new(policy: ClientPolicy) -> Self {
        Self {
            state: ClientState::Init,
            policy
        }
    }

    pub fn state(&self) -> &ClientState {
        &self.state
    }

    pub fn policy(&self) -> &ClientPolicy {
        &self.policy
    }
}

impl HandshakeMachine for ClientHandshake {
    // Start handshake process.
    fn start(&mut self) -> Result<Option<HandshakeMessage>, HandshakeError> {
        match self.state {
            ClientState::Init => {
                self.state = ClientState::AwaitServerHello;
                Ok(None)
            }
            // Wait for the Server Hellow, mark this state as complete.
            ClientState::AwaitServerHello | ClientState::Complete => Err(HandshakeError::AlreadyComplete),
        }
    }

    // Get message back from server.
    fn on_message(&mut self, msg: HandshakeMessage) -> Result<HandshakeAction, HandshakeError> {
        match self.state {
            // Waiting for hello from server.
            ClientState::AwaitServerHello => match msg {
                // Error.
                HandshakeMessage::ServerHello(_) => Err(HandshakeError::Failed), // implement later
                _ => Err(HandshakeError::UnexpectedMessage {
                    expected: MSG_SERVER_HELLO,
                    got: msg_type(&msg),
                }),
            },
            ClientState::Init => Err(HandshakeError::Protocol("client not started".into())),
            ClientState::Complete => Err(HandshakeError::AlreadyComplete),
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