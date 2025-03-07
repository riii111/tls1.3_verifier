use crate::error::{Error, Result};
use crate::handshake::{CipherSuite, HandshakeMessage, HandshakeType};
use super::{StateHandler, ConnectionState};

pub struct ServerState {
    state: ConnectionState,
    selected_cipher_suite: Option<CipherSuite>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Initial,
            selected_cipher_suite: None,
        }
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateHandler for ServerState {
    fn process_message(&mut self, message: Box<dyn HandshakeMessage>) -> Result<()> {
        match (self.state, message.message_type()) {
            (ConnectionState::Initial, HandshakeType::ClientHello) => {
                // Server received ClientHello, transition to Negotiating
                self.state = ConnectionState::Negotiating;
                // Implementation would select a cipher suite here
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::Finished) => {
                // Process client Finished message
                self.state = ConnectionState::Connected;
                Ok(())
            },
            _ => Err(Error::ProtocolError(format!(
                "Unexpected message {:?} in state {:?}",
                message.message_type(),
                self.state
            ))),
        }
    }

    fn get_state(&self) -> ConnectionState {
        self.state
    }

    fn is_handshake_complete(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    fn get_selected_cipher_suite(&self) -> Option<CipherSuite> {
        self.selected_cipher_suite
    }
    
    fn get_server_name(&self) -> Option<&str> {
        None // Server doesn't have a server name
    }
    
    fn get_certificate_verifier(&self) -> Option<&crate::certificate::CertificateVerifier> {
        None // Server doesn't do certificate verification
    }
}