use crate::error::{Error, Result};
use crate::handshake::{CipherSuite, HandshakeMessage, HandshakeType};
use super::{StateHandler, ConnectionState};

pub struct ClientState {
    state: ConnectionState,
    selected_cipher_suite: Option<CipherSuite>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Initial,
            selected_cipher_suite: None,
        }
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateHandler for ClientState {
    fn process_message(&mut self, message: Box<dyn HandshakeMessage>) -> Result<()> {
        match (self.state, message.message_type()) {
            (ConnectionState::Initial, HandshakeType::ServerHello) => {
                // Client received ServerHello, transition to Handshaking
                self.state = ConnectionState::Handshaking;
                // Implementation would extract the cipher suite here
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::EncryptedExtensions) => {
                // Process encrypted extensions
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::Certificate) => {
                // Process server certificate
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::CertificateVerify) => {
                // Process certificate verify message
                // In a real implementation, we would:
                // 1. Verify the signature using the public key from the certificate
                // 2. Check that the signature was created over the correct transcript hash
                // 3. Validate that the signature algorithm is acceptable
                
                // For now, we just transition the state in the same way
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::Finished) => {
                // Process server Finished message
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
}