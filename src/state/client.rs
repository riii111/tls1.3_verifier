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
                // In a real implementation, we would extract the public key from the certificate
                // and verify the signature over the transcript hash up to this point.
                // Since we don't have full transcript hash tracking yet, we just transition the state.
                
                // Example of how verification would work with a real message:
                // if let Some(cert_verify) = message.as_any().downcast_ref::<crate::handshake::CertificateVerify>() {
                //     let server_public_key = /* from certificate */;
                //     let transcript_hash = /* computed from all handshake messages */;
                //     cert_verify.verify(transcript_hash, server_public_key, true)?;
                // }
                
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