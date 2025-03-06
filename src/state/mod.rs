use crate::error::Result;
use crate::handshake::{CipherSuite, HandshakeMessage};

pub mod client;
pub mod server;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Initial,
    Negotiating,
    Handshaking,
    Connected,
    Closing,
    Closed,
    Failed,
}

pub trait StateHandler {
    fn process_message(&mut self, message: Box<dyn HandshakeMessage>) -> Result<()>;
    fn get_state(&self) -> ConnectionState;
    fn is_handshake_complete(&self) -> bool;
    fn get_selected_cipher_suite(&self) -> Option<CipherSuite>;
}

pub struct HandshakeState {
    role: ConnectionRole,
    state: ConnectionState,
    handler: Box<dyn StateHandler>,
}

impl HandshakeState {
    pub fn new_client() -> Self {
        Self {
            role: ConnectionRole::Client,
            state: ConnectionState::Initial,
            handler: Box::new(client::ClientState::new()),
        }
    }
    
    pub fn new_server() -> Self {
        Self {
            role: ConnectionRole::Server,
            state: ConnectionState::Initial,
            handler: Box::new(server::ServerState::new()),
        }
    }
    
    pub fn process_message(&mut self, message: Box<dyn HandshakeMessage>) -> Result<()> {
        self.handler.process_message(message)?;
        self.state = self.handler.get_state();
        Ok(())
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.handler.is_handshake_complete()
    }
    
    pub fn get_state(&self) -> ConnectionState {
        self.state
    }
    
    pub fn get_role(&self) -> ConnectionRole {
        self.role
    }
    
    pub fn get_selected_cipher_suite(&self) -> Option<CipherSuite> {
        self.handler.get_selected_cipher_suite()
    }
}