use crate::handshake::CipherSuite;
use crate::state::{HandshakeState, ConnectionRole, ConnectionState};
use std::time::{SystemTime, Duration};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    #[zeroize(skip)]
    pub cipher_suite: CipherSuite,
    pub client_traffic_secret: Vec<u8>,
    pub server_traffic_secret: Vec<u8>,
    #[zeroize(skip)]
    pub created_at: SystemTime,
}

impl SessionKeys {
    pub fn new(
        cipher_suite: CipherSuite,
        client_traffic_secret: Vec<u8>,
        server_traffic_secret: Vec<u8>,
    ) -> Self {
        Self {
            cipher_suite,
            client_traffic_secret,
            server_traffic_secret,
            created_at: SystemTime::now(),
        }
    }
    
    pub fn is_expired(&self, ttl: Duration) -> bool {
        SystemTime::now().duration_since(self.created_at)
            .map(|elapsed| elapsed > ttl)
            .unwrap_or(true) // If clock went backwards, consider expired
    }
}

pub struct SessionManager {
    current_state: HandshakeState,
    session_keys: Option<SessionKeys>,
    session_id: Option<Vec<u8>>,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new_client() -> Self {
        Self {
            current_state: HandshakeState::new_client(),
            session_keys: None,
            session_id: None,
            session_timeout: Duration::from_secs(3600), // 1 hour default
        }
    }
    
    pub fn new_server() -> Self {
        Self {
            current_state: HandshakeState::new_server(),
            session_keys: None,
            session_id: None,
            session_timeout: Duration::from_secs(3600), // 1 hour default
        }
    }
    
    pub fn set_session_id(&mut self, session_id: Vec<u8>) {
        self.session_id = Some(session_id);
    }
    
    pub fn set_session_timeout(&mut self, timeout: Duration) {
        self.session_timeout = timeout;
    }
    
    pub fn get_handshake_state(&self) -> ConnectionState {
        self.current_state.get_state()
    }
    
    pub fn get_role(&self) -> ConnectionRole {
        self.current_state.get_role()
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.current_state.is_handshake_complete()
    }
    
    pub fn set_session_keys(
        &mut self,
        cipher_suite: CipherSuite,
        client_traffic_secret: Vec<u8>,
        server_traffic_secret: Vec<u8>,
    ) {
        self.session_keys = Some(SessionKeys::new(
            cipher_suite,
            client_traffic_secret,
            server_traffic_secret,
        ));
    }
    
    pub fn get_session_keys(&self) -> Option<&SessionKeys> {
        self.session_keys.as_ref()
    }
    
    pub fn clear_session(&mut self) {
        self.session_keys = None;
    }
}