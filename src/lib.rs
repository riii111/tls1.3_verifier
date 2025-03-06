pub mod record;
pub mod handshake;
pub mod crypto;
pub mod certificate;
pub mod state;
pub mod error;
pub mod utils;
pub mod tls;
pub mod alert;
pub mod session;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn init_logging() {
    let _ = env_logger::builder().try_init();
}

pub struct TlsHandshakeVerifier {
    // Implementation will come later
}

impl TlsHandshakeVerifier {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn process_data(&mut self, _data: &[u8]) -> Result<()> {
        Err(Error::NotImplemented("TlsHandshakeVerifier::process_data".to_string()))
    }
    
    pub fn generate_message(&self) -> Result<Vec<u8>> {
        Err(Error::NotImplemented("TlsHandshakeVerifier::generate_message".to_string()))
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        false
    }
}

impl Default for TlsHandshakeVerifier {
    fn default() -> Self {
        Self::new()
    }
}
