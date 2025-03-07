use crate::error::{Error, Result};
use crate::handshake::{HandshakeType, HandshakeMessage};

#[derive(Debug)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn new(verify_data: Vec<u8>) -> Self {
        Self { verify_data }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos > data.len() {
            return Err(Error::ParseError("Finished message truncated".to_string()));
        }
        
        let verify_data = data[*pos..].to_vec();
        *pos = data.len(); // Consume all remaining data
        
        Ok(Self { verify_data })
    }
}

impl HandshakeMessage for Finished {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::Finished
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.verify_data.clone())
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}