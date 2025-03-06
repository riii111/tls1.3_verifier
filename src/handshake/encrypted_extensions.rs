use crate::error::{Error, Result};
use crate::utils;
use crate::handshake::{HandshakeType, HandshakeMessage};
use crate::handshake::extensions::Extension;

#[derive(Debug)]
pub struct EncryptedExtensions {
    pub extensions: Vec<Extension>,
}

impl EncryptedExtensions {
    pub fn new(extensions: Vec<Extension>) -> Self {
        Self { extensions }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        let extensions_length = utils::read_u16(data, pos)? as usize;
        
        if *pos + extensions_length > data.len() {
            return Err(Error::ParseError("EncryptedExtensions message truncated".to_string()));
        }
        
        let extensions_end = *pos + extensions_length;
        let mut extensions = Vec::new();
        
        while *pos < extensions_end {
            let extension = Extension::parse(data, pos)?;
            extensions.push(extension);
        }
        
        Ok(Self { extensions })
    }

    pub fn get_extension(&self, extension_type: crate::handshake::extensions::ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extension_type == extension_type)
    }
}

impl HandshakeMessage for EncryptedExtensions {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::EncryptedExtensions
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.serialize());
        }
        
        utils::write_u16(&mut result, extensions_data.len() as u16);
        result.extend_from_slice(&extensions_data);
        
        Ok(result)
    }
}