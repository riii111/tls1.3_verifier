use crate::error::{Error, Result};
use crate::utils;
use crate::handshake::{HandshakeType, HandshakeMessage, CipherSuite};
use crate::handshake::extensions::Extension;
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn new(
        legacy_version: u16,
        random: [u8; 32],
        legacy_session_id: Vec<u8>,
        cipher_suites: Vec<CipherSuite>,
        legacy_compression_methods: Vec<u8>,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
        }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        let legacy_version = utils::read_u16(data, pos)?;
        
        if *pos + 32 > data.len() {
            return Err(Error::ParseError("ClientHello random field truncated".to_string()));
        }
        
        let mut random = [0u8; 32];
        random.copy_from_slice(utils::read_bytes(data, pos, 32)?);
        
        let session_id = utils::read_vector_u8(data, pos)?.to_vec();
        
        let cipher_suites_bytes = utils::read_vector_u16(data, pos)?;
        if cipher_suites_bytes.len() % 2 != 0 {
            return Err(Error::ParseError("Cipher suites length must be even".to_string()));
        }
        
        let mut cipher_suites = Vec::with_capacity(cipher_suites_bytes.len() / 2);
        let mut cs_pos = 0;
        while cs_pos < cipher_suites_bytes.len() {
            let suite = u16::from_be_bytes([cipher_suites_bytes[cs_pos], cipher_suites_bytes[cs_pos + 1]]);
            cipher_suites.push(CipherSuite::try_from(suite)?);
            cs_pos += 2;
        }
        
        let compression_methods = utils::read_vector_u8(data, pos)?.to_vec();
        
        let mut extensions = Vec::new();
        
        if *pos < data.len() {
            let extensions_length = utils::read_u16(data, pos)? as usize;
            let extensions_end = *pos + extensions_length;
            
            if extensions_end > data.len() {
                return Err(Error::ParseError("Extensions length exceeds available data".to_string()));
            }
            
            while *pos < extensions_end {
                let extension = Extension::parse(data, pos)?;
                extensions.push(extension);
            }
        }
        
        Ok(Self {
            legacy_version,
            random,
            legacy_session_id: session_id,
            cipher_suites,
            legacy_compression_methods: compression_methods,
            extensions,
        })
    }
    
    // Find a specific extension by type
    pub fn get_extension(&self, extension_type: crate::handshake::extensions::ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extension_type == extension_type)
    }
}

impl HandshakeMessage for ClientHello {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::ClientHello
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        utils::write_u16(&mut result, self.legacy_version);
        result.extend_from_slice(&self.random);
        utils::write_vector_u8(&mut result, &self.legacy_session_id);
        
        let mut cipher_suites = Vec::with_capacity(2 + self.cipher_suites.len() * 2);
        utils::write_u16(&mut cipher_suites, (self.cipher_suites.len() * 2) as u16);
        for suite in &self.cipher_suites {
            utils::write_u16(&mut cipher_suites, *suite as u16);
        }
        result.extend_from_slice(&cipher_suites);
        
        utils::write_vector_u8(&mut result, &self.legacy_compression_methods);
        
        if !self.extensions.is_empty() {
            let mut extensions_data = Vec::new();
            for ext in &self.extensions {
                extensions_data.extend_from_slice(&ext.serialize());
            }
            
            utils::write_u16(&mut result, extensions_data.len() as u16);
            result.extend_from_slice(&extensions_data);
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::extensions::ExtensionType;

    #[test]
    fn test_client_hello_parsing() {
        // A minimal ClientHello message
        let client_hello_data = [
            0x03, 0x03, // TLS 1.2 legacy version
            // Random 32 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00, // Empty session ID
            0x00, 0x04, // Cipher suites length: 4 bytes (2 cipher suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0x01, 0x00, // Compression methods: 1 byte, null compression
            0x00, 0x08, // Extensions length: 8 bytes
            0x00, 0x2B, // Supported versions extension
            0x00, 0x04, // Length 4
            0x00, 0x02, // List length 2
            0x03, 0x04, // TLS 1.3
        ];
        
        let mut pos = 0;
        let client_hello = ClientHello::parse(&client_hello_data, &mut pos).unwrap();
        
        assert_eq!(client_hello.legacy_version, 0x0303);
        assert_eq!(client_hello.random[0], 0x01);
        assert_eq!(client_hello.random[31], 0x20);
        assert!(client_hello.legacy_session_id.is_empty());
        assert_eq!(client_hello.cipher_suites.len(), 2);
        assert_eq!(client_hello.cipher_suites[0], CipherSuite::TlsAes128GcmSha256);
        assert_eq!(client_hello.cipher_suites[1], CipherSuite::TlsChacha20Poly1305Sha256);
        assert_eq!(client_hello.legacy_compression_methods, vec![0x00]);
        assert_eq!(client_hello.extensions.len(), 1);
        assert_eq!(client_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    }
    
    #[test]
    fn test_client_hello_roundtrip() {
        let random = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        
        let supported_versions_ext = Extension::new(
            ExtensionType::SupportedVersions,
            vec![0x00, 0x02, 0x03, 0x04], // List with TLS 1.3
        );
        
        let client_hello = ClientHello::new(
            0x0303, // Legacy version: TLS 1.2
            random,
            vec![], // Empty session ID
            vec![
                CipherSuite::TlsAes128GcmSha256,
                CipherSuite::TlsChacha20Poly1305Sha256,
            ],
            vec![0x00], // Null compression
            vec![supported_versions_ext],
        );
        
        let serialized = client_hello.serialize().unwrap();
        
        // Now parse it back
        let mut pos = 0;
        let parsed_hello = ClientHello::parse(&serialized, &mut pos).unwrap();
        
        assert_eq!(parsed_hello.legacy_version, 0x0303);
        assert_eq!(parsed_hello.random, random);
        assert!(parsed_hello.legacy_session_id.is_empty());
        assert_eq!(parsed_hello.cipher_suites.len(), 2);
        assert_eq!(parsed_hello.cipher_suites[0], CipherSuite::TlsAes128GcmSha256);
        assert_eq!(parsed_hello.cipher_suites[1], CipherSuite::TlsChacha20Poly1305Sha256);
        assert_eq!(parsed_hello.legacy_compression_methods, vec![0x00]);
        assert_eq!(parsed_hello.extensions.len(), 1);
        assert_eq!(parsed_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    }
}