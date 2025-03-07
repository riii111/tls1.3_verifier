use crate::error::{Error, Result};
use crate::utils;
use crate::handshake::{HandshakeType, HandshakeMessage, CipherSuite};
use crate::handshake::extensions::{Extension, ExtensionType};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn new(
        legacy_version: u16,
        random: [u8; 32],
        legacy_session_id_echo: Vec<u8>,
        cipher_suite: CipherSuite,
        legacy_compression_method: u8,
        extensions: Vec<Extension>,
    ) -> Self {
        Self {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        let legacy_version = utils::read_u16(data, pos)?;
        
        if *pos + 32 > data.len() {
            return Err(Error::ParseError("ServerHello random field truncated".to_string()));
        }
        
        let mut random = [0u8; 32];
        random.copy_from_slice(utils::read_bytes(data, pos, 32)?);
        
        let session_id = utils::read_vector_u8(data, pos)?.to_vec();
        
        if *pos + 2 > data.len() {
            return Err(Error::ParseError("ServerHello cipher suite field truncated".to_string()));
        }
        
        let cipher_suite = CipherSuite::try_from(utils::read_u16(data, pos)?)?;
        
        if *pos >= data.len() {
            return Err(Error::ParseError("ServerHello compression method field truncated".to_string()));
        }
        
        let compression_method = utils::read_u8(data, pos)?;
        
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
            legacy_session_id_echo: session_id,
            cipher_suite,
            legacy_compression_method: compression_method,
            extensions,
        })
    }
    
    // Check if this is a HelloRetryRequest
    pub fn is_hello_retry_request(&self) -> bool {
        self.random == [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ]
    }
    
    // Find a specific extension by type
    pub fn get_extension(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.extensions.iter().find(|e| e.extension_type == extension_type)
    }
}

impl HandshakeMessage for ServerHello {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::ServerHello
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        utils::write_u16(&mut result, self.legacy_version);
        result.extend_from_slice(&self.random);
        utils::write_vector_u8(&mut result, &self.legacy_session_id_echo);
        utils::write_u16(&mut result, self.cipher_suite as u16);
        utils::write_u8(&mut result, self.legacy_compression_method);
        
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
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_parsing() {
        // A minimal ServerHello message
        let server_hello_data = [
            0x03, 0x03, // TLS 1.2 legacy version
            // Random 32 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
            0x00, // Empty session ID echo
            0x13, 0x01, // TLS_AES_128_GCM_SHA256 cipher suite
            0x00, // Null compression
            0x00, 0x08, // Extensions length: 8 bytes
            0x00, 0x2B, // Supported versions extension
            0x00, 0x04, // Length 4
            0x00, 0x02, // List length 2
            0x03, 0x04, // TLS 1.3
        ];
        
        let mut pos = 0;
        let server_hello = ServerHello::parse(&server_hello_data, &mut pos).unwrap();
        
        assert_eq!(server_hello.legacy_version, 0x0303);
        assert_eq!(server_hello.random[0], 0x01);
        assert_eq!(server_hello.random[31], 0x20);
        assert!(server_hello.legacy_session_id_echo.is_empty());
        assert_eq!(server_hello.cipher_suite, CipherSuite::TlsAes128GcmSha256);
        assert_eq!(server_hello.legacy_compression_method, 0x00);
        assert_eq!(server_hello.extensions.len(), 1);
        assert_eq!(server_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    }
    
    #[test]
    fn test_server_hello_roundtrip() {
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
        
        let server_hello = ServerHello::new(
            0x0303, // Legacy version: TLS 1.2
            random,
            vec![], // Empty session ID echo
            CipherSuite::TlsAes128GcmSha256,
            0x00, // Null compression
            vec![supported_versions_ext],
        );
        
        let serialized = server_hello.serialize().unwrap();
        
        // Now parse it back
        let mut pos = 0;
        let parsed_hello = ServerHello::parse(&serialized, &mut pos).unwrap();
        
        assert_eq!(parsed_hello.legacy_version, 0x0303);
        assert_eq!(parsed_hello.random, random);
        assert!(parsed_hello.legacy_session_id_echo.is_empty());
        assert_eq!(parsed_hello.cipher_suite, CipherSuite::TlsAes128GcmSha256);
        assert_eq!(parsed_hello.legacy_compression_method, 0x00);
        assert_eq!(parsed_hello.extensions.len(), 1);
        assert_eq!(parsed_hello.extensions[0].extension_type, ExtensionType::SupportedVersions);
    }
    
    #[test]
    fn test_hello_retry_request() {
        // Special random value that indicates a HelloRetryRequest
        let hrr_random = [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
        ];
        
        let hello_retry = ServerHello::new(
            0x0303,
            hrr_random,
            vec![],
            CipherSuite::TlsAes128GcmSha256,
            0x00,
            vec![],
        );
        
        // Should be identified as a HelloRetryRequest
        assert!(hello_retry.is_hello_retry_request());
        
        // Regular ServerHello should not be identified as a HelloRetryRequest
        let mut regular_random = [0u8; 32];
        regular_random.copy_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ]);
        
        let regular_hello = ServerHello::new(
            0x0303,
            regular_random,
            vec![],
            CipherSuite::TlsAes128GcmSha256,
            0x00,
            vec![],
        );
        
        assert!(!regular_hello.is_hello_retry_request());
    }
}