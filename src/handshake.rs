use crate::error::{Error, Result};
use crate::utils;
use std::fmt::Debug;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

impl TryFrom<u8> for HandshakeType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            4 => Ok(HandshakeType::NewSessionTicket),
            5 => Ok(HandshakeType::EndOfEarlyData),
            8 => Ok(HandshakeType::EncryptedExtensions),
            11 => Ok(HandshakeType::Certificate),
            13 => Ok(HandshakeType::CertificateRequest),
            15 => Ok(HandshakeType::CertificateVerify),
            20 => Ok(HandshakeType::Finished),
            24 => Ok(HandshakeType::KeyUpdate),
            254 => Ok(HandshakeType::MessageHash),
            _ => Err(Error::ParseError(format!(
                "Invalid HandshakeType value: {}",
                value
            ))),
        }
    }
}

pub trait HandshakeMessage: Debug {
    fn message_type(&self) -> HandshakeType;
    fn serialize(&self) -> Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct HandshakeMessageHeader {
    pub msg_type: HandshakeType,
    pub length: u32,
}

impl HandshakeMessageHeader {
    pub fn new(msg_type: HandshakeType, length: u32) -> Self {
        Self { msg_type, length }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos + 4 > data.len() {
            return Err(Error::ParseError(
                "Handshake message header too short".to_string(),
            ));
        }

        let msg_type = HandshakeType::try_from(utils::read_u8(data, pos)?)?;
        let length = utils::read_u24(data, pos)?;

        Ok(Self { msg_type, length })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4);
        utils::write_u8(&mut result, self.msg_type as u8);
        utils::write_u24(&mut result, self.length);
        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    TlsAes128GcmSha256 = 0x1301,
    TlsAes256GcmSha384 = 0x1302,
    TlsChacha20Poly1305Sha256 = 0x1303,
    TlsAes128CcmSha256 = 0x1304,
    TlsAes128Ccm8Sha256 = 0x1305,
}

impl TryFrom<u16> for CipherSuite {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x1301 => Ok(CipherSuite::TlsAes128GcmSha256),
            0x1302 => Ok(CipherSuite::TlsAes256GcmSha384),
            0x1303 => Ok(CipherSuite::TlsChacha20Poly1305Sha256),
            0x1304 => Ok(CipherSuite::TlsAes128CcmSha256),
            0x1305 => Ok(CipherSuite::TlsAes128Ccm8Sha256),
            _ => Err(Error::ParseError(format!("Invalid CipherSuite value: {:#06x}", value))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    RecordSizeLimit = 28,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}

impl TryFrom<u16> for ExtensionType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0 => Ok(ExtensionType::ServerName),
            1 => Ok(ExtensionType::MaxFragmentLength),
            10 => Ok(ExtensionType::SupportedGroups),
            13 => Ok(ExtensionType::SignatureAlgorithms),
            14 => Ok(ExtensionType::UseSrtp),
            15 => Ok(ExtensionType::Heartbeat),
            16 => Ok(ExtensionType::ApplicationLayerProtocolNegotiation),
            18 => Ok(ExtensionType::SignedCertificateTimestamp),
            19 => Ok(ExtensionType::ClientCertificateType),
            20 => Ok(ExtensionType::ServerCertificateType),
            21 => Ok(ExtensionType::Padding),
            28 => Ok(ExtensionType::RecordSizeLimit),
            41 => Ok(ExtensionType::PreSharedKey),
            42 => Ok(ExtensionType::EarlyData),
            43 => Ok(ExtensionType::SupportedVersions),
            44 => Ok(ExtensionType::Cookie),
            45 => Ok(ExtensionType::PskKeyExchangeModes),
            47 => Ok(ExtensionType::CertificateAuthorities),
            48 => Ok(ExtensionType::OidFilters),
            49 => Ok(ExtensionType::PostHandshakeAuth),
            50 => Ok(ExtensionType::SignatureAlgorithmsCert),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(Error::ParseError(format!("Invalid ExtensionType value: {}", value))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn new(extension_type: ExtensionType, data: Vec<u8>) -> Self {
        Self { extension_type, data }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos + 4 > data.len() {
            return Err(Error::ParseError("Extension too short".to_string()));
        }

        let extension_type = ExtensionType::try_from(utils::read_u16(data, pos)?)?;
        let length = utils::read_u16(data, pos)? as usize;

        if *pos + length > data.len() {
            return Err(Error::ParseError("Extension data length exceeds available data".to_string()));
        }

        let extension_data = utils::read_bytes(data, pos, length)?;
        
        Ok(Self {
            extension_type,
            data: extension_data.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + self.data.len());
        utils::write_u16(&mut result, self.extension_type as u16);
        utils::write_u16(&mut result, self.data.len() as u16);
        result.extend_from_slice(&self.data);
        result
    }
}

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

pub struct HandshakeLayer {
    // Will be expanded in future implementations
}

impl HandshakeLayer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn parse_handshake_message(
        &self,
        data: &[u8],
    ) -> Result<(Box<dyn HandshakeMessage>, usize)> {
        if data.len() < 4 {
            return Err(Error::ParseError("Handshake message too short".to_string()));
        }

        let mut pos = 0;
        let header = HandshakeMessageHeader::parse(data, &mut pos)?;

        if pos + header.length as usize > data.len() {
            return Err(Error::ParseError(
                "Handshake message length exceeds available data".to_string(),
            ));
        }
        
        let message_data = &data[pos..pos + header.length as usize];
        let mut msg_pos = 0;
        
        let message: Box<dyn HandshakeMessage> = match header.msg_type {
            HandshakeType::ClientHello => {
                Box::new(ClientHello::parse(message_data, &mut msg_pos)?)
            },
            _ => return Err(Error::NotImplemented(
                format!("Parsing handshake message type {:?} not yet implemented", header.msg_type)
            ))
        };
        
        pos += header.length as usize;
        
        Ok((message, pos))
    }
}

impl Default for HandshakeLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_header_parsing() {
        let data = [
            0x01, // ClientHello
            0x00, 0x00, 0x03, // Length 3
            0xAA, 0xBB, 0xCC, // Dummy payload
        ];

        let mut pos = 0;
        let header = HandshakeMessageHeader::parse(&data, &mut pos).unwrap();

        assert_eq!(header.msg_type, HandshakeType::ClientHello);
        assert_eq!(header.length, 3);
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_handshake_header_serialization() {
        let header = HandshakeMessageHeader::new(HandshakeType::ClientHello, 3);
        let serialized = header.serialize();

        let expected = [
            0x01, // ClientHello
            0x00, 0x00, 0x03, // Length 3
        ];

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_invalid_handshake_type() {
        let data = [
            0x30, // Invalid type
            0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC,
        ];

        let mut pos = 0;
        assert!(HandshakeMessageHeader::parse(&data, &mut pos).is_err());
    }
    
    #[test]
    fn test_extension_parsing() {
        let extension_data = [
            0x00, 0x0A, // SupportedGroups extension type
            0x00, 0x04, // Length 4
            0x00, 0x02, // List length 2
            0x00, 0x1D, // x25519 group
        ];
        
        let mut pos = 0;
        let extension = Extension::parse(&extension_data, &mut pos).unwrap();
        
        assert_eq!(extension.extension_type, ExtensionType::SupportedGroups);
        assert_eq!(extension.data, &[0x00, 0x02, 0x00, 0x1D]);
        assert_eq!(pos, 8);
    }
    
    #[test]
    fn test_extension_serialization() {
        let extension = Extension::new(
            ExtensionType::SupportedGroups,
            vec![0x00, 0x02, 0x00, 0x1D],
        );
        
        let serialized = extension.serialize();
        
        let expected = [
            0x00, 0x0A, // SupportedGroups extension type
            0x00, 0x04, // Length 4
            0x00, 0x02, 0x00, 0x1D, // Extension data
        ];
        
        assert_eq!(serialized, expected);
    }
    
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
