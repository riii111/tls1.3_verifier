use crate::error::{Error, Result};
use crate::utils;
use std::fmt::Debug;
use std::convert::TryFrom;

// Re-export modules
pub mod client_hello;
pub mod server_hello;
pub mod extensions;
pub mod encrypted_extensions;
pub mod certificate;
pub mod certificate_verify;
pub mod finished;

// Re-export main types from child modules
pub use client_hello::ClientHello;
pub use server_hello::ServerHello;
pub use encrypted_extensions::EncryptedExtensions;
pub use certificate::Certificate;
pub use certificate_verify::CertificateVerify;
pub use finished::Finished;
pub use extensions::{Extension, ExtensionType};
pub use extensions::key_share::{KeyShareEntry, NamedGroup};

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
    
    // Allow downcasting for specific message types
    fn as_any(&self) -> &dyn std::any::Any;
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
                Box::new(client_hello::ClientHello::parse(message_data, &mut msg_pos)?)
            },
            HandshakeType::ServerHello => {
                Box::new(server_hello::ServerHello::parse(message_data, &mut msg_pos)?)
            },
            HandshakeType::EncryptedExtensions => {
                Box::new(encrypted_extensions::EncryptedExtensions::parse(message_data, &mut msg_pos)?)
            },
            HandshakeType::Certificate => {
                Box::new(certificate::Certificate::parse(message_data, &mut msg_pos)?)
            },
            HandshakeType::CertificateVerify => {
                Box::new(certificate_verify::CertificateVerify::parse(message_data, &mut msg_pos)?)
            },
            HandshakeType::Finished => {
                Box::new(finished::Finished::parse(message_data, &mut msg_pos)?)
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
}