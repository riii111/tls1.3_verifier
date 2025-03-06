use crate::error::{Error, Result};
use crate::utils;
use std::fmt::Debug;

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

        // Placeholder - will be expanded for each message type
        Err(Error::NotImplemented(
            "Parsing specific handshake message types not yet implemented".to_string(),
        ))
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
