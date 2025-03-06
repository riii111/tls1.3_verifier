use crate::error::{Error, Result};
use crate::utils;
use std::convert::TryFrom;

// Re-export modules
pub mod key_share;
// pub mod supported_versions;  // Will be implemented in future PRs

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

#[cfg(test)]
mod tests {
    use super::*;

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
}