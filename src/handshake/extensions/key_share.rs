use crate::error::{Error, Result};
use crate::utils;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedGroup {
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}

impl TryFrom<u16> for NamedGroup {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0017 => Ok(NamedGroup::Secp256r1),
            0x0018 => Ok(NamedGroup::Secp384r1),
            0x0019 => Ok(NamedGroup::Secp521r1),
            0x001D => Ok(NamedGroup::X25519),
            0x001E => Ok(NamedGroup::X448),
            0x0100 => Ok(NamedGroup::Ffdhe2048),
            0x0101 => Ok(NamedGroup::Ffdhe3072),
            0x0102 => Ok(NamedGroup::Ffdhe4096),
            0x0103 => Ok(NamedGroup::Ffdhe6144),
            0x0104 => Ok(NamedGroup::Ffdhe8192),
            _ => Err(Error::ParseError(format!("Invalid NamedGroup value: {:#06x}", value))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

impl KeyShareEntry {
    pub fn new(group: NamedGroup, key_exchange: Vec<u8>) -> Self {
        Self { group, key_exchange }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos + 4 > data.len() {
            return Err(Error::ParseError("KeyShareEntry too short".to_string()));
        }

        let group = NamedGroup::try_from(utils::read_u16(data, pos)?)?;
        let key_exchange = utils::read_vector_u16(data, pos)?.to_vec();

        Ok(Self { group, key_exchange })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(4 + self.key_exchange.len());
        utils::write_u16(&mut result, self.group as u16);
        utils::write_vector_u16(&mut result, &self.key_exchange);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_share_entry_parsing() {
        let key_share_data = [
            0x00, 0x1D, // X25519 named group
            0x00, 0x20, // Key exchange length: 32 bytes
            // Public key, 32 bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        
        let mut pos = 0;
        let key_share = KeyShareEntry::parse(&key_share_data, &mut pos).unwrap();
        
        assert_eq!(key_share.group, NamedGroup::X25519);
        assert_eq!(key_share.key_exchange.len(), 32);
        assert_eq!(key_share.key_exchange[0], 0x01);
        assert_eq!(key_share.key_exchange[31], 0x20);
        assert_eq!(pos, 36);
    }
    
    #[test]
    fn test_key_share_entry_serialization() {
        let key_exchange = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        ];
        
        let key_share = KeyShareEntry::new(NamedGroup::X25519, key_exchange.clone());
        let serialized = key_share.serialize();
        
        let expected = [
            0x00, 0x1D, // X25519 named group
            0x00, 0x20, // Key exchange length: 32 bytes
        ].iter().chain(key_exchange.iter()).copied().collect::<Vec<u8>>();
        
        assert_eq!(serialized, expected);
    }
}