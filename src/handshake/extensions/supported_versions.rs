use crate::error::{Error, Result};
use crate::utils;
use crate::tls::constants;
use crate::handshake::extensions::{Extension, ExtensionType};

pub struct SupportedVersions {
    pub versions: Vec<u16>,
}

impl SupportedVersions {
    pub fn new(versions: Vec<u16>) -> Self {
        Self { versions }
    }

    pub fn create_extension(&self) -> Extension {
        let mut data = Vec::new();
        
        if !self.versions.is_empty() {
            // For ClientHello: length byte followed by version list
            utils::write_u8(&mut data, (self.versions.len() * 2) as u8);
            for version in &self.versions {
                utils::write_u16(&mut data, *version);
            }
        } else {
            // Empty list with zero length
            utils::write_u8(&mut data, 0);
        }
        
        Extension::new(ExtensionType::SupportedVersions, data)
    }

    pub fn create_server_extension(selected_version: u16) -> Extension {
        let mut data = Vec::new();
        utils::write_u16(&mut data, selected_version);
        Extension::new(ExtensionType::SupportedVersions, data)
    }

    pub fn parse_client(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos >= data.len() {
            return Err(Error::ParseError("SupportedVersions extension truncated".to_string()));
        }
        
        let versions_length = utils::read_u8(data, pos)? as usize;
        if versions_length % 2 != 0 {
            return Err(Error::ParseError("SupportedVersions list length must be even".to_string()));
        }
        
        if *pos + versions_length > data.len() {
            return Err(Error::ParseError("SupportedVersions extension truncated".to_string()));
        }
        
        let num_versions = versions_length / 2;
        let mut versions = Vec::with_capacity(num_versions);
        
        for _ in 0..num_versions {
            versions.push(utils::read_u16(data, pos)?);
        }
        
        Ok(Self { versions })
    }

    pub fn parse_server(data: &[u8], pos: &mut usize) -> Result<u16> {
        if *pos + 2 > data.len() {
            return Err(Error::ParseError("ServerHello SupportedVersions extension truncated".to_string()));
        }
        
        Ok(utils::read_u16(data, pos)?)
    }

    pub fn supports_tls13(&self) -> bool {
        self.versions.contains(&constants::TLS13)
    }
}