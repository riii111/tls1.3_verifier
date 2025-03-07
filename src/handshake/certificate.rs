use crate::error::{Error, Result};
use crate::utils;
use crate::handshake::{HandshakeType, HandshakeMessage};
use crate::handshake::extensions::Extension;

#[derive(Debug)]
pub struct CertificateEntry {
    pub cert_data: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl CertificateEntry {
    pub fn new(cert_data: Vec<u8>, extensions: Vec<Extension>) -> Self {
        Self { cert_data, extensions }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        let cert_length = utils::read_u24(data, pos)? as usize;
        
        if *pos + cert_length > data.len() {
            return Err(Error::ParseError("Certificate entry truncated".to_string()));
        }
        
        let cert_data = utils::read_bytes(data, pos, cert_length)?.to_vec();
        
        let extensions_length = utils::read_u16(data, pos)? as usize;
        if *pos + extensions_length > data.len() {
            return Err(Error::ParseError("Certificate extensions truncated".to_string()));
        }
        
        let extensions_end = *pos + extensions_length;
        let mut extensions = Vec::new();
        
        while *pos < extensions_end {
            let extension = Extension::parse(data, pos)?;
            extensions.push(extension);
        }
        
        Ok(Self { cert_data, extensions })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        utils::write_u24(&mut result, self.cert_data.len() as u32);
        result.extend_from_slice(&self.cert_data);
        
        let mut extensions_data = Vec::new();
        for ext in &self.extensions {
            extensions_data.extend_from_slice(&ext.serialize());
        }
        
        utils::write_u16(&mut result, extensions_data.len() as u16);
        result.extend_from_slice(&extensions_data);
        
        result
    }
}

#[derive(Debug)]
pub struct Certificate {
    pub cert_request_context: Vec<u8>,
    pub certificate_list: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn new(cert_request_context: Vec<u8>, certificate_list: Vec<CertificateEntry>) -> Self {
        Self { cert_request_context, certificate_list }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        let context_length = utils::read_u8(data, pos)? as usize;
        
        if *pos + context_length > data.len() {
            return Err(Error::ParseError("Certificate request context truncated".to_string()));
        }
        
        let cert_request_context = utils::read_bytes(data, pos, context_length)?.to_vec();
        
        let certs_length = utils::read_u24(data, pos)? as usize;
        if *pos + certs_length > data.len() {
            return Err(Error::ParseError("Certificate list truncated".to_string()));
        }
        
        let certs_end = *pos + certs_length;
        let mut certificate_list = Vec::new();
        
        while *pos < certs_end {
            let cert_entry = CertificateEntry::parse(data, pos)?;
            certificate_list.push(cert_entry);
        }
        
        Ok(Self { cert_request_context, certificate_list })
    }
}

impl HandshakeMessage for Certificate {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::Certificate
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        utils::write_u8(&mut result, self.cert_request_context.len() as u8);
        result.extend_from_slice(&self.cert_request_context);
        
        let mut certs_data = Vec::new();
        for cert in &self.certificate_list {
            certs_data.extend_from_slice(&cert.serialize());
        }
        
        utils::write_u24(&mut result, certs_data.len() as u32);
        result.extend_from_slice(&certs_data);
        
        Ok(result)
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}