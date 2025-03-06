use crate::error::Result;

pub mod x509;
pub mod validation;

pub use x509::*;
pub use validation::*;

pub struct Certificate {
    pub der_data: Vec<u8>,
    pub parsed: Option<x509::ParsedCertificate>,
}

impl Certificate {
    pub fn new(der_data: Vec<u8>) -> Self {
        Self {
            der_data,
            parsed: None,
        }
    }

    pub fn parse(&mut self) -> Result<&x509::ParsedCertificate> {
        if self.parsed.is_none() {
            self.parsed = Some(x509::parse_certificate(&self.der_data)?);
        }
        
        Ok(self.parsed.as_ref().unwrap())
    }
}