use crate::error::{Error, Result};
use std::path::Path;
use std::fs::File;
use std::io::Read;

pub mod x509;
pub mod validation;

pub use x509::*;
pub use validation::*;

#[derive(Clone)]
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
    
    pub fn from_pem_file(path: &Path) -> Result<Vec<Self>> {
        let mut file = File::open(path)
            .map_err(|e| Error::CertificateError(format!("Failed to open PEM file: {}", e)))?;
        
        let mut pem_data = Vec::new();
        file.read_to_end(&mut pem_data)
            .map_err(|e| Error::CertificateError(format!("Failed to read PEM file: {}", e)))?;
        
        Self::from_pem(&pem_data)
    }
    
    pub fn from_pem(pem_data: &[u8]) -> Result<Vec<Self>> {
        let mut result = Vec::new();
        
        let mut cursor = std::io::Cursor::new(pem_data);
        let certs = rustls_pemfile::certs(&mut cursor)
            .map_err(|e| Error::CertificateError(format!("Failed to parse PEM data: {}", e)))?;
        
        for cert in certs {
            result.push(Self::new(cert));
        }
        
        Ok(result)
    }
    
    pub fn from_der_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path)
            .map_err(|e| Error::CertificateError(format!("Failed to open DER file: {}", e)))?;
        
        let mut der_data = Vec::new();
        file.read_to_end(&mut der_data)
            .map_err(|e| Error::CertificateError(format!("Failed to read DER file: {}", e)))?;
        
        Ok(Self::new(der_data))
    }
}

pub struct CertificateVerifier {
    trust_store: validation::TrustStore,
    validation_options: validation::ValidationOptions,
}

impl CertificateVerifier {
    pub fn new() -> Self {
        Self {
            trust_store: validation::TrustStore::new(),
            validation_options: validation::ValidationOptions::default(),
        }
    }
    
    pub fn with_root_cert(mut self, cert: Certificate) -> Result<Self> {
        self.trust_store.add_trust_anchor(cert)?;
        Ok(self)
    }
    
    pub fn with_root_cert_pem_file(mut self, path: &Path) -> Result<Self> {
        let certs = Certificate::from_pem_file(path)?;
        self.trust_store.add_trust_anchors(certs)?;
        Ok(self)
    }
    
    pub fn with_validation_options(mut self, options: validation::ValidationOptions) -> Self {
        self.validation_options = options;
        self
    }
    
    pub fn verify_chain(&self, cert_chain: &[Certificate]) -> Result<validation::ValidationStatus> {
        self.trust_store.validate_certificate_chain(cert_chain, &self.validation_options)
    }
    
    pub fn verify_server_certificate(&self, 
        cert_chain: &[Certificate], 
        server_name: Option<&str>
    ) -> Result<validation::ValidationStatus> {
        let chain_status = self.verify_chain(cert_chain)?;
        if chain_status != validation::ValidationStatus::Valid {
            return Ok(chain_status);
        }
        
        if let Some(name) = server_name {
            let leaf = &cert_chain[0];
            let parsed = leaf.parsed.as_ref().ok_or_else(|| {
                Error::CertificateError("Certificate not parsed".to_string())
            })?;
            
            if !self.check_hostname(parsed, name) {
                return Err(Error::CertificateError(format!(
                    "Hostname '{}' doesn't match certificate", name
                )));
            }
        }
        
        Ok(validation::ValidationStatus::Valid)
    }
    
    fn check_hostname(&self, cert: &ParsedCertificate, hostname: &str) -> bool {
        for san in &cert.subject_alt_names {
            if san.starts_with("DNS:") {
                let name = &san[4..];
                if name == hostname {
                    return true;
                }
                
                if name.starts_with("*.") && hostname.contains('.') {
                    let wildcard_suffix = &name[1..];
                    let hostname_suffix = &hostname[hostname.find('.').unwrap()..];
                    if wildcard_suffix == hostname_suffix {
                        return true;
                    }
                }
            }
        }
        
        if cert.subject.contains(&format!("CN={}", hostname)) {
            return true;
        }
        
        false
    }
}

impl Default for CertificateVerifier {
    fn default() -> Self {
        Self::new()
    }
}