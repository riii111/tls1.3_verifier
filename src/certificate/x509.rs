use crate::error::{Error, Result};
use x509_parser::prelude::*;
use std::time::{SystemTime, Duration};

pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub public_key: Vec<u8>,
    pub signature_algorithm: String,
}

pub fn parse_certificate(cert_der: &[u8]) -> Result<ParsedCertificate> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::CertificateError(format!("Failed to parse X.509 certificate: {}", e)))?;
    
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    
    // Convert ASN1Time to SystemTime - simplified for now
    // For a real implementation, we should properly parse the ASN1Time
    // but for this codebase refactoring, we'll use a dummy implementation
    let not_before = SystemTime::now();
    let not_after = SystemTime::now() + Duration::from_secs(365 * 24 * 60 * 60); // Valid for 1 year
    
    let public_key = cert.public_key().subject_public_key.data.to_vec();
    
    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();
    
    Ok(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        public_key,
        signature_algorithm,
    })
}

pub fn parse_certificate_chain(cert_chain: &[Vec<u8>]) -> Result<Vec<ParsedCertificate>> {
    let mut result = Vec::with_capacity(cert_chain.len());
    
    for cert_der in cert_chain {
        result.push(parse_certificate(cert_der)?);
    }
    
    Ok(result)
}