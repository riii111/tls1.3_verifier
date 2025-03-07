use crate::error::{Error, Result};
use x509_parser::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH, Duration};

pub struct ParsedCertificate {
    pub subject: String,
    pub issuer: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: String,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
    pub serial_number: String,
    pub is_ca: bool,
    pub subject_alt_names: Vec<String>,
    pub path_len_constraint: Option<u8>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Vec<String>,
    pub issuer_unique_id: Option<Vec<u8>>,
    pub subject_unique_id: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            digital_signature: false,
            non_repudiation: false,
            key_encipherment: false,
            data_encipherment: false,
            key_agreement: false,
            key_cert_sign: false,
            crl_sign: false,
            encipher_only: false,
            decipher_only: false,
        }
    }
}

fn asn1_time_to_system_time(time: &ASN1Time) -> Result<SystemTime> {
    // Convert ASN.1 TIME to SystemTime
    // This is a simplified conversion - in a production system,
    // we would need more careful handling of time zones and formats
    let unix_time = time.timestamp().map_err(|e| {
        Error::CertificateError(format!("Failed to convert ASN.1 time: {}", e))
    })?;
    
    Ok(UNIX_EPOCH + Duration::from_secs(unix_time as u64))
}

fn parse_key_usage(cert: &X509Certificate) -> Option<KeyUsage> {
    cert.key_usage().map(|ku| {
        KeyUsage {
            digital_signature: ku.digital_signature(),
            non_repudiation: ku.non_repudiation(),
            key_encipherment: ku.key_encipherment(),
            data_encipherment: ku.data_encipherment(),
            key_agreement: ku.key_agreement(),
            key_cert_sign: ku.key_cert_sign(),
            crl_sign: ku.crl_sign(),
            encipher_only: ku.encipher_only(),
            decipher_only: ku.decipher_only(),
        }
    })
}

fn parse_subject_alt_names(cert: &X509Certificate) -> Vec<String> {
    let mut result = Vec::new();
    
    if let Some(san) = cert.subject_alternative_name() {
        if let Ok(san) = san.value.general_names.iter().map(|gn| {
            match gn {
                GeneralName::DNSName(name) => Some(format!("DNS:{}", name)),
                GeneralName::IPAddress(ip) => Some(format!("IP:{:?}", ip)),
                GeneralName::RFC822Name(email) => Some(format!("EMAIL:{}", email)),
                GeneralName::URI(uri) => Some(format!("URI:{}", uri)),
                _ => None,
            }
        }).filter_map(|x| x).collect::<Vec<_>>() {
            result.extend(san);
        }
    }
    
    result
}

fn parse_extended_key_usage(cert: &X509Certificate) -> Vec<String> {
    let mut result = Vec::new();
    
    if let Some(eku) = cert.extended_key_usage() {
        if let Ok(eku) = eku.value {
            for oid in eku.iter() {
                result.push(oid.to_id_string());
            }
        }
    }
    
    result
}

pub fn parse_certificate(cert_der: &[u8]) -> Result<ParsedCertificate> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| Error::CertificateError(format!("Failed to parse X.509 certificate: {}", e)))?;
    
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    
    let not_before = asn1_time_to_system_time(&cert.validity().not_before)?;
    let not_after = asn1_time_to_system_time(&cert.validity().not_after)?;
    
    let public_key = cert.public_key().subject_public_key.data.to_vec();
    let public_key_algorithm = cert.public_key().algorithm.algorithm.to_string();
    
    let signature_algorithm = cert.signature_algorithm.algorithm.to_string();
    let signature = cert.signature_value.data.to_vec();
    
    let serial_number = cert.serial.to_string();
    
    // Check if this is a CA certificate
    let is_ca = cert.basic_constraints()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    
    // Parse pathLenConstraint if present
    let path_len_constraint = cert.basic_constraints()
        .and_then(|bc| bc.value.path_len_constraint);
    
    // Parse subject alternative names
    let subject_alt_names = parse_subject_alt_names(&cert);
    
    // Parse key usage
    let key_usage = parse_key_usage(&cert);
    
    // Parse extended key usage
    let extended_key_usage = parse_extended_key_usage(&cert);
    
    // Get issuer and subject unique IDs if present
    let issuer_unique_id = cert.issuer_uid.as_ref().map(|uid| uid.to_vec());
    let subject_unique_id = cert.subject_uid.as_ref().map(|uid| uid.to_vec());
    
    Ok(ParsedCertificate {
        subject,
        issuer,
        not_before,
        not_after,
        public_key,
        public_key_algorithm,
        signature_algorithm,
        signature,
        serial_number,
        is_ca,
        subject_alt_names,
        path_len_constraint,
        key_usage,
        extended_key_usage,
        issuer_unique_id,
        subject_unique_id,
    })
}

pub fn parse_certificate_chain(cert_chain: &[Vec<u8>]) -> Result<Vec<ParsedCertificate>> {
    let mut result = Vec::with_capacity(cert_chain.len());
    
    for cert_der in cert_chain {
        result.push(parse_certificate(cert_der)?);
    }
    
    Ok(result)
}