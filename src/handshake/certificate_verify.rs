use crate::error::{Error, Result};
use crate::utils;
use crate::handshake::{HandshakeType, HandshakeMessage};
use crate::crypto::signature::SignatureScheme;

#[derive(Debug)]
pub struct CertificateVerify {
    pub algorithm: SignatureScheme,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn new(algorithm: SignatureScheme, signature: Vec<u8>) -> Self {
        Self { algorithm, signature }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos + 4 > data.len() {
            return Err(Error::ParseError("CertificateVerify message truncated".to_string()));
        }
        
        let algorithm_value = utils::read_u16(data, pos)?;
        let algorithm = match algorithm_value {
            0x0401 => SignatureScheme::RsaPkcs1Sha256,
            0x0501 => SignatureScheme::RsaPkcs1Sha384,
            0x0601 => SignatureScheme::RsaPkcs1Sha512,
            0x0403 => SignatureScheme::EcdsaSecp256r1Sha256,
            0x0503 => SignatureScheme::EcdsaSecp384r1Sha384,
            0x0603 => SignatureScheme::EcdsaSecp521r1Sha512,
            0x0804 => SignatureScheme::RsaPssRsaeSha256,
            0x0805 => SignatureScheme::RsaPssRsaeSha384,
            0x0806 => SignatureScheme::RsaPssRsaeSha512,
            0x0807 => SignatureScheme::Ed25519,
            0x0808 => SignatureScheme::Ed448,
            _ => return Err(Error::ParseError(format!(
                "Unsupported signature algorithm: {:#06x}", algorithm_value
            ))),
        };
        
        // Read signature
        let signature_length = utils::read_u16(data, pos)? as usize;
        if *pos + signature_length > data.len() {
            return Err(Error::ParseError("Signature data truncated".to_string()));
        }
        
        let signature = utils::read_bytes(data, pos, signature_length)?.to_vec();
        
        Ok(Self { algorithm, signature })
    }
    
    pub fn verify(&self, transcript_hash: &[u8], public_key: &[u8]) -> Result<()> {
        // In TLS 1.3, the context string is different for client and server
        // Since this is the server certificate verify message in our case (in client mode), 
        // we'll use the server context string
        let is_server = true;
        
        crate::crypto::signature::verify_certificate_verify(
            self.algorithm,
            public_key,
            &self.signature,
            transcript_hash,
            is_server
        )
    }
}

impl HandshakeMessage for CertificateVerify {
    fn message_type(&self) -> HandshakeType {
        HandshakeType::CertificateVerify
    }
    
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        
        // Write signature algorithm
        utils::write_u16(&mut result, self.algorithm as u16);
        
        // Write signature
        utils::write_u16(&mut result, self.signature.len() as u16);
        result.extend_from_slice(&self.signature);
        
        Ok(result)
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_verify_parsing() {
        let certificate_verify_data = [
            0x08, 0x04, // RSA-PSS-RSAE + SHA-256
            0x00, 0x10, // Signature length (16 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Signature data
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        
        let mut pos = 0;
        let cert_verify = CertificateVerify::parse(&certificate_verify_data, &mut pos).unwrap();
        
        assert_eq!(cert_verify.algorithm, SignatureScheme::RsaPssRsaeSha256);
        assert_eq!(cert_verify.signature.len(), 16);
        assert_eq!(cert_verify.signature[0], 0x01);
        assert_eq!(cert_verify.signature[15], 0x10);
        assert_eq!(pos, certificate_verify_data.len());
    }
    
    #[test]
    fn test_certificate_verify_serialization() {
        let signature = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        
        let cert_verify = CertificateVerify::new(
            SignatureScheme::RsaPssRsaeSha256,
            signature.clone(),
        );
        
        let serialized = cert_verify.serialize().unwrap();
        
        assert_eq!(serialized.len(), 4 + signature.len());
        assert_eq!(serialized[0], 0x08); // SignatureScheme high byte
        assert_eq!(serialized[1], 0x04); // SignatureScheme low byte
        assert_eq!(serialized[2], 0x00); // Signature length high byte
        assert_eq!(serialized[3], 0x10); // Signature length low byte (16)
        
        // Check signature bytes
        for i in 0..signature.len() {
            assert_eq!(serialized[4 + i], signature[i]);
        }
    }
    
    #[test]
    fn test_invalid_signature_algorithm() {
        let invalid_data = [
            0xFF, 0xFF, // Invalid signature algorithm
            0x00, 0x10, // Signature length (16 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Signature data
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];
        
        let mut pos = 0;
        let result = CertificateVerify::parse(&invalid_data, &mut pos);
        assert!(result.is_err());
        
        if let Err(Error::ParseError(msg)) = result {
            assert!(msg.contains("Unsupported signature algorithm"));
        } else {
            panic!("Expected ParseError for invalid signature algorithm");
        }
    }
}