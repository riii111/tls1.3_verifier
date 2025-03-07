// Signature verification for TLS 1.3
use crate::error::{Error, Result};
use crate::crypto::hkdf::HashAlgorithm;
use ring::signature;

// Signature algorithms supported in TLS 1.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,
    Ed25519 = 0x0807,
    Ed448 = 0x0808,
}

impl SignatureScheme {
    // Get the verification algorithm for this signature scheme
    fn verification_algorithm(&self) -> Result<&'static dyn signature::VerificationAlgorithm> {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
            SignatureScheme::RsaPkcs1Sha384 => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
            SignatureScheme::RsaPkcs1Sha512 => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
            SignatureScheme::RsaPssRsaeSha256 => Ok(&signature::RSA_PSS_2048_8192_SHA256),
            SignatureScheme::RsaPssRsaeSha384 => Ok(&signature::RSA_PSS_2048_8192_SHA384),
            SignatureScheme::RsaPssRsaeSha512 => Ok(&signature::RSA_PSS_2048_8192_SHA512),
            SignatureScheme::EcdsaSecp256r1Sha256 => Ok(&signature::ECDSA_P256_SHA256_ASN1),
            SignatureScheme::EcdsaSecp384r1Sha384 => Ok(&signature::ECDSA_P384_SHA384_ASN1),
            // These are not yet supported by Ring, would need external implementation
            SignatureScheme::EcdsaSecp521r1Sha512 => Err(Error::CryptoError("ECDSA P-521 with SHA-512 not supported yet".to_string())),
            SignatureScheme::Ed25519 => Err(Error::CryptoError("Ed25519 not supported yet".to_string())),
            SignatureScheme::Ed448 => Err(Error::CryptoError("Ed448 not supported yet".to_string())),
        }
    }
    
    // Get the hash algorithm associated with this signature scheme
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            SignatureScheme::RsaPkcs1Sha256 |
            SignatureScheme::EcdsaSecp256r1Sha256 |
            SignatureScheme::RsaPssRsaeSha256 |
            SignatureScheme::Ed25519 => HashAlgorithm::Sha256,
            
            SignatureScheme::RsaPkcs1Sha384 |
            SignatureScheme::EcdsaSecp384r1Sha384 |
            SignatureScheme::RsaPssRsaeSha384 => HashAlgorithm::Sha384,
            
            SignatureScheme::RsaPkcs1Sha512 |
            SignatureScheme::EcdsaSecp521r1Sha512 |
            SignatureScheme::RsaPssRsaeSha512 |
            SignatureScheme::Ed448 => HashAlgorithm::Sha384, // Note: SHA-512 not directly supported in our HashAlgorithm enum yet
        }
    }
    
    // Check if this is an RSA signature scheme
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            SignatureScheme::RsaPkcs1Sha256 |
            SignatureScheme::RsaPkcs1Sha384 |
            SignatureScheme::RsaPkcs1Sha512 |
            SignatureScheme::RsaPssRsaeSha256 |
            SignatureScheme::RsaPssRsaeSha384 |
            SignatureScheme::RsaPssRsaeSha512
        )
    }
    
    // Check if this is an ECDSA signature scheme
    pub fn is_ecdsa(&self) -> bool {
        matches!(
            self,
            SignatureScheme::EcdsaSecp256r1Sha256 |
            SignatureScheme::EcdsaSecp384r1Sha384 |
            SignatureScheme::EcdsaSecp521r1Sha512
        )
    }
    
    // Check if this is an EdDSA signature scheme
    pub fn is_eddsa(&self) -> bool {
        matches!(
            self,
            SignatureScheme::Ed25519 |
            SignatureScheme::Ed448
        )
    }
}

// Fixed padding used in TLS 1.3 signature context
const SERVER_CONTEXT_STRING: &[u8] = b"TLS 1.3, server CertificateVerify";
const CLIENT_CONTEXT_STRING: &[u8] = b"TLS 1.3, client CertificateVerify";
const CONTEXT_PREFIX_PADDING: [u8; 64] = [0x20; 64];

pub fn generate_signature_context(transcript_hash: &[u8], is_server: bool) -> Vec<u8> {
    let mut context = Vec::new();
    
    context.extend_from_slice(&CONTEXT_PREFIX_PADDING);
    context.extend_from_slice(if is_server { SERVER_CONTEXT_STRING } else { CLIENT_CONTEXT_STRING });
    context.push(0x00); // separator byte
    context.extend_from_slice(transcript_hash);
    
    context
}

pub fn verify_signature(
    signature_scheme: SignatureScheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let algorithm = signature_scheme.verification_algorithm()?;
    let public_key = signature::UnparsedPublicKey::new(algorithm, public_key);
    
    public_key.verify(message, signature)
        .map_err(|_| Error::CryptoError("Signature verification failed".to_string()))?;
    
    Ok(())
}

pub fn verify_certificate_verify(
    scheme: SignatureScheme,
    public_key: &[u8],
    signature: &[u8],
    transcript_hash: &[u8],
    is_server: bool,
) -> Result<()> {
    let context = generate_signature_context(transcript_hash, is_server);
    verify_signature(scheme, public_key, &context, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_signature_context_generation() {
        let transcript_hash = [0x01, 0x02, 0x03, 0x04, 0x05];
        
        // Server context
        let server_context = generate_signature_context(&transcript_hash, true);
        assert_eq!(server_context.len(), 64 + SERVER_CONTEXT_STRING.len() + 1 + transcript_hash.len());
        assert_eq!(&server_context[0..64], &CONTEXT_PREFIX_PADDING);
        assert_eq!(&server_context[64..(64 + SERVER_CONTEXT_STRING.len())], SERVER_CONTEXT_STRING);
        assert_eq!(server_context[64 + SERVER_CONTEXT_STRING.len()], 0x00);
        assert_eq!(&server_context[(64 + SERVER_CONTEXT_STRING.len() + 1)..], &transcript_hash);
        
        // Client context
        let client_context = generate_signature_context(&transcript_hash, false);
        assert_eq!(client_context.len(), 64 + CLIENT_CONTEXT_STRING.len() + 1 + transcript_hash.len());
        assert_eq!(&client_context[0..64], &CONTEXT_PREFIX_PADDING);
        assert_eq!(&client_context[64..(64 + CLIENT_CONTEXT_STRING.len())], CLIENT_CONTEXT_STRING);
        assert_eq!(client_context[64 + CLIENT_CONTEXT_STRING.len()], 0x00);
        assert_eq!(&client_context[(64 + CLIENT_CONTEXT_STRING.len() + 1)..], &transcript_hash);
    }
    
    #[test]
    fn test_signature_scheme_properties() {
        // RSA schemes
        assert!(SignatureScheme::RsaPkcs1Sha256.is_rsa());
        assert!(!SignatureScheme::RsaPkcs1Sha256.is_ecdsa());
        assert!(!SignatureScheme::RsaPkcs1Sha256.is_eddsa());
        
        // ECDSA schemes
        assert!(SignatureScheme::EcdsaSecp256r1Sha256.is_ecdsa());
        assert!(!SignatureScheme::EcdsaSecp256r1Sha256.is_rsa());
        assert!(!SignatureScheme::EcdsaSecp256r1Sha256.is_eddsa());
        
        // EdDSA schemes
        assert!(SignatureScheme::Ed25519.is_eddsa());
        assert!(!SignatureScheme::Ed25519.is_rsa());
        assert!(!SignatureScheme::Ed25519.is_ecdsa());
    }
    
    #[test]
    fn test_hash_algorithm_mapping() {
        assert_eq!(SignatureScheme::RsaPkcs1Sha256.hash_algorithm(), HashAlgorithm::Sha256);
        assert_eq!(SignatureScheme::EcdsaSecp256r1Sha256.hash_algorithm(), HashAlgorithm::Sha256);
        assert_eq!(SignatureScheme::RsaPssRsaeSha256.hash_algorithm(), HashAlgorithm::Sha256);
        
        assert_eq!(SignatureScheme::RsaPkcs1Sha384.hash_algorithm(), HashAlgorithm::Sha384);
        assert_eq!(SignatureScheme::EcdsaSecp384r1Sha384.hash_algorithm(), HashAlgorithm::Sha384);
        assert_eq!(SignatureScheme::RsaPssRsaeSha384.hash_algorithm(), HashAlgorithm::Sha384);
    }
}