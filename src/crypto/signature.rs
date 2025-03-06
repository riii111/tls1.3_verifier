// Signature verification for TLS 1.3
use crate::error::{Error, Result};
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
            _ => Err(Error::CryptoError(format!("Signature scheme {:?} not supported", self))),
        }
    }
}

// Verify a signature using the specified scheme
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