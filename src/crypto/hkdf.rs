// HKDF key derivation functions for TLS 1.3
use crate::error::{Error, Result};
use crate::handshake::CipherSuite;
use ring::hmac;

// Define hash algorithms used for HKDF
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl HashAlgorithm {
    // Get output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
        }
    }
    
    // Get the hash algorithm for a cipher suite
    pub fn for_cipher_suite(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::TlsAes128GcmSha256 => HashAlgorithm::Sha256,
            CipherSuite::TlsAes256GcmSha384 => HashAlgorithm::Sha384,
            CipherSuite::TlsChacha20Poly1305Sha256 => HashAlgorithm::Sha256,
            CipherSuite::TlsAes128CcmSha256 => HashAlgorithm::Sha256,
            CipherSuite::TlsAes128Ccm8Sha256 => HashAlgorithm::Sha256,
        }
    }
}

// Extract the PRK from input key material using HKDF-Extract
pub fn extract(
    hash_algorithm: HashAlgorithm,
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Result<Vec<u8>> {
    // Select the appropriate HMAC algorithm based on the hash algorithm
    let hmac_alg = match hash_algorithm {
        HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
    };
    
    // Use the salt or zero key as described in RFC 5869
    let salt_bytes = salt.unwrap_or(&[]);
    let key = hmac::Key::new(hmac_alg, salt_bytes);
    
    // Compute HMAC(salt, ikm) which is the extract operation
    let tag = hmac::sign(&key, ikm);
    
    Ok(tag.as_ref().to_vec())
}

// Expand derived key using HKDF-Expand
pub fn expand(
    hash_algorithm: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    let hmac_alg = match hash_algorithm {
        HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
    };
    
    // Create key from PRK
    let key = hmac::Key::new(hmac_alg, prk);
    
    // Manual implementation of HKDF-Expand
    let hash_len = hash_algorithm.output_size();
    // Calculate ceiling division (equivalent to div_ceil in newer Rust versions)
    let n = if output_len % hash_len == 0 {
        output_len / hash_len
    } else {
        output_len / hash_len + 1
    };
    
    if n > 255 {
        return Err(Error::CryptoError("HKDF output length too large".to_string()));
    }
    
    let mut output = Vec::with_capacity(n * hash_len);
    let mut t = Vec::new();
    
    for i in 1..=n {
        let mut context = Vec::with_capacity(t.len() + info.len() + 1);
        context.extend_from_slice(&t);
        context.extend_from_slice(info);
        context.push(i as u8);
        
        t = hmac::sign(&key, &context).as_ref().to_vec();
        output.extend_from_slice(&t);
    }
    
    output.truncate(output_len);
    Ok(output)
}

// TLS 1.3 Key Schedule Implementation

// Labels for different key derivation steps
const LABEL_DERIVED: &[u8] = b"derived";
const LABEL_C_HS_TRAFFIC: &[u8] = b"c hs traffic";
const LABEL_S_HS_TRAFFIC: &[u8] = b"s hs traffic";
const LABEL_C_AP_TRAFFIC: &[u8] = b"c ap traffic";
const LABEL_S_AP_TRAFFIC: &[u8] = b"s ap traffic";
const LABEL_KEY: &[u8] = b"key";
const LABEL_IV: &[u8] = b"iv";

// Additional labels not used yet but included for completeness
#[allow(dead_code)]
mod labels {
    pub const LABEL_EXT_BINDER: &[u8] = b"ext binder";
    pub const LABEL_RES_BINDER: &[u8] = b"res binder";
    pub const LABEL_C_E_TRAFFIC: &[u8] = b"c e traffic";
    pub const LABEL_E_EXP_MASTER: &[u8] = b"e exp master";
    pub const LABEL_EXP_MASTER: &[u8] = b"exp master";
    pub const LABEL_RES_MASTER: &[u8] = b"res master";
    pub const LABEL_FINISHED: &[u8] = b"finished";
}

// Empty hash values
const EMPTY_HASH_SHA256: [u8; 32] = [
    0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
    0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55,
];

const EMPTY_HASH_SHA384: [u8; 48] = [
    0x38, 0xB0, 0x60, 0xA7, 0x51, 0xAC, 0x96, 0x38, 0x4C, 0xD9, 0x32, 0x7E, 0xB1, 0xB1, 0xE3, 0x6A,
    0x21, 0xFD, 0xB7, 0x11, 0x14, 0xBE, 0x07, 0x43, 0x4C, 0x0C, 0xC7, 0xBF, 0x63, 0xF6, 0xE1, 0xDA,
    0x27, 0x4E, 0xDE, 0xBF, 0xE7, 0x6F, 0x65, 0xFB, 0xD5, 0x1A, 0xD2, 0xF1, 0x48, 0x98, 0xB9, 0x5B,
];

pub struct HkdfLabel {
    pub length: u16,
    pub label: Vec<u8>,
    pub context: Vec<u8>,
}

impl HkdfLabel {
    pub fn new(length: u16, label: &[u8], context: &[u8]) -> Self {
        Self {
            length,
            label: label.to_vec(),
            context: context.to_vec(),
        }
    }
    
    pub fn encode(&self) -> Vec<u8> {
        let tls13_label = [b"tls13 ", self.label.as_slice()].concat();
        
        let mut result = Vec::new();
        result.extend_from_slice(&self.length.to_be_bytes());
        result.push(tls13_label.len() as u8);
        result.extend_from_slice(&tls13_label);
        result.push(self.context.len() as u8);
        result.extend_from_slice(&self.context);
        result
    }
}

// Derive-Secret function used in TLS 1.3 key schedule
pub fn derive_secret(
    hash_algorithm: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let length = hash_algorithm.output_size() as u16;
    let hkdf_label = HkdfLabel::new(length, label, transcript_hash).encode();
    
    expand(hash_algorithm, secret, &hkdf_label, length as usize)
}

// Get the early secret
pub fn extract_early_secret(
    hash_algorithm: HashAlgorithm,
    psk: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let psk_or_zero = psk.unwrap_or(match hash_algorithm {
        HashAlgorithm::Sha256 => &[0u8; 32],
        HashAlgorithm::Sha384 => &[0u8; 48],
    });
    
    extract(hash_algorithm, None, psk_or_zero)
}

// Derive the handshake secret from early secret and shared key
pub fn derive_handshake_secret(
    hash_algorithm: HashAlgorithm,
    early_secret: &[u8],
    shared_key: &[u8],
) -> Result<Vec<u8>> {
    // First derive the "derived" secret
    let empty_hash = match hash_algorithm {
        HashAlgorithm::Sha256 => &EMPTY_HASH_SHA256[..],
        HashAlgorithm::Sha384 => &EMPTY_HASH_SHA384[..],
    };
    
    let derived = derive_secret(hash_algorithm, early_secret, LABEL_DERIVED, empty_hash)?;
    
    // Then extract with the shared key
    extract(hash_algorithm, Some(&derived), shared_key)
}

// Derive the main secrets from the handshake secret
pub fn derive_traffic_secrets(
    hash_algorithm: HashAlgorithm,
    handshake_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let client_traffic_secret = derive_secret(
        hash_algorithm,
        handshake_secret,
        LABEL_C_HS_TRAFFIC,
        transcript_hash,
    )?;
    
    let server_traffic_secret = derive_secret(
        hash_algorithm,
        handshake_secret,
        LABEL_S_HS_TRAFFIC,
        transcript_hash,
    )?;
    
    Ok((client_traffic_secret, server_traffic_secret))
}

// Derive application traffic secrets
pub fn derive_application_secrets(
    hash_algorithm: HashAlgorithm,
    master_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let client_traffic_secret = derive_secret(
        hash_algorithm,
        master_secret,
        LABEL_C_AP_TRAFFIC,
        transcript_hash,
    )?;
    
    let server_traffic_secret = derive_secret(
        hash_algorithm,
        master_secret,
        LABEL_S_AP_TRAFFIC,
        transcript_hash,
    )?;
    
    Ok((client_traffic_secret, server_traffic_secret))
}

// Derive the master secret from handshake secret
pub fn derive_master_secret(
    hash_algorithm: HashAlgorithm,
    handshake_secret: &[u8],
) -> Result<Vec<u8>> {
    let empty_hash = match hash_algorithm {
        HashAlgorithm::Sha256 => &EMPTY_HASH_SHA256[..],
        HashAlgorithm::Sha384 => &EMPTY_HASH_SHA384[..],
    };
    
    let derived = derive_secret(hash_algorithm, handshake_secret, LABEL_DERIVED, empty_hash)?;
    
    // Extract with a zeroed key
    let zeroed_key = vec![0u8; hash_algorithm.output_size()];
    extract(hash_algorithm, Some(&derived), &zeroed_key)
}

// Derive traffic keys from a traffic secret
pub fn derive_traffic_keys(
    hash_algorithm: HashAlgorithm,
    traffic_secret: &[u8],
    key_size: usize,
    iv_size: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let key_label = HkdfLabel::new(key_size as u16, LABEL_KEY, &[]).encode();
    let iv_label = HkdfLabel::new(iv_size as u16, LABEL_IV, &[]).encode();
    
    let key = expand(hash_algorithm, traffic_secret, &key_label, key_size)?;
    let iv = expand(hash_algorithm, traffic_secret, &iv_label, iv_size)?;
    
    Ok((key, iv))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_extract_expand() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";
        
        let prk = extract(HashAlgorithm::Sha256, Some(salt), ikm).unwrap();
        assert_eq!(prk.len(), 32);
        
        let output = expand(HashAlgorithm::Sha256, &prk, info, 32).unwrap();
        assert_eq!(output.len(), 32);
    }
    
    #[test]
    fn test_hkdf_label_encoding() {
        let label = HkdfLabel::new(32, b"key", b"context");
        let encoded = label.encode();
        
        assert_eq!(encoded[0], 0);  // Length high byte
        assert_eq!(encoded[1], 32); // Length low byte
        assert_eq!(encoded[2], 9);  // Label length ("tls13 key")
        assert_eq!(&encoded[3..12], b"tls13 key"); // Label
        assert_eq!(encoded[12], 7);  // Context length
        assert_eq!(&encoded[13..20], b"context"); // Context
    }
    
    #[test]
    fn test_derive_secrets() {
        let early_secret = extract_early_secret(HashAlgorithm::Sha256, None).unwrap();
        assert_eq!(early_secret.len(), 32);
        
        let shared_key = vec![0u8; 32];
        let handshake_secret = derive_handshake_secret(
            HashAlgorithm::Sha256, 
            &early_secret, 
            &shared_key
        ).unwrap();
        assert_eq!(handshake_secret.len(), 32);
        
        let transcript_hash = &EMPTY_HASH_SHA256[..];
        let (client_hs, server_hs) = derive_traffic_secrets(
            HashAlgorithm::Sha256,
            &handshake_secret, 
            transcript_hash
        ).unwrap();
        
        assert_eq!(client_hs.len(), 32);
        assert_eq!(server_hs.len(), 32);
        
        let master_secret = derive_master_secret(
            HashAlgorithm::Sha256, 
            &handshake_secret
        ).unwrap();
        assert_eq!(master_secret.len(), 32);
        
        let (client_app, server_app) = derive_application_secrets(
            HashAlgorithm::Sha256,
            &master_secret, 
            transcript_hash
        ).unwrap();
        
        assert_eq!(client_app.len(), 32);
        assert_eq!(server_app.len(), 32);
        
        let (key, iv) = derive_traffic_keys(
            HashAlgorithm::Sha256,
            &client_hs,
            16, // AES-128 key size
            12  // GCM nonce size
        ).unwrap();
        
        assert_eq!(key.len(), 16);
        assert_eq!(iv.len(), 12);
    }
}