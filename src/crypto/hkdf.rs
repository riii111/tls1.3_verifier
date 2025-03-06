// HKDF key derivation functions for TLS 1.3
use crate::error::{Error, Result};
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