use crate::error::{Error, Result};
use crate::handshake::CipherSuite;
use ring::aead;

pub struct AeadAlgorithm {
    algorithm: &'static aead::Algorithm,
    key_len: usize,
    nonce_len: usize,
    tag_len: usize,
}

impl AeadAlgorithm {
    pub fn from_cipher_suite(cipher_suite: CipherSuite) -> Result<Self> {
        match cipher_suite {
            CipherSuite::TlsAes128GcmSha256 => Ok(Self {
                algorithm: &aead::AES_128_GCM,
                key_len: 16,
                nonce_len: 12,
                tag_len: 16,
            }),
            CipherSuite::TlsAes256GcmSha384 => Ok(Self {
                algorithm: &aead::AES_256_GCM,
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            CipherSuite::TlsChacha20Poly1305Sha256 => Ok(Self {
                algorithm: &aead::CHACHA20_POLY1305,
                key_len: 32,
                nonce_len: 12,
                tag_len: 16,
            }),
            _ => Err(Error::CryptoError(format!(
                "Cipher suite {:?} not supported for AEAD",
                cipher_suite
            ))),
        }
    }

    pub fn key_len(&self) -> usize {
        self.key_len
    }

    pub fn nonce_len(&self) -> usize {
        self.nonce_len
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }
}

pub struct AeadKey {
    key: aead::LessSafeKey,
}

impl AeadKey {
    pub fn new(algorithm: &AeadAlgorithm, key_material: &[u8]) -> Result<Self> {
        if key_material.len() != algorithm.key_len {
            return Err(Error::CryptoError(format!(
                "Invalid key length {}, expected {}",
                key_material.len(),
                algorithm.key_len
            )));
        }

        let unbound_key = aead::UnboundKey::new(algorithm.algorithm, key_material)
            .map_err(|_| Error::CryptoError("Failed to create AEAD key".to_string()))?;

        Ok(Self {
            key: aead::LessSafeKey::new(unbound_key),
        })
    }
    
    pub fn from_traffic_secret(
        algorithm: &AeadAlgorithm,
        hash_algorithm: crate::crypto::hkdf::HashAlgorithm,
        traffic_secret: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let (key, iv) = crate::crypto::hkdf::derive_traffic_keys(
            hash_algorithm,
            traffic_secret,
            algorithm.key_len,
            algorithm.nonce_len,
        )?;
        
        let aead_key = Self::new(algorithm, &key)?;
        Ok((aead_key, iv))
    }

    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::CryptoError("Invalid nonce".to_string()))?;

        let mut in_out = plaintext.to_vec();
        let tag = self.key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| Error::CryptoError("AEAD encryption failed".to_string()))?;

        in_out.extend_from_slice(tag.as_ref());
        Ok(in_out)
    }

    pub fn open(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| Error::CryptoError("Invalid nonce".to_string()))?;

        let mut in_out = ciphertext.to_vec();
        let plaintext_len = self.key
            .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| Error::CryptoError("AEAD decryption failed".to_string()))?
            .len();

        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

pub struct RecordProtection {
    aead_key: AeadKey,
    iv: Vec<u8>,
    sequence_number: u64,
}

impl RecordProtection {
    pub fn new(aead_key: AeadKey, iv: Vec<u8>) -> Self {
        Self {
            aead_key,
            iv,
            sequence_number: 0,
        }
    }
    
    pub fn from_traffic_secret(
        algorithm: &AeadAlgorithm,
        hash_algorithm: crate::crypto::hkdf::HashAlgorithm,
        traffic_secret: &[u8],
    ) -> Result<Self> {
        let (aead_key, iv) = AeadKey::from_traffic_secret(algorithm, hash_algorithm, traffic_secret)?;
        Ok(Self::new(aead_key, iv))
    }
    
    fn compute_nonce(&self) -> Vec<u8> {
        let mut nonce = self.iv.clone();
        
        // XOR the sequence number with the end of the IV
        // as described in RFC 8446 Section 5.3
        let seq_bytes = self.sequence_number.to_be_bytes();
        let offset = nonce.len() - seq_bytes.len();
        
        for (i, byte) in seq_bytes.iter().enumerate() {
            nonce[offset + i] ^= byte;
        }
        
        nonce
    }
    
    pub fn encrypt_record(&mut self, record_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.compute_nonce();
        
        // In TLS 1.3, the additional authenticated data (AAD) is the TLS record header
        // We'll use a placeholder header since the actual header depends on the record layer
        let aad = [
            0x17, // content type: application_data
            0x03, 0x03, // protocol version: TLS 1.2 (for middlebox compatibility)
            0x00, 0x00, // placeholder length, will be filled in by the record layer
        ];
        
        // Create a plaintext that includes the real record type
        let mut plaintext = payload.to_vec();
        plaintext.push(record_type); // Append the actual record type
        
        let ciphertext = self.aead_key.seal(&nonce, &aad, &plaintext)?;
        
        // Increment the sequence number for the next record
        self.sequence_number += 1;
        
        Ok(ciphertext)
    }
    
    pub fn decrypt_record(&mut self, header: &[u8], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        let nonce = self.compute_nonce();
        
        // The AAD is the record header
        let plaintext = self.aead_key.open(&nonce, header, ciphertext)?;
        
        // The last byte of the plaintext is the actual record type
        if plaintext.is_empty() {
            return Err(Error::CryptoError("Empty plaintext after decryption".to_string()));
        }
        
        let record_type = plaintext[plaintext.len() - 1];
        let payload = plaintext[..plaintext.len() - 1].to_vec();
        
        // Increment the sequence number for the next record
        self.sequence_number += 1;
        
        Ok((record_type, payload))
    }
    
    pub fn get_sequence_number(&self) -> u64 {
        self.sequence_number
    }
    
    pub fn reset_sequence_number(&mut self) {
        self.sequence_number = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hkdf::HashAlgorithm;
    
    #[test]
    fn test_aead_algorithm() {
        let alg = AeadAlgorithm::from_cipher_suite(CipherSuite::TlsAes128GcmSha256).unwrap();
        assert_eq!(alg.key_len(), 16);
        assert_eq!(alg.nonce_len(), 12);
        assert_eq!(alg.tag_len(), 16);
        
        let alg = AeadAlgorithm::from_cipher_suite(CipherSuite::TlsAes256GcmSha384).unwrap();
        assert_eq!(alg.key_len(), 32);
        
        let alg = AeadAlgorithm::from_cipher_suite(CipherSuite::TlsChacha20Poly1305Sha256).unwrap();
        assert_eq!(alg.key_len(), 32);
    }
    
    #[test]
    fn test_aead_encryption_decryption() {
        let alg = AeadAlgorithm::from_cipher_suite(CipherSuite::TlsAes128GcmSha256).unwrap();
        
        // Create a random key
        let key = vec![0x42; alg.key_len()];
        let aead_key = AeadKey::new(&alg, &key).unwrap();
        
        // Create a nonce
        let nonce = vec![0x01; alg.nonce_len()];
        
        // Encrypt some data
        let plaintext = b"Hello, AEAD!";
        let aad = b"additional data";
        let ciphertext = aead_key.seal(&nonce, aad, plaintext).unwrap();
        
        // The ciphertext should be longer than plaintext due to the authentication tag
        assert!(ciphertext.len() > plaintext.len());
        assert_eq!(ciphertext.len(), plaintext.len() + alg.tag_len());
        
        // Decrypt the data
        let decrypted = aead_key.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_record_protection() {
        let algorithm = AeadAlgorithm::from_cipher_suite(CipherSuite::TlsAes128GcmSha256).unwrap();
        let hash_algorithm = HashAlgorithm::Sha256;
        
        // Create a fake traffic secret
        let traffic_secret = vec![0x42; 32];
        
        // Create record protection
        let mut record_protection = RecordProtection::from_traffic_secret(
            &algorithm,
            hash_algorithm,
            &traffic_secret
        ).unwrap();
        
        // Check sequence number
        assert_eq!(record_protection.get_sequence_number(), 0);
        
        // Encrypt a record
        let record_type = 0x17; // application_data
        let payload = b"Hello, protected record!";
        let encrypted = record_protection.encrypt_record(record_type, payload).unwrap();
        
        // Sequence number should have incremented
        assert_eq!(record_protection.get_sequence_number(), 1);
        
        // Resetting sequence number to 0 for decryption
        record_protection.reset_sequence_number();
        
        // Header for decryption
        let header = [0x17, 0x03, 0x03, 0x00, 0x00];
        
        // Decrypt the record
        let (decrypted_type, decrypted_payload) = record_protection.decrypt_record(&header, &encrypted).unwrap();
        
        assert_eq!(decrypted_type, record_type);
        assert_eq!(decrypted_payload, payload);
        assert_eq!(record_protection.get_sequence_number(), 1);
    }
}