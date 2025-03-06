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