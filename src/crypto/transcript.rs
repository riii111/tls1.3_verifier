use crate::error::Result;
use crate::handshake::{HandshakeMessage, HandshakeType};
use crate::handshake::client_hello::ClientHello;
use crate::handshake::server_hello::ServerHello;
use ring::digest::{Context, SHA256, SHA384};
use std::fmt;

/// The transcript hash maintains the running hash of all handshake messages
/// This is critical for the TLS 1.3 authentication and key derivation
pub struct TranscriptHash {
    context: Context,
    algorithm: HashAlgorithm,
    messages: Vec<HandshakeMessageInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Sha384 => write!(f, "SHA-384"),
        }
    }
}

#[derive(Debug)]
struct HandshakeMessageInfo {
    message_type: HandshakeType,
    data: Vec<u8>,
}

impl TranscriptHash {
    /// Create a new transcript hash with SHA-256 as the default
    pub fn new() -> Self {
        Self::with_algorithm(HashAlgorithm::Sha256)
    }

    /// Create a new transcript hash with a specific algorithm
    pub fn with_algorithm(algorithm: HashAlgorithm) -> Self {
        let context = match algorithm {
            HashAlgorithm::Sha256 => Context::new(&SHA256),
            HashAlgorithm::Sha384 => Context::new(&SHA384),
        };

        Self {
            context,
            algorithm,
            messages: Vec::new(),
        }
    }

    /// Update the transcript hash with a handshake message
    pub fn update(&mut self, message: &dyn HandshakeMessage) -> Result<()> {
        // Serialize the message to get its wire format
        let serialized = message.serialize()?;
        
        // For ClientHello and ServerHello, check if we need to switch hash algorithms
        match message.message_type() {
            HandshakeType::ClientHello => {
                // If this is ClientHello, check if we need to use SHA-384 based on cipher suites
                if let Some(client_hello) = message.as_any().downcast_ref::<ClientHello>() {
                    for suite in &client_hello.cipher_suites {
                        if self.is_sha384_suite(*suite) {
                            // If a SHA-384 suite is offered and we're currently using SHA-256, switch
                            if self.algorithm == HashAlgorithm::Sha256 && self.messages.is_empty() {
                                // Only switch if this is the first message
                                return self.restart_with_algorithm(HashAlgorithm::Sha384, message);
                            }
                        }
                    }
                }
            },
            HandshakeType::ServerHello => {
                // If this is ServerHello, check if we need to use SHA-384 based on selected cipher suite
                if let Some(server_hello) = message.as_any().downcast_ref::<ServerHello>() {
                    if self.is_sha384_suite(server_hello.cipher_suite) {
                        // If a SHA-384 suite is selected and we're currently using SHA-256, switch
                        if self.algorithm == HashAlgorithm::Sha256 {
                            return self.restart_with_algorithm(HashAlgorithm::Sha384, message);
                        }
                    }
                }
            },
            _ => {}
        }

        // Store message info for transcript
        self.messages.push(HandshakeMessageInfo {
            message_type: message.message_type(),
            data: serialized.clone(),
        });

        // Prepend with TLS handshake header (1 byte type, 3 bytes length)
        let mut message_with_header = Vec::with_capacity(4 + serialized.len());
        message_with_header.push(message.message_type() as u8);
        message_with_header.extend_from_slice(&(serialized.len() as u32).to_be_bytes()[1..4]); // 3 bytes
        message_with_header.extend_from_slice(&serialized);

        // Update the hash context
        self.context.update(&message_with_header);

        Ok(())
    }

    /// Restart the hash with a different algorithm and replay all messages
    fn restart_with_algorithm(&mut self, algorithm: HashAlgorithm, current_message: &dyn HandshakeMessage) -> Result<()> {
        // Create a new context with the new algorithm
        let new_context = match algorithm {
            HashAlgorithm::Sha256 => Context::new(&SHA256),
            HashAlgorithm::Sha384 => Context::new(&SHA384),
        };

        // Store old messages
        let old_messages = std::mem::replace(&mut self.messages, Vec::new());

        // Update instance
        self.context = new_context;
        self.algorithm = algorithm;

        // Replay all previous messages with the new context
        for message_info in old_messages {
            // Prepend with TLS handshake header
            let mut message_with_header = Vec::with_capacity(4 + message_info.data.len());
            message_with_header.push(message_info.message_type as u8);
            message_with_header.extend_from_slice(&(message_info.data.len() as u32).to_be_bytes()[1..4]);
            message_with_header.extend_from_slice(&message_info.data);

            // Update the hash context
            self.context.update(&message_with_header);

            // Store the message info again
            self.messages.push(message_info);
        }

        // Now update with the current message (to avoid duplicate ServersHello)
        let serialized = current_message.serialize()?;
        
        // Store message info for transcript
        self.messages.push(HandshakeMessageInfo {
            message_type: current_message.message_type(),
            data: serialized.clone(),
        });

        // Prepend with TLS handshake header
        let mut message_with_header = Vec::with_capacity(4 + serialized.len());
        message_with_header.push(current_message.message_type() as u8);
        message_with_header.extend_from_slice(&(serialized.len() as u32).to_be_bytes()[1..4]);
        message_with_header.extend_from_slice(&serialized);

        // Update the hash context
        self.context.update(&message_with_header);

        Ok(())
    }

    /// Get the current transcript hash
    pub fn get_current_hash(&self) -> Vec<u8> {
        let digest = self.context.clone().finish();
        digest.as_ref().to_vec()
    }

    /// Get the algorithm used by this transcript hash
    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Check if a cipher suite uses SHA-384
    fn is_sha384_suite(&self, suite: crate::handshake::CipherSuite) -> bool {
        match suite {
            crate::handshake::CipherSuite::TlsAes256GcmSha384 => true,
            _ => false,
        }
    }

    /// Get stored messages for debugging
    pub fn get_messages(&self) -> Vec<HandshakeType> {
        self.messages.iter().map(|m| m.message_type).collect()
    }
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::CipherSuite;
    use crate::handshake::extensions::{Extension, ExtensionType};

    #[test]
    fn test_transcript_hash_sha256() {
        let mut transcript = TranscriptHash::new();
        assert_eq!(transcript.get_algorithm(), HashAlgorithm::Sha256);
        
        // Create a mock ClientHello message only with TLS_AES_128_GCM_SHA256
        let random = [0; 32];
        let client_hello = ClientHello::new(
            0x0303, // TLS 1.2 legacy version
            random,
            vec![], // Empty session ID
            vec![CipherSuite::TlsAes128GcmSha256], // SHA-256 cipher suite
            vec![0], // Compression methods
            vec![], // No extensions
        );
        
        // Update transcript with ClientHello
        transcript.update(&client_hello).unwrap();
        
        // Verify algorithm hasn't changed
        assert_eq!(transcript.get_algorithm(), HashAlgorithm::Sha256);
        
        // Verify messages are stored correctly
        assert_eq!(transcript.get_messages(), vec![HandshakeType::ClientHello]);
    }

    #[test]
    fn test_transcript_hash_sha384_switch() {
        let mut transcript = TranscriptHash::new();
        assert_eq!(transcript.get_algorithm(), HashAlgorithm::Sha256);
        
        // Create a mock ServerHello with TLS_AES_256_GCM_SHA384
        let random = [0; 32];
        let server_hello = ServerHello::new(
            0x0303, // TLS 1.2 legacy version
            random,
            vec![], // Empty session ID
            CipherSuite::TlsAes256GcmSha384, // SHA-384 cipher suite
            0, // Compression method
            vec![], // No extensions
        );
        
        // Update transcript with ServerHello
        transcript.update(&server_hello).unwrap();
        
        // Verify algorithm has switched to SHA-384
        assert_eq!(transcript.get_algorithm(), HashAlgorithm::Sha384);
        
        // Verify messages are stored correctly
        assert_eq!(transcript.get_messages(), vec![HandshakeType::ServerHello]);
    }
}