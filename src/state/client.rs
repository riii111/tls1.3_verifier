use crate::error::{Error, Result};
use crate::handshake::{CipherSuite, HandshakeMessage, HandshakeType};
use crate::handshake::server_hello::ServerHello;
use crate::certificate::{Certificate, CertificateVerifier, ValidationStatus};
use crate::handshake::certificate_verify::CertificateVerify;
use crate::handshake::certificate::Certificate as HandshakeCertificate;
use crate::handshake::finished::Finished;
use crate::crypto::TranscriptHash;
use crate::crypto::signature::SignatureScheme;
use super::{StateHandler, ConnectionState};

pub struct ClientState {
    state: ConnectionState,
    selected_cipher_suite: Option<CipherSuite>,
    server_certificates: Vec<Certificate>,
    server_name: Option<String>,
    cert_verifier: Option<CertificateVerifier>,
    transcript_hash: TranscriptHash,  // Store the running hash of handshake messages
    server_signature_scheme: Option<SignatureScheme>,
}

impl ClientState {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Initial,
            selected_cipher_suite: None,
            server_certificates: Vec::new(),
            server_name: None,
            cert_verifier: None,
            transcript_hash: TranscriptHash::new(),
            server_signature_scheme: None,
        }
    }
    
    pub fn with_certificate_verifier(mut self, verifier: CertificateVerifier) -> Self {
        self.cert_verifier = Some(verifier);
        self
    }
    
    pub fn with_server_name(mut self, server_name: String) -> Self {
        self.server_name = Some(server_name);
        self
    }
    
    // Update the transcript hash with a handshake message
    fn update_transcript_hash(&mut self, message: &dyn HandshakeMessage) -> Result<()> {
        self.transcript_hash.update(message)
    }
}

impl Default for ClientState {
    fn default() -> Self {
        Self::new()
    }
}

impl StateHandler for ClientState {
    fn process_message(&mut self, message: Box<dyn HandshakeMessage>) -> Result<()> {
        // Update the transcript hash with this handshake message
        self.update_transcript_hash(message.as_ref())?;
        
        match (self.state, message.message_type()) {
            (ConnectionState::Initial, HandshakeType::ServerHello) => {
                // Client received ServerHello, transition to Handshaking
                self.state = ConnectionState::Handshaking;
                
                // Extract the cipher suite and check that it's TLS 1.3
                if let Some(server_hello) = message.as_any().downcast_ref::<ServerHello>() {
                    // Store the selected cipher suite
                    self.selected_cipher_suite = Some(server_hello.cipher_suite);
                    
                    // Check for supported version extension to confirm TLS 1.3
                    let is_tls13 = server_hello.get_extension(crate::handshake::extensions::ExtensionType::SupportedVersions)
                        .map(|ext| {
                            // TLS 1.3 uses 0x0304 as the protocol version in the extension
                            ext.data.len() >= 2 && ext.data[0] == 0x03 && ext.data[1] == 0x04
                        })
                        .unwrap_or(false);
                    
                    if !is_tls13 {
                        return Err(Error::ProtocolError("Not a TLS 1.3 ServerHello".to_string()));
                    }
                    
                    log::debug!("Selected cipher suite: {:?}", server_hello.cipher_suite);
                } else {
                    return Err(Error::ProtocolError("Failed to cast to ServerHello".to_string()));
                }
                
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::EncryptedExtensions) => {
                // Process encrypted extensions
                // In a real implementation, we would extract relevant extensions here
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::Certificate) => {
                // Process the server certificate message
                // Convert from handshake::Certificate to certificate::Certificate
                let cert_msg = message.as_any().downcast_ref::<HandshakeCertificate>()
                    .ok_or_else(|| Error::ProtocolError("Failed to cast to Certificate".to_string()))?;
                
                // Clear any existing certificates
                self.server_certificates.clear();
                
                // Process each certificate in the chain
                for entry in &cert_msg.certificate_list {
                    let mut cert = Certificate::new(entry.cert_data.clone());
                    cert.parse()?;  // Parse the certificate now
                    self.server_certificates.push(cert);
                }
                
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::CertificateVerify) => {
                // Verify the certificate chain first if we have a verifier
                if let Some(verifier) = &self.cert_verifier {
                    if self.server_certificates.is_empty() {
                        return Err(Error::ProtocolError("No server certificates received".to_string()));
                    }
                    
                    let server_name = self.server_name.as_deref();
                    let status = verifier.verify_server_certificate(
                        &self.server_certificates, 
                        server_name
                    )?;
                    
                    if status != ValidationStatus::Valid {
                        return Err(Error::CertificateError(
                            format!("Certificate validation failed: {:?}", status)
                        ));
                    }
                }
                
                // Verify the CertificateVerify signature
                if let Some(cert_verify) = message.as_any().downcast_ref::<CertificateVerify>() {
                    if self.server_certificates.is_empty() {
                        return Err(Error::ProtocolError("No server certificates received".to_string()));
                    }
                    
                    // Get the leaf certificate (first in the chain)
                    let leaf_cert = &self.server_certificates[0];
                    let parsed = leaf_cert.parsed.as_ref().ok_or_else(|| {
                        Error::CertificateError("Certificate not parsed".to_string())
                    })?;
                    
                    // Store the signature scheme for later use
                    self.server_signature_scheme = Some(cert_verify.algorithm);
                    
                    // Get the current transcript hash
                    let transcript_hash = self.transcript_hash.get_current_hash();
                    
                    // Verify the signature using the leaf certificate's public key
                    cert_verify.verify(&transcript_hash, &parsed.public_key)?;
                }
                
                Ok(())
            },
            (ConnectionState::Handshaking, HandshakeType::Finished) => {
                // Verify the Finished message
                if let Some(finished) = message.as_any().downcast_ref::<Finished>() {
                    // Get the cipher suite
                    if self.selected_cipher_suite.is_none() {
                        return Err(Error::ProtocolError("No cipher suite selected".to_string()));
                    }
                    
                    // In a full implementation, we would:
                    // 1. Derive the server_handshake_traffic_secret using HKDF
                    // 2. Derive the server_finished_key from the traffic secret
                    // 3. Compute HMAC over the transcript hash using the finished key
                    // 4. Compare with the verify_data in the Finished message
                    
                    // For now, we just log the verify data for debugging
                    log::debug!("Server Finished verify_data: {:?}", finished.verify_data);
                    log::debug!("Transcript hash: {:?}", self.transcript_hash.get_current_hash());
                    
                    // Transition to Connected state
                    self.state = ConnectionState::Connected;
                } else {
                    return Err(Error::ProtocolError("Failed to cast to Finished".to_string()));
                }
                Ok(())
            },
            _ => Err(Error::ProtocolError(format!(
                "Unexpected message {:?} in state {:?}",
                message.message_type(),
                self.state
            ))),
        }
    }

    fn get_state(&self) -> ConnectionState {
        self.state
    }

    fn is_handshake_complete(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    fn get_selected_cipher_suite(&self) -> Option<CipherSuite> {
        self.selected_cipher_suite
    }
    
    fn get_server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
    
    fn get_certificate_verifier(&self) -> Option<&crate::certificate::CertificateVerifier> {
        self.cert_verifier.as_ref()
    }
}