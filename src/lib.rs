pub mod record;
pub mod handshake;
pub mod crypto;
pub mod certificate;
pub mod state;
pub mod error;
pub mod utils;
pub mod tls;
pub mod alert;
pub mod session;

pub use error::{Error, Result};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn init_logging() {
    let _ = env_logger::builder().try_init();
}

pub struct TlsVerifierParams {
    pub server_name: Option<String>,
    pub trusted_certs_path: Option<String>,
    pub allow_self_signed: bool,
}

impl Default for TlsVerifierParams {
    fn default() -> Self {
        Self {
            server_name: None,
            trusted_certs_path: None,
            allow_self_signed: false,
        }
    }
}

pub struct TlsHandshakeVerifier {
    handshake_state: state::HandshakeState,
    record_layer: record::RecordLayer,
}

impl TlsHandshakeVerifier {
    pub fn new(params: TlsVerifierParams) -> Result<Self> {
        // Set up certificate verification if trusted certs are provided
        let handshake_state = if let Some(cert_path) = params.trusted_certs_path {
            let mut cert_verifier = certificate::CertificateVerifier::new();
            
            // Load trusted certificates
            cert_verifier = cert_verifier.with_root_cert_pem_file(std::path::Path::new(&cert_path))?;
            
            // Set validation options if needed
            if params.allow_self_signed {
                let mut options = certificate::ValidationOptions::default();
                options.allow_self_signed = true;
                cert_verifier = cert_verifier.with_validation_options(options);
            }
            
            state::HandshakeState::new_client_with_certificate_verifier(
                cert_verifier,
                params.server_name,
            )
        } else {
            state::HandshakeState::new_client()
        };
        
        Ok(Self {
            handshake_state,
            record_layer: record::RecordLayer::new(),
        })
    }
    
    pub fn process_tls_record(&mut self, data: &[u8]) -> Result<()> {
        // Process the TLS record
        let records = self.record_layer.process_records(data)?;
        
        // Process each record
        for record in records {
            match record.content_type {
                record::ContentType::Handshake => {
                    self.process_handshake_data(&record.fragment)?;
                }
                record::ContentType::Alert => {
                    log::warn!("Received alert: {:?}", record.fragment);
                }
                _ => {
                    log::debug!("Ignoring non-handshake record: {:?}", record.content_type);
                }
            }
        }
        
        Ok(())
    }
    
    fn process_handshake_data(&mut self, data: &[u8]) -> Result<()> {
        // Parse handshake messages from data
        let handshake_layer = handshake::HandshakeLayer::new();
        let mut pos = 0;
        
        while pos < data.len() {
            let (message, consumed) = handshake_layer.parse_handshake_message(&data[pos..])?;
            pos += consumed;
            
            // Process the handshake message
            self.handshake_state.process_message(message)?;
        }
        
        Ok(())
    }
    
    pub fn verify_certificate(&self, cert_data: &[u8], hostname: Option<&str>) -> Result<certificate::ValidationStatus> {
        // Parse the certificate
        let cert_vec = certificate::Certificate::from_pem(cert_data)?;
        if cert_vec.is_empty() {
            return Err(Error::CertificateError("No certificates found in PEM data".to_string()));
        }
        
        // Build a certificate verifier
        let server_name = hostname.or_else(|| {
            self.handshake_state.get_server_name()
        });
        
        // We need to get the certificate verifier from the handshake state
        let cert_verifier = self.handshake_state.get_certificate_verifier()
            .ok_or_else(|| Error::NotImplemented("Certificate verification not initialized".to_string()))?;
        
        // Verify the certificate
        cert_verifier.verify_server_certificate(&cert_vec, server_name)
    }
    
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_state.is_handshake_complete()
    }
    
    pub fn get_negotiated_cipher_suite(&self) -> Option<handshake::CipherSuite> {
        self.handshake_state.get_selected_cipher_suite()
    }
    
    pub fn get_handshake_state(&self) -> state::ConnectionState {
        self.handshake_state.get_state()
    }
}

impl Default for TlsHandshakeVerifier {
    fn default() -> Self {
        Self::new(TlsVerifierParams::default()).unwrap()
    }
}
