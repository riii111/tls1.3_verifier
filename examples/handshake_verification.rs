use std::env;
use std::path::Path;
use tls13_verifier::certificate::CertificateVerifier;
use tls13_verifier::state::HandshakeState;
use tls13_verifier::handshake::{
    ServerHello, EncryptedExtensions, Certificate as HandshakeCertificate,
    CertificateVerify, Finished, CipherSuite,
};
use tls13_verifier::handshake::extensions::{Extension, ExtensionType};
use tls13_verifier::handshake::certificate::CertificateEntry;
use tls13_verifier::error::Result;

fn main() -> Result<()> {
    // Get the CA certificate file path from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <ca_cert_path> [hostname]", args[0]);
        println!("Example: {} /path/to/ca.pem example.com", args[0]);
        return Ok(());
    }

    let ca_cert_path = &args[1];
    let hostname = args.get(2).map(|s| s.to_string());

    println!("Setting up TLS 1.3 handshake verifier...");
    
    // Create a certificate verifier with the root CA certificate
    let mut cert_verifier = CertificateVerifier::new();
    println!("Loading CA certificate from {}", ca_cert_path);
    cert_verifier = cert_verifier.with_root_cert_pem_file(Path::new(ca_cert_path))?;

    // Create a handshake state with the certificate verifier
    let mut handshake_state = HandshakeState::new_client_with_certificate_verifier(
        cert_verifier,
        hostname,
    );

    println!("Initial state: {:?}", handshake_state.get_state());
    
    // In a real implementation, we would extract these from network packets
    // For this example, we'll create mock handshake messages
    
    // Mock ServerHello
    let server_hello = create_mock_server_hello();
    println!("Processing ServerHello...");
    handshake_state.process_message(Box::new(server_hello))?;
    println!("State after ServerHello: {:?}", handshake_state.get_state());
    
    // Mock EncryptedExtensions
    let encrypted_extensions = create_mock_encrypted_extensions();
    println!("Processing EncryptedExtensions...");
    handshake_state.process_message(Box::new(encrypted_extensions))?;
    
    // Mock Certificate
    let certificate = create_mock_certificate();
    println!("Processing Certificate...");
    handshake_state.process_message(Box::new(certificate))?;
    
    // Mock CertificateVerify
    let _certificate_verify = create_mock_certificate_verify();
    println!("Processing CertificateVerify...");
    // Note: In a real implementation, this would fail without real certificates
    // For the example, we just skip this step
    // handshake_state.process_message(Box::new(certificate_verify))?;
    println!("Skipping CertificateVerify (would need real certificates)");
    
    // Mock Finished
    let finished = create_mock_finished();
    println!("Processing Finished...");
    handshake_state.process_message(Box::new(finished))?;
    
    println!("Final state: {:?}", handshake_state.get_state());
    
    if handshake_state.is_handshake_complete() {
        println!("Handshake verification completed successfully!");
    } else {
        println!("Handshake verification incomplete.");
    }

    println!("Selected cipher suite: {:?}", handshake_state.get_selected_cipher_suite());

    Ok(())
}

// Helper functions to create mock handshake messages

fn create_mock_server_hello() -> ServerHello {
    let random = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    
    let supported_versions_ext = Extension::new(
        ExtensionType::SupportedVersions,
        vec![0x03, 0x04], // TLS 1.3
    );
    
    let key_share_ext = Extension::new(
        ExtensionType::KeyShare,
        vec![
            0x00, 0x1d, // X25519
            0x00, 0x20, // Key length (32 bytes)
            // Public key bytes (just mock data)
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ],
    );
    
    ServerHello::new(
        0x0303, // Legacy version: TLS 1.2
        random,
        vec![], // Empty session ID echo
        CipherSuite::TlsAes128GcmSha256,
        0x00, // Null compression
        vec![supported_versions_ext, key_share_ext],
    )
}

fn create_mock_encrypted_extensions() -> EncryptedExtensions {
    EncryptedExtensions::new(vec![])
}

fn create_mock_certificate() -> HandshakeCertificate {
    // In a real implementation, this would be a proper X.509 certificate
    let cert_entry = CertificateEntry::new(
        vec![0x01, 0x02, 0x03, 0x04], // Mock certificate data
        vec![],                        // No extensions
    );
    
    HandshakeCertificate::new(
        vec![], // No certificate request context
        vec![cert_entry],
    )
}

fn create_mock_certificate_verify() -> CertificateVerify {
    use tls13_verifier::crypto::signature::SignatureScheme;
    
    CertificateVerify::new(
        SignatureScheme::RsaPssRsaeSha256,
        vec![0x01, 0x02, 0x03, 0x04], // Mock signature
    )
}

fn create_mock_finished() -> Finished {
    Finished::new(vec![0x01, 0x02, 0x03, 0x04]) // Mock verify data
}