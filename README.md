# TLS 1.3 Verifier

A Rust library for verifying TLS 1.3 handshakes and certificates.

## Overview

The TLS 1.3 Verifier is a specialized Rust library designed to verify TLS 1.3 handshake messages and validate X.509 certificates. It provides functionality to:

- Parse and validate TLS 1.3 handshake messages
- Process X.509 certificates and certificate chains
- Perform cryptographic operations required for TLS 1.3
- Validate server certificates against trust anchors
- Verify transcript hash for handshake message integrity

## Features

- **TLS 1.3 Record Layer Processing**
  - Parsing and serializing TLS record structures
  - Support for different content types
  - Handling of multiple records

- **Handshake Message Handling**
  - ClientHello, ServerHello
  - EncryptedExtensions, Certificate
  - CertificateVerify, Finished
  - Full transcript hash verification

- **X.509 Certificate Processing**
  - Certificate parsing and validation
  - Certificate chain verification
  - Hostname validation
  - Trust anchor management

- **Cryptographic Operations**
  - Key exchange (X25519)
  - HKDF-based key derivation
  - Signature verification
  - Transcript hash computation

## Command-Line Tools

The library includes several example command-line tools to demonstrate its capabilities:

- **verify_tls13_handshake**: Verifies a complete TLS 1.3 handshake from a capture file
- **certificate_verification**: Verifies X.509 certificates against a trust anchor
- **tls_verifier_cli**: A comprehensive CLI with multiple verification modes

## Usage Examples

### Using the High-Level API

```rust
use tls13_verifier::{TlsHandshakeVerifier, TlsVerifierParams, Result};

// Set up verifier with parameters
let params = TlsVerifierParams {
    server_name: Some("example.com".to_string()),
    trusted_certs_path: Some("/path/to/ca.pem".to_string()),
    allow_self_signed: false,
};

let mut verifier = TlsHandshakeVerifier::new(params)?;

// Process TLS records from a capture
let tls_data = std::fs::read("captured_handshake.bin")?;
verifier.process_tls_record(&tls_data)?;

// Check verification results
if verifier.is_handshake_complete() {
    println!("TLS 1.3 handshake verified successfully!");
    
    // Get negotiated parameters
    if let Some(cipher_suite) = verifier.get_negotiated_cipher_suite() {
        println!("Negotiated cipher suite: {:?}", cipher_suite);
    }
}
```

### Verifying a Certificate Chain

```rust
use tls13_verifier::certificate::{Certificate, CertificateVerifier, ValidationStatus};
use std::path::Path;

// Create a certificate verifier with a trust anchor
let mut verifier = CertificateVerifier::new();
verifier = verifier.with_root_cert_pem_file(Path::new("/path/to/ca.pem"))?;

// Load and parse certificates
let cert_data = std::fs::read("/path/to/server.pem")?;
let mut certs = Certificate::from_pem(&cert_data)?;
for cert in &mut certs {
    cert.parse()?;
}

// Verify the certificate chain with hostname validation
let result = verifier.verify_server_certificate(&certs, Some("example.com"))?;

match result {
    ValidationStatus::Valid => println!("Certificate is valid!"),
    status => println!("Certificate validation failed: {:?}", status),
}
```

### Using the State Machine Directly

```rust
use tls13_verifier::state::HandshakeState;
use tls13_verifier::certificate::CertificateVerifier;
use tls13_verifier::handshake::HandshakeMessage;

// Set up a handshake state with certificate verification
let verifier = CertificateVerifier::new().with_root_cert_pem_file(
    Path::new("/path/to/ca.pem")
)?;

let mut state = HandshakeState::new_client_with_certificate_verifier(
    verifier,
    Some("example.com".to_string())
);

// Process handshake messages (this maintains the transcript hash internally)
state.process_message(server_hello)?;
state.process_message(encrypted_extensions)?;
state.process_message(certificate)?;
state.process_message(certificate_verify)?;
state.process_message(finished)?;

// Check if handshake is complete with correct cipher suite
if state.is_handshake_complete() {
    println!("Handshake verified successfully!");
    println!("Negotiated cipher suite: {:?}", state.get_selected_cipher_suite());
}
```

## Building and Testing

```bash
# Build the library
cargo build

# Run tests
cargo test

# Try the examples
cargo run --example verify_tls13_handshake -- /path/to/ca.pem /path/to/capture.bin example.com
cargo run --example certificate_verification -- /path/to/ca.pem /path/to/server.pem example.com
```

## Status

This library is under active development and is not yet production-ready. It is intended for educational purposes and security research.

## License

TBD
