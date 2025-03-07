use std::env;
use std::io::Read;
use tls13_verifier::{TlsHandshakeVerifier, TlsVerifierParams, Result, certificate};

fn main() -> Result<()> {
    // Initialize logging
    tls13_verifier::init_logging();
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("TLS 1.3 Verifier CLI");
        println!("===================\n");
        println!("Usage:");
        println!("  {} verify-handshake <ca_cert_path> <tls_traffic_file> [hostname]", args[0]);
        println!("  {} verify-cert <ca_cert_path> <cert_file> [hostname]", args[0]);
        println!("\nExamples:");
        println!("  {} verify-handshake /path/to/ca.pem /path/to/traffic.bin example.com", args[0]);
        println!("  {} verify-cert /path/to/ca.pem /path/to/server.pem example.com", args[0]);
        return Ok(());
    }
    
    match args[1].as_str() {
        "verify-handshake" => {
            if args.len() < 4 {
                println!("Usage: {} verify-handshake <ca_cert_path> <tls_traffic_file> [hostname]", args[0]);
                return Ok(());
            }
            
            let ca_cert_path = &args[2];
            let tls_traffic_file = &args[3];
            let hostname = args.get(4).cloned();
            
            verify_handshake(ca_cert_path, tls_traffic_file, hostname)?;
        },
        "verify-cert" => {
            if args.len() < 4 {
                println!("Usage: {} verify-cert <ca_cert_path> <cert_file> [hostname]", args[0]);
                return Ok(());
            }
            
            let ca_cert_path = &args[2];
            let cert_file = &args[3];
            let hostname = args.get(4).map(|s| s.as_str());
            
            verify_certificate(ca_cert_path, cert_file, hostname)?;
        },
        _ => {
            println!("Unknown command: {}", args[1]);
            println!("Use one of: verify-handshake, verify-cert");
        }
    }
    
    Ok(())
}

fn verify_handshake(ca_cert_path: &str, tls_traffic_file: &str, hostname: Option<String>) -> Result<()> {
    println!("TLS 1.3 Handshake Verification");
    println!("============================");
    println!("CA Certificates: {}", ca_cert_path);
    println!("TLS Traffic File: {}", tls_traffic_file);
    if let Some(host) = &hostname {
        println!("Hostname: {}", host);
    }
    println!();
    
    // Initialize the verifier
    let params = TlsVerifierParams {
        server_name: hostname,
        trusted_certs_path: Some(ca_cert_path.to_string()),
        allow_self_signed: false,
    };
    
    let mut verifier = TlsHandshakeVerifier::new(params)?;
    
    // Read the TLS traffic file
    let mut file = std::fs::File::open(tls_traffic_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    // Process the TLS records
    println!("Processing TLS records...");
    verifier.process_tls_record(&buffer)?;
    
    // Get results
    let handshake_state = verifier.get_handshake_state();
    let cipher_suite = verifier.get_negotiated_cipher_suite();
    
    println!("Handshake state: {:?}", handshake_state);
    if let Some(cs) = cipher_suite {
        println!("Negotiated cipher suite: {:?}", cs);
    } else {
        println!("No cipher suite negotiated yet");
    }
    
    if verifier.is_handshake_complete() {
        println!("\n✅ TLS 1.3 handshake completed successfully!");
    } else {
        println!("\n❌ TLS 1.3 handshake incomplete or failed");
    }
    
    Ok(())
}

fn verify_certificate(ca_cert_path: &str, cert_file: &str, hostname: Option<&str>) -> Result<()> {
    println!("TLS Certificate Verification");
    println!("==========================");
    println!("CA Certificates: {}", ca_cert_path);
    println!("Certificate File: {}", cert_file);
    if let Some(host) = hostname {
        println!("Hostname: {}", host);
    }
    println!();
    
    // Load the CA certificates
    println!("Loading CA certificates...");
    let ca_data = std::fs::read(ca_cert_path)?;
    let ca_certs = certificate::Certificate::from_pem(&ca_data)?;
    
    // Build a certificate verifier
    let mut cert_verifier = certificate::CertificateVerifier::new();
    for cert in ca_certs {
        cert_verifier = cert_verifier.with_root_cert(cert)?;
    }
    
    // Load the certificate to verify
    println!("Loading certificate to verify...");
    let cert_data = std::fs::read(cert_file)?;
    let certs = certificate::Certificate::from_pem(&cert_data)?;
    
    if certs.is_empty() {
        println!("No certificates found in the file");
        return Ok(());
    }
    
    // Parse the certificates
    println!("Parsing certificates...");
    let mut parsed_certs = Vec::new();
    for mut cert in certs {
        cert.parse()?;
        parsed_certs.push(cert);
    }
    
    // Print certificate information
    for (i, cert) in parsed_certs.iter().enumerate() {
        if let Some(parsed) = &cert.parsed {
            println!("Certificate {}: Subject: {}", i, parsed.subject);
            println!("Certificate {}: Issuer: {}", i, parsed.issuer);
            println!("Certificate {}: Valid from: {:?}", i, parsed.not_before);
            println!("Certificate {}: Valid until: {:?}", i, parsed.not_after);
            println!("Certificate {}: Is CA: {}", i, parsed.is_ca);
            
            if !parsed.subject_alt_names.is_empty() {
                println!("Certificate {}: Subject Alternative Names:", i);
                for san in &parsed.subject_alt_names {
                    println!("  - {}", san);
                }
            }
            println!();
        }
    }
    
    // Verify the certificate
    println!("Verifying certificate...");
    let status = cert_verifier.verify_server_certificate(&parsed_certs, hostname)?;
    
    match status {
        certificate::ValidationStatus::Valid => println!("\n✅ Certificate is valid!"),
        certificate::ValidationStatus::Expired => println!("\n❌ Certificate is expired!"),
        certificate::ValidationStatus::NotYetValid => println!("\n❌ Certificate is not yet valid!"),
        certificate::ValidationStatus::InvalidSignature => println!("\n❌ Certificate has an invalid signature!"),
        certificate::ValidationStatus::Revoked => println!("\n❌ Certificate is revoked!"),
        certificate::ValidationStatus::UnknownIssuer => println!("\n❌ Certificate has an unknown issuer!"),
        certificate::ValidationStatus::PathLengthExceeded => println!("\n❌ Certificate path length constraint exceeded!"),
        certificate::ValidationStatus::UnhandledCriticalExtension => println!("\n❌ Certificate has unhandled critical extensions!"),
        certificate::ValidationStatus::UnsupportedSignatureAlgorithm => println!("\n❌ Certificate uses an unsupported signature algorithm!"),
    }
    
    Ok(())
}