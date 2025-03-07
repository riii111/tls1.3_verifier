use std::env;
use std::path::Path;
use tls13_verifier::certificate::{Certificate, CertificateVerifier, ValidationStatus};
use tls13_verifier::error::Result;

fn main() -> Result<()> {
    // Get the certificate file path from command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <ca_cert_path> <server_cert_path> [hostname]", args[0]);
        println!("Example: {} /path/to/ca.pem /path/to/server.pem example.com", args[0]);
        return Ok(());
    }

    let ca_cert_path = &args[1];
    let server_cert_path = &args[2];
    let hostname = args.get(3).map(|s| s.as_str());

    println!("Setting up certificate verifier...");
    
    // Create a certificate verifier with the root CA certificate
    let mut verifier = CertificateVerifier::new();
    
    // Load the CA certificate(s)
    println!("Loading CA certificate from {}", ca_cert_path);
    verifier = verifier.with_root_cert_pem_file(Path::new(ca_cert_path))?;

    // Load the server certificate(s)
    println!("Loading server certificate from {}", server_cert_path);
    let server_certs = Certificate::from_pem_file(Path::new(server_cert_path))?;
    
    // Parse all certificates
    let mut parsed_certs = Vec::new();
    for mut cert in server_certs {
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
    println!("Verifying certificate chain...");
    
    let status = if let Some(name) = hostname {
        println!("Verifying hostname: {}", name);
        verifier.verify_server_certificate(&parsed_certs, Some(name))?
    } else {
        verifier.verify_chain(&parsed_certs)?
    };

    match status {
        ValidationStatus::Valid => println!("Certificate is valid!"),
        ValidationStatus::Expired => println!("Certificate is expired!"),
        ValidationStatus::NotYetValid => println!("Certificate is not yet valid!"),
        ValidationStatus::InvalidSignature => println!("Certificate has an invalid signature!"),
        ValidationStatus::Revoked => println!("Certificate is revoked!"),
        ValidationStatus::UnknownIssuer => println!("Certificate has an unknown issuer!"),
        ValidationStatus::PathLengthExceeded => println!("Certificate path length constraint exceeded!"),
        ValidationStatus::UnhandledCriticalExtension => println!("Certificate has unhandled critical extensions!"),
    }

    Ok(())
}