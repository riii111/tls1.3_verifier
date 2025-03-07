use tls13_verifier::{TlsHandshakeVerifier, TlsVerifierParams, Result};
use std::env;
use std::fs;
use std::io::Read;

fn main() -> Result<()> {
    // Initialize logging
    std::env::set_var("RUST_LOG", "debug");
    tls13_verifier::init_logging();

    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <ca_cert_path> <traffic_capture> [hostname]", args[0]);
        println!("  ca_cert_path: Path to CA certificate PEM file");
        println!("  traffic_capture: Path to file containing TLS 1.3 handshake records");
        println!("  hostname: Optional server hostname to verify (SNI)");
        return Ok(());
    }

    let ca_path = &args[1];
    let traffic_file = &args[2];
    let hostname = args.get(3).cloned();

    println!("TLS 1.3 Handshake Verifier");
    println!("==========================");
    println!("CA Certificates: {}", ca_path);
    println!("TLS Traffic File: {}", traffic_file);
    if let Some(host) = &hostname {
        println!("Hostname to verify: {}", host);
    }
    println!();

    // Create TLS verifier with our parameters
    let params = TlsVerifierParams {
        server_name: hostname,
        trusted_certs_path: Some(ca_path.to_string()),
        allow_self_signed: false,
    };

    let mut verifier = TlsHandshakeVerifier::new(params)?;

    // Read the TLS traffic capture
    println!("Reading TLS traffic file...");
    let traffic_data = read_file(traffic_file)?;

    // Process the TLS traffic
    println!("Processing TLS records...");
    verifier.process_tls_record(&traffic_data)?;

    // Check the results
    let handshake_state = verifier.get_handshake_state();
    println!("\nVerification Results:");
    println!("-------------------");
    println!("Final handshake state: {:?}", handshake_state);

    if let Some(cipher_suite) = verifier.get_negotiated_cipher_suite() {
        println!("Negotiated cipher suite: {:?}", cipher_suite);
    } else {
        println!("No cipher suite negotiated");
    }

    if verifier.is_handshake_complete() {
        println!("\n✅ TLS 1.3 handshake verified successfully!");
    } else {
        println!("\n❌ TLS 1.3 handshake verification incomplete or failed");
    }

    Ok(())
}

fn read_file(path: &str) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}