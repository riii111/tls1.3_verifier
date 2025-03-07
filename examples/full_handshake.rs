use std::env;
use std::io::Read;
use tls13_verifier::{TlsHandshakeVerifier, TlsVerifierParams, Result};

fn main() -> Result<()> {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <ca_cert_path> <tls_traffic_file> [hostname]", args[0]);
        println!("Example: {} /path/to/ca.pem /path/to/traffic.bin example.com", args[0]);
        return Ok(());
    }

    let ca_cert_path = &args[1];
    let tls_traffic_file = &args[2];
    let hostname = args.get(3).cloned();

    println!("TLS 1.3 Handshake Verifier");
    println!("==========================");
    println!("CA Certificates: {}", ca_cert_path);
    println!("TLS Traffic File: {}", tls_traffic_file);
    if let Some(host) = &hostname {
        println!("Hostname: {}", host);
    }
    println!();

    // Initialize verifier with parameters
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
    
    // Process the TLS traffic
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
        println!("TLS 1.3 handshake completed successfully!");
    } else {
        println!("TLS 1.3 handshake incomplete");
    }
    
    Ok(())
}
