// Cryptographic operations module
use crate::error::Result;

// Re-export submodules
pub mod key_exchange;
pub mod signature;
pub mod hkdf;
pub mod aead;

// Re-export main types from child modules
pub use key_exchange::*;
pub use signature::*;
pub use hkdf::*;
pub use aead::*;

// Common crypto initialization and utilities
pub fn init() -> Result<()> {
    // Initialize crypto subsystems if needed
    Ok(())
}