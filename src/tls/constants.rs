// TLS Protocol Constants

// TLS 1.3 Version
pub const TLS13: u16 = 0x0304;

// Legacy version identifiers
pub const TLS12: u16 = 0x0303;
pub const TLS11: u16 = 0x0302;
pub const TLS10: u16 = 0x0301;

// Record types
pub const RECORD_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const RECORD_TYPE_ALERT: u8 = 21;
pub const RECORD_TYPE_HANDSHAKE: u8 = 22;
pub const RECORD_TYPE_APPLICATION_DATA: u8 = 23;

// Limits
pub const MAX_RECORD_SIZE: usize = 16384 + 256; // Record size + max overhead
pub const MAX_HANDSHAKE_SIZE: usize = 65536; // Maximum handshake message size
pub const MAX_EARLY_DATA_SIZE: usize = 14336; // Maximum early data size

// Special placeholder values
pub const LEGACY_VERSION: u16 = TLS12; // TLS 1.2 version used for compatibility