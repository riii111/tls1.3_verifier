use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error("Certificate error: {0}")]
    CertificateError(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

pub type Result<T> = std::result::Result<T, Error>;
