use crate::error::{Error, Result};
use crate::tls::types::{AlertLevel, AlertDescription};
use crate::utils;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn new(level: AlertLevel, description: AlertDescription) -> Self {
        Self { level, description }
    }

    pub fn parse(data: &[u8], pos: &mut usize) -> Result<Self> {
        if *pos + 2 > data.len() {
            return Err(Error::ParseError("Alert message truncated".to_string()));
        }

        let level_byte = utils::read_u8(data, pos)?;
        let level = match level_byte {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => return Err(Error::ParseError(format!("Invalid alert level: {}", level_byte))),
        };

        let description_byte = utils::read_u8(data, pos)?;
        let description = match description_byte {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            _ => return Err(Error::ParseError(format!("Invalid alert description: {}", description_byte))),
        };

        Ok(Self { level, description })
    }

    pub fn serialize(&self) -> Vec<u8> {
        vec![self.level as u8, self.description as u8]
    }

    pub fn is_fatal(&self) -> bool {
        self.level == AlertLevel::Fatal
    }
}