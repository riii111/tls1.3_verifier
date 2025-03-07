use crate::error::{Error, Result};
use crate::utils;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            _ => Err(Error::ParseError(format!("Invalid ContentType value: {}", value))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsRecord<'a> {
    pub record_type: ContentType,
    pub content_type: ContentType, // Alias for record_type for clarity
    pub legacy_version: u16,
    pub fragment: &'a [u8],
}

pub struct RecordLayer {
    max_fragment_length: usize,
}

impl RecordLayer {
    pub fn new() -> Self {
        RecordLayer {
            max_fragment_length: 16384, // Default max fragment length
        }
    }

    pub fn parse_record<'a>(&self, data: &'a [u8]) -> Result<(TlsRecord<'a>, usize)> {
        let mut pos = 0;
        
        if data.len() < 5 {
            return Err(Error::ParseError("Record too short".to_string()));
        }
        
        let record_type = ContentType::try_from(utils::read_u8(data, &mut pos)?)?;
        let legacy_version = utils::read_u16(data, &mut pos)?;
        let length = utils::read_u16(data, &mut pos)? as usize;
        
        if pos + length > data.len() {
            return Err(Error::ParseError("Record fragment length exceeds available data".to_string()));
        }
        
        if length > self.max_fragment_length {
            return Err(Error::ProtocolError(format!(
                "Record fragment length {} exceeds maximum allowed {}",
                length, 
                self.max_fragment_length
            )));
        }
        
        let fragment = utils::read_bytes(data, &mut pos, length)?;
        
        Ok((
            TlsRecord {
                record_type,
                content_type: record_type, // Set both fields to the same value
                legacy_version,
                fragment,
            },
            pos
        ))
    }
    
    pub fn process_records<'a>(&self, data: &'a [u8]) -> Result<Vec<TlsRecord<'a>>> {
        let mut records = Vec::new();
        let mut pos = 0;
        
        while pos < data.len() {
            match self.parse_record(&data[pos..]) {
                Ok((record, consumed)) => {
                    records.push(record);
                    pos += consumed;
                }
                Err(Error::ParseError(e)) if e == "Record too short" && pos > 0 => {
                    // If we've successfully parsed at least one record and 
                    // we have a partial record at the end, we're done
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        
        Ok(records)
    }

    pub fn serialize_record(&self, record: &TlsRecord<'_>) -> Result<Vec<u8>> {
        if record.fragment.len() > self.max_fragment_length {
            return Err(Error::ProtocolError(format!(
                "Record fragment length {} exceeds maximum allowed {}",
                record.fragment.len(),
                self.max_fragment_length
            )));
        }
        
        let mut result = Vec::with_capacity(5 + record.fragment.len());
        
        utils::write_u8(&mut result, record.record_type as u8);
        utils::write_u16(&mut result, record.legacy_version);
        utils::write_u16(&mut result, record.fragment.len() as u16);
        result.extend_from_slice(record.fragment);
        
        Ok(result)
    }
    
    pub fn set_max_fragment_length(&mut self, length: usize) -> Result<()> {
        if length > 16384 {
            return Err(Error::ProtocolError("Max fragment length exceeds TLS limit".to_string()));
        }
        self.max_fragment_length = length;
        Ok(())
    }
}

impl Default for RecordLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_record_parsing() {
        let record_data = [
            22, // Handshake record type
            0x03, 0x03, // TLS 1.2 legacy version
            0x00, 0x05, // Length 5
            0x01, 0x02, 0x03, 0x04, 0x05, // Fragment data
        ];
        
        let record_layer = RecordLayer::new();
        let (record, pos) = record_layer.parse_record(&record_data).unwrap();
        
        assert_eq!(record.record_type, ContentType::Handshake);
        assert_eq!(record.legacy_version, 0x0303);
        assert_eq!(record.fragment, &record_data[5..10]);
        assert_eq!(pos, 10);
    }
    
    #[test]
    fn test_record_serialization() {
        let fragment = [0x01, 0x02, 0x03, 0x04, 0x05];
        let record = TlsRecord {
            record_type: ContentType::Handshake,
            content_type: ContentType::Handshake,
            legacy_version: 0x0303,
            fragment: &fragment,
        };
        
        let record_layer = RecordLayer::new();
        let serialized = record_layer.serialize_record(&record).unwrap();
        
        let expected = [
            22, // Handshake record type
            0x03, 0x03, // TLS 1.2 legacy version
            0x00, 0x05, // Length 5
            0x01, 0x02, 0x03, 0x04, 0x05, // Fragment data
        ];
        
        assert_eq!(serialized, expected);
    }
    
    #[test]
    fn test_record_too_large() {
        let mut record_layer = RecordLayer::new();
        record_layer.set_max_fragment_length(10).unwrap();
        
        let large_fragment = vec![0; 11];
        let record = TlsRecord {
            record_type: ContentType::Handshake,
            content_type: ContentType::Handshake,
            legacy_version: 0x0303,
            fragment: &large_fragment,
        };
        
        assert!(record_layer.serialize_record(&record).is_err());
    }
    
    #[test]
    fn test_invalid_content_type() {
        let record_data = [
            25, // Invalid content type
            0x03, 0x03,
            0x00, 0x05,
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        
        let record_layer = RecordLayer::new();
        assert!(record_layer.parse_record(&record_data).is_err());
    }
    
    #[test]
    fn test_process_multiple_records() {
        let record_data = [
            // Record 1: Handshake
            22, // Handshake record type
            0x03, 0x03, // TLS 1.2 legacy version
            0x00, 0x05, // Length 5
            0x01, 0x02, 0x03, 0x04, 0x05, // Fragment data
            
            // Record 2: Alert
            21, // Alert record type
            0x03, 0x03, // TLS 1.2 legacy version
            0x00, 0x02, // Length 2
            0x01, 0x02, // Fragment data
        ];
        
        let record_layer = RecordLayer::new();
        let records = record_layer.process_records(&record_data).unwrap();
        
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type, ContentType::Handshake);
        assert_eq!(records[0].fragment.len(), 5);
        assert_eq!(records[1].record_type, ContentType::Alert);
        assert_eq!(records[1].fragment.len(), 2);
    }
}