use crate::error::{Error, Result};

pub fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8> {
    if *pos >= data.len() {
        return Err(Error::ParseError("Unexpected end of data while reading u8".to_string()));
    }
    
    let value = data[*pos];
    *pos += 1;
    Ok(value)
}

pub fn read_u16(data: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > data.len() {
        return Err(Error::ParseError("Unexpected end of data while reading u16".to_string()));
    }
    
    let value = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

pub fn read_u24(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 3 > data.len() {
        return Err(Error::ParseError("Unexpected end of data while reading u24".to_string()));
    }
    
    let value = u32::from_be_bytes([0, data[*pos], data[*pos + 1], data[*pos + 2]]);
    *pos += 3;
    Ok(value)
}

pub fn read_u32(data: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > data.len() {
        return Err(Error::ParseError("Unexpected end of data while reading u32".to_string()));
    }
    
    let value = u32::from_be_bytes([
        data[*pos],
        data[*pos + 1],
        data[*pos + 2],
        data[*pos + 3],
    ]);
    *pos += 4;
    Ok(value)
}

pub fn read_bytes<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *pos + len > data.len() {
        return Err(Error::ParseError(format!(
            "Unexpected end of data while reading {} bytes", len
        )));
    }
    
    let bytes = &data[*pos..*pos + len];
    *pos += len;
    Ok(bytes)
}

pub fn read_vector_u8<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_u8(data, pos)? as usize;
    read_bytes(data, pos, len)
}

pub fn read_vector_u16<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_u16(data, pos)? as usize;
    read_bytes(data, pos, len)
}

pub fn read_vector_u24<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_u24(data, pos)? as usize;
    read_bytes(data, pos, len)
}

pub fn validate_length(data: &[u8], expected: usize) -> Result<()> {
    if data.len() != expected {
        return Err(Error::ParseError(format!(
            "Invalid length: expected {}, got {}",
            expected,
            data.len()
        )));
    }
    Ok(())
}

pub fn write_u8(vec: &mut Vec<u8>, value: u8) {
    vec.push(value);
}

pub fn write_u16(vec: &mut Vec<u8>, value: u16) {
    vec.extend_from_slice(&value.to_be_bytes());
}

pub fn write_u24(vec: &mut Vec<u8>, value: u32) {
    if value > 0xFF_FFFF {
        panic!("Value too large for u24");
    }
    let bytes = value.to_be_bytes();
    vec.extend_from_slice(&bytes[1..4]);
}

pub fn write_u32(vec: &mut Vec<u8>, value: u32) {
    vec.extend_from_slice(&value.to_be_bytes());
}

pub fn write_vector_u8(vec: &mut Vec<u8>, data: &[u8]) {
    if data.len() > 255 {
        panic!("Data too large for u8 length prefix");
    }
    write_u8(vec, data.len() as u8);
    vec.extend_from_slice(data);
}

pub fn write_vector_u16(vec: &mut Vec<u8>, data: &[u8]) {
    if data.len() > 65535 {
        panic!("Data too large for u16 length prefix");
    }
    write_u16(vec, data.len() as u16);
    vec.extend_from_slice(data);
}

pub fn write_vector_u24(vec: &mut Vec<u8>, data: &[u8]) {
    if data.len() > 0xFF_FFFF {
        panic!("Data too large for u24 length prefix");
    }
    write_u24(vec, data.len() as u32);
    vec.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_read_u8() {
        let data = [0x12, 0x34, 0x56];
        let mut pos = 0;
        
        assert_eq!(read_u8(&data, &mut pos).unwrap(), 0x12);
        assert_eq!(pos, 1);
        
        assert_eq!(read_u8(&data, &mut pos).unwrap(), 0x34);
        assert_eq!(pos, 2);
        
        assert_eq!(read_u8(&data, &mut pos).unwrap(), 0x56);
        assert_eq!(pos, 3);
        
        assert!(read_u8(&data, &mut pos).is_err());
    }
    
    #[test]
    fn test_read_u16() {
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut pos = 0;
        
        assert_eq!(read_u16(&data, &mut pos).unwrap(), 0x1234);
        assert_eq!(pos, 2);
        
        assert_eq!(read_u16(&data, &mut pos).unwrap(), 0x5678);
        assert_eq!(pos, 4);
        
        assert!(read_u16(&data, &mut pos).is_err());
    }
    
    #[test]
    fn test_read_u24() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let mut pos = 0;
        
        assert_eq!(read_u24(&data, &mut pos).unwrap(), 0x123456);
        assert_eq!(pos, 3);
        
        assert_eq!(read_u24(&data, &mut pos).unwrap(), 0x789ABC);
        assert_eq!(pos, 6);
        
        assert!(read_u24(&data, &mut pos).is_err());
    }
    
    #[test]
    fn test_read_vector_u8() {
        let data = [0x02, 0x12, 0x34, 0x03, 0x56, 0x78, 0x9A];
        let mut pos = 0;
        
        assert_eq!(read_vector_u8(&data, &mut pos).unwrap(), &[0x12, 0x34]);
        assert_eq!(pos, 3);
        
        assert_eq!(read_vector_u8(&data, &mut pos).unwrap(), &[0x56, 0x78, 0x9A]);
        assert_eq!(pos, 7);
        
        assert!(read_vector_u8(&data, &mut pos).is_err());
    }
    
    #[test]
    fn test_write_functions() {
        let mut vec = Vec::new();
        
        write_u8(&mut vec, 0x12);
        write_u16(&mut vec, 0x3456);
        write_u24(&mut vec, 0x789ABC);
        write_u32(&mut vec, 0xDEF01234);
        
        assert_eq!(vec, [
            0x12,
            0x34, 0x56,
            0x78, 0x9A, 0xBC,
            0xDE, 0xF0, 0x12, 0x34
        ]);
        
        let mut vec = Vec::new();
        write_vector_u8(&mut vec, &[0x12, 0x34]);
        write_vector_u16(&mut vec, &[0x56, 0x78, 0x9A]);
        
        assert_eq!(vec, [
            0x02, 0x12, 0x34,
            0x00, 0x03, 0x56, 0x78, 0x9A
        ]);
    }
}