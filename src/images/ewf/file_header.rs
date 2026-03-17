//! EWF file-header parsing.

use super::constants::{FILE_HEADER_MAGIC, FILE_HEADER_SIZE};
use crate::{DataSource, Error, Result};

/// Parsed EWF segment file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EwfFileHeader {
  /// Segment number encoded in the header.
  pub segment_number: u16,
}

impl EwfFileHeader {
  /// Read the file header from the start of a source.
  pub fn read(source: &dyn DataSource) -> Result<Self> {
    let data = source.read_bytes_at(0, FILE_HEADER_SIZE)?;
    Self::parse(&data)
  }

  /// Parse the file header from 13 bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != FILE_HEADER_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf file header must be {FILE_HEADER_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..8] != FILE_HEADER_MAGIC {
      return Err(Error::InvalidFormat(
        "ewf file header signature is missing".to_string(),
      ));
    }
    if data[8] != 0x01 {
      return Err(Error::InvalidFormat(
        "ewf file header start-of-fields marker is invalid".to_string(),
      ));
    }
    if data[11..13] != [0x00, 0x00] {
      return Err(Error::InvalidFormat(
        "ewf file header end-of-fields marker is invalid".to_string(),
      ));
    }

    Ok(Self {
      segment_number: u16::from_le_bytes([data[9], data[10]]),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_segment_number() {
    let header = EwfFileHeader::parse(&[
      0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
    ])
    .unwrap();

    assert_eq!(header.segment_number, 1);
  }
}
