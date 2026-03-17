//! EWF error2 section parsing.

use adler2::adler32_slice;

use super::constants::{ERROR2_ENTRY_SIZE, ERROR2_FOOTER_SIZE, ERROR2_HEADER_SIZE};
use crate::{Error, Result};

/// Range of sectors flagged as erroneous in an EWF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EwfErrorRange {
  /// First affected sector number.
  pub start_sector: u32,
  /// Number of affected sectors.
  pub sector_count: u32,
}

/// Parsed error2 section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfErrorSection {
  /// Reported error ranges.
  pub ranges: Vec<EwfErrorRange>,
}

impl EwfErrorSection {
  /// Parse an error2 section payload.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() < ERROR2_HEADER_SIZE + ERROR2_FOOTER_SIZE {
      return Err(Error::InvalidFormat(
        "ewf error2 section payload is too small".to_string(),
      ));
    }

    let entry_count = read_u32_le(data, 0) as usize;
    let expected_size = ERROR2_HEADER_SIZE
      .checked_add(
        entry_count
          .checked_mul(ERROR2_ENTRY_SIZE)
          .ok_or_else(|| Error::InvalidRange("ewf error2 entry array size overflow".to_string()))?,
      )
      .and_then(|size| size.checked_add(ERROR2_FOOTER_SIZE))
      .ok_or_else(|| Error::InvalidRange("ewf error2 size overflow".to_string()))?;
    if data.len() != expected_size {
      return Err(Error::InvalidFormat(format!(
        "ewf error2 payload size does not match entry count: expected {expected_size}, got {}",
        data.len()
      )));
    }

    let stored_header_checksum = read_u32_le(data, 516);
    let calculated_header_checksum = adler32_slice(&data[..516]);
    if stored_header_checksum != calculated_header_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf error2 header checksum mismatch: stored 0x{stored_header_checksum:08x}, calculated 0x{calculated_header_checksum:08x}"
      )));
    }

    let entries_start = ERROR2_HEADER_SIZE;
    let entries_end = entries_start + entry_count * ERROR2_ENTRY_SIZE;
    let stored_entry_checksum = read_u32_le(data, entries_end);
    let calculated_entry_checksum = adler32_slice(&data[entries_start..entries_end]);
    if stored_entry_checksum != calculated_entry_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf error2 entry checksum mismatch: stored 0x{stored_entry_checksum:08x}, calculated 0x{calculated_entry_checksum:08x}"
      )));
    }

    let mut ranges = Vec::with_capacity(entry_count);
    let mut offset = entries_start;
    for _ in 0..entry_count {
      ranges.push(EwfErrorRange {
        start_sector: read_u32_le(data, offset),
        sector_count: read_u32_le(data, offset + 4),
      });
      offset += ERROR2_ENTRY_SIZE;
    }

    Ok(Self { ranges })
  }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
  u32::from_le_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
  ])
}

#[cfg(test)]
mod tests {
  use adler2::adler32_slice;

  use super::*;

  #[test]
  fn parses_error_ranges() {
    let mut data = vec![0u8; ERROR2_HEADER_SIZE + ERROR2_ENTRY_SIZE + ERROR2_FOOTER_SIZE];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    let header_checksum = adler32_slice(&data[..516]);
    data[516..520].copy_from_slice(&header_checksum.to_le_bytes());
    data[520..524].copy_from_slice(&301u32.to_le_bytes());
    data[524..528].copy_from_slice(&11256u32.to_le_bytes());
    let entry_checksum = adler32_slice(&data[520..528]);
    data[528..532].copy_from_slice(&entry_checksum.to_le_bytes());

    let section = EwfErrorSection::parse(&data).unwrap();

    assert_eq!(section.ranges.len(), 1);
    assert_eq!(section.ranges[0].start_sector, 301);
    assert_eq!(section.ranges[0].sector_count, 11256);
  }
}
