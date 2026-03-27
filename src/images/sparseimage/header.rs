//! Sparseimage header parsing.

use crate::{ByteSource, Error, Result};

pub(super) const HEADER_BLOCK_SIZE: usize = 4096;
const HEADER_SIZE: usize = 64;
pub(super) const HEADER_MAGIC: &[u8; 4] = b"sprs";
pub(super) const SECTOR_SIZE: u64 = 512;

/// Parsed sparseimage file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseImageHeader {
  /// Header format version.
  pub format_version: u32,
  /// Number of sectors stored in each band.
  pub sectors_per_band: u32,
  /// Total number of sectors in the image.
  pub sector_count: u32,
}

impl SparseImageHeader {
  pub fn read(source: &dyn ByteSource) -> Result<(Self, Vec<u8>)> {
    let block = source.read_bytes_at(0, HEADER_BLOCK_SIZE)?;
    let header = Self::from_bytes(&block)?;
    Ok((header, block))
  }

  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < HEADER_SIZE {
      return Err(Error::InvalidFormat(
        "sparseimage header block is too small".to_string(),
      ));
    }
    if &data[0..4] != HEADER_MAGIC {
      return Err(Error::InvalidFormat(
        "sparseimage header signature is missing".to_string(),
      ));
    }

    let sectors_per_band = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if sectors_per_band == 0 {
      return Err(Error::InvalidFormat(
        "sparseimage sectors per band must be non-zero".to_string(),
      ));
    }
    let sector_count = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
    if sector_count == 0 {
      return Err(Error::InvalidFormat(
        "sparseimage sector count must be non-zero".to_string(),
      ));
    }

    Ok(Self {
      format_version: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
      sectors_per_band,
      sector_count,
    })
  }

  pub fn band_size(self) -> Result<u64> {
    u64::from(self.sectors_per_band)
      .checked_mul(SECTOR_SIZE)
      .ok_or_else(|| Error::InvalidRange("sparseimage band size overflow".to_string()))
  }

  pub fn media_size(self) -> Result<u64> {
    u64::from(self.sector_count)
      .checked_mul(SECTOR_SIZE)
      .ok_or_else(|| Error::InvalidRange("sparseimage media size overflow".to_string()))
  }

  pub fn band_count(self) -> u32 {
    self.sector_count.div_ceil(self.sectors_per_band)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_header() -> [u8; HEADER_SIZE] {
    let mut data = [0u8; HEADER_SIZE];
    data[0..4].copy_from_slice(HEADER_MAGIC);
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[8..12].copy_from_slice(&2048u32.to_be_bytes());
    data[12..16].copy_from_slice(&1u32.to_be_bytes());
    data[16..20].copy_from_slice(&8192u32.to_be_bytes());
    data
  }

  #[test]
  fn parses_sparseimage_header_fields() {
    let header = SparseImageHeader::from_bytes(&sample_header()).unwrap();

    assert_eq!(header.format_version, 3);
    assert_eq!(header.sectors_per_band, 2048);
    assert_eq!(header.sector_count, 8192);
    assert_eq!(header.band_count(), 4);
    assert_eq!(header.band_size().unwrap(), 1_048_576);
  }

  #[test]
  fn rejects_invalid_signature() {
    let mut data = sample_header();
    data[0] = 0;

    let result = SparseImageHeader::from_bytes(&data);

    assert!(matches!(result, Err(Error::InvalidFormat(_))));
  }
}
