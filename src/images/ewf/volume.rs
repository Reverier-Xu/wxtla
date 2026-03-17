//! EWF volume/data section parsing.

use adler2::adler32_slice;

use super::{
  constants::{E01_VOLUME_DATA_SIZE, S01_VOLUME_DATA_SIZE},
  types::EwfMediaType,
};
use crate::{Error, Result};

/// Parsed EWF-E01 volume information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfVolumeInfo {
  /// Media type encoded in the section.
  pub media_type: EwfMediaType,
  /// Number of logical chunks.
  pub chunk_count: u32,
  /// Number of sectors per chunk.
  pub sectors_per_chunk: u32,
  /// Number of bytes per sector.
  pub bytes_per_sector: u32,
  /// Number of addressable sectors.
  pub sector_count: u64,
  /// EWF media flags.
  pub media_flags: u8,
  /// EWF compression level.
  pub compression_level: u8,
  /// EWF error granularity.
  pub error_granularity: u32,
  /// Segment set identifier.
  pub set_identifier: [u8; 16],
}

impl EwfVolumeInfo {
  /// Parse an E01-style 1052-byte volume or data section payload.
  pub fn parse_e01(data: &[u8]) -> Result<Self> {
    if data.len() != E01_VOLUME_DATA_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf volume section must be {E01_VOLUME_DATA_SIZE} bytes, got {}",
        data.len()
      )));
    }

    let stored_checksum = u32::from_le_bytes([data[1048], data[1049], data[1050], data[1051]]);
    let calculated_checksum = adler32_slice(&data[..1048]);
    if stored_checksum != 0 && stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf volume checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Self {
      media_type: EwfMediaType::from_byte(data[0]),
      chunk_count: read_u32_le(data, 4),
      sectors_per_chunk: read_u32_le(data, 8),
      bytes_per_sector: read_u32_le(data, 12),
      sector_count: read_u64_le(data, 16),
      media_flags: data[36],
      compression_level: data[52],
      error_granularity: read_u32_le(data, 56),
      set_identifier: data[64..80].try_into().unwrap(),
    })
  }

  /// Parse an S01-style 94-byte volume section payload.
  pub fn parse_s01(data: &[u8]) -> Result<Self> {
    if data.len() != S01_VOLUME_DATA_SIZE {
      return Err(Error::InvalidFormat(format!(
        "ewf s01 volume section must be {S01_VOLUME_DATA_SIZE} bytes, got {}",
        data.len()
      )));
    }

    let stored_checksum = u32::from_le_bytes([data[90], data[91], data[92], data[93]]);
    let calculated_checksum = adler32_slice(&data[..90]);
    if stored_checksum != calculated_checksum {
      return Err(Error::InvalidFormat(format!(
        "ewf s01 volume checksum mismatch: stored 0x{stored_checksum:08x}, calculated 0x{calculated_checksum:08x}"
      )));
    }

    Ok(Self {
      media_type: EwfMediaType::Unknown(0),
      chunk_count: read_u32_le(data, 4),
      sectors_per_chunk: read_u32_le(data, 8),
      bytes_per_sector: read_u32_le(data, 12),
      sector_count: u64::from(read_u32_le(data, 16)),
      media_flags: 0,
      compression_level: 0,
      error_granularity: 0,
      set_identifier: [0; 16],
    })
  }

  /// Return the logical chunk size in bytes.
  pub fn chunk_size(&self) -> Result<u32> {
    self
      .sectors_per_chunk
      .checked_mul(self.bytes_per_sector)
      .ok_or_else(|| Error::InvalidRange("ewf chunk size overflow".to_string()))
  }

  /// Return the logical media size in bytes.
  pub fn media_size(&self) -> Result<u64> {
    self
      .sector_count
      .checked_mul(u64::from(self.bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("ewf media size overflow".to_string()))
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

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
  u64::from_le_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
    data[offset + 4],
    data[offset + 5],
    data[offset + 6],
    data[offset + 7],
  ])
}

#[cfg(test)]
mod tests {
  use adler2::adler32_slice;

  use super::*;

  #[test]
  fn parses_e01_volume_fields() {
    let mut data = [0u8; E01_VOLUME_DATA_SIZE];
    data[0] = 1;
    data[4..8].copy_from_slice(&128u32.to_le_bytes());
    data[8..12].copy_from_slice(&64u32.to_le_bytes());
    data[12..16].copy_from_slice(&512u32.to_le_bytes());
    data[16..24].copy_from_slice(&8192u64.to_le_bytes());
    data[36] = 1;
    data[52] = 2;
    data[56..60].copy_from_slice(&64u32.to_le_bytes());
    data[64..80].copy_from_slice(&[1; 16]);
    let checksum = adler32_slice(&data[..1048]);
    data[1048..1052].copy_from_slice(&checksum.to_le_bytes());

    let volume = EwfVolumeInfo::parse_e01(&data).unwrap();

    assert_eq!(volume.media_type, EwfMediaType::Fixed);
    assert_eq!(volume.chunk_count, 128);
    assert_eq!(volume.chunk_size().unwrap(), 32768);
    assert_eq!(volume.media_size().unwrap(), 4_194_304);
  }

  #[test]
  fn parses_s01_volume_fields() {
    let mut data = [0u8; S01_VOLUME_DATA_SIZE];
    data[0..4].copy_from_slice(&1u32.to_le_bytes());
    data[4..8].copy_from_slice(&45u32.to_le_bytes());
    data[8..12].copy_from_slice(&64u32.to_le_bytes());
    data[12..16].copy_from_slice(&512u32.to_le_bytes());
    data[16..20].copy_from_slice(&2880u32.to_le_bytes());
    data[85..90].copy_from_slice(b"SMART");
    let checksum = adler32_slice(&data[..90]);
    data[90..94].copy_from_slice(&checksum.to_le_bytes());

    let volume = EwfVolumeInfo::parse_s01(&data).unwrap();

    assert_eq!(volume.chunk_count, 45);
    assert_eq!(volume.chunk_size().unwrap(), 32768);
    assert_eq!(volume.media_size().unwrap(), 1_474_560);
  }
}
