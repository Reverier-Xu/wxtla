//! BitLocker metadata block parsing.

use crate::{Error, Result};

const SIGNATURE: &[u8; 8] = b"-FVE-FS-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerMetadataBlockHeader {
  pub version: u16,
  pub encrypted_volume_size: u64,
  pub volume_header_sector_count: u32,
  pub metadata_offsets: [u64; 3],
  pub volume_header_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerMetadataHeader {
  pub metadata_size: u32,
  pub version: u32,
  pub header_size: u32,
  pub volume_identifier: [u8; 16],
  pub next_nonce_counter: u32,
  pub encryption_method: u32,
  pub creation_time: u64,
}

impl BitlockerMetadataBlockHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 64 {
      return Err(Error::InvalidFormat(
        "bitlocker metadata block header must be 64 bytes".to_string(),
      ));
    }
    if &data[0..8] != SIGNATURE {
      return Err(Error::InvalidFormat(
        "bitlocker metadata block signature is missing".to_string(),
      ));
    }

    let version = u16::from_le_bytes([data[10], data[11]]);
    if version != 2 {
      return Err(Error::InvalidFormat(format!(
        "unsupported bitlocker metadata block version: {version}"
      )));
    }
    let volume_header_sector_count = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    if volume_header_sector_count == 0 {
      return Err(Error::InvalidFormat(
        "bitlocker volume header sector count must be non-zero".to_string(),
      ));
    }

    let mut metadata_offsets = [0u64; 3];
    for (index, slot) in metadata_offsets.iter_mut().enumerate() {
      let start = 32 + index * 8;
      *slot = u64::from_le_bytes(data[start..start + 8].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker metadata block offset length mismatch".to_string())
      })?);
    }

    Ok(Self {
      version,
      encrypted_volume_size: u64::from_le_bytes(data[16..24].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker encrypted size length mismatch".to_string())
      })?),
      volume_header_sector_count,
      metadata_offsets,
      volume_header_offset: u64::from_le_bytes(data[56..64].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker volume header offset length mismatch".to_string())
      })?),
    })
  }
}

impl BitlockerMetadataHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 48 {
      return Err(Error::InvalidFormat(
        "bitlocker metadata header must be 48 bytes".to_string(),
      ));
    }

    let metadata_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if metadata_size < 48 {
      return Err(Error::InvalidFormat(
        "bitlocker metadata size must be at least the header size".to_string(),
      ));
    }
    let header_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if header_size != 48 {
      return Err(Error::InvalidFormat(format!(
        "unsupported bitlocker metadata header size: {header_size}"
      )));
    }

    Ok(Self {
      metadata_size,
      version: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
      header_size,
      volume_identifier: data[16..32].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker metadata identifier length mismatch".to_string())
      })?,
      next_nonce_counter: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
      encryption_method: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
      creation_time: u64::from_le_bytes(data[40..48].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker creation time length mismatch".to_string())
      })?),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_metadata_block_header_sample() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/metadata_block_header.1"
    ))
    .unwrap();
    let header = BitlockerMetadataBlockHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.version, 2);
    assert_eq!(header.encrypted_volume_size, 262_144_000);
    assert_eq!(header.volume_header_sector_count, 10_480);
  }

  #[test]
  fn parses_metadata_header_sample() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/metadata_header.1"
    ))
    .unwrap();
    let header = BitlockerMetadataHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.version, 1);
    assert_eq!(header.header_size, 48);
    assert_eq!(header.encryption_method, 0x8000);
  }
}
