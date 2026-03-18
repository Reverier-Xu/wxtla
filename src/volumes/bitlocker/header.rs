//! BitLocker volume header parsing.

use crate::{Error, Result};

const SIGNATURE_FIXED: &[u8; 8] = b"-FVE-FS-";
const SIGNATURE_TO_GO: &[u8; 8] = b"MSWIN4.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitlockerHeaderFlavor {
  Fixed,
  ToGo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitlockerVolumeHeader {
  pub flavor: BitlockerHeaderFlavor,
  pub bytes_per_sector: u16,
  pub sectors_per_cluster: u8,
  pub hidden_sector_count: u32,
  pub identifier: [u8; 16],
  pub metadata_offsets: [u64; 3],
}

impl BitlockerVolumeHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 512 {
      return Err(Error::InvalidFormat(
        "bitlocker volume header must be at least 512 bytes".to_string(),
      ));
    }
    if data[510..512] != [0x55, 0xAA] {
      return Err(Error::InvalidFormat(
        "bitlocker volume header sector signature is missing".to_string(),
      ));
    }

    let (flavor, identifier_offset, metadata_offset_base) = if &data[3..11] == SIGNATURE_FIXED {
      (BitlockerHeaderFlavor::Fixed, 160usize, 176usize)
    } else if &data[3..11] == SIGNATURE_TO_GO {
      (BitlockerHeaderFlavor::ToGo, 424usize, 440usize)
    } else {
      return Err(Error::InvalidFormat(
        "bitlocker header signature is missing".to_string(),
      ));
    };

    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    if bytes_per_sector == 0 {
      return Err(Error::InvalidFormat(
        "bitlocker bytes-per-sector must be non-zero".to_string(),
      ));
    }
    let sectors_per_cluster = data[13];
    if sectors_per_cluster == 0 {
      return Err(Error::InvalidFormat(
        "bitlocker sectors-per-cluster must be non-zero".to_string(),
      ));
    }

    let mut metadata_offsets = [0u64; 3];
    for (index, slot) in metadata_offsets.iter_mut().enumerate() {
      let start = metadata_offset_base + index * 8;
      *slot = u64::from_le_bytes(data[start..start + 8].try_into().map_err(|_| {
        Error::InvalidFormat("bitlocker metadata offset length mismatch".to_string())
      })?);
    }
    if metadata_offsets.iter().all(|offset| *offset == 0) {
      return Err(Error::InvalidFormat(
        "bitlocker headers must contain at least one metadata block offset".to_string(),
      ));
    }

    Ok(Self {
      flavor,
      bytes_per_sector,
      sectors_per_cluster,
      hidden_sector_count: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
      identifier: data[identifier_offset..identifier_offset + 16]
        .try_into()
        .map_err(|_| Error::InvalidFormat("bitlocker identifier length mismatch".to_string()))?,
      metadata_offsets,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_fixed_volume_header_sample() {
    let bytes = std::fs::read(concat!(
      env!("CARGO_MANIFEST_DIR"),
      "/formats/bitlocker/volume_header.1"
    ))
    .unwrap();
    let header = BitlockerVolumeHeader::from_bytes(&bytes).unwrap();

    assert_eq!(header.flavor, BitlockerHeaderFlavor::Fixed);
    assert_eq!(header.bytes_per_sector, 512);
    assert_eq!(header.sectors_per_cluster, 8);
    assert_eq!(header.metadata_offsets[0], 34_603_008);
  }
}
