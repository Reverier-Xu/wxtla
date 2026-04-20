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
  pub metadata_size: u64,
  pub volume_size: u64,
  pub version: u32,
  pub identifier: [u8; 16],
  pub metadata_offsets: [u64; 3],
}

impl BitlockerVolumeHeader {
  pub fn from_bytes(data: &[u8]) -> Result<Self> {
    if data.len() < 512 {
      return Err(Error::invalid_format(
        "bitlocker volume header must be at least 512 bytes".to_string(),
      ));
    }
    if data[510..512] != [0x55, 0xAA] {
      return Err(Error::invalid_format(
        "bitlocker volume header sector signature is missing".to_string(),
      ));
    }

    let (flavor, identifier_offset, metadata_offset_base) = if &data[3..11] == SIGNATURE_FIXED {
      (BitlockerHeaderFlavor::Fixed, 160usize, 176usize)
    } else if &data[3..11] == SIGNATURE_TO_GO {
      (BitlockerHeaderFlavor::ToGo, 424usize, 440usize)
    } else {
      return Err(Error::invalid_format(
        "bitlocker header signature is missing".to_string(),
      ));
    };

    let bytes_per_sector = u16::from_le_bytes([data[11], data[12]]);
    if bytes_per_sector == 0 {
      return Err(Error::invalid_format(
        "bitlocker bytes-per-sector must be non-zero".to_string(),
      ));
    }
    let sectors_per_cluster = data[13];
    if sectors_per_cluster == 0 {
      return Err(Error::invalid_format(
        "bitlocker sectors-per-cluster must be non-zero".to_string(),
      ));
    }

    let total_number_of_sectors = {
      let total16 = u64::from(u16::from_le_bytes([data[19], data[20]]));
      if total16 != 0 {
        total16
      } else {
        let total32 = u64::from(u32::from_le_bytes([data[32], data[33], data[34], data[35]]));
        if total32 != 0 {
          total32
        } else {
          u64::from_le_bytes([
            data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
          ])
        }
      }
    };
    let volume_size = total_number_of_sectors
      .checked_mul(u64::from(bytes_per_sector))
      .ok_or_else(|| Error::invalid_range("bitlocker volume size overflow"))?;
    let mut metadata_offsets = [0u64; 3];
    for (index, slot) in metadata_offsets.iter_mut().enumerate() {
      let start = metadata_offset_base + index * 8;
      *slot = u64::from_le_bytes(
        data[start..start + 8]
          .try_into()
          .map_err(|_| Error::invalid_format("bitlocker metadata offset length mismatch"))?,
      );
    }
    let mut version = match flavor {
      BitlockerHeaderFlavor::Fixed => 7,
      BitlockerHeaderFlavor::ToGo => u32::from(b'T'),
    };
    let mut metadata_size = 65_536u64;
    if matches!(flavor, BitlockerHeaderFlavor::Fixed)
      && metadata_offsets.iter().all(|offset| *offset == 0)
    {
      let metadata_lcn = u64::from_le_bytes([
        data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
      ]);
      if metadata_lcn != 0 {
        let cluster_size = u64::from(bytes_per_sector)
          .checked_mul(u64::from(sectors_per_cluster))
          .ok_or_else(|| Error::invalid_range("bitlocker cluster size overflow"))?;
        metadata_offsets[0] = metadata_lcn
          .checked_mul(cluster_size)
          .ok_or_else(|| Error::invalid_range("bitlocker metadata offset overflow"))?;
        metadata_size = (16 * 1024u64)
          .div_ceil(cluster_size)
          .checked_mul(cluster_size)
          .ok_or_else(|| Error::invalid_range("bitlocker metadata size overflow"))?;
        version = 6;
      }
    }
    if metadata_offsets.iter().all(|offset| *offset == 0) {
      return Err(Error::invalid_format(
        "bitlocker headers must contain at least one metadata block offset".to_string(),
      ));
    }

    Ok(Self {
      flavor,
      bytes_per_sector,
      sectors_per_cluster,
      hidden_sector_count: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
      metadata_size,
      volume_size,
      version,
      identifier: data[identifier_offset..identifier_offset + 16]
        .try_into()
        .map_err(|_| Error::invalid_format("bitlocker identifier length mismatch"))?,
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
    assert_eq!(header.metadata_size, 65_536);
    assert_eq!(header.volume_size, 0);
    assert_eq!(header.version, 7);
    assert_eq!(header.metadata_offsets[0], 34_603_008);
  }

  #[test]
  fn derives_vista_metadata_offsets_from_the_metadata_lcn() {
    let mut data = [0u8; 512];
    data[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
    data[3..11].copy_from_slice(SIGNATURE_FIXED);
    data[11..13].copy_from_slice(&512u16.to_le_bytes());
    data[13] = 8;
    data[40..48].copy_from_slice(&8192u64.to_le_bytes());
    data[56..64].copy_from_slice(&4u64.to_le_bytes());
    data[510..512].copy_from_slice(&[0x55, 0xAA]);

    let header = BitlockerVolumeHeader::from_bytes(&data).unwrap();

    assert_eq!(header.version, 6);
    assert_eq!(header.volume_size, 8192 * 512);
    assert_eq!(header.metadata_size, 16 * 1024);
    assert_eq!(header.metadata_offsets, [16_384, 0, 0]);
  }
}
