//! Apple Partition Map partition entry parsing.

use super::constants::{PARTITION_ENTRY_SIZE, PARTITION_MAP_SIGNATURE};
use crate::{
  Error, Result,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan},
};

/// Parsed APM partition map entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApmPartitionMapEntry {
  /// Total number of entries in the partition map.
  pub total_entry_count: u32,
  /// Partition start block.
  pub start_block: u32,
  /// Partition block count.
  pub block_count: u32,
  /// Partition name.
  pub name: String,
  /// Partition type identifier.
  pub type_identifier: String,
  /// Data area start block.
  pub data_area_start_block: u32,
  /// Data area block count.
  pub data_area_block_count: u32,
  /// Status flags.
  pub status_flags: u32,
  /// Boot code start block.
  pub boot_code_start_block: u32,
  /// Boot code block count.
  pub boot_code_block_count: u32,
  /// Boot code address.
  pub boot_code_address: u32,
  /// Boot code entry point.
  pub boot_code_entry_point: u32,
  /// Boot code checksum.
  pub boot_code_checksum: u32,
  /// Processor type identifier.
  pub processor_type: String,
}

impl ApmPartitionMapEntry {
  /// Parse a partition map entry from exactly 512 bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != PARTITION_ENTRY_SIZE {
      return Err(Error::InvalidFormat(format!(
        "apm partition entry must be {PARTITION_ENTRY_SIZE} bytes, got {}",
        data.len()
      )));
    }
    if &data[0..2] != PARTITION_MAP_SIGNATURE {
      return Err(Error::InvalidFormat(
        "apm partition entry signature is missing".to_string(),
      ));
    }

    Ok(Self {
      total_entry_count: read_u32_be(data, 4),
      start_block: read_u32_be(data, 8),
      block_count: read_u32_be(data, 12),
      name: read_ascii_string(data, 16, 32),
      type_identifier: read_ascii_string(data, 48, 32),
      data_area_start_block: read_u32_be(data, 80),
      data_area_block_count: read_u32_be(data, 84),
      status_flags: read_u32_be(data, 88),
      boot_code_start_block: read_u32_be(data, 92),
      boot_code_block_count: read_u32_be(data, 96),
      boot_code_address: read_u32_be(data, 100),
      boot_code_entry_point: read_u32_be(data, 108),
      boot_code_checksum: read_u32_be(data, 116),
      processor_type: read_ascii_string(data, 120, 16),
    })
  }

  /// Convert the entry into generic volume metadata.
  pub fn into_partition_info(self, index: usize, block_size: u16) -> Result<ApmPartitionInfo> {
    let block_size = u64::from(block_size);
    let byte_offset = u64::from(self.start_block)
      .checked_mul(block_size)
      .ok_or_else(|| Error::InvalidRange("apm partition offset overflow".to_string()))?;
    let byte_size = u64::from(self.block_count)
      .checked_mul(block_size)
      .ok_or_else(|| Error::InvalidRange("apm partition size overflow".to_string()))?;
    let mut record = VolumeRecord::new(
      index,
      VolumeSpan::new(byte_offset, byte_size),
      VolumeRole::Primary,
    );
    if !self.name.is_empty() {
      record = record.with_name(self.name.clone());
    }

    Ok(ApmPartitionInfo {
      record,
      entry: self,
    })
  }
}

/// Parsed APM partition metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApmPartitionInfo {
  /// Generic volume record.
  pub record: VolumeRecord,
  /// Parsed APM entry details.
  pub entry: ApmPartitionMapEntry,
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
  u32::from_be_bytes([
    data[offset],
    data[offset + 1],
    data[offset + 2],
    data[offset + 3],
  ])
}

fn read_ascii_string(data: &[u8], offset: usize, len: usize) -> String {
  let bytes = &data[offset..offset + len];
  let nul = bytes
    .iter()
    .position(|byte| *byte == 0)
    .unwrap_or(bytes.len());
  String::from_utf8_lossy(&bytes[..nul]).into_owned()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_partition_entry_fields() {
    let mut data = [0u8; PARTITION_ENTRY_SIZE];
    data[0..2].copy_from_slice(b"PM");
    data[4..8].copy_from_slice(&3u32.to_be_bytes());
    data[8..12].copy_from_slice(&64u32.to_be_bytes());
    data[12..16].copy_from_slice(&8112u32.to_be_bytes());
    data[16..26].copy_from_slice(b"disk image");
    data[48..57].copy_from_slice(b"Apple_HFS");
    data[80..84].copy_from_slice(&64u32.to_be_bytes());
    data[84..88].copy_from_slice(&8112u32.to_be_bytes());
    data[88..92].copy_from_slice(&0x4000_0033u32.to_be_bytes());

    let entry = ApmPartitionMapEntry::parse(&data).unwrap();

    assert_eq!(entry.total_entry_count, 3);
    assert_eq!(entry.start_block, 64);
    assert_eq!(entry.block_count, 8112);
    assert_eq!(entry.name, "disk image");
    assert_eq!(entry.type_identifier, "Apple_HFS");
    assert_eq!(entry.status_flags, 0x4000_0033);
  }
}
