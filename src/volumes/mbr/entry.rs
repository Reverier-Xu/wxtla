//! MBR partition entry parsing and metadata.

use super::constants::{
  PARTITION_TYPE_EMPTY, PARTITION_TYPE_EXTENDED_CHS, PARTITION_TYPE_EXTENDED_LBA,
  PARTITION_TYPE_EXTENDED_LINUX, PARTITION_TYPE_GPT_PROTECTIVE,
};
use crate::{
  Error, Result,
  volumes::{VolumeRecord, VolumeRole, VolumeSpan},
};

/// Raw MBR partition entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartitionEntry {
  /// Boot indicator byte.
  pub boot_indicator: u8,
  /// Raw CHS start bytes.
  pub start_chs: [u8; 3],
  /// Partition type code.
  pub partition_type: u8,
  /// Raw CHS end bytes.
  pub end_chs: [u8; 3],
  /// Start LBA as stored in the entry.
  pub start_lba: u32,
  /// Sector count as stored in the entry.
  pub sector_count: u32,
}

impl MbrPartitionEntry {
  /// Parse an MBR partition entry from exactly 16 bytes.
  pub fn parse(data: &[u8]) -> Result<Self> {
    if data.len() != 16 {
      return Err(Error::InvalidFormat(format!(
        "mbr partition entry must be 16 bytes, got {}",
        data.len()
      )));
    }

    Ok(Self {
      boot_indicator: data[0],
      start_chs: [data[1], data[2], data[3]],
      partition_type: data[4],
      end_chs: [data[5], data[6], data[7]],
      start_lba: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
      sector_count: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
    })
  }

  /// Return `true` when the partition entry is unused.
  pub fn is_unused(self) -> bool {
    self.partition_type == PARTITION_TYPE_EMPTY || self.sector_count == 0
  }

  /// Return `true` when the entry marks a bootable partition.
  pub fn is_bootable(self) -> bool {
    self.boot_indicator == 0x80
  }

  /// Return `true` when the entry points to an extended partition container.
  pub fn is_extended(self) -> bool {
    matches!(
      self.partition_type,
      PARTITION_TYPE_EXTENDED_CHS | PARTITION_TYPE_EXTENDED_LBA | PARTITION_TYPE_EXTENDED_LINUX
    )
  }

  /// Return `true` when the entry is GPT-protective.
  pub fn is_protective(self) -> bool {
    self.partition_type == PARTITION_TYPE_GPT_PROTECTIVE
  }

  /// Return the generic volume role for a primary entry.
  pub fn primary_role(self) -> VolumeRole {
    if self.is_protective() {
      VolumeRole::Protective
    } else if self.is_extended() {
      VolumeRole::ExtendedContainer
    } else {
      VolumeRole::Primary
    }
  }

  /// Compute a byte span using an absolute LBA and bytes-per-sector value.
  pub fn span_at(self, absolute_start_lba: u64, bytes_per_sector: u32) -> Result<VolumeSpan> {
    if self.sector_count == 0 {
      return Err(Error::InvalidFormat(
        "mbr partition entry has zero sectors".to_string(),
      ));
    }

    let byte_offset = absolute_start_lba
      .checked_mul(u64::from(bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("mbr partition offset overflow".to_string()))?;
    let byte_size = u64::from(self.sector_count)
      .checked_mul(u64::from(bytes_per_sector))
      .ok_or_else(|| Error::InvalidRange("mbr partition size overflow".to_string()))?;

    Ok(VolumeSpan::new(byte_offset, byte_size))
  }
}

/// Where an MBR partition entry originates from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbrPartitionOrigin {
  /// Primary table entry from the main MBR sector.
  Primary,
  /// Logical entry discovered through the EBR chain.
  Logical,
}

/// Parsed MBR partition metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbrPartitionInfo {
  /// Generic volume record.
  pub record: VolumeRecord,
  /// Where the partition entry originated from.
  pub origin: MbrPartitionOrigin,
  /// Whether the partition is marked bootable.
  pub bootable: bool,
  /// Raw MBR type code.
  pub type_code: u8,
  /// Start LBA as stored in the entry.
  pub relative_start_lba: u32,
  /// Absolute start LBA on the backing image.
  pub absolute_start_lba: u64,
  /// Sector count.
  pub sector_count: u32,
}

impl MbrPartitionInfo {
  /// Build partition metadata from a parsed entry.
  pub fn from_entry(
    index: usize, entry: MbrPartitionEntry, absolute_start_lba: u64, role: VolumeRole,
    origin: MbrPartitionOrigin, bytes_per_sector: u32,
  ) -> Result<Self> {
    let span = entry.span_at(absolute_start_lba, bytes_per_sector)?;
    let record = VolumeRecord::new(index, span, role);

    Ok(Self {
      record,
      origin,
      bootable: entry.is_bootable(),
      type_code: entry.partition_type,
      relative_start_lba: entry.start_lba,
      absolute_start_lba,
      sector_count: entry.sector_count,
    })
  }

  /// Build partition metadata for a primary entry.
  pub fn from_primary(
    index: usize, entry: MbrPartitionEntry, bytes_per_sector: u32,
  ) -> Result<Self> {
    Self::from_entry(
      index,
      entry,
      u64::from(entry.start_lba),
      entry.primary_role(),
      MbrPartitionOrigin::Primary,
      bytes_per_sector,
    )
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_partition_entry_fields() {
    let entry = MbrPartitionEntry::parse(&[
      0x80, 0x20, 0x21, 0x00, 0x07, 0xDF, 0x13, 0x0C, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x03,
      0x00,
    ])
    .unwrap();

    assert!(entry.is_bootable());
    assert_eq!(entry.partition_type, 0x07);
    assert_eq!(entry.start_lba, 2048);
    assert_eq!(entry.sector_count, 204800);
  }

  #[test]
  fn classifies_extended_and_protective_entries() {
    let extended = MbrPartitionEntry::parse(&[
      0x00, 0x00, 0x00, 0x00, 0x0F, 0, 0, 0, 0x34, 0x12, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    ])
    .unwrap();
    let protective =
      MbrPartitionEntry::parse(&[0x00, 0, 0, 0, 0xEE, 0, 0, 0, 0x01, 0, 0, 0, 0xFF, 0, 0, 0])
        .unwrap();

    assert!(extended.is_extended());
    assert_eq!(extended.primary_role(), VolumeRole::ExtendedContainer);
    assert!(protective.is_protective());
    assert_eq!(protective.primary_role(), VolumeRole::Protective);
  }
}
